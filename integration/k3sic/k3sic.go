// Package k3sic wraps a single-container k3s cluster (server + agent) as a
// privileged sibling container on the host docker daemon, like the
// DERP-in-container wrapper in the dsic package.
//
// It exists so that integration tests can install the real Tailscale
// Kubernetes operator (via its Helm chart) into a real Kubernetes cluster and
// point it at an in-test Headscale. k3s bundles kubectl and we run helm inside
// the container through Execute, so the host dev shell needs no kube tooling.
//
// The operator is pointed at Headscale over plain HTTP (see
// hsic.WithoutTLS), so the operator and proxy pods need no CA: there is no
// image baking and no CoreDNS hostname mapping. To run instead against a TLS
// Headscale with a private CA, see tls-ca-baking.md.
//
// The harness runs as sibling containers on the host docker daemon (the
// test-suite container has the host docker socket bind-mounted); it is NOT
// docker-in-docker. We therefore run the purpose-built single-container k3s image
// as one more privileged sibling joined to the scenario networks, rather than using
// k3d/kind which shell out to the docker daemon and fight the sibling model.
// Privileged is the harness-wide norm here, not a k3s-specific escalation: the
// tsic (client) and dsic (DERP) containers run privileged too (see
// dockertestutil.DockerAllowNetworkAdministration).
package k3sic

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"runtime"
	"strings"
	"time"

	"github.com/juanfont/headscale/hscontrol/capver"
	"github.com/juanfont/headscale/integration/dockertestutil"
	"github.com/juanfont/headscale/integration/integrationutil"
	"github.com/ory/dockertest/v3"
	"github.com/ory/dockertest/v3/docker"
	"tailscale.com/util/rands"
)

const (
	k3sicHashLength = 6

	// K3sImage is the single-container k3s server+agent image, pinned on ghcr (no
	// anonymous Docker Hub rate limit). Pinned rather than resolved from the k3s
	// stable channel because that channel floats the k8s minor unpredictably and
	// would outrun the cgroup-v2 and br_netfilter workarounds below. Bump by hand.
	K3sImage = "ghcr.io/k3s-io/k3s:v1.35.5-k3s1"

	// operatorImageRepo and proxyImageRepo are the ghcr-hosted operator and
	// proxy images. ghcr is used instead of Docker Hub to avoid anonymous pull
	// rate limits; the pods pull these directly.
	operatorImageRepo = "ghcr.io/tailscale/k8s-operator"
	proxyImageRepo    = "ghcr.io/tailscale/tailscale"

	dockerExecuteTimeout = 300 * time.Second

	// helmVersionFallback is used when the latest helm release cannot be
	// resolved at runtime (see resolveHelmVersion). The image ships no helm and
	// cannot fetch it itself, so we inject a binary that matches the container
	// arch.
	helmVersionFallback = "v3.19.1"

	// kubeconfigPath is where k3s writes the kubeconfig (see RunOptions.Env);
	// helm needs it pointed explicitly, kubectl finds it by default.
	kubeconfigPath = "/etc/rancher/k3s/k3s.yaml"

	// kubectlBin is the in-container kubectl the k3s image ships on PATH.
	kubectlBin = "kubectl"

	// shellBin is the in-container shell used for compound commands.
	shellBin = "/bin/sh"

	// tailscaleNamespace is where the operator and its proxies are installed.
	tailscaleNamespace = "tailscale"

	// kubeSystemNamespace holds CoreDNS and the rest of the k3s system addons.
	kubeSystemNamespace = "kube-system"
)

var (
	errHelmDownload     = errors.New("helm download failed")
	errHelmNotInTarball = errors.New("helm binary not found in release tarball")

	errNoKubeDNSEndpoints = errors.New("kube-dns Service has no ready endpoints yet")
)

// OperatorImageTag is the image tag the operator and proxy images use, derived
// from the Tailscale minor Headscale tracks via capver (e.g. "v1.98"). The
// operator shares the Tailscale release train, so this keeps the images and the
// Helm chart in lockstep with the client versions Headscale is tested against,
// without a hand-pinned constant. The tag is a rolling tag within the minor.
func OperatorImageTag() string {
	return capver.TailscaleLatestMajorMinor(1, false)[0]
}

// OperatorImage and ProxyImage are the ghcr operator/proxy image references the
// test wires into the Helm chart.
func OperatorImage() string { return operatorImageRepo + ":" + OperatorImageTag() }
func ProxyImage() string    { return proxyImageRepo + ":" + OperatorImageTag() }

// OperatorChartVersion is the Helm chart version constraint matching the derived
// minor; helm resolves the latest patch in that line. The top-level loginServer
// value the operator needs to target Headscale instead of the Tailscale SaaS
// first shipped in chart 1.98.4.
func OperatorChartVersion() string {
	return strings.TrimPrefix(OperatorImageTag(), "v") + ".*"
}

// K3sInContainer represents a k3s cluster running in a single privileged
// container (K3sInContainer, hence k3sic).
type K3sInContainer struct {
	hostname string

	pool      *dockertest.Pool
	container *dockertest.Resource
	networks  []*dockertest.Network
}

// New starts a new [K3sInContainer] joined to the given networks.
func New(
	pool *dockertest.Pool,
	networks []*dockertest.Network,
) (*K3sInContainer, error) {
	hash := rands.HexString(k3sicHashLength)

	// Include the run ID in the hostname for easier identification of which
	// test run owns this container, matching the dsic/tsic convention.
	runID := dockertestutil.GetIntegrationRunID()

	var hostname string

	if runID != "" {
		runIDShort := runID[len(runID)-6:]
		hostname = fmt.Sprintf("k3s-%s-%s", runIDShort, hash)
	} else {
		hostname = "k3s-" + hash
	}

	k := &K3sInContainer{
		hostname: hostname,
		pool:     pool,
		networks: networks,
	}

	// Pull the k3s image (ghcr, not built) via PullWithAuth, as hsic does for
	// prebuilt/pulled images.
	err := dockertestutil.PullWithAuth(pool, K3sImage)
	if err != nil {
		return nil, fmt.Errorf("pulling %s: %w", K3sImage, err)
	}

	repo, tag, ok := strings.Cut(K3sImage, ":")
	if !ok {
		return nil, fmt.Errorf("invalid k3s image reference %q", K3sImage) //nolint:err113
	}

	runOptions := &dockertest.RunOptions{
		Name:       hostname,
		Repository: repo,
		Tag:        tag,
		Networks:   networks,
		// "server" runs both the control plane and a built-in agent in one
		// container. --disable traefik/servicelb/metrics-server keeps the
		// cluster lean: the test only needs the API server and the ability to
		// schedule the operator pods. --tls-san pins the hostname into the
		// apiserver cert (not strictly needed since we exec kubectl in-container,
		// but harmless and future-proof).
		Cmd: []string{
			"server",
			"--disable", "traefik",
			"--disable", "servicelb",
			"--disable", "metrics-server",
			"--disable-network-policy",
			"--snapshotter", "native",
			"--tls-san", hostname,
		},
		Env: []string{
			"K3S_KUBECONFIG_OUTPUT=" + kubeconfigPath,
			"K3S_KUBECONFIG_MODE=0644",
		},
	}

	// Stamp the run-id label or the reaper leaks the container.
	dockertestutil.DockerAddIntegrationLabels(runOptions, "k3s")

	// dockertest does not handle pre-existing containers well; make sure a
	// stale one with this name is gone first.
	err = pool.RemoveContainerByName(hostname)
	if err != nil {
		return nil, err
	}

	container, err := pool.RunWithOptions(
		runOptions,
		dockertestutil.DockerRestartPolicy,
		// Privileged + NET_ADMIN: k3s manages iptables/ipvs, mounts cgroups and
		// runs containerd. This is the same knob dsic uses for the DERP server.
		dockertestutil.DockerAllowNetworkAdministration,
		withK3sHostConfig,
	)
	if err != nil {
		return nil, fmt.Errorf("%s starting k3s container: %w", hostname, err)
	}

	log.Printf("Created %s container\n", hostname)

	k.container = container

	// Make ClusterIP DNAT work before k3s programs kube-proxy rules; without it
	// in-cluster DNS times out on hosts where br_netfilter is not preloaded.
	k.ensureBridgeNetfilter()

	return k, nil
}

// withK3sHostConfig sets the HostConfig knobs k3s needs beyond
// privileged/NET_ADMIN: a tmpfs on /run and /var/run, which the k3s image
// expects.
//
// It deliberately does NOT bind-mount the host /sys/fs/cgroup. On a cgroup-v2
// host, bind-mounting the host cgroup tree into a container that keeps its own
// (private) cgroup namespace makes the cgroup root visible to the container
// disagree with the namespace runc places workload pods under. The kubelet can
// then start (the apiserver and node go Ready), but every workload pod fails to
// create its sandbox with "failed to apply cgroup configuration: ...
// cgroup.procs: no such file or directory", so nothing the operator schedules
// ever runs. Leaving the bind-mount off lets the privileged k3s entrypoint set
// up cgroup-v2 delegation within its own namespace, which it is
// designed to do, and workload pods schedule normally.
func withK3sHostConfig(config *docker.HostConfig) {
	config.Tmpfs = map[string]string{
		"/run":     "",
		"/var/run": "",
	}

	// Bind the host kernel modules read-only so the container can load
	// br_netfilter (see ensureBridgeNetfilter). Without bridge netfilter,
	// kube-proxy's ClusterIP DNAT rules do not apply to bridged pod-to-pod
	// traffic, so kube-dns (and every other Service) is unreachable from pods —
	// the in-cluster DNS timeout seen on the arm64 CI runner. The container
	// shares the host kernel, so the modules match.
	config.Binds = append(config.Binds, "/lib/modules:/lib/modules:ro")
}

// ensureBridgeNetfilter loads br_netfilter and enables the sysctls that make
// kube-proxy's ClusterIP DNAT apply to bridged pod-to-pod traffic. On a host
// where the module is already loaded (e.g. the amd64 dev box, where Docker
// loads it for bridge networks) these are no-ops; on the arm64 CI runner the
// module is absent and pods cannot reach any Service IP — kube-dns included —
// so in-cluster DNS times out. Best-effort: k3s also loads the module, and a
// genuinely missing module surfaces in DumpDiagnostics rather than here.
func (k *K3sInContainer) ensureBridgeNetfilter() {
	for _, cmd := range []string{
		"modprobe br_netfilter || true",
		"sysctl -w net.bridge.bridge-nf-call-iptables=1 || true",
		"sysctl -w net.bridge.bridge-nf-call-ip6tables=1 || true",
		"sysctl -w net.ipv4.ip_forward=1 || true",
	} {
		out, stderr, err := k.Execute([]string{shellBin, "-c", cmd})
		if err != nil {
			log.Printf("[k3s] %q failed: %v (stdout: %s, stderr: %s)", cmd, err, out, stderr)
		}
	}
}

// Hostname returns the hostname of the [K3sInContainer].
func (k *K3sInContainer) Hostname() string {
	return k.hostname
}

// ID returns the docker container ID of the [K3sInContainer].
func (k *K3sInContainer) ID() string {
	return k.container.Container.ID
}

// ConnectToNetwork connects the cluster container to an additional network.
func (k *K3sInContainer) ConnectToNetwork(network *dockertest.Network) error {
	return k.container.ConnectToNetwork(network)
}

// Execute runs a command inside the k3s container and returns its stdout.
// kubectl and the k3s-bundled tools (and helm, once installed via
// [K3sInContainer.InstallHelm]) are on PATH. KUBECONFIG is exported so helm,
// which (unlike the image's kubectl) does not default to the k3s config, can
// reach the cluster.
func (k *K3sInContainer) Execute(command []string) (string, string, error) {
	return dockertestutil.ExecuteCommand(
		k.container,
		command,
		[]string{"KUBECONFIG=" + kubeconfigPath},
		dockertestutil.ExecuteCommandTimeout(dockerExecuteTimeout),
	)
}

// WriteFile saves a file inside the container.
func (k *K3sInContainer) WriteFile(path string, data []byte) error {
	return integrationutil.WriteFileToContainer(k.pool, k.container, path, data)
}

// WaitForRunning blocks until the cluster is ready to schedule DNS-dependent
// workloads: the kube-apiserver is serving, the single node reports Ready, and
// in-cluster DNS is servable (CoreDNS rolled out with a backed kube-dns
// Service). Gating on DNS here pins a missing-DNS failure at its source rather
// than letting the operator crashloop on an opaque lookup timeout.
func (k *K3sInContainer) WaitForRunning() error {
	log.Printf("waiting for k3s API server in %s to be ready", k.hostname)

	err := k.pool.Retry(func() error {
		// `kubectl get --raw=/readyz` returns "ok" once the apiserver is up.
		out, _, err := k.Execute([]string{
			kubectlBin, "get", "--raw=/readyz",
		})
		if err != nil {
			return fmt.Errorf("k3s apiserver not ready: %w", err)
		}

		if !strings.Contains(out, "ok") {
			return fmt.Errorf("k3s apiserver readyz returned %q", strings.TrimSpace(out)) //nolint:err113
		}

		// Wait for the node object to exist and be Ready before returning so
		// pods can actually be scheduled.
		nodeOut, _, err := k.Execute([]string{
			kubectlBin, "get", "nodes", "--no-headers",
		})
		if err != nil {
			return fmt.Errorf("k3s node not ready: %w", err)
		}

		if !strings.Contains(nodeOut, " Ready") {
			return fmt.Errorf("k3s node not Ready yet: %q", strings.TrimSpace(nodeOut)) //nolint:err113
		}

		return nil
	})
	if err != nil {
		return err
	}

	return k.waitForClusterDNS()
}

// InstallHelm installs the helm binary into the container so the operator can be
// installed. The k3s image ships kubectl but not helm, has no curl, and its
// busybox wget cannot do HTTPS, so we download helm in the test process (which
// has network egress) and inject the binary. helm's own HTTPS client then
// fetches the operator chart from inside the container.
func (k *K3sInContainer) InstallHelm() error {
	bin, err := fetchHelmBinary(resolveHelmVersion(), runtime.GOARCH)
	if err != nil {
		return fmt.Errorf("fetching helm: %w", err)
	}

	err = k.WriteFile("/usr/local/bin/helm", bin)
	if err != nil {
		return fmt.Errorf("writing helm binary: %w", err)
	}

	// WriteFile uploads with mode 0; make it readable+executable.
	_, stderr, err := k.Execute([]string{"chmod", "0755", "/usr/local/bin/helm"})
	if err != nil {
		return fmt.Errorf("chmod helm (stderr: %s): %w", stderr, err)
	}

	return nil
}

// waitForClusterDNS blocks until CoreDNS is rolled out and the kube-dns Service
// has at least one ready endpoint — i.e. in-cluster name resolution is actually
// servable, which every workload (starting with the operator) depends on. k3s
// deploys CoreDNS via its addon manager shortly after the node reports Ready, so
// the deployment may not exist yet; retry until it does before checking rollout.
func (k *K3sInContainer) waitForClusterDNS() error {
	err := k.pool.Retry(func() error {
		_, stderr, err := k.Execute([]string{
			kubectlBin, "-n", kubeSystemNamespace, "get", "deployment", "coredns",
		})
		if err != nil {
			return fmt.Errorf("coredns deployment not present yet (stderr: %s): %w", stderr, err)
		}

		return nil
	})
	if err != nil {
		return fmt.Errorf("waiting for coredns deployment to appear: %w", err)
	}

	_, stderr, err := k.Execute([]string{
		kubectlBin, "-n", kubeSystemNamespace, "rollout", "status",
		"deployment/coredns", "--timeout=150s",
	})
	if err != nil {
		return fmt.Errorf("coredns did not become available (stderr: %s): %w", stderr, err)
	}

	return k.pool.Retry(func() error {
		// A populated endpoint set means a CoreDNS pod is serving :53 and
		// kube-proxy has a backend to DNAT the kube-dns ClusterIP to; empty means
		// in-cluster lookups will time out no matter how long a client waits.
		out, stderr, err := k.Execute([]string{
			kubectlBin, "-n", kubeSystemNamespace, "get", "endpoints", "kube-dns",
			"-o", "jsonpath={.subsets[*].addresses[*].ip}",
		})
		if err != nil {
			return fmt.Errorf("reading kube-dns endpoints (stderr: %s): %w", stderr, err)
		}

		if strings.TrimSpace(out) == "" {
			return errNoKubeDNSEndpoints
		}

		return nil
	})
}

// ConfigureCoreDNSHost makes in-cluster pods resolve hostname to ip via CoreDNS.
// The operator targets Headscale's control plane by IP, but the embedded DERP map
// references Headscale by hostname; without this, the proxy pods cannot resolve
// the DERP server, never connect to it, and — since they only advertise
// unreachable pod-network endpoints — get no data path to nodes outside the
// cluster. It installs a coredns-custom ConfigMap (a k3s-native extension point:
// keys ending in .server become additional server blocks), which CoreDNS's reload
// plugin picks up without a restart.
func (k *K3sInContainer) ConfigureCoreDNSHost(hostname, ip string) error {
	manifest := fmt.Sprintf(`apiVersion: v1
kind: ConfigMap
metadata:
  name: coredns-custom
  namespace: kube-system
data:
  headscale.server: |
    %s {
      hosts {
        %s %s
        fallthrough
      }
    }
`, hostname, ip, hostname)

	return k.ApplyManifest("coredns-custom", manifest)
}

// DumpDiagnostics logs cluster state useful for debugging a failed operator
// install: pod status across namespaces and the operator's own logs and events.
// Best-effort — every command's failure is logged, not returned.
func (k *K3sInContainer) DumpDiagnostics() {
	for _, c := range [][]string{
		{kubectlBin, "get", "pods", "-A", "-o", "wide"},
		{kubectlBin, "-n", tailscaleNamespace, "get", "events", "--sort-by=.lastTimestamp"},
		{kubectlBin, "-n", tailscaleNamespace, "describe", "pods"},
		{kubectlBin, "-n", tailscaleNamespace, "logs", "deployment/operator", "--tail=200"},
		// A crashlooping operator's fatal error is in the previous container.
		{kubectlBin, "-n", tailscaleNamespace, "logs", "deployment/operator", "--previous", "--tail=200"},
		{kubectlBin, "-n", tailscaleNamespace, "get", "statefulsets,pods", "-o", "wide"},
		// Proxy pods' tailscaled logs: DERP-connection and registration failures
		// (the data-path culprits) surface here, not in the operator log.
		{
			shellBin, "-c",
			"for p in $(kubectl -n " + tailscaleNamespace + " get pods -o name | grep /ts-); do " +
				"echo \"== $p ==\"; kubectl -n " + tailscaleNamespace +
				" logs $p -c tailscale --tail=80 2>&1; done",
		},
		// In-cluster DNS: the operator's first dependency. A "lookup
		// kubernetes.default.svc ... i/o timeout" crash means CoreDNS is not
		// serving, so capture its pod state, logs (Corefile parse errors land
		// here), and the Service endpoints.
		{kubectlBin, "-n", kubeSystemNamespace, "get", "pods", "-l", "k8s-app=kube-dns", "-o", "wide"},
		{kubectlBin, "-n", kubeSystemNamespace, "logs", "-l", "k8s-app=kube-dns", "--tail=100"},
		{kubectlBin, "-n", kubeSystemNamespace, "get", "endpoints", "kube-dns", "-o", "wide"},
		// Host network state behind a ClusterIP-unreachable DNS timeout: whether
		// br_netfilter is loaded and the call-iptables/forward sysctls are on, and
		// whether kube-proxy actually programmed the kube-dns DNAT rule. If CoreDNS
		// is healthy (above) but these are missing, the fault is the Service DNAT
		// path, not DNS.
		{shellBin, "-c", "lsmod | grep -E 'br_netfilter|nf_conntrack' || echo 'br_netfilter NOT loaded'"},
		{shellBin, "-c", "sysctl net.bridge.bridge-nf-call-iptables net.ipv4.ip_forward 2>&1 || true"},
		{shellBin, "-c", "iptables-save -t nat 2>/dev/null | grep -iE 'KUBE-SERVICES|kube-dns|10.43.0.10' | head -40 || echo 'no kube-dns nat rules'"},
	} {
		out, stderr, err := k.Execute(c)
		label := strings.Join(c, " ")

		if err != nil {
			log.Printf("[k3s diag] %s failed: %v (stderr: %s)", label, err, stderr)
			continue
		}

		log.Printf("[k3s diag] %s:\n%s", label, out)
	}
}

// resolveHelmVersion returns the latest published helm release tag (e.g.
// "v3.19.1"), falling back to [helmVersionFallback] if it cannot be resolved.
// get.helm.sh is not Docker Hub and has no anonymous rate limit, so a "rolling"
// latest is cheap; the fallback keeps a broken release from breaking CI.
func resolveHelmVersion() string {
	req, err := http.NewRequestWithContext(
		context.Background(), http.MethodGet, "https://get.helm.sh/helm-latest-version", nil)
	if err != nil {
		return helmVersionFallback
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return helmVersionFallback
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return helmVersionFallback
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 32))
	if err != nil {
		return helmVersionFallback
	}

	version := strings.TrimSpace(string(body))
	if !strings.HasPrefix(version, "v") {
		return helmVersionFallback
	}

	return version
}

// fetchHelmBinary downloads the helm release tarball for version and goarch and
// returns the helm binary bytes.
func fetchHelmBinary(version, goarch string) ([]byte, error) {
	url := fmt.Sprintf("https://get.helm.sh/helm-%s-linux-%s.tar.gz", version, goarch)

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: %s returned status %d", errHelmDownload, url, resp.StatusCode)
	}

	gz, err := gzip.NewReader(resp.Body)
	if err != nil {
		return nil, err
	}
	defer gz.Close()

	want := "linux-" + goarch + "/helm"
	tr := tar.NewReader(gz)

	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}

		if err != nil {
			return nil, err
		}

		if hdr.Name == want {
			return io.ReadAll(tr)
		}
	}

	return nil, fmt.Errorf("%w: %s", errHelmNotInTarball, want)
}

// Shutdown saves the container log and then runs k3s-killall in-container so
// k3s's own child processes/containers (containerd-shims, pods) do not leak,
// before purging the container itself.
func (k *K3sInContainer) Shutdown() error {
	err := k.SaveLog("/tmp/control")
	if err != nil {
		log.Printf("saving log from %s: %s", k.hostname, err)
	}

	// k3s spawns containerd and a tree of child processes inside this
	// container; the bundled k3s-killall.sh tears them down. Best-effort: the
	// Purge below removes the container regardless.
	_, _, err = k.Execute([]string{shellBin, "-c", "k3s-killall.sh || true"})
	if err != nil {
		log.Printf("running k3s-killall in %s: %s", k.hostname, err)
	}

	return k.pool.Purge(k.container)
}

// SaveLog saves the container stdout/stderr logs to a path on the host.
func (k *K3sInContainer) SaveLog(path string) error {
	_, _, err := dockertestutil.SaveLog(k.pool, k.container, path)

	return err
}
