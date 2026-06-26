package k3sic

import (
	"fmt"
	"strings"
)

// This file holds the reusable building blocks for driving the Tailscale
// Kubernetes operator inside the cluster: installing it and applying the CRs and
// workloads a test needs. Tests compose these methods rather than embedding
// kubectl/helm invocations, so adding a new operator test is a few method calls.

// ApplyManifest writes manifest into the container as /tmp/<name>.yaml and
// kubectl-applies it. It is the building block the helpers below use, and is
// exported so tests can apply ad-hoc manifests without a bespoke method.
func (k *K3sInContainer) ApplyManifest(name, manifest string) error {
	path := "/tmp/" + name + ".yaml"

	err := k.WriteFile(path, []byte(manifest))
	if err != nil {
		return fmt.Errorf("writing manifest %s: %w", name, err)
	}

	_, stderr, err := k.Execute([]string{kubectlBin, "apply", "-f", path})
	if err != nil {
		return fmt.Errorf("applying manifest %s (stderr: %s): %w", name, stderr, err)
	}

	return nil
}

// InstallOperator installs the Tailscale Kubernetes operator via Helm into the
// tailscale namespace, pointed at loginServer with the given OAuth client
// credentials. loginServer is used by the operator for both the control plane
// and the management API; for an in-test Headscale pass its HTTP endpoint by IP
// (hsic.HeadscaleInContainer.GetIPEndpoint) so the pods need no DNS or CA. The
// operator and proxy images come from ghcr at the capver-derived tag. Blocks
// (helm --wait) until the operator deployment is available.
func (k *K3sInContainer) InstallOperator(loginServer, clientID, clientSecret string) error {
	repoAdd := "helm repo add tailscale https://pkgs.tailscale.com/helmcharts && helm repo update"

	_, stderr, err := k.Execute([]string{shellBin, "-c", repoAdd})
	if err != nil {
		return fmt.Errorf("helm repo add/update (stderr: %s): %w", stderr, err)
	}

	_, stderr, err = k.Execute([]string{
		kubectlBin, "create", "namespace", tailscaleNamespace,
	})
	if err != nil {
		return fmt.Errorf("creating %s namespace (stderr: %s): %w", tailscaleNamespace, stderr, err)
	}

	// Precreate the operator-oauth Secret with --from-literal instead of the
	// chart's oauth.clientId/clientSecret: the chart interpolates those unquoted,
	// so an all-digit credential renders as a YAML number and the apiserver
	// rejects it. --from-literal always stores strings. The chart uses a Secret
	// named operator-oauth when oauth.clientId is unset.
	_, stderr, err = k.Execute([]string{
		kubectlBin, "-n", tailscaleNamespace, "create", "secret", "generic", "operator-oauth",
		"--from-literal=client_id=" + clientID,
		"--from-literal=client_secret=" + clientSecret,
	})
	if err != nil {
		return fmt.Errorf("creating operator-oauth secret (stderr: %s): %w", stderr, err)
	}

	opRepo, opTag, _ := strings.Cut(OperatorImage(), ":")
	proxyRepo, proxyTag, _ := strings.Cut(ProxyImage(), ":")

	const set = "--set-string"

	install := []string{
		"helm", "upgrade", "--install", "tailscale-operator",
		"tailscale/tailscale-operator",
		"--version", OperatorChartVersion(),
		"--namespace", tailscaleNamespace,
		set, "loginServer=" + loginServer,
		set, "operatorConfig.image.repository=" + opRepo,
		set, "operatorConfig.image.tag=" + opTag,
		set, "proxyConfig.image.repository=" + proxyRepo,
		set, "proxyConfig.image.tag=" + proxyTag,
		"--wait", "--timeout", "5m",
	}

	_, stderr, err = k.Execute(install)
	if err != nil {
		k.DumpDiagnostics()
		return fmt.Errorf("helm install operator (stderr: %s): %w", stderr, err)
	}

	// hsic serves the embedded DERP without TLS, but a proxy dials DERP over HTTPS
	// and so cannot relay through it. Pods on the k3s pod network can only reach
	// off-cluster nodes via DERP (their only endpoint is an unreachable pod IP),
	// so without this the ingress/egress proxies get no data path. The ProxyClass
	// injects TS_DEBUG_DERP_WS_CLIENT + TS_DEBUG_USE_DERP_HTTP, switching proxies to
	// plain-HTTP websocket DERP. The proxy-creating helpers below reference it.
	return k.applyDERPWebsocketProxyClass()
}

// DERPWebsocketProxyClass is the ProxyClass [InstallOperator] creates to make
// operator proxies reach the embedded (non-TLS) DERP over websocket. Proxy
// resources reference it via spec.proxyClass / the tailscale.com/proxy-class
// annotation.
const DERPWebsocketProxyClass = "headscale-derp-ws" //nolint:gosec // G101 false positive: a ProxyClass name, not a credential

func (k *K3sInContainer) applyDERPWebsocketProxyClass() error {
	manifest := fmt.Sprintf(`apiVersion: tailscale.com/v1alpha1
kind: ProxyClass
metadata:
  name: %s
spec:
  statefulSet:
    pod:
      tailscaleContainer:
        env:
          - name: TS_DEBUG_DERP_WS_CLIENT
            value: "true"
          - name: TS_DEBUG_USE_DERP_HTTP
            value: "true"
`, DERPWebsocketProxyClass)

	return k.ApplyManifest("proxyclass-"+DERPWebsocketProxyClass, manifest)
}

// DeployConnector applies a Connector CR advertising an egress subnet router for
// advertiseRoutes, tagged with tags. The operator provisions a proxy and
// registers it as a node in Headscale.
func (k *K3sInContainer) DeployConnector(name string, tags, advertiseRoutes []string) error {
	manifest := fmt.Sprintf(`apiVersion: tailscale.com/v1alpha1
kind: Connector
metadata:
  name: %s
spec:
  proxyClass: %s
  tags:
%s
  subnetRouter:
    advertiseRoutes:
%s
`, name, DERPWebsocketProxyClass, yamlList(tags, 4), yamlList(advertiseRoutes, 6))

	return k.ApplyManifest("connector-"+name, manifest)
}

// DeployProxyGroup applies a ProxyGroup CR of the given type ("ingress" or
// "egress") with replicas proxies tagged with tags. ProxyGroups are the current
// way to run a pool of operator proxies for HA ingress/egress.
func (k *K3sInContainer) DeployProxyGroup(name, proxyType string, replicas int, tags []string) error {
	manifest := fmt.Sprintf(`apiVersion: tailscale.com/v1alpha1
kind: ProxyGroup
metadata:
  name: %s
spec:
  type: %s
  replicas: %d
  proxyClass: %s
  tags:
%s
`, name, proxyType, replicas, DERPWebsocketProxyClass, yamlList(tags, 4))

	return k.ApplyManifest("proxygroup-"+name, manifest)
}

// DeployEchoServer deploys a minimal HTTP server (agnhost, served from
// registry.k8s.io to avoid Docker Hub rate limits) labelled app=<name> with a
// ClusterIP Service of the same name on port 80. Use it as the in-cluster target
// for connectivity tests; expose it to the tailnet with [ExposeServiceToTailnet].
func (k *K3sInContainer) DeployEchoServer(name string) error {
	manifest := fmt.Sprintf(`apiVersion: apps/v1
kind: Deployment
metadata:
  name: %s
spec:
  replicas: 1
  selector:
    matchLabels:
      app: %s
  template:
    metadata:
      labels:
        app: %s
    spec:
      containers:
        - name: echo
          image: registry.k8s.io/e2e-test-images/agnhost:2.47
          args: ["netexec", "--http-port=80"]
          ports:
            - containerPort: 80
---
apiVersion: v1
kind: Service
metadata:
  name: %s
spec:
  selector:
    app: %s
  ports:
    - port: 80
      targetPort: 80
`, name, name, name, name, name)

	return k.ApplyManifest("echo-"+name, manifest)
}

// ExposeServiceToTailnet creates a tailscale LoadBalancer Service named
// "<name>-ts" that exposes the pods labelled app=<name> to the tailnet, tagged
// with tags. The operator provisions an ingress proxy and registers a node, so a
// node outside the cluster (a regular tsic client) can reach the service over
// the tailnet.
func (k *K3sInContainer) ExposeServiceToTailnet(name string, tags []string) error {
	manifest := fmt.Sprintf(`apiVersion: v1
kind: Service
metadata:
  name: %s-ts
  annotations:
    tailscale.com/tags: "%s"
    tailscale.com/proxy-class: %s
spec:
  type: LoadBalancer
  loadBalancerClass: tailscale
  selector:
    app: %s
  ports:
    - port: 80
      targetPort: 80
`, name, strings.Join(tags, ","), DERPWebsocketProxyClass, name)

	return k.ApplyManifest("expose-"+name, manifest)
}

// yamlList renders items as a YAML block sequence indented by indent spaces,
// e.g. "    - tag:k8s". Returns "" for an empty list.
func yamlList(items []string, indent int) string {
	var b strings.Builder

	pad := strings.Repeat(" ", indent)
	for _, item := range items {
		fmt.Fprintf(&b, "%s- %s\n", pad, item)
	}

	return strings.TrimRight(b.String(), "\n")
}
