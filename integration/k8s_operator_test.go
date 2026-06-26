package integration

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	clientv1 "github.com/juanfont/headscale/gen/client/v1"
	policyv2 "github.com/juanfont/headscale/hscontrol/policy/v2"
	"github.com/juanfont/headscale/integration/hsic"
	"github.com/juanfont/headscale/integration/integrationutil"
	"github.com/juanfont/headscale/integration/k3sic"
	"github.com/juanfont/headscale/integration/tsic"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
)

const (
	tagK8sOperator = "tag:k8s-operator"
	tagK8s         = "tag:k8s"
)

// k8sOperatorPolicy is the tagOwners policy the Tailscale Kubernetes operator
// requires: tag:k8s-operator is self/admin-owned, and the operator
// (tag:k8s-operator) owns tag:k8s so it can mint auth keys for the proxy nodes
// it spins up. The wildcard ACL lets the in-cluster proxies and the out-of-cluster
// tsic client reach each other for the connectivity checks.
func k8sOperatorPolicy() *policyv2.Policy {
	return &policyv2.Policy{
		TagOwners: policyv2.TagOwners{
			tagK8sOperator: policyv2.Owners{},
			tagK8s:         policyv2.Owners{new(policyv2.Tag(tagK8sOperator))},
		},
		ACLs: []policyv2.ACL{
			{
				Action:  "accept",
				Sources: []policyv2.Alias{policyv2.Wildcard},
				Destinations: []policyv2.AliasWithPorts{
					{Alias: policyv2.Wildcard, Ports: []tailcfg.PortRange{tailcfg.PortRangeAny}},
				},
			},
		},
	}
}

// TestK8sOperator verifies that the real Tailscale Kubernetes operator, installed
// into a real k3s cluster via its Helm chart and pointed at an in-test Headscale,
// can authenticate with OAuth client credentials, mint auth keys, and register
// nodes that then interoperate with a regular tailnet node.
//
// The operator targets Headscale over plain HTTP by IP (hsic.WithoutTLS +
// GetIPEndpoint), so the operator and proxy pods need no CA and no DNS entry for
// Headscale. See integration/k3sic/tls-ca-baking.md for the TLS variant.
//
// The cluster-side steps are reusable building blocks on k3sic.K3sInContainer
// (InstallOperator, DeployConnector, DeployEchoServer, ExposeServiceToTailnet,
// DeployProxyGroup), so further operator scenarios are a few method calls.
//
// Run it with `go run ./cmd/hi run "TestK8sOperator"`.
func TestK8sOperator(t *testing.T) {
	IntegrationSkip(t)

	// One regular user+node provides the out-of-cluster tailnet peer used by the
	// connectivity subtest; the operator registers its own nodes on top.
	spec := ScenarioSpec{
		Users:        []string{"k8s-user"},
		NodesPerUser: 1,
	}

	scenario, err := NewScenario(spec)
	require.NoError(t, err)

	defer scenario.ShutdownAssertNoPanics(t)

	err = scenario.CreateHeadscaleEnv(
		// The tsic client reaches the in-cluster proxy only via DERP (no direct
		// path to the k3s pod network), and hsic's embedded DERP is non-TLS, so the
		// client must reach DERP over plain-HTTP websockets — as the proxy pods do.
		[]tsic.Option{tsic.WithDERPOverHTTP()},
		hsic.WithTestName("k8soperator"),
		hsic.WithoutTLS(),
		hsic.WithACLPolicy(k8sOperatorPolicy()),
	)
	require.NoError(t, err)

	headscale, err := scenario.Headscale()
	require.NoError(t, err)

	// Mint an OAuth client for the operator: devices:core + auth_keys scopes,
	// tagged tag:k8s-operator. CreateOAuthClient mints the admin API key and calls
	// the v2 keys API itself.
	clientID, clientSecret, err := headscale.CreateOAuthClient(
		t.Context(),
		[]string{"devices:core", "auth_keys"},
		[]string{tagK8sOperator},
	)
	require.NoError(t, err, "creating OAuth client (server-side OAuth must be implemented)")
	require.NotEmpty(t, clientID)
	require.NotEmpty(t, clientSecret)

	// Bring up the k3s cluster on the scenario networks.
	k3s, err := k3sic.New(scenario.Pool(), scenario.Networks())
	require.NoError(t, err)

	defer func() {
		shutdownErr := k3s.Shutdown()
		if shutdownErr != nil {
			t.Logf("shutting down k3s: %s", shutdownErr)
		}
	}()

	// Registered after Shutdown so it runs first (defers are LIFO): dump cluster
	// state while it is still up if anything below fails.
	defer func() {
		if t.Failed() {
			k3s.DumpDiagnostics()
		}
	}()

	require.NoError(t, k3s.WaitForRunning())
	require.NoError(t, k3s.InstallHelm())

	// The operator reaches the control plane by IP, but the embedded DERP map
	// references Headscale by hostname; teach CoreDNS to resolve it so the proxy
	// pods can connect to DERP and get a data path to nodes outside the cluster.
	hsIP := headscale.GetIPInNetwork(scenario.Networks()[0])
	require.NoError(t, k3s.ConfigureCoreDNSHost(headscale.GetHostname(), hsIP))

	// loginServer is the in-cluster-reachable HTTP endpoint by IP; the operator
	// uses it for both the control plane and the management API.
	loginServer := headscale.GetIPEndpoint()
	require.NoError(t, k3s.InstallOperator(loginServer, clientID, clientSecret))

	t.Run("operator-registers", func(t *testing.T) {
		assert.EventuallyWithT(t, func(c *assert.CollectT) {
			nodes, err := headscale.ListNodes()
			assert.NoError(c, err)
			assert.True(c, hasNodeWithTag(nodes, tagK8sOperator),
				"expected a node tagged %s registered by the operator, got %s",
				tagK8sOperator, describeNodes(nodes))
		}, integrationutil.ScaledTimeout(180*time.Second), 2*time.Second,
			"operator node should register and be tagged "+tagK8sOperator)
	})

	t.Run("egress-connector", func(t *testing.T) {
		require.NoError(t, k3s.DeployConnector("k8s-egress", []string{tagK8s}, []string{"10.40.0.0/14"}))

		assert.EventuallyWithT(t, func(c *assert.CollectT) {
			nodes, err := headscale.ListNodes()
			assert.NoError(c, err)
			assert.True(c, hasNodeWithTag(nodes, tagK8s),
				"expected a proxy node tagged %s registered by the operator, got %s",
				tagK8s, describeNodes(nodes))
		}, integrationutil.ScaledTimeout(180*time.Second), 2*time.Second,
			"egress proxy node should register and be tagged "+tagK8s)
	})

	t.Run("ingress-service-reachable-from-tailnet", func(t *testing.T) {
		require.NoError(t, k3s.DeployEchoServer("echo"))
		require.NoError(t, k3s.ExposeServiceToTailnet("echo", []string{tagK8s}))

		clients, err := scenario.ListTailscaleClients("k8s-user")
		require.NoError(t, err)
		require.NotEmpty(t, clients)

		// The operator registers the ingress proxy as a tailnet node named after
		// the exposed Service (<namespace>-<service>, here default-echo-ts). Read
		// its IP from Headscale rather than the Service's LoadBalancer status,
		// which the operator does not populate against Headscale.
		var svcIP string

		assert.EventuallyWithT(t, func(c *assert.CollectT) {
			nodes, err := headscale.ListNodes()
			assert.NoError(c, err)

			ip, ok := nodeIPv4ByName(nodes, "echo")
			assert.True(c, ok, "ingress proxy node for echo should register, got %s", describeNodes(nodes))

			svcIP = ip
		}, integrationutil.ScaledTimeout(180*time.Second), 2*time.Second,
			"operator should register an ingress proxy node for the exposed service")

		// The out-of-cluster node reaches the in-cluster service through the proxy
		// over the tailnet. /hostname is an agnhost endpoint that returns the
		// backend pod's hostname, proving the request reached the service.
		assert.EventuallyWithT(t, func(c *assert.CollectT) {
			body, err := clients[0].Curl("http://" + svcIP + "/hostname")
			assert.NoError(c, err)
			assert.NotEmpty(c, body, "expected a response from the exposed service")
		}, integrationutil.ScaledTimeout(120*time.Second), 2*time.Second,
			"tsic node should reach the k8s-exposed service over the tailnet")
	})

	t.Run("proxy-group", func(t *testing.T) {
		nodes, err := headscale.ListNodes()
		require.NoError(t, err)

		before := countNodesWithTag(nodes, tagK8s)

		const replicas = 2

		require.NoError(t, k3s.DeployProxyGroup("ts-ingress", "ingress", replicas, []string{tagK8s}))

		// A ProxyGroup runs a pool of proxies; each replica registers its own node.
		assert.EventuallyWithT(t, func(c *assert.CollectT) {
			nodes, err := headscale.ListNodes()
			assert.NoError(c, err)
			assert.GreaterOrEqual(c, countNodesWithTag(nodes, tagK8s), before+replicas,
				"expected %d more %s nodes from the ProxyGroup, got %s",
				replicas, tagK8s, describeNodes(nodes))
		}, integrationutil.ScaledTimeout(180*time.Second), 2*time.Second,
			"ProxyGroup replicas should each register a node tagged "+tagK8s)
	})
}

// hasNodeWithTag reports whether any node carries the given tag.
func hasNodeWithTag(nodes []*clientv1.Node, tag string) bool {
	return countNodesWithTag(nodes, tag) > 0
}

// countNodesWithTag counts the nodes carrying the given tag.
func countNodesWithTag(nodes []*clientv1.Node, tag string) int {
	count := 0

	for _, node := range nodes {
		if slices.Contains(node.Tags, tag) {
			count++
		}
	}

	return count
}

// nodeIPv4ByName returns the IPv4 of the first node whose given name contains
// substr, identifying an operator-registered proxy by the Service/Connector it
// fronts (e.g. "echo" matches the default-echo-ts ingress proxy).
func nodeIPv4ByName(nodes []*clientv1.Node, substr string) (string, bool) {
	for _, node := range nodes {
		if !strings.Contains(node.GivenName, substr) {
			continue
		}

		for _, ip := range node.IpAddresses {
			addr, err := netip.ParseAddr(ip)
			if err == nil && addr.Is4() {
				return ip, true
			}
		}
	}

	return "", false
}

// describeNodes renders a compact name->tags summary for failure messages.
func describeNodes(nodes []*clientv1.Node) string {
	parts := make([]string, 0, len(nodes))
	for _, node := range nodes {
		parts = append(parts, fmt.Sprintf("%s%v", node.Name, node.Tags))
	}

	return "[" + strings.Join(parts, " ") + "]"
}
