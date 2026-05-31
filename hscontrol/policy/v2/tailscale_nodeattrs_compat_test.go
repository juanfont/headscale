// This file implements a data-driven test runner for nodeAttrs
// compatibility tests. It loads HuJSON golden files from
// testdata/nodeattrs_results/nodeattrs-*.hujson, captured from a
// Tailscale-hosted control plane, and compares headscale's
// `compileNodeAttrs` output against each captured netmap's SelfNode.CapMap.
//
// Each file is a testcapture.Capture containing:
//   - A full policy with a `nodeAttrs` block (and optionally `ipPool`)
//   - The expected per-node netmap from SaaS, including the cap map
//
// Tests known to fail due to unimplemented features are skipped with a
// TODO comment explaining the root cause. As headscale's nodeAttrs
// implementation grows, tests should be removed from the skip list.
//
// Test data source: testdata/nodeattrs_results/nodeattrs-*.hujson
// Source format:    github.com/juanfont/headscale/hscontrol/types/testcapture

package v2

import (
	"net/netip"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/types/testcapture"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"tailscale.com/tailcfg"
	"tailscale.com/types/views"
)

// nodeAttrsCompatUsers returns the three norse-god users the capture
// tool's anonymizer rewrites the SaaS users into.
func nodeAttrsCompatUsers() types.Users {
	return types.Users{
		{Model: gorm.Model{ID: 1}, Name: "odin", Email: "odin@example.com"},
		{Model: gorm.Model{ID: 2}, Name: "thor", Email: "thor@example.org"},
		{Model: gorm.Model{ID: 3}, Name: "freya", Email: "freya@example.com"},
	}
}

// buildNodeAttrsNodesFromCapture mirrors the grants compat helper: each
// scenario's clean-slate run produces a different IP for the same
// hostname, so the node set comes from the capture's topology rather
// than a fixed table.
//
// [tailcfg.Hostinfo.RoutableIPs] and [types.Node.ApprovedRoutes]
// round-trip from the topology so [types.NodeView.IsExitNode] reflects
// the captured approval state — the suggest-exit-node peer-cap rule
// only fires when a peer's exit routes are approved.
func buildNodeAttrsNodesFromCapture(
	t *testing.T,
	users types.Users,
	tf *testcapture.Capture,
) types.Nodes {
	t.Helper()

	nodes := make(types.Nodes, 0, len(tf.Topology.Nodes))
	autoID := 1

	for _, nodeDef := range tf.Topology.Nodes {
		node := &types.Node{
			ID:        types.NodeID(autoID), //nolint:gosec
			GivenName: nodeDef.Hostname,
			IPv4:      ptrAddr(nodeDef.IPv4),
			IPv6:      ptrAddr(nodeDef.IPv6),
			Tags:      nodeDef.Tags,
			Hostinfo: &tailcfg.Hostinfo{
				RoutableIPs: parsePrefixes(t, nodeDef.Hostname+".RoutableIPs", nodeDef.RoutableIPs),
			},
			ApprovedRoutes: parsePrefixes(t, nodeDef.Hostname+".ApprovedRoutes", nodeDef.ApprovedRoutes),
		}
		autoID++

		if len(nodeDef.Tags) == 0 && nodeDef.User != "" {
			for i := range users {
				if users[i].Name == nodeDef.User {
					node.User = &users[i]
					node.UserID = &users[i].ID

					break
				}
			}
		}

		nodes = append(nodes, node)
	}

	return nodes
}

// parsePrefixes converts a slice of CIDR strings into [netip.Prefix].
// Bad entries fail loud through t.Fatalf — the topology files are
// authoritative routing data, so a malformed CIDR is a testdata bug
// that should surface, not silently drop the route and corrupt
// downstream IsExitNode checks.
func parsePrefixes(t *testing.T, name string, s []string) []netip.Prefix {
	t.Helper()

	if len(s) == 0 {
		return nil
	}

	out := make([]netip.Prefix, 0, len(s))

	for _, p := range s {
		pre, err := netip.ParsePrefix(p)
		if err != nil {
			t.Fatalf("topology %q: malformed CIDR %q: %v", name, p, err)
		}

		out = append(out, pre)
	}

	return out
}

// nodeAttrsSkipReasons documents the captured scenarios SaaS accepts and
// headscale deliberately rejects at validate time. The rejection itself is
// covered by TestNodeAttrsValidate; this list keeps the compat diff focused
// on shapes both control planes agree on.
//
//	IPPOOL_ALLOCATOR — `ipPool` is parsed but the allocator that
//	    consumes it is not yet implemented.
//	FUNNEL_NOT_SUPPORTED — `funnel` cap is rejected pending the DNS /
//	    ACME machinery the feature requires.
//	NO_USER_ROLES — `autogroup:admin` and `autogroup:owner` depend on
//	    user-role and tailnet-ownership concepts headscale does not
//	    model.
var nodeAttrsSkipReasons = map[string]string{
	"nodeattrs-ippool-g1-admin":            "IPPOOL_ALLOCATOR",
	"nodeattrs-ippool-g2-group":            "IPPOOL_ALLOCATOR",
	"nodeattrs-ippool-g3-mixed":            "IPPOOL_ALLOCATOR",
	"nodeattrs-target-a10-autogroup-admin": "NO_USER_ROLES: autogroup:admin",
	"nodeattrs-target-a11-autogroup-owner": "NO_USER_ROLES: autogroup:owner",
	"nodeattrs-attr-c1-funnel":             "FUNNEL_NOT_SUPPORTED",
	"nodeattrs-funnel-f1-tag":              "FUNNEL_NOT_SUPPORTED",
	"nodeattrs-funnel-f2-user":             "FUNNEL_NOT_SUPPORTED",
}

// TestNodeAttrsCompat is a data-driven test that loads every captured
// nodeAttrs scenario and compares headscale's compiled CapMap against
// the corresponding SaaS-rendered netmap.
func TestNodeAttrsCompat(t *testing.T) {
	t.Parallel()

	files, err := filepath.Glob(
		filepath.Join("testdata", "nodeattrs_results", "*.hujson"),
	)
	require.NoError(t, err, "failed to glob test files")

	if len(files) == 0 {
		t.Skip(
			"testdata/nodeattrs_results is empty — re-run the capture " +
				"tool against the nodeattrs scenario set and copy the " +
				"anonymized results into " +
				"hscontrol/policy/v2/testdata/nodeattrs_results/",
		)
	}

	t.Logf("Loaded %d nodeAttrs test files", len(files))

	users := nodeAttrsCompatUsers()

	for _, file := range files {
		tf := loadGrantTestFile(t, file)

		t.Run(tf.TestID, func(t *testing.T) {
			t.Parallel()

			if reason, ok := nodeAttrsSkipReasons[tf.TestID]; ok {
				t.Skipf("TODO: %s", reason)
			}

			nodes := buildNodeAttrsNodesFromCapture(t, users, tf)
			policyJSON := convertPolicyUserEmails(tf.Input.FullPolicy)

			if tf.Input.APIResponseCode == 400 || tf.Error {
				testNodeAttrsError(t, policyJSON, tf)

				return
			}

			testNodeAttrsSuccess(t, policyJSON, tf, users, nodes)
		})
	}
}

func testNodeAttrsError(t *testing.T, policyJSON []byte, tf *testcapture.Capture) {
	t.Helper()

	// SaaS error wording is not stable enough to compare exactly — the
	// e3-autogroup-self capture comes back as "internal server error",
	// for instance. The contract this test enforces is the weaker but
	// still-meaningful one: headscale must also refuse the policy at
	// parse or validate time.
	pol, err := unmarshalPolicy(policyJSON)
	if err != nil {
		return
	}

	err = pol.validate()
	if err != nil {
		return
	}

	wantMsg := ""
	if tf.Input.APIResponseBody != nil {
		wantMsg = tf.Input.APIResponseBody.Message
	}

	// The dispatch in TestNodeAttrsCompat fires for either
	// APIResponseCode==400 or tf.Error==true; reflect the actual
	// trigger in the diagnostic so a tf.Error scenario doesn't get
	// reported as "saas code=0".
	t.Errorf(
		"%s: expected error (api_code=%d capture_error=%t msg=%q) "+
			"but policy parsed and validated successfully",
		tf.TestID, tf.Input.APIResponseCode, tf.Error, wantMsg,
	)
}

func testNodeAttrsSuccess(
	t *testing.T,
	policyJSON []byte,
	tf *testcapture.Capture,
	users types.Users,
	nodes types.Nodes,
) {
	t.Helper()

	pol, err := unmarshalPolicy(policyJSON)
	require.NoErrorf(t, err, "%s: policy should parse", tf.TestID)
	require.NoErrorf(t, pol.validate(), "%s: policy should validate", tf.TestID)

	got, err := pol.compileNodeAttrs(users, nodes.ViewSlice())
	require.NoErrorf(t, err, "%s: compileNodeAttrs", tf.TestID)

	// Mirror the prod self-build: route function is irrelevant for CapMap.
	//
	// Taildrop.Enabled defaults to true here because every capture is
	// taken with the SaaS default Send Files state. The Tailscale v2
	// TailnetSettings API does not expose the Send Files toggle, so
	// tscap cannot vary it; the off-path is covered directly by
	// TestTaildropDisabledWithholdsFileSharingCap in servertest.
	// TODO: wire Taildrop.Enabled from tf.Input.Tailnet.Settings.FileSharing
	// once the field is added to the public TailnetSettings API.
	cfg := &types.Config{Taildrop: types.TaildropConfig{Enabled: true}}
	if v := tf.Input.Tailnet.Settings.DevicesAutoUpdatesOn; v != nil && *v {
		cfg.AutoUpdate = types.AutoUpdateConfig{Enabled: true}
	}

	emptyRoutes := func(types.NodeID) []netip.Prefix { return nil }

	selfCapMap := func(t *testing.T, node *types.Node) tailcfg.NodeCapMap {
		t.Helper()

		tn, err := node.View().TailNode(0, emptyRoutes, cfg, got[node.ID])
		require.NoErrorf(t, err, "%s/%s: TailNode", tf.TestID, node.GivenName)

		return tn.CapMap
	}

	for nodeName, capture := range tf.Captures {
		if capture.Netmap == nil || !capture.Netmap.SelfNode.Valid() {
			continue
		}

		t.Run(nodeName, func(t *testing.T) {
			node := findNodeByGivenName(nodes, nodeName)
			require.NotNilf(t, node,
				"node %q from capture not found in test setup", nodeName)

			gotSelf := stripUnmodelledTailnetStateCaps(selfCapMap(t, node))
			wantSelf := stripUnmodelledTailnetStateCaps(
				capMapFromView(capture.Netmap.SelfNode.CapMap()),
			)

			if diff := cmp.Diff(wantSelf, gotSelf, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf(
					"%s/%s: SelfNode.CapMap mismatch (-tailscale +headscale):\n%s",
					tf.TestID, nodeName, diff,
				)
			}

			for _, peer := range capture.Netmap.Peers {
				peerName := peer.ComputedName()

				peerNode := findNodeByGivenName(nodes, peerName)
				if peerNode == nil {
					// A captured peer with no matching node in the
					// constructed topology is almost always topology
					// drift — fail loud so the gap is visible instead
					// of silently dropping the comparison.
					t.Errorf("%s/%s: capture peer %q not found in topology",
						tf.TestID, nodeName, peerName)

					continue
				}

				gotPeer := stripUnmodelledTailnetStateCaps(
					PeerCapMap(peerNode.View(), got[peerNode.ID]),
				)
				wantPeer := stripUnmodelledTailnetStateCaps(
					capMapFromView(peer.CapMap()),
				)

				if diff := cmp.Diff(wantPeer, gotPeer, cmpopts.EquateEmpty()); diff != "" {
					t.Errorf(
						"%s/%s/peer=%s: Peer.CapMap mismatch (-tailscale +headscale):\n%s",
						tf.TestID, nodeName, peerName, diff,
					)
				}
			}
		})
	}
}

// capMapFromView materialises a captured CapMap view into the
// [tailcfg.NodeCapMap] shape headscale renders, so both sides of the
// diff have the same concrete type.
func capMapFromView(view views.MapSlice[tailcfg.NodeCapability, tailcfg.RawMessage]) tailcfg.NodeCapMap {
	if view.Len() == 0 {
		return nil
	}

	out := make(tailcfg.NodeCapMap, view.Len())
	for k, v := range view.All() {
		out[k] = v.AsSlice()
	}

	return out
}
