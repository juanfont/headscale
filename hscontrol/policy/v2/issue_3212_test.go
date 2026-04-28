// Tests pinned against tscap captures for juanfont/headscale#3212.
//
// The captures were taken on 2026-04-28 against a live Tailscale SaaS
// tailnet. They reproduce the literal #3212 setup: an ACL granting
// access to autogroup:internet:* combined with autoApprovers.exitNode
// approving exit routes on tagged exit nodes. SaaS surfaces those exit
// nodes as peers in the ACL source's netmap with 0.0.0.0/0 and ::/0 in
// AllowedIPs. Headscale must do the same — that is the user-visible UX
// driving `tailscale exit-node list`.
//
// Captures live under testdata/issue_3212/ rather than testdata/
// routes_results/ so the broader TestRoutesCompat / *PeerAllowedIPs /
// *ReduceRoutes machinery does not pull them in. Those tests assume a
// PacketFilterRules wire format (CIDR prefix per dest entry) that
// differs from what SaaS emits for autogroup:internet (range form per
// IPSet range — e.g. "0.0.0.0-9.255.255.255"). Aligning that wire
// format is tracked separately; the #3212 fix is about peer
// visibility, not packet-filter encoding.

package v2

import (
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/types/testcapture"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/net/tsaddr"
)

// TestIssue3212AutogroupInternetExitVisibility loads the b17/b18
// SaaS captures and asserts headscale's BuildPeerMap surfaces every
// exit-route advertiser to every ACL-source node — matching the peer
// list in the captured netmap.
//
// The bug fixed by this PR (#3212) was that headscale skipped
// autogroup:internet during FilterRule compilation, which silently
// dropped the matchers that Node.CanAccess reads via DestsIsTheInternet.
// The captures pin the SaaS-equivalent expectation as a regression
// guard so the same skip cannot sneak back in unnoticed.
func TestIssue3212AutogroupInternetExitVisibility(t *testing.T) {
	t.Parallel()

	files := []string{
		"routes-b17-autogroup-internet-with-exit-autoapprover",
		"routes-b18-autogroup-internet-wildcard-src-with-exit-autoapprover",
	}

	for _, testID := range files {
		path := filepath.Join(
			"testdata", "issue_3212", testID+".hujson",
		)
		tf := loadRoutesTestFile(t, path)

		t.Run(tf.TestID, func(t *testing.T) {
			t.Parallel()

			users, nodes := buildRoutesUsersAndNodes(t, tf.Topology)
			policyJSON := convertPolicyUserEmails(tf.Input.FullPolicy)

			pm, err := NewPolicyManager(
				policyJSON, users, nodes.ViewSlice(),
			)
			require.NoErrorf(t, err,
				"%s: failed to create PolicyManager", tf.TestID,
			)

			peerMap := pm.BuildPeerMap(nodes.ViewSlice())

			expected := expectedExitPeerVisibility(t, tf, nodes)
			require.NotEmptyf(t, expected,
				"%s: capture exposes no source→exit relationships — "+
					"the test is meaningless if SaaS itself never "+
					"surfaced an exit node to a source",
				tf.TestID,
			)

			for srcName, exitNames := range expected {
				srcNode := findNodeByGivenName(nodes, srcName)
				require.NotNilf(t, srcNode,
					"%s: src node %q missing from topology",
					tf.TestID, srcName,
				)

				peerIDs := make(
					map[types.NodeID]struct{},
					len(peerMap[srcNode.ID]),
				)
				for _, p := range peerMap[srcNode.ID] {
					peerIDs[p.ID()] = struct{}{}
				}

				for _, exitName := range exitNames {
					exitNode := findNodeByGivenName(nodes, exitName)
					require.NotNilf(t, exitNode,
						"%s: exit node %q missing from topology",
						tf.TestID, exitName,
					)

					_, found := peerIDs[exitNode.ID]
					assert.Truef(t, found,
						"%s: source %q must see exit node %q "+
							"as a peer via the autogroup:internet "+
							"ACL — Tailscale SaaS does (#3212)",
						tf.TestID, srcName, exitName,
					)
				}
			}
		})
	}
}

// expectedExitPeerVisibility extracts (source-node, exit-node) pairs
// the capture's netmaps witness. A node is treated as an exit-route
// advertiser when its ApprovedRoutes contain 0.0.0.0/0 or ::/0;
// a (source, exit) pair is recorded when the source's captured netmap
// lists the advertiser as a peer with 0.0.0.0/0 or ::/0 in AllowedIPs.
func expectedExitPeerVisibility(
	t *testing.T,
	tf *testcapture.Capture,
	nodes types.Nodes,
) map[string][]string {
	t.Helper()

	v4Exit := tsaddr.AllIPv4()
	v6Exit := tsaddr.AllIPv6()

	exitAdvertisers := make(map[string]bool)

	for _, n := range nodes {
		if slices.Contains(n.ApprovedRoutes, v4Exit) ||
			slices.Contains(n.ApprovedRoutes, v6Exit) {
			exitAdvertisers[n.GivenName] = true
		}
	}

	expected := make(map[string][]string)

	for srcName, capture := range tf.Captures {
		if capture.Netmap == nil {
			continue
		}

		var seen []string

		for _, peer := range capture.Netmap.Peers {
			peerName := strings.Split(peer.Name(), ".")[0]

			if !exitAdvertisers[peerName] {
				continue
			}

			peerAllowed := peer.AllowedIPs().AsSlice()
			if !slices.Contains(peerAllowed, v4Exit) &&
				!slices.Contains(peerAllowed, v6Exit) {
				continue
			}

			seen = append(seen, peerName)
		}

		if len(seen) > 0 {
			expected[srcName] = seen
		}
	}

	return expected
}
