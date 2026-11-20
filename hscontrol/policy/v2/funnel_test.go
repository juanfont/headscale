package v2

import (
	"bytes"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
	"tailscale.com/tailcfg/peercap"
)

// hasIngressFrom reports whether rules carry a CapGrant giving src the
// ingress capability towards dst.
func hasIngressFrom(rules []tailcfg.FilterRule, src, dst netip.Addr) bool {
	for _, r := range rules {
		if !slices.ContainsFunc(r.SrcIPs, func(s string) bool {
			p, err := netip.ParsePrefix(s)
			if err != nil {
				a, err := netip.ParseAddr(s)

				return err == nil && a == src
			}

			return p.Contains(src)
		}) {
			continue
		}

		for _, cg := range r.CapGrant {
			if _, ok := cg.CapMap[peercap.Ingress]; !ok {
				continue
			}

			if slices.ContainsFunc(cg.Dsts, func(p netip.Prefix) bool { return p.Contains(dst) }) {
				return true
			}
		}
	}

	return false
}

func TestFunnelIngressGrant(t *testing.T) {
	t.Parallel()

	users := nodeAttrsTestUsers()
	nodes := nodeAttrsTestNodes(users)

	// alice-laptop (1) may funnel; server (3, tag:server) is the relay.
	// The ACL only lets bob reach bob, so any link between the relay and
	// alice-laptop comes from the funnel grant.
	const restricted = `{
		"tagOwners": {` + nodeAttrsTagOwners + `},
		"acls": [{"action": "accept", "src": ["bob@example.org"], "dst": ["bob@example.org:*"]}],
		"nodeAttrs": [{"target": ["alice@example.com"], "attr": ["funnel"]}]
	}`

	// Without acls or grants, everything is allowed.
	const noRules = `{
		"tagOwners": {` + nodeAttrsTagOwners + `},
		"nodeAttrs": [{"target": ["alice@example.com"], "attr": ["funnel"]}]
	}`

	relay := netip.MustParseAddr("100.64.0.3")
	alice := netip.MustParseAddr("100.64.0.1")
	bob := netip.MustParseAddr("100.64.0.2")

	tests := []struct {
		name        string
		policy      string
		relayTags   []string
		wantIngress bool
		wantPeers   bool
	}{
		{
			name:        "relay tag configured",
			policy:      restricted,
			relayTags:   []string{"tag:server"},
			wantIngress: true,
			wantPeers:   true,
		},
		{
			name:   "no relay tag",
			policy: restricted,
		},
		{
			name:      "relay tag carried by no node",
			policy:    restricted,
			relayTags: []string{"tag:absent"},
		},
		{
			name:        "policy without rules keeps allow-all",
			policy:      noRules,
			relayTags:   []string{"tag:server"},
			wantIngress: true,
			wantPeers:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			pm, err := NewPolicyManager([]byte(tt.policy), users, nodes.ViewSlice(), WithFunnelRelayTags(tt.relayTags))
			require.NoError(t, err)

			aliceRules, err := pm.FilterForNode(nodes[0].View())
			require.NoError(t, err)
			assert.Equal(t, tt.wantIngress, hasIngressFrom(aliceRules, relay, alice), "ingress from relay on alice-laptop")

			bobRules, err := pm.FilterForNode(nodes[1].View())
			require.NoError(t, err)
			assert.False(t, hasIngressFrom(bobRules, relay, bob), "bob-laptop has no funnel attribute")

			peers := pm.BuildPeerMap(nodes.ViewSlice())
			assert.Equal(t, tt.wantPeers, slices.Contains(peers[types.NodeID(3)], types.NodeID(1)), "relay sees alice-laptop")
			assert.Equal(t, tt.wantPeers, slices.Contains(peers[types.NodeID(1)], types.NodeID(3)), "alice-laptop sees relay")

			if tt.policy == noRules {
				assert.Contains(t, peers[types.NodeID(1)], types.NodeID(2), "allow-all still links alice-laptop and bob-laptop")
			}
		})
	}
}

// TestFunnelAttrWarning checks the load-time warning for a funnel nodeAttr:
// only when the server config was passed and leaves funnel disabled, not
// when nothing is known about it, as in `headscale check`.
func TestFunnelAttrWarning(t *testing.T) {
	var buf bytes.Buffer

	prev, prevLevel := log.Logger, zerolog.GlobalLevel()
	log.Logger = zerolog.New(&buf)

	zerolog.SetGlobalLevel(zerolog.WarnLevel)

	t.Cleanup(func() {
		log.Logger = prev

		zerolog.SetGlobalLevel(prevLevel)
	})

	users := nodeAttrsTestUsers()
	nodes := nodeAttrsTestNodes(users)

	pol := []byte(`{
		"tagOwners": {` + nodeAttrsTagOwners + `},
		"nodeAttrs": [{"target": ["alice@example.com"], "attr": ["funnel"]}]
	}`)

	for _, tt := range []struct {
		name     string
		opts     []Option
		wantWarn bool
	}{
		{name: "config not passed"},
		{name: "funnel disabled", opts: []Option{WithFunnelRelayTags(nil)}, wantWarn: true},
		{name: "funnel enabled", opts: []Option{WithFunnelRelayTags([]string{"tag:server"})}},
	} {
		buf.Reset()

		_, err := NewPolicyManager(pol, users, nodes.ViewSlice(), tt.opts...)
		require.NoError(t, err, tt.name)

		assert.Equal(t, tt.wantWarn, strings.Contains(buf.String(), "funnel nodeAttr has no effect"), tt.name)
	}
}
