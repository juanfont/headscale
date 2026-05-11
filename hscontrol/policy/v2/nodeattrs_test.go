package v2

import (
	"net/netip"
	"slices"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"tailscale.com/tailcfg"
)

// nodeAttrsTestUsers returns a minimal user set: two passkey-style users on
// different domains, mirroring the production multi-domain shape so user-target
// resolution is exercised across both.
func nodeAttrsTestUsers() types.Users {
	return types.Users{
		{Model: gorm.Model{ID: 1}, Name: "alice", Email: "alice@example.com"},
		{Model: gorm.Model{ID: 2}, Name: "bob", Email: "bob@example.org"},
	}
}

// nodeAttrsTestNodes returns a fixed mix of user-owned and tagged nodes used
// by every nodeAttrs unit test. Two user-owned nodes (one per user) and three
// tagged nodes (server, client, prod) so target resolution can be exercised
// across user, group, tag, autogroup, and wildcard alias forms.
func nodeAttrsTestNodes(users types.Users) types.Nodes {
	return types.Nodes{
		{
			ID:        1,
			GivenName: "alice-laptop",
			User:      &users[0],
			UserID:    &users[0].ID,
			IPv4:      ptrAddr("100.64.0.1"),
			IPv6:      ptrAddr("fd7a:115c:a1e0::1"),
			Hostinfo:  &tailcfg.Hostinfo{},
		},
		{
			ID:        2,
			GivenName: "bob-laptop",
			User:      &users[1],
			UserID:    &users[1].ID,
			IPv4:      ptrAddr("100.64.0.2"),
			IPv6:      ptrAddr("fd7a:115c:a1e0::2"),
			Hostinfo:  &tailcfg.Hostinfo{},
		},
		{
			ID:        3,
			GivenName: "server",
			Tags:      []string{"tag:server"},
			IPv4:      ptrAddr("100.64.0.3"),
			IPv6:      ptrAddr("fd7a:115c:a1e0::3"),
			Hostinfo:  &tailcfg.Hostinfo{},
		},
		{
			ID:        4,
			GivenName: "client",
			Tags:      []string{"tag:client"},
			IPv4:      ptrAddr("100.64.0.4"),
			IPv6:      ptrAddr("fd7a:115c:a1e0::4"),
			Hostinfo:  &tailcfg.Hostinfo{},
		},
		{
			ID:        5,
			GivenName: "prod",
			Tags:      []string{"tag:prod"},
			IPv4:      ptrAddr("100.64.0.5"),
			IPv6:      ptrAddr("fd7a:115c:a1e0::5"),
			Hostinfo:  &tailcfg.Hostinfo{},
		},
	}
}

const nodeAttrsTagOwners = `"tag:server": ["alice@example.com"],
		"tag:client": ["alice@example.com"],
		"tag:prod":   ["alice@example.com"]`

func TestNodeAttrsCompile(t *testing.T) {
	t.Parallel()

	capMap := func(c tailcfg.NodeCapability) tailcfg.NodeCapMap {
		return tailcfg.NodeCapMap{c: nil}
	}

	tests := []struct {
		name string
		// extra is appended inside the policy block alongside tagOwners.
		extra string
		want  map[types.NodeID]tailcfg.NodeCapMap
	}{
		{
			name:  "wildcard target hits every node",
			extra: `"nodeAttrs": [{"target": ["*"], "attr": ["randomize-client-port"]}]`,
			want: map[types.NodeID]tailcfg.NodeCapMap{
				1: capMap(tailcfg.NodeAttrRandomizeClientPort),
				2: capMap(tailcfg.NodeAttrRandomizeClientPort),
				3: capMap(tailcfg.NodeAttrRandomizeClientPort),
				4: capMap(tailcfg.NodeAttrRandomizeClientPort),
				5: capMap(tailcfg.NodeAttrRandomizeClientPort),
			},
		},
		{
			name:  "user target hits only that user's untagged nodes",
			extra: `"nodeAttrs": [{"target": ["alice@example.com"], "attr": ["randomize-client-port"]}]`,
			want: map[types.NodeID]tailcfg.NodeCapMap{
				1: capMap(tailcfg.NodeAttrRandomizeClientPort),
			},
		},
		{
			name:  "tag target hits only matching tagged nodes",
			extra: `"nodeAttrs": [{"target": ["tag:server"], "attr": ["drive:share", "drive:access"]}]`,
			want: map[types.NodeID]tailcfg.NodeCapMap{
				3: {
					tailcfg.NodeAttrsTaildriveShare:  nil,
					tailcfg.NodeAttrsTaildriveAccess: nil,
				},
			},
		},
		{
			name:  "autogroup:member hits untagged nodes only",
			extra: `"nodeAttrs": [{"target": ["autogroup:member"], "attr": ["randomize-client-port"]}]`,
			want: map[types.NodeID]tailcfg.NodeCapMap{
				1: capMap(tailcfg.NodeAttrRandomizeClientPort),
				2: capMap(tailcfg.NodeAttrRandomizeClientPort),
			},
		},
		{
			name:  "autogroup:tagged hits tagged nodes only",
			extra: `"nodeAttrs": [{"target": ["autogroup:tagged"], "attr": ["disable-captive-portal-detection"]}]`,
			want: map[types.NodeID]tailcfg.NodeCapMap{
				3: capMap(tailcfg.NodeAttrDisableCaptivePortalDetection),
				4: capMap(tailcfg.NodeAttrDisableCaptivePortalDetection),
				5: capMap(tailcfg.NodeAttrDisableCaptivePortalDetection),
			},
		},
		{
			name: "merging two grants on overlapping targets unions attrs",
			extra: `"nodeAttrs": [
				{"target": ["*"],          "attr": ["drive:access"]},
				{"target": ["tag:server"], "attr": ["drive:share"]}
			]`,
			want: map[types.NodeID]tailcfg.NodeCapMap{
				1: capMap(tailcfg.NodeAttrsTaildriveAccess),
				2: capMap(tailcfg.NodeAttrsTaildriveAccess),
				3: {
					tailcfg.NodeAttrsTaildriveAccess: nil,
					tailcfg.NodeAttrsTaildriveShare:  nil,
				},
				4: capMap(tailcfg.NodeAttrsTaildriveAccess),
				5: capMap(tailcfg.NodeAttrsTaildriveAccess),
			},
		},
		{
			name:  "empty entry compiles to nothing",
			extra: `"nodeAttrs": [{"target": ["*"]}]`,
			want:  nil,
		},
		{
			name:  "top-level randomizeClientPort stamps every node",
			extra: `"randomizeClientPort": true`,
			want: map[types.NodeID]tailcfg.NodeCapMap{
				1: capMap(tailcfg.NodeAttrRandomizeClientPort),
				2: capMap(tailcfg.NodeAttrRandomizeClientPort),
				3: capMap(tailcfg.NodeAttrRandomizeClientPort),
				4: capMap(tailcfg.NodeAttrRandomizeClientPort),
				5: capMap(tailcfg.NodeAttrRandomizeClientPort),
			},
		},
		{
			name: "global randomize plus per-tag entry merges",
			extra: `"randomizeClientPort": true,
				"nodeAttrs": [{"target": ["tag:server"], "attr": ["disable-captive-portal-detection"]}]`,
			want: map[types.NodeID]tailcfg.NodeCapMap{
				1: capMap(tailcfg.NodeAttrRandomizeClientPort),
				2: capMap(tailcfg.NodeAttrRandomizeClientPort),
				3: {
					tailcfg.NodeAttrRandomizeClientPort:           nil,
					tailcfg.NodeAttrDisableCaptivePortalDetection: nil,
				},
				4: capMap(tailcfg.NodeAttrRandomizeClientPort),
				5: capMap(tailcfg.NodeAttrRandomizeClientPort),
			},
		},
	}

	users := nodeAttrsTestUsers()
	nodes := nodeAttrsTestNodes(users)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			policy := `{
		"tagOwners": {` + nodeAttrsTagOwners + `},
		` + tt.extra + `
	}`

			pm, err := NewPolicyManager([]byte(policy), users, nodes.ViewSlice())
			require.NoErrorf(t, err, "policy must parse and validate:\n%s", policy)

			got, err := pm.pol.compileNodeAttrs(users, pm.nodes)
			require.NoError(t, err)

			if diff := cmp.Diff(tt.want, got, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("compileNodeAttrs (-want +got):\n%s", diff)
			}
		})
	}
}

func TestNodeAttrsValidate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		extra   string
		wantErr error
	}{
		{
			name:    "autogroup:self target rejected",
			extra:   `"nodeAttrs": [{"target": ["autogroup:self"], "attr": ["randomize-client-port"]}]`,
			wantErr: ErrNodeAttrsAutogroupNotAllowed,
		},
		{
			name:    "autogroup:admin target rejected with user-role hint",
			extra:   `"nodeAttrs": [{"target": ["autogroup:admin"], "attr": ["randomize-client-port"]}]`,
			wantErr: ErrNodeAttrsAutogroupNotAllowed,
		},
		{
			name:    "autogroup:owner target rejected with user-role hint",
			extra:   `"nodeAttrs": [{"target": ["autogroup:owner"], "attr": ["randomize-client-port"]}]`,
			wantErr: ErrNodeAttrsAutogroupNotAllowed,
		},
		{
			name:    "funnel attr rejected as unsupported",
			extra:   `"nodeAttrs": [{"target": ["*"], "attr": ["funnel"]}]`,
			wantErr: ErrNodeAttrUnsupported,
		},
		{
			name:    "ipPool set rejected as unsupported",
			extra:   `"nodeAttrs": [{"target": ["autogroup:member"], "ipPool": ["100.81.0.0/16"]}]`,
			wantErr: ErrNodeAttrIPPoolUnsupported,
		},
		{
			name:    "ipPool overlapping reserved range rejected at validate",
			extra:   `"nodeAttrs": [{"target": ["autogroup:member"], "ipPool": ["100.100.100.0/24"]}]`,
			wantErr: ErrNodeAttrsIPPoolReserved,
		},
	}

	users := nodeAttrsTestUsers()
	nodes := nodeAttrsTestNodes(users)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			policy := `{
		"tagOwners": {` + nodeAttrsTagOwners + `},
		` + tt.extra + `
	}`

			_, err := NewPolicyManager([]byte(policy), users, nodes.ViewSlice())
			require.Error(t, err)
			assert.ErrorIs(t, err, tt.wantErr)
		})
	}
}

func TestNodeAttrsIPPoolValidator(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		prefix  string
		wantErr error
	}{
		{name: "in cgnat", prefix: "100.81.0.0/16"},
		{name: "outside cgnat", prefix: "10.0.0.0/8", wantErr: ErrNodeAttrsIPPoolOutOfRange},
		{name: "less specific than cgnat", prefix: "100.0.0.0/8", wantErr: ErrNodeAttrsIPPoolOutOfRange},
		{name: "whole cgnat overlaps reserved", prefix: "100.64.0.0/10", wantErr: ErrNodeAttrsIPPoolReserved},
		{name: "overlaps quad100", prefix: "100.100.100.0/24", wantErr: ErrNodeAttrsIPPoolReserved},
		{name: "overlaps ipn", prefix: "100.115.92.0/24", wantErr: ErrNodeAttrsIPPoolReserved},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := validateNodeAttrIPPool(netip.MustParsePrefix(tt.prefix))
			if tt.wantErr != nil {
				require.Error(t, err)
				assert.ErrorIs(t, err, tt.wantErr)

				return
			}

			require.NoError(t, err)
		})
	}
}

func TestNodesWithChangedCapMap(t *testing.T) {
	t.Parallel()

	users := nodeAttrsTestUsers()
	nodes := nodeAttrsTestNodes(users)

	policyA := `{
		"tagOwners": {` + nodeAttrsTagOwners + `},
		"nodeAttrs": [{
			"target": ["tag:server"],
			"attr":   ["randomize-client-port"]
		}]
	}`

	pm, err := NewPolicyManager([]byte(policyA), users, nodes.ViewSlice())
	require.NoError(t, err)

	initial := pm.NodesWithChangedCapMap()
	slices.Sort(initial)
	assert.Equal(t, []types.NodeID{3}, initial,
		"first build reports every node with a non-empty CapMap")

	// Swap targets: server loses the attr, client and prod gain it.
	policyB := `{
		"tagOwners": {` + nodeAttrsTagOwners + `},
		"nodeAttrs": [{
			"target": ["tag:client", "tag:prod"],
			"attr":   ["randomize-client-port"]
		}]
	}`

	changed, err := pm.SetPolicy([]byte(policyB))
	require.NoError(t, err)
	require.True(t, changed)

	delta := pm.NodesWithChangedCapMap()
	slices.Sort(delta)
	assert.Equal(t, []types.NodeID{3, 4, 5}, delta,
		"server lost the cap, client and prod gained it -- diff is the symmetric difference")

	assert.Empty(t, pm.NodesWithChangedCapMap(),
		"NodesWithChangedCapMap drains its buffer on read")

	// Reload the same bytes. updateLocked still runs, but no node's
	// CapMap hash should change.
	_, err = pm.SetPolicy([]byte(policyB))
	require.NoError(t, err)

	assert.Empty(t, pm.NodesWithChangedCapMap(),
		"reloading the same policy must not produce CapMap diffs")
}
