package change

import (
	"reflect"
	"testing"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"tailscale.com/tailcfg"
)

func TestChange_FieldSync(t *testing.T) {
	r := Change{}
	fieldNames := r.boolFieldNames()

	typ := reflect.TypeFor[Change]()
	boolCount := 0

	for i := range typ.NumField() {
		if typ.Field(i).Type.Kind() == reflect.Bool {
			boolCount++
		}
	}

	if len(fieldNames) != boolCount {
		t.Fatalf("boolFieldNames() returns %d fields but struct has %d bool fields; "+
			"update boolFieldNames() when adding new bool fields", len(fieldNames), boolCount)
	}
}

func TestChange_IsEmpty(t *testing.T) {
	tests := []struct {
		name     string
		response Change
		want     bool
	}{
		{
			name:     "zero value is empty",
			response: Change{},
			want:     true,
		},
		{
			name:     "only reason is still empty",
			response: Change{Reason: "test"},
			want:     true,
		},
		{
			name:     "IncludeSelf not empty",
			response: Change{IncludeSelf: true},
			want:     false,
		},
		{
			name:     "IncludeDERPMap not empty",
			response: Change{IncludeDERPMap: true},
			want:     false,
		},
		{
			name:     "IncludeDNS not empty",
			response: Change{IncludeDNS: true},
			want:     false,
		},
		{
			name:     "IncludeDomain not empty",
			response: Change{IncludeDomain: true},
			want:     false,
		},
		{
			name:     "IncludePolicy not empty",
			response: Change{IncludePolicy: true},
			want:     false,
		},
		{
			name:     "SendAllPeers not empty",
			response: Change{SendAllPeers: true},
			want:     false,
		},
		{
			name:     "PeersChanged not empty",
			response: Change{PeersChanged: []types.NodeID{1}},
			want:     false,
		},
		{
			name:     "PeersRemoved not empty",
			response: Change{PeersRemoved: []types.NodeID{1}},
			want:     false,
		},
		{
			name:     "PeerPatches not empty",
			response: Change{PeerPatches: []*tailcfg.PeerChange{{}}},
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.response.IsEmpty()
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestChange_IsSelfOnly(t *testing.T) {
	tests := []struct {
		name     string
		response Change
		want     bool
	}{
		{
			name:     "empty is not self only",
			response: Change{},
			want:     false,
		},
		{
			name:     "IncludeSelf without TargetNode is not self only",
			response: Change{IncludeSelf: true},
			want:     false,
		},
		{
			name:     "TargetNode without IncludeSelf is not self only",
			response: Change{TargetNode: 1},
			want:     false,
		},
		{
			name:     "TargetNode with IncludeSelf is self only",
			response: Change{TargetNode: 1, IncludeSelf: true},
			want:     true,
		},
		{
			name:     "self only with SendAllPeers is not self only",
			response: Change{TargetNode: 1, IncludeSelf: true, SendAllPeers: true},
			want:     false,
		},
		{
			name:     "self only with PeersChanged is not self only",
			response: Change{TargetNode: 1, IncludeSelf: true, PeersChanged: []types.NodeID{2}},
			want:     false,
		},
		{
			name:     "self only with PeersRemoved is not self only",
			response: Change{TargetNode: 1, IncludeSelf: true, PeersRemoved: []types.NodeID{2}},
			want:     false,
		},
		{
			name:     "self only with PeerPatches is not self only",
			response: Change{TargetNode: 1, IncludeSelf: true, PeerPatches: []*tailcfg.PeerChange{{}}},
			want:     false,
		},
		{
			name: "self only with other include flags is still self only",
			response: Change{
				TargetNode:    1,
				IncludeSelf:   true,
				IncludePolicy: true,
				IncludeDNS:    true,
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.response.IsSelfOnly()
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestChange_Merge(t *testing.T) {
	tests := []struct {
		name string
		r1   Change
		r2   Change
		want Change
	}{
		{
			name: "empty merge",
			r1:   Change{},
			r2:   Change{},
			want: Change{},
		},
		{
			name: "bool fields OR together",
			r1:   Change{IncludeSelf: true, IncludePolicy: true},
			r2:   Change{IncludeDERPMap: true, IncludePolicy: true},
			want: Change{IncludeSelf: true, IncludeDERPMap: true, IncludePolicy: true},
		},
		{
			name: "all bool fields merge",
			r1:   Change{IncludeSelf: true, IncludeDNS: true, IncludePolicy: true},
			r2:   Change{IncludeDERPMap: true, IncludeDomain: true, SendAllPeers: true},
			want: Change{
				IncludeSelf:    true,
				IncludeDERPMap: true,
				IncludeDNS:     true,
				IncludeDomain:  true,
				IncludePolicy:  true,
				SendAllPeers:   true,
			},
		},
		{
			name: "peers deduplicated and sorted",
			r1:   Change{PeersChanged: []types.NodeID{3, 1}},
			r2:   Change{PeersChanged: []types.NodeID{2, 1}},
			want: Change{PeersChanged: []types.NodeID{1, 2, 3}},
		},
		{
			name: "peers removed deduplicated",
			r1:   Change{PeersRemoved: []types.NodeID{1, 2}},
			r2:   Change{PeersRemoved: []types.NodeID{2, 3}},
			want: Change{PeersRemoved: []types.NodeID{1, 2, 3}},
		},
		{
			name: "peer patches concatenated",
			r1:   Change{PeerPatches: []*tailcfg.PeerChange{{NodeID: 1}}},
			r2:   Change{PeerPatches: []*tailcfg.PeerChange{{NodeID: 2}}},
			want: Change{PeerPatches: []*tailcfg.PeerChange{{NodeID: 1}, {NodeID: 2}}},
		},
		{
			name: "reasons combined when different",
			r1:   Change{Reason: "route change"},
			r2:   Change{Reason: "tag change"},
			want: Change{Reason: "route change; tag change"},
		},
		{
			name: "same reason not duplicated",
			r1:   Change{Reason: "policy"},
			r2:   Change{Reason: "policy"},
			want: Change{Reason: "policy"},
		},
		{
			name: "empty reason takes other",
			r1:   Change{},
			r2:   Change{Reason: "update"},
			want: Change{Reason: "update"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.r1.Merge(tt.r2)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestChange_Constructors(t *testing.T) {
	tests := []struct {
		name        string
		constructor func() Change
		wantReason  string
		want        Change
	}{
		{
			name:        "FullUpdateResponse",
			constructor: FullUpdate,
			wantReason:  "full update",
			want: Change{
				Reason:         "full update",
				IncludeSelf:    true,
				IncludeDERPMap: true,
				IncludeDNS:     true,
				IncludeDomain:  true,
				IncludePolicy:  true,
				SendAllPeers:   true,
			},
		},
		{
			name:        "PolicyOnlyResponse",
			constructor: PolicyOnly,
			wantReason:  "policy update",
			want: Change{
				Reason:        "policy update",
				IncludePolicy: true,
			},
		},
		{
			name:        "DERPMapResponse",
			constructor: DERPMap,
			wantReason:  "DERP map update",
			want: Change{
				Reason:         "DERP map update",
				IncludeDERPMap: true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := tt.constructor()
			assert.Equal(t, tt.wantReason, r.Reason)
			assert.Equal(t, tt.want, r)
		})
	}
}

func TestSelfUpdate(t *testing.T) {
	r := SelfUpdate(42)
	assert.Equal(t, "self update", r.Reason)
	assert.Equal(t, types.NodeID(42), r.TargetNode)
	assert.True(t, r.IncludeSelf)
	assert.True(t, r.IsSelfOnly())
}

func TestPolicyAndPeers(t *testing.T) {
	r := PolicyAndPeers(1, 2, 3)
	assert.Equal(t, "policy and peers update", r.Reason)
	assert.True(t, r.IncludePolicy)
	assert.Equal(t, []types.NodeID{1, 2, 3}, r.PeersChanged)
}

func TestVisibilityChange(t *testing.T) {
	r := VisibilityChange("tag change", []types.NodeID{1}, []types.NodeID{2, 3})
	assert.Equal(t, "tag change", r.Reason)
	assert.True(t, r.IncludePolicy)
	assert.Equal(t, []types.NodeID{1}, r.PeersChanged)
	assert.Equal(t, []types.NodeID{2, 3}, r.PeersRemoved)
}

func TestPeersChanged(t *testing.T) {
	r := PeersChanged("routes approved", 1, 2)
	assert.Equal(t, "routes approved", r.Reason)
	assert.Equal(t, []types.NodeID{1, 2}, r.PeersChanged)
	assert.False(t, r.IncludePolicy)
}

func TestPeersRemoved(t *testing.T) {
	r := PeersRemoved(1, 2, 3)
	assert.Equal(t, "peers removed", r.Reason)
	assert.Equal(t, []types.NodeID{1, 2, 3}, r.PeersRemoved)
}

func TestPeerPatched(t *testing.T) {
	patch := &tailcfg.PeerChange{NodeID: 1}
	r := PeerPatched("endpoint change", patch)
	assert.Equal(t, "endpoint change", r.Reason)
	assert.Equal(t, []*tailcfg.PeerChange{patch}, r.PeerPatches)
}

func TestChange_Type(t *testing.T) {
	tests := []struct {
		name     string
		response Change
		want     string
	}{
		{
			name:     "full update",
			response: FullUpdate(),
			want:     "full",
		},
		{
			name:     "self only",
			response: SelfUpdate(1),
			want:     "self",
		},
		{
			name:     "policy with runtime computation",
			response: PolicyChange(),
			want:     "policy",
		},
		{
			name:     "patch only",
			response: PeerPatched("test", &tailcfg.PeerChange{NodeID: 1}),
			want:     "patch",
		},
		{
			name:     "peers changed",
			response: PeersChanged("test", 1, 2),
			want:     "peers",
		},
		{
			name:     "peers removed",
			response: PeersRemoved(1, 2),
			want:     "peers",
		},
		{
			name:     "config - DERP map",
			response: DERPMap(),
			want:     "config",
		},
		{
			name:     "config - DNS",
			response: DNSConfig(),
			want:     "config",
		},
		{
			name:     "config - policy only (no runtime)",
			response: PolicyOnly(),
			want:     "config",
		},
		{
			name:     "empty is unknown",
			response: Change{},
			want:     "unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.response.Type()
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestUniqueNodeIDs(t *testing.T) {
	tests := []struct {
		name  string
		input []types.NodeID
		want  []types.NodeID
	}{
		{
			name:  "nil input",
			input: nil,
			want:  nil,
		},
		{
			name:  "empty input",
			input: []types.NodeID{},
			want:  nil,
		},
		{
			name:  "single element",
			input: []types.NodeID{1},
			want:  []types.NodeID{1},
		},
		{
			name:  "no duplicates",
			input: []types.NodeID{1, 2, 3},
			want:  []types.NodeID{1, 2, 3},
		},
		{
			name:  "with duplicates",
			input: []types.NodeID{3, 1, 2, 1, 3},
			want:  []types.NodeID{1, 2, 3},
		},
		{
			name:  "all same",
			input: []types.NodeID{5, 5, 5, 5},
			want:  []types.NodeID{5},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := uniqueNodeIDs(tt.input)
			assert.Equal(t, tt.want, got)
		})
	}
}
