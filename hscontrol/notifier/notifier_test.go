package notifier

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"tailscale.com/tailcfg"
)

func TestBatcher(t *testing.T) {
	tests := []struct {
		name    string
		updates []types.StateUpdate
		want    []types.StateUpdate
	}{
		{
			name: "full-passthrough",
			updates: []types.StateUpdate{
				{
					Type: types.StateFullUpdate,
				},
			},
			want: []types.StateUpdate{
				{
					Type: types.StateFullUpdate,
				},
			},
		},
		{
			name: "derp-passthrough",
			updates: []types.StateUpdate{
				{
					Type: types.StateDERPUpdated,
				},
			},
			want: []types.StateUpdate{
				{
					Type: types.StateDERPUpdated,
				},
			},
		},
		{
			name: "single-node-update",
			updates: []types.StateUpdate{
				{
					Type: types.StatePeerChanged,
					ChangeNodes: []types.NodeID{
						2,
					},
				},
			},
			want: []types.StateUpdate{
				{
					Type: types.StatePeerChanged,
					ChangeNodes: []types.NodeID{
						2,
					},
				},
			},
		},
		{
			name: "merge-node-update",
			updates: []types.StateUpdate{
				{
					Type: types.StatePeerChanged,
					ChangeNodes: []types.NodeID{
						2, 4,
					},
				},
				{
					Type: types.StatePeerChanged,
					ChangeNodes: []types.NodeID{
						2, 3,
					},
				},
			},
			want: []types.StateUpdate{
				{
					Type: types.StatePeerChanged,
					ChangeNodes: []types.NodeID{
						2, 3, 4,
					},
				},
			},
		},
		{
			name: "single-patch-update",
			updates: []types.StateUpdate{
				{
					Type: types.StatePeerChangedPatch,
					ChangePatches: []*tailcfg.PeerChange{
						{
							NodeID:     2,
							DERPRegion: 5,
						},
					},
				},
			},
			want: []types.StateUpdate{
				{
					Type: types.StatePeerChangedPatch,
					ChangePatches: []*tailcfg.PeerChange{
						{
							NodeID:     2,
							DERPRegion: 5,
						},
					},
				},
			},
		},
		{
			name: "merge-patch-to-same-node-update",
			updates: []types.StateUpdate{
				{
					Type: types.StatePeerChangedPatch,
					ChangePatches: []*tailcfg.PeerChange{
						{
							NodeID:     2,
							DERPRegion: 5,
						},
					},
				},
				{
					Type: types.StatePeerChangedPatch,
					ChangePatches: []*tailcfg.PeerChange{
						{
							NodeID:     2,
							DERPRegion: 6,
						},
					},
				},
			},
			want: []types.StateUpdate{
				{
					Type: types.StatePeerChangedPatch,
					ChangePatches: []*tailcfg.PeerChange{
						{
							NodeID:     2,
							DERPRegion: 6,
						},
					},
				},
			},
		},
		{
			name: "merge-patch-to-multiple-node-update",
			updates: []types.StateUpdate{
				{
					Type: types.StatePeerChangedPatch,
					ChangePatches: []*tailcfg.PeerChange{
						{
							NodeID: 3,
							Endpoints: []netip.AddrPort{
								netip.MustParseAddrPort("1.1.1.1:9090"),
							},
						},
					},
				},
				{
					Type: types.StatePeerChangedPatch,
					ChangePatches: []*tailcfg.PeerChange{
						{
							NodeID: 3,
							Endpoints: []netip.AddrPort{
								netip.MustParseAddrPort("1.1.1.1:9090"),
								netip.MustParseAddrPort("2.2.2.2:8080"),
							},
						},
					},
				},
				{
					Type: types.StatePeerChangedPatch,
					ChangePatches: []*tailcfg.PeerChange{
						{
							NodeID:     4,
							DERPRegion: 6,
						},
					},
				},
				{
					Type: types.StatePeerChangedPatch,
					ChangePatches: []*tailcfg.PeerChange{
						{
							NodeID: 4,
							Cap:    tailcfg.CapabilityVersion(54),
						},
					},
				},
			},
			want: []types.StateUpdate{
				{
					Type: types.StatePeerChangedPatch,
					ChangePatches: []*tailcfg.PeerChange{
						{
							NodeID: 3,
							Endpoints: []netip.AddrPort{
								netip.MustParseAddrPort("1.1.1.1:9090"),
								netip.MustParseAddrPort("2.2.2.2:8080"),
							},
						},
						{
							NodeID:     4,
							DERPRegion: 6,
							Cap:        tailcfg.CapabilityVersion(54),
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := NewNotifier(&types.Config{
				Tuning: types.Tuning{
					// We will call flush manually for the tests,
					// so do not run the worker.
					BatchChangeDelay: time.Hour,
				},
			})

			ch := make(chan types.StateUpdate, 30)
			defer close(ch)
			n.AddNode(1, ch)
			defer n.RemoveNode(1)

			for _, u := range tt.updates {
				n.NotifyAll(context.Background(), u)
			}

			n.b.flush()

			var got []types.StateUpdate
			for len(ch) > 0 {
				out := <-ch
				got = append(got, out)
			}

			if diff := cmp.Diff(tt.want, got, util.Comparers...); diff != "" {
				t.Errorf("batcher() unexpected result (-want +got):\n%s", diff)
			}
		})
	}
}
