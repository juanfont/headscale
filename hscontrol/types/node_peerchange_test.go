package types

import (
	"testing"

	"tailscale.com/tailcfg"
)

// TestApplyPeerChangeDERPDoesNotMutateSharedHostinfo guards the NodeStore
// copy-on-write invariant: published snapshots share the *tailcfg.Hostinfo /
// *tailcfg.NetInfo pointers, so ApplyPeerChange must never write a DERP region
// through them in place. It must produce fresh pointers, leaving any
// previously-shared Hostinfo untouched.
func TestApplyPeerChangeDERPDoesNotMutateSharedHostinfo(t *testing.T) {
	const newRegion = 2

	t.Run("existing NetInfo", func(t *testing.T) {
		shared := &tailcfg.Hostinfo{
			Hostname: "n",
			NetInfo:  &tailcfg.NetInfo{PreferredDERP: 1},
		}
		node := &Node{Hostinfo: shared}

		node.ApplyPeerChange(&tailcfg.PeerChange{DERPRegion: newRegion})

		if got := node.Hostinfo.NetInfo.PreferredDERP; got != newRegion {
			t.Fatalf("node PreferredDERP = %d, want %d", got, newRegion)
		}

		if got := shared.NetInfo.PreferredDERP; got != 1 {
			t.Errorf("shared NetInfo mutated in place: PreferredDERP = %d, want 1", got)
		}

		if node.Hostinfo == shared {
			t.Error("node.Hostinfo still aliases the shared Hostinfo pointer")
		}

		if node.Hostinfo.NetInfo == shared.NetInfo {
			t.Error("node.Hostinfo.NetInfo still aliases the shared NetInfo pointer")
		}
	})

	t.Run("nil NetInfo", func(t *testing.T) {
		shared := &tailcfg.Hostinfo{Hostname: "n"}
		node := &Node{Hostinfo: shared}

		node.ApplyPeerChange(&tailcfg.PeerChange{DERPRegion: newRegion})

		if got := node.Hostinfo.NetInfo.PreferredDERP; got != newRegion {
			t.Fatalf("node PreferredDERP = %d, want %d", got, newRegion)
		}

		if shared.NetInfo != nil {
			t.Errorf("shared Hostinfo gained a NetInfo in place: %+v", shared.NetInfo)
		}

		if node.Hostinfo == shared {
			t.Error("node.Hostinfo still aliases the shared Hostinfo pointer")
		}
	})
}
