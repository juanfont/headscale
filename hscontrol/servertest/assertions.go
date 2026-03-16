package servertest

import (
	"net/netip"
	"testing"
	"time"
)

// AssertMeshComplete verifies that every client in the slice sees
// exactly (len(clients) - 1) peers, i.e. a fully connected mesh.
func AssertMeshComplete(tb testing.TB, clients []*TestClient) {
	tb.Helper()

	expected := len(clients) - 1
	for _, c := range clients {
		nm := c.Netmap()
		if nm == nil {
			tb.Errorf("AssertMeshComplete: %s has no netmap", c.Name)

			continue
		}

		if got := len(nm.Peers); got != expected {
			tb.Errorf("AssertMeshComplete: %s has %d peers, want %d (peers: %v)",
				c.Name, got, expected, c.PeerNames())
		}
	}
}

// AssertSymmetricVisibility checks that peer visibility is symmetric:
// if client A sees client B, then client B must also see client A.
func AssertSymmetricVisibility(tb testing.TB, clients []*TestClient) {
	tb.Helper()

	for _, a := range clients {
		for _, b := range clients {
			if a == b {
				continue
			}

			_, aSeesB := a.PeerByName(b.Name)

			_, bSeesA := b.PeerByName(a.Name)
			if aSeesB != bSeesA {
				tb.Errorf("AssertSymmetricVisibility: %s sees %s = %v, but %s sees %s = %v",
					a.Name, b.Name, aSeesB, b.Name, a.Name, bSeesA)
			}
		}
	}
}

// AssertPeerOnline checks that the observer sees peerName as online.
func AssertPeerOnline(tb testing.TB, observer *TestClient, peerName string) {
	tb.Helper()

	peer, ok := observer.PeerByName(peerName)
	if !ok {
		tb.Errorf("AssertPeerOnline: %s does not see peer %s", observer.Name, peerName)

		return
	}

	isOnline, known := peer.Online().GetOk()
	if !known || !isOnline {
		tb.Errorf("AssertPeerOnline: %s sees peer %s but Online=%v (known=%v), want true",
			observer.Name, peerName, isOnline, known)
	}
}

// AssertPeerOffline checks that the observer sees peerName as offline.
func AssertPeerOffline(tb testing.TB, observer *TestClient, peerName string) {
	tb.Helper()

	peer, ok := observer.PeerByName(peerName)
	if !ok {
		// Peer gone entirely counts as "offline" for this assertion.
		return
	}

	isOnline, known := peer.Online().GetOk()
	if known && isOnline {
		tb.Errorf("AssertPeerOffline: %s sees peer %s as online, want offline",
			observer.Name, peerName)
	}
}

// AssertPeerGone checks that the observer does NOT have peerName in
// its peer list at all.
func AssertPeerGone(tb testing.TB, observer *TestClient, peerName string) {
	tb.Helper()

	_, ok := observer.PeerByName(peerName)
	if ok {
		tb.Errorf("AssertPeerGone: %s still sees peer %s", observer.Name, peerName)
	}
}

// AssertPeerHasAllowedIPs checks that a peer has the expected
// AllowedIPs prefixes.
func AssertPeerHasAllowedIPs(tb testing.TB, observer *TestClient, peerName string, want []netip.Prefix) {
	tb.Helper()

	peer, ok := observer.PeerByName(peerName)
	if !ok {
		tb.Errorf("AssertPeerHasAllowedIPs: %s does not see peer %s", observer.Name, peerName)

		return
	}

	got := make([]netip.Prefix, 0, peer.AllowedIPs().Len())
	for i := range peer.AllowedIPs().Len() {
		got = append(got, peer.AllowedIPs().At(i))
	}

	if len(got) != len(want) {
		tb.Errorf("AssertPeerHasAllowedIPs: %s sees %s with AllowedIPs %v, want %v",
			observer.Name, peerName, got, want)

		return
	}

	// Build a set for comparison.
	wantSet := make(map[netip.Prefix]bool, len(want))
	for _, p := range want {
		wantSet[p] = true
	}

	for _, p := range got {
		if !wantSet[p] {
			tb.Errorf("AssertPeerHasAllowedIPs: %s sees %s with unexpected AllowedIP %v (want %v)",
				observer.Name, peerName, p, want)
		}
	}
}

// AssertConsistentState checks that all clients agree on peer
// properties: every connected client should see the same set of
// peer hostnames.
func AssertConsistentState(tb testing.TB, clients []*TestClient) {
	tb.Helper()

	for _, c := range clients {
		nm := c.Netmap()
		if nm == nil {
			continue
		}

		peerNames := make(map[string]bool, len(nm.Peers))
		for _, p := range nm.Peers {
			hi := p.Hostinfo()
			if hi.Valid() {
				peerNames[hi.Hostname()] = true
			}
		}

		// Check that c sees all other connected clients.
		for _, other := range clients {
			if other == c || other.Netmap() == nil {
				continue
			}

			if !peerNames[other.Name] {
				tb.Errorf("AssertConsistentState: %s does not see %s (peers: %v)",
					c.Name, other.Name, c.PeerNames())
			}
		}
	}
}

// EventuallyAssertMeshComplete retries AssertMeshComplete up to
// timeout, useful when waiting for state to propagate.
func EventuallyAssertMeshComplete(tb testing.TB, clients []*TestClient, timeout time.Duration) {
	tb.Helper()

	expected := len(clients) - 1
	deadline := time.After(timeout)

	for {
		allGood := true

		for _, c := range clients {
			nm := c.Netmap()
			if nm == nil || len(nm.Peers) < expected {
				allGood = false

				break
			}
		}

		if allGood {
			// Final strict check.
			AssertMeshComplete(tb, clients)

			return
		}

		select {
		case <-deadline:
			// Report the failure with details.
			for _, c := range clients {
				nm := c.Netmap()

				got := 0
				if nm != nil {
					got = len(nm.Peers)
				}

				if got != expected {
					tb.Errorf("EventuallyAssertMeshComplete: %s has %d peers, want %d (timeout %v)",
						c.Name, got, expected, timeout)
				}
			}

			return
		case <-time.After(100 * time.Millisecond):
			// Poll again.
		}
	}
}
