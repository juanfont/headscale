package servertest

import (
	"testing"
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

// AssertDERPMapPresent checks that the netmap contains a DERP map.
func AssertDERPMapPresent(tb testing.TB, client *TestClient) {
	tb.Helper()

	nm := client.Netmap()
	if nm == nil {
		tb.Errorf("AssertDERPMapPresent: %s has no netmap", client.Name)

		return
	}

	if nm.DERPMap == nil {
		tb.Errorf("AssertDERPMapPresent: %s has nil DERPMap", client.Name)

		return
	}

	if len(nm.DERPMap.Regions) == 0 {
		tb.Errorf("AssertDERPMapPresent: %s has empty DERPMap regions", client.Name)
	}
}

// AssertSelfHasAddresses checks that the self node has at least one address.
func AssertSelfHasAddresses(tb testing.TB, client *TestClient) {
	tb.Helper()

	nm := client.Netmap()
	if nm == nil {
		tb.Errorf("AssertSelfHasAddresses: %s has no netmap", client.Name)

		return
	}

	if !nm.SelfNode.Valid() {
		tb.Errorf("AssertSelfHasAddresses: %s self node is invalid", client.Name)

		return
	}

	if nm.SelfNode.Addresses().Len() == 0 {
		tb.Errorf("AssertSelfHasAddresses: %s self node has no addresses", client.Name)
	}
}
