package integration

import (
	"testing"
	"time"

	"github.com/juanfont/headscale/integration/tsic"
)

func pingAllHelper(t *testing.T, clients []TailscaleClient, addrs []string) int {
	t.Helper()
	success := 0

	for _, client := range clients {
		for _, addr := range addrs {
			err := client.Ping(addr)
			if err != nil {
				t.Errorf("failed to ping %s from %s: %s", addr, client.Hostname(), err)
			} else {
				success++
			}
		}
	}

	return success
}

func pingDerpAllHelper(t *testing.T, clients []TailscaleClient, addrs []string) int {
	t.Helper()
	success := 0

	for _, client := range clients {
		for _, addr := range addrs {
			if isSelfClient(client, addr) {
				continue
			}

			err := client.PingViaDERP(
				addr,
				tsic.WithPingTimeout(2*time.Second),
				tsic.WithPingCount(10),
			)
			if err != nil {
				t.Errorf("failed to ping %s from %s: %s", addr, client.Hostname(), err)
			} else {
				success++
			}
		}
	}

	return success
}

func isSelfClient(client TailscaleClient, addr string) bool {
	if addr == client.Hostname() {
		return true
	}

	ips, err := client.IPs()
	if err != nil {
		return false
	}

	for _, ip := range ips {
		if ip.String() == addr {
			return true
		}
	}

	return false
}

// pingAllNegativeHelper is intended to have 1 or more nodes timeing out from the ping,
// it counts failures instead of successes.
// func pingAllNegativeHelper(t *testing.T, clients []TailscaleClient, addrs []string) int {
// 	t.Helper()
// 	failures := 0
//
// 	timeout := 100
// 	count := 3
//
// 	for _, client := range clients {
// 		for _, addr := range addrs {
// 			err := client.Ping(
// 				addr,
// 				tsic.WithPingTimeout(time.Duration(timeout)*time.Millisecond),
// 				tsic.WithPingCount(count),
// 			)
// 			if err != nil {
// 				failures++
// 			}
// 		}
// 	}
//
// 	return failures
// }

// // findPeerByIP takes an IP and a map of peers from status.Peer, and returns a *ipnstate.PeerStatus
// // if there is a peer with the given IP. If no peer is found, nil is returned.
// func findPeerByIP(
// 	ip netip.Addr,
// 	peers map[key.NodePublic]*ipnstate.PeerStatus,
// ) *ipnstate.PeerStatus {
// 	for _, peer := range peers {
// 		for _, peerIP := range peer.TailscaleIPs {
// 			if ip == peerIP {
// 				return peer
// 			}
// 		}
// 	}
//
// 	return nil
// }
//
// // findPeerByHostname takes a hostname and a map of peers from status.Peer, and returns a *ipnstate.PeerStatus
// // if there is a peer with the given hostname. If no peer is found, nil is returned.
// func findPeerByHostname(
// 	hostname string,
// 	peers map[key.NodePublic]*ipnstate.PeerStatus,
// ) *ipnstate.PeerStatus {
// 	for _, peer := range peers {
// 		if hostname == peer.HostName {
// 			return peer
// 		}
// 	}
//
// 	return nil
// }
