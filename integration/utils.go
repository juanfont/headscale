package integration

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/juanfont/headscale/integration/tsic"
)

const (
	derpPingTimeout = 2 * time.Second
	derpPingCount   = 10
)

func assertNoErr(t *testing.T, err error) {
	t.Helper()
	assertNoErrf(t, "unexpected error: %s", err)
}

func assertNoErrf(t *testing.T, msg string, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf(msg, err)
	}
}

func assertNoErrHeadscaleEnv(t *testing.T, err error) {
	t.Helper()
	assertNoErrf(t, "failed to create headscale environment: %s", err)
}

func assertNoErrGetHeadscale(t *testing.T, err error) {
	t.Helper()
	assertNoErrf(t, "failed to get headscale: %s", err)
}

func assertNoErrListClients(t *testing.T, err error) {
	t.Helper()
	assertNoErrf(t, "failed to list clients: %s", err)
}

func assertNoErrListClientIPs(t *testing.T, err error) {
	t.Helper()
	assertNoErrf(t, "failed to get client IPs: %s", err)
}

func assertNoErrSync(t *testing.T, err error) {
	t.Helper()
	assertNoErrf(t, "failed to have all clients sync up: %s", err)
}

func assertNoErrListFQDN(t *testing.T, err error) {
	t.Helper()
	assertNoErrf(t, "failed to list FQDNs: %s", err)
}

func assertNoErrLogout(t *testing.T, err error) {
	t.Helper()
	assertNoErrf(t, "failed to log out tailscale nodes: %s", err)
}

func assertContains(t *testing.T, str, subStr string) {
	t.Helper()
	if !strings.Contains(str, subStr) {
		t.Fatalf("%#v does not contain %#v", str, subStr)
	}
}

func pingAllHelper(t *testing.T, clients []TailscaleClient, addrs []string) int {
	t.Helper()
	success := 0

	for _, client := range clients {
		for _, addr := range addrs {
			err := client.Ping(addr)
			if err != nil {
				t.Fatalf("failed to ping %s from %s: %s", addr, client.Hostname(), err)
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

			err := client.Ping(
				addr,
				tsic.WithPingTimeout(derpPingTimeout),
				tsic.WithPingCount(derpPingCount),
				tsic.WithPingUntilDirect(false),
			)
			if err != nil {
				t.Fatalf("failed to ping %s from %s: %s", addr, client.Hostname(), err)
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

func isCI() bool {
	if _, ok := os.LookupEnv("CI"); ok {
		return true
	}

	if _, ok := os.LookupEnv("GITHUB_RUN_ID"); ok {
		return true
	}

	return false
}

func dockertestMaxWait() time.Duration {
	wait := 60 * time.Second //nolint

	if isCI() {
		wait = 300 * time.Second //nolint
	}

	return wait
}

// func dockertestCommandTimeout() time.Duration {
// 	timeout := 10 * time.Second //nolint
//
// 	if isCI() {
// 		timeout = 60 * time.Second //nolint
// 	}
//
// 	return timeout
// }

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
