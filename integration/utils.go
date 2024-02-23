package integration

import (
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/juanfont/headscale/integration/tsic"
	"github.com/stretchr/testify/assert"
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

func assertNotNil(t *testing.T, thing interface{}) {
	t.Helper()
	if thing == nil {
		t.Fatal("got unexpected nil")
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

func pingAllHelper(t *testing.T, clients []TailscaleClient, addrs []string, opts ...tsic.PingOption) int {
	t.Helper()
	success := 0

	for _, client := range clients {
		for _, addr := range addrs {
			err := client.Ping(addr, opts...)
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

// assertClientsState validates the status and netmap of a list of
// clients for the general case of all to all connectivity.
func assertClientsState(t *testing.T, clients []TailscaleClient) {
	t.Helper()

	var wg sync.WaitGroup

	for _, client := range clients {
		wg.Add(1)
		c := client // Avoid loop pointer
		go func() {
			defer wg.Done()
			assertValidStatus(t, c)
			assertValidNetcheck(t, c)
			assertValidNetmap(t, c)
		}()
	}

	t.Logf("waiting for client state checks to finish")
	wg.Wait()
}

// assertValidNetmap asserts that the netmap of a client has all
// the minimum required fields set to a known working config for
// the general case. Fields are checked on self, then all peers.
// This test is not suitable for ACL/partial connection tests.
// This test can only be run on clients from 1.56.1. It will
// automatically pass all clients below that and is safe to call
// for all versions.
func assertValidNetmap(t *testing.T, client TailscaleClient) {
	t.Helper()

	if !util.TailscaleVersionNewerOrEqual("1.56", client.Version()) {
		t.Logf("%q has version %q, skipping netmap check...", client.Hostname(), client.Version())

		return
	}

	t.Logf("Checking netmap of %q", client.Hostname())

	netmap, err := client.Netmap()
	if err != nil {
		t.Fatalf("getting netmap for %q: %s", client.Hostname(), err)
	}

	assert.Truef(t, netmap.SelfNode.Hostinfo().Valid(), "%q does not have Hostinfo", client.Hostname())
	if hi := netmap.SelfNode.Hostinfo(); hi.Valid() {
		assert.LessOrEqual(t, 1, netmap.SelfNode.Hostinfo().Services().Len(), "%q does not have enough services, got: %v", client.Hostname(), netmap.SelfNode.Hostinfo().Services())
	}

	assert.NotEmptyf(t, netmap.SelfNode.AllowedIPs(), "%q does not have any allowed IPs", client.Hostname())
	assert.NotEmptyf(t, netmap.SelfNode.Addresses(), "%q does not have any addresses", client.Hostname())

	if netmap.SelfNode.Online() != nil {
		assert.Truef(t, *netmap.SelfNode.Online(), "%q is not online", client.Hostname())
	} else {
		t.Errorf("Online should not be nil for %s", client.Hostname())
	}

	assert.Falsef(t, netmap.SelfNode.Key().IsZero(), "%q does not have a valid NodeKey", client.Hostname())
	assert.Falsef(t, netmap.SelfNode.Machine().IsZero(), "%q does not have a valid MachineKey", client.Hostname())
	assert.Falsef(t, netmap.SelfNode.DiscoKey().IsZero(), "%q does not have a valid DiscoKey", client.Hostname())

	for _, peer := range netmap.Peers {
		assert.NotEqualf(t, "127.3.3.40:0", peer.DERP(), "peer (%s) has no home DERP in %q's netmap, got: %s", peer.ComputedName(), client.Hostname(), peer.DERP())

		assert.Truef(t, peer.Hostinfo().Valid(), "peer (%s) of %q does not have Hostinfo", peer.ComputedName(), client.Hostname())
		if hi := peer.Hostinfo(); hi.Valid() {
			assert.LessOrEqualf(t, 3, peer.Hostinfo().Services().Len(), "peer (%s) of %q does not have enough services, got: %v", peer.ComputedName(), client.Hostname(), peer.Hostinfo().Services())

			// Netinfo is not always set
			// assert.Truef(t, hi.NetInfo().Valid(), "peer (%s) of %q does not have NetInfo", peer.ComputedName(), client.Hostname())
			if ni := hi.NetInfo(); ni.Valid() {
				assert.NotEqualf(t, 0, ni.PreferredDERP(), "peer (%s) has no home DERP in %q's netmap, got: %s", peer.ComputedName(), client.Hostname(), peer.Hostinfo().NetInfo().PreferredDERP())
			}
		}

		assert.NotEmptyf(t, peer.Endpoints(), "peer (%s) of %q does not have any endpoints", peer.ComputedName(), client.Hostname())
		assert.NotEmptyf(t, peer.AllowedIPs(), "peer (%s) of %q does not have any allowed IPs", peer.ComputedName(), client.Hostname())
		assert.NotEmptyf(t, peer.Addresses(), "peer (%s) of %q does not have any addresses", peer.ComputedName(), client.Hostname())

		assert.Truef(t, *peer.Online(), "peer (%s) of %q is not online", peer.ComputedName(), client.Hostname())

		assert.Falsef(t, peer.Key().IsZero(), "peer (%s) of %q does not have a valid NodeKey", peer.ComputedName(), client.Hostname())
		assert.Falsef(t, peer.Machine().IsZero(), "peer (%s) of %q does not have a valid MachineKey", peer.ComputedName(), client.Hostname())
		assert.Falsef(t, peer.DiscoKey().IsZero(), "peer (%s) of %q does not have a valid DiscoKey", peer.ComputedName(), client.Hostname())
	}
}

// assertValidStatus asserts that the status of a client has all
// the minimum required fields set to a known working config for
// the general case. Fields are checked on self, then all peers.
// This test is not suitable for ACL/partial connection tests.
func assertValidStatus(t *testing.T, client TailscaleClient) {
	t.Helper()
	status, err := client.Status(true)
	if err != nil {
		t.Fatalf("getting status for %q: %s", client.Hostname(), err)
	}

	assert.NotEmptyf(t, status.Self.HostName, "%q does not have HostName set, likely missing Hostinfo", client.Hostname())
	assert.NotEmptyf(t, status.Self.OS, "%q does not have OS set, likely missing Hostinfo", client.Hostname())
	assert.NotEmptyf(t, status.Self.Relay, "%q does not have a relay, likely missing Hostinfo/Netinfo", client.Hostname())

	assert.NotEmptyf(t, status.Self.TailscaleIPs, "%q does not have Tailscale IPs", client.Hostname())

	// This seem to not appear until version 1.56
	if status.Self.AllowedIPs != nil {
		assert.NotEmptyf(t, status.Self.AllowedIPs, "%q does not have any allowed IPs", client.Hostname())
	}

	assert.NotEmptyf(t, status.Self.Addrs, "%q does not have any endpoints", client.Hostname())

	assert.Truef(t, status.Self.Online, "%q is not online", client.Hostname())

	assert.Truef(t, status.Self.InNetworkMap, "%q is not in network map", client.Hostname())

	// This isnt really relevant for Self as it wont be in its own socket/wireguard.
	// assert.Truef(t, status.Self.InMagicSock, "%q is not tracked by magicsock", client.Hostname())
	// assert.Truef(t, status.Self.InEngine, "%q is not in in wireguard engine", client.Hostname())

	for _, peer := range status.Peer {
		assert.NotEmptyf(t, peer.HostName, "peer (%s) of %q does not have HostName set, likely missing Hostinfo", peer.DNSName, client.Hostname())
		assert.NotEmptyf(t, peer.OS, "peer (%s) of %q does not have OS set, likely missing Hostinfo", peer.DNSName, client.Hostname())
		assert.NotEmptyf(t, peer.Relay, "peer (%s) of %q does not have a relay, likely missing Hostinfo/Netinfo", peer.DNSName, client.Hostname())

		assert.NotEmptyf(t, peer.TailscaleIPs, "peer (%s) of %q does not have Tailscale IPs", peer.DNSName, client.Hostname())

		// This seem to not appear until version 1.56
		if peer.AllowedIPs != nil {
			assert.NotEmptyf(t, peer.AllowedIPs, "peer (%s) of %q does not have any allowed IPs", peer.DNSName, client.Hostname())
		}

		// Addrs does not seem to appear in the status from peers.
		// assert.NotEmptyf(t, peer.Addrs, "peer (%s) of %q does not have any endpoints", peer.DNSName, client.Hostname())

		assert.Truef(t, peer.Online, "peer (%s) of %q is not online", peer.DNSName, client.Hostname())

		assert.Truef(t, peer.InNetworkMap, "peer (%s) of %q is not in network map", peer.DNSName, client.Hostname())
		assert.Truef(t, peer.InMagicSock, "peer (%s) of %q is not tracked by magicsock", peer.DNSName, client.Hostname())

		// TODO(kradalby): InEngine is only true when a proper tunnel is set up,
		// there might be some interesting stuff to test here in the future.
		// assert.Truef(t, peer.InEngine, "peer (%s) of %q is not in wireguard engine", peer.DNSName, client.Hostname())
	}
}

func assertValidNetcheck(t *testing.T, client TailscaleClient) {
	t.Helper()
	report, err := client.Netcheck()
	if err != nil {
		t.Fatalf("getting status for %q: %s", client.Hostname(), err)
	}

	assert.NotEqualf(t, 0, report.PreferredDERP, "%q does not have a DERP relay", client.Hostname())
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
	wait := 120 * time.Second //nolint

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
