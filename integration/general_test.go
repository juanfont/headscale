package integration

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/integration/hsic"
	"github.com/juanfont/headscale/integration/tsic"
	"github.com/rs/zerolog/log"
	"github.com/samber/lo"
	"github.com/stretchr/testify/assert"
	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/types/key"
)

func TestPingAllByIP(t *testing.T) {
	IntegrationSkip(t)
	t.Parallel()

	scenario, err := NewScenario(dockertestMaxWait())
	assertNoErr(t, err)
	defer scenario.Shutdown()

	// TODO(kradalby): it does not look like the user thing works, only second
	// get created? maybe only when many?
	spec := map[string]int{
		"user1": len(MustTestVersions),
		"user2": len(MustTestVersions),
	}

	err = scenario.CreateHeadscaleEnv(spec,
		[]tsic.Option{},
		hsic.WithTestName("pingallbyip"),
		hsic.WithEmbeddedDERPServerOnly(),
		hsic.WithTLS(),
		hsic.WithHostnameAsServerURL(),
		hsic.WithIPAllocationStrategy(types.IPAllocationStrategyRandom),
	)
	assertNoErrHeadscaleEnv(t, err)

	allClients, err := scenario.ListTailscaleClients()
	assertNoErrListClients(t, err)

	allIps, err := scenario.ListTailscaleClientsIPs()
	assertNoErrListClientIPs(t, err)

	err = scenario.WaitForTailscaleSync()
	assertNoErrSync(t, err)

	// assertClientsState(t, allClients)

	allAddrs := lo.Map(allIps, func(x netip.Addr, index int) string {
		return x.String()
	})

	success := pingAllHelper(t, allClients, allAddrs)
	t.Logf("%d successful pings out of %d", success, len(allClients)*len(allIps))
}

func TestPingAllByIPPublicDERP(t *testing.T) {
	IntegrationSkip(t)
	t.Parallel()

	scenario, err := NewScenario(dockertestMaxWait())
	assertNoErr(t, err)
	defer scenario.Shutdown()

	spec := map[string]int{
		"user1": len(MustTestVersions),
		"user2": len(MustTestVersions),
	}

	err = scenario.CreateHeadscaleEnv(spec,
		[]tsic.Option{},
		hsic.WithTestName("pingallbyippubderp"),
	)
	assertNoErrHeadscaleEnv(t, err)

	allClients, err := scenario.ListTailscaleClients()
	assertNoErrListClients(t, err)

	allIps, err := scenario.ListTailscaleClientsIPs()
	assertNoErrListClientIPs(t, err)

	err = scenario.WaitForTailscaleSync()
	assertNoErrSync(t, err)

	// assertClientsState(t, allClients)

	allAddrs := lo.Map(allIps, func(x netip.Addr, index int) string {
		return x.String()
	})

	success := pingAllHelper(t, allClients, allAddrs)
	t.Logf("%d successful pings out of %d", success, len(allClients)*len(allIps))
}

func TestAuthKeyLogoutAndRelogin(t *testing.T) {
	IntegrationSkip(t)
	t.Parallel()

	scenario, err := NewScenario(dockertestMaxWait())
	assertNoErr(t, err)
	defer scenario.Shutdown()

	spec := map[string]int{
		"user1": len(MustTestVersions),
		"user2": len(MustTestVersions),
	}

	err = scenario.CreateHeadscaleEnv(spec, []tsic.Option{}, hsic.WithTestName("pingallbyip"))
	assertNoErrHeadscaleEnv(t, err)

	allClients, err := scenario.ListTailscaleClients()
	assertNoErrListClients(t, err)

	err = scenario.WaitForTailscaleSync()
	assertNoErrSync(t, err)

	// assertClientsState(t, allClients)

	clientIPs := make(map[TailscaleClient][]netip.Addr)
	for _, client := range allClients {
		ips, err := client.IPs()
		if err != nil {
			t.Fatalf("failed to get IPs for client %s: %s", client.Hostname(), err)
		}
		clientIPs[client] = ips
	}

	for _, client := range allClients {
		err := client.Logout()
		if err != nil {
			t.Fatalf("failed to logout client %s: %s", client.Hostname(), err)
		}
	}

	err = scenario.WaitForTailscaleLogout()
	assertNoErrLogout(t, err)

	t.Logf("all clients logged out")

	headscale, err := scenario.Headscale()
	assertNoErrGetHeadscale(t, err)

	for userName := range spec {
		key, err := scenario.CreatePreAuthKey(userName, true, false)
		if err != nil {
			t.Fatalf("failed to create pre-auth key for user %s: %s", userName, err)
		}

		err = scenario.RunTailscaleUp(userName, headscale.GetEndpoint(), key.GetKey())
		if err != nil {
			t.Fatalf("failed to run tailscale up for user %s: %s", userName, err)
		}
	}

	err = scenario.WaitForTailscaleSync()
	assertNoErrSync(t, err)

	// assertClientsState(t, allClients)

	allClients, err = scenario.ListTailscaleClients()
	assertNoErrListClients(t, err)

	allIps, err := scenario.ListTailscaleClientsIPs()
	assertNoErrListClientIPs(t, err)

	allAddrs := lo.Map(allIps, func(x netip.Addr, index int) string {
		return x.String()
	})

	success := pingAllHelper(t, allClients, allAddrs)
	t.Logf("%d successful pings out of %d", success, len(allClients)*len(allIps))

	for _, client := range allClients {
		ips, err := client.IPs()
		if err != nil {
			t.Fatalf("failed to get IPs for client %s: %s", client.Hostname(), err)
		}

		// lets check if the IPs are the same
		if len(ips) != len(clientIPs[client]) {
			t.Fatalf("IPs changed for client %s", client.Hostname())
		}

		for _, ip := range ips {
			found := false
			for _, oldIP := range clientIPs[client] {
				if ip == oldIP {
					found = true

					break
				}
			}

			if !found {
				t.Fatalf(
					"IPs changed for client %s. Used to be %v now %v",
					client.Hostname(),
					clientIPs[client],
					ips,
				)
			}
		}
	}
}

func TestEphemeral(t *testing.T) {
	IntegrationSkip(t)
	t.Parallel()

	scenario, err := NewScenario(dockertestMaxWait())
	assertNoErr(t, err)
	defer scenario.Shutdown()

	spec := map[string]int{
		"user1": len(MustTestVersions),
		"user2": len(MustTestVersions),
	}

	headscale, err := scenario.Headscale(hsic.WithTestName("ephemeral"))
	assertNoErrHeadscaleEnv(t, err)

	for userName, clientCount := range spec {
		err = scenario.CreateUser(userName)
		if err != nil {
			t.Fatalf("failed to create user %s: %s", userName, err)
		}

		err = scenario.CreateTailscaleNodesInUser(userName, "all", clientCount, []tsic.Option{}...)
		if err != nil {
			t.Fatalf("failed to create tailscale nodes in user %s: %s", userName, err)
		}

		key, err := scenario.CreatePreAuthKey(userName, true, true)
		if err != nil {
			t.Fatalf("failed to create pre-auth key for user %s: %s", userName, err)
		}

		err = scenario.RunTailscaleUp(userName, headscale.GetEndpoint(), key.GetKey())
		if err != nil {
			t.Fatalf("failed to run tailscale up for user %s: %s", userName, err)
		}
	}

	err = scenario.WaitForTailscaleSync()
	assertNoErrSync(t, err)

	allClients, err := scenario.ListTailscaleClients()
	assertNoErrListClients(t, err)

	allIps, err := scenario.ListTailscaleClientsIPs()
	assertNoErrListClientIPs(t, err)

	allAddrs := lo.Map(allIps, func(x netip.Addr, index int) string {
		return x.String()
	})

	success := pingAllHelper(t, allClients, allAddrs)
	t.Logf("%d successful pings out of %d", success, len(allClients)*len(allIps))

	for _, client := range allClients {
		err := client.Logout()
		if err != nil {
			t.Fatalf("failed to logout client %s: %s", client.Hostname(), err)
		}
	}

	err = scenario.WaitForTailscaleLogout()
	assertNoErrLogout(t, err)

	t.Logf("all clients logged out")

	for userName := range spec {
		nodes, err := headscale.ListNodesInUser(userName)
		if err != nil {
			log.Error().
				Err(err).
				Str("user", userName).
				Msg("Error listing nodes in user")

			return
		}

		if len(nodes) != 0 {
			t.Fatalf("expected no nodes, got %d in user %s", len(nodes), userName)
		}
	}
}

func TestPingAllByHostname(t *testing.T) {
	IntegrationSkip(t)
	t.Parallel()

	scenario, err := NewScenario(dockertestMaxWait())
	assertNoErr(t, err)
	defer scenario.Shutdown()

	spec := map[string]int{
		"user3": len(MustTestVersions),
		"user4": len(MustTestVersions),
	}

	err = scenario.CreateHeadscaleEnv(spec, []tsic.Option{}, hsic.WithTestName("pingallbyname"))
	assertNoErrHeadscaleEnv(t, err)

	allClients, err := scenario.ListTailscaleClients()
	assertNoErrListClients(t, err)

	err = scenario.WaitForTailscaleSync()
	assertNoErrSync(t, err)

	// assertClientsState(t, allClients)

	allHostnames, err := scenario.ListTailscaleClientsFQDNs()
	assertNoErrListFQDN(t, err)

	success := pingAllHelper(t, allClients, allHostnames)

	t.Logf("%d successful pings out of %d", success, len(allClients)*len(allClients))
}

// If subtests are parallel, then they will start before setup is run.
// This might mean we approach setup slightly wrong, but for now, ignore
// the linter
// nolint:tparallel
func TestTaildrop(t *testing.T) {
	IntegrationSkip(t)
	t.Parallel()

	retry := func(times int, sleepInverval time.Duration, doWork func() error) error {
		var err error
		for attempts := 0; attempts < times; attempts++ {
			err = doWork()
			if err == nil {
				return nil
			}
			time.Sleep(sleepInverval)
		}

		return err
	}

	scenario, err := NewScenario(dockertestMaxWait())
	assertNoErr(t, err)
	defer scenario.Shutdown()

	spec := map[string]int{
		"taildrop": len(MustTestVersions),
	}

	err = scenario.CreateHeadscaleEnv(spec, []tsic.Option{}, hsic.WithTestName("taildrop"))
	assertNoErrHeadscaleEnv(t, err)

	allClients, err := scenario.ListTailscaleClients()
	assertNoErrListClients(t, err)

	err = scenario.WaitForTailscaleSync()
	assertNoErrSync(t, err)

	// This will essentially fetch and cache all the FQDNs
	_, err = scenario.ListTailscaleClientsFQDNs()
	assertNoErrListFQDN(t, err)

	for _, client := range allClients {
		if !strings.Contains(client.Hostname(), "head") {
			command := []string{"apk", "add", "curl"}
			_, _, err := client.Execute(command)
			if err != nil {
				t.Fatalf("failed to install curl on %s, err: %s", client.Hostname(), err)
			}
		}
		curlCommand := []string{
			"curl",
			"--unix-socket",
			"/var/run/tailscale/tailscaled.sock",
			"http://local-tailscaled.sock/localapi/v0/file-targets",
		}
		err = retry(10, 1*time.Second, func() error {
			result, _, err := client.Execute(curlCommand)
			if err != nil {
				return err
			}
			var fts []apitype.FileTarget
			err = json.Unmarshal([]byte(result), &fts)
			if err != nil {
				return err
			}

			if len(fts) != len(allClients)-1 {
				ftStr := fmt.Sprintf("FileTargets for %s:\n", client.Hostname())
				for _, ft := range fts {
					ftStr += fmt.Sprintf("\t%s\n", ft.Node.Name)
				}
				return fmt.Errorf(
					"client %s does not have all its peers as FileTargets, got %d, want: %d\n%s",
					client.Hostname(),
					len(fts),
					len(allClients)-1,
					ftStr,
				)
			}

			return err
		})
		if err != nil {
			t.Errorf(
				"failed to query localapi for filetarget on %s, err: %s",
				client.Hostname(),
				err,
			)
		}
	}

	for _, client := range allClients {
		command := []string{"touch", fmt.Sprintf("/tmp/file_from_%s", client.Hostname())}

		if _, _, err := client.Execute(command); err != nil {
			t.Fatalf("failed to create taildrop file on %s, err: %s", client.Hostname(), err)
		}

		for _, peer := range allClients {
			if client.Hostname() == peer.Hostname() {
				continue
			}

			// It is safe to ignore this error as we handled it when caching it
			peerFQDN, _ := peer.FQDN()

			t.Run(fmt.Sprintf("%s-%s", client.Hostname(), peer.Hostname()), func(t *testing.T) {
				command := []string{
					"tailscale", "file", "cp",
					fmt.Sprintf("/tmp/file_from_%s", client.Hostname()),
					fmt.Sprintf("%s:", peerFQDN),
				}

				err := retry(10, 1*time.Second, func() error {
					t.Logf(
						"Sending file from %s to %s\n",
						client.Hostname(),
						peer.Hostname(),
					)
					_, _, err := client.Execute(command)

					return err
				})
				if err != nil {
					t.Fatalf(
						"failed to send taildrop file on %s with command %q, err: %s",
						client.Hostname(),
						strings.Join(command, " "),
						err,
					)
				}
			})
		}
	}

	for _, client := range allClients {
		command := []string{
			"tailscale", "file",
			"get",
			"/tmp/",
		}
		if _, _, err := client.Execute(command); err != nil {
			t.Fatalf("failed to get taildrop file on %s, err: %s", client.Hostname(), err)
		}

		for _, peer := range allClients {
			if client.Hostname() == peer.Hostname() {
				continue
			}

			t.Run(fmt.Sprintf("%s-%s", client.Hostname(), peer.Hostname()), func(t *testing.T) {
				command := []string{
					"ls",
					fmt.Sprintf("/tmp/file_from_%s", peer.Hostname()),
				}
				log.Printf(
					"Checking file in %s from %s\n",
					client.Hostname(),
					peer.Hostname(),
				)

				result, _, err := client.Execute(command)
				assertNoErrf(t, "failed to execute command to ls taildrop: %s", err)

				log.Printf("Result for %s: %s\n", peer.Hostname(), result)
				if fmt.Sprintf("/tmp/file_from_%s\n", peer.Hostname()) != result {
					t.Fatalf(
						"taildrop result is not correct %s, wanted %s",
						result,
						fmt.Sprintf("/tmp/file_from_%s\n", peer.Hostname()),
					)
				}
			})
		}
	}
}

func TestResolveMagicDNS(t *testing.T) {
	IntegrationSkip(t)
	t.Parallel()

	scenario, err := NewScenario(dockertestMaxWait())
	assertNoErr(t, err)
	defer scenario.Shutdown()

	spec := map[string]int{
		"magicdns1": len(MustTestVersions),
		"magicdns2": len(MustTestVersions),
	}

	err = scenario.CreateHeadscaleEnv(spec, []tsic.Option{}, hsic.WithTestName("magicdns"))
	assertNoErrHeadscaleEnv(t, err)

	allClients, err := scenario.ListTailscaleClients()
	assertNoErrListClients(t, err)

	err = scenario.WaitForTailscaleSync()
	assertNoErrSync(t, err)

	// assertClientsState(t, allClients)

	// Poor mans cache
	_, err = scenario.ListTailscaleClientsFQDNs()
	assertNoErrListFQDN(t, err)

	_, err = scenario.ListTailscaleClientsIPs()
	assertNoErrListClientIPs(t, err)

	for _, client := range allClients {
		for _, peer := range allClients {
			// It is safe to ignore this error as we handled it when caching it
			peerFQDN, _ := peer.FQDN()

			command := []string{
				"tailscale",
				"ip", peerFQDN,
			}
			result, _, err := client.Execute(command)
			if err != nil {
				t.Fatalf(
					"failed to execute resolve/ip command %s from %s: %s",
					peerFQDN,
					client.Hostname(),
					err,
				)
			}

			ips, err := peer.IPs()
			if err != nil {
				t.Fatalf(
					"failed to get ips for %s: %s",
					peer.Hostname(),
					err,
				)
			}

			for _, ip := range ips {
				if !strings.Contains(result, ip.String()) {
					t.Fatalf("ip %s is not found in \n%s\n", ip.String(), result)
				}
			}
		}
	}
}

func TestExpireNode(t *testing.T) {
	IntegrationSkip(t)
	t.Parallel()

	scenario, err := NewScenario(dockertestMaxWait())
	assertNoErr(t, err)
	defer scenario.Shutdown()

	spec := map[string]int{
		"user1": len(MustTestVersions),
	}

	err = scenario.CreateHeadscaleEnv(spec, []tsic.Option{}, hsic.WithTestName("expirenode"))
	assertNoErrHeadscaleEnv(t, err)

	allClients, err := scenario.ListTailscaleClients()
	assertNoErrListClients(t, err)

	allIps, err := scenario.ListTailscaleClientsIPs()
	assertNoErrListClientIPs(t, err)

	err = scenario.WaitForTailscaleSync()
	assertNoErrSync(t, err)

	// assertClientsState(t, allClients)

	allAddrs := lo.Map(allIps, func(x netip.Addr, index int) string {
		return x.String()
	})

	success := pingAllHelper(t, allClients, allAddrs)
	t.Logf("before expire: %d successful pings out of %d", success, len(allClients)*len(allIps))

	for _, client := range allClients {
		status, err := client.Status()
		assertNoErr(t, err)

		// Assert that we have the original count - self
		assert.Len(t, status.Peers(), spec["user1"]-1)
	}

	headscale, err := scenario.Headscale()
	assertNoErr(t, err)

	// TODO(kradalby): This is Headscale specific and would not play nicely
	// with other implementations of the ControlServer interface
	result, err := headscale.Execute([]string{
		"headscale", "nodes", "expire", "--identifier", "1", "--output", "json",
	})
	assertNoErr(t, err)

	var node v1.Node
	err = json.Unmarshal([]byte(result), &node)
	assertNoErr(t, err)

	var expiredNodeKey key.NodePublic
	err = expiredNodeKey.UnmarshalText([]byte(node.GetNodeKey()))
	assertNoErr(t, err)

	t.Logf("Node %s with node_key %s has been expired", node.GetName(), expiredNodeKey.String())

	time.Sleep(2 * time.Minute)

	now := time.Now()

	// Verify that the expired node has been marked in all peers list.
	for _, client := range allClients {
		status, err := client.Status()
		assertNoErr(t, err)

		if client.Hostname() != node.GetName() {
			t.Logf("available peers of %s: %v", client.Hostname(), status.Peers())

			// Ensures that the node is present, and that it is expired.
			if peerStatus, ok := status.Peer[expiredNodeKey]; ok {
				assertNotNil(t, peerStatus.Expired)
				assert.NotNil(t, peerStatus.KeyExpiry)

				t.Logf(
					"node %q should have a key expire before %s, was %s",
					peerStatus.HostName,
					now.String(),
					peerStatus.KeyExpiry,
				)
				if peerStatus.KeyExpiry != nil {
					assert.Truef(
						t,
						peerStatus.KeyExpiry.Before(now),
						"node %q should have a key expire before %s, was %s",
						peerStatus.HostName,
						now.String(),
						peerStatus.KeyExpiry,
					)
				}

				assert.Truef(
					t,
					peerStatus.Expired,
					"node %q should be expired, expired is %v",
					peerStatus.HostName,
					peerStatus.Expired,
				)

				_, stderr, _ := client.Execute([]string{"tailscale", "ping", node.GetName()})
				if !strings.Contains(stderr, "node key has expired") {
					t.Errorf(
						"expected to be unable to ping expired host %q from %q",
						node.GetName(),
						client.Hostname(),
					)
				}
			} else {
				t.Errorf("failed to find node %q with nodekey (%s) in mapresponse, should be present even if it is expired", node.GetName(), expiredNodeKey)
			}
		} else {
			if status.Self.KeyExpiry != nil {
				assert.Truef(t, status.Self.KeyExpiry.Before(now), "node %q should have a key expire before %s, was %s", status.Self.HostName, now.String(), status.Self.KeyExpiry)
			}

			// NeedsLogin means that the node has understood that it is no longer
			// valid.
			assert.Equalf(t, "NeedsLogin", status.BackendState, "checking node %q", status.Self.HostName)
		}
	}
}

func TestNodeOnlineStatus(t *testing.T) {
	IntegrationSkip(t)
	t.Parallel()

	scenario, err := NewScenario(dockertestMaxWait())
	assertNoErr(t, err)
	defer scenario.Shutdown()

	spec := map[string]int{
		"user1": len(MustTestVersions),
	}

	err = scenario.CreateHeadscaleEnv(spec, []tsic.Option{}, hsic.WithTestName("online"))
	assertNoErrHeadscaleEnv(t, err)

	allClients, err := scenario.ListTailscaleClients()
	assertNoErrListClients(t, err)

	allIps, err := scenario.ListTailscaleClientsIPs()
	assertNoErrListClientIPs(t, err)

	err = scenario.WaitForTailscaleSync()
	assertNoErrSync(t, err)

	// assertClientsState(t, allClients)

	allAddrs := lo.Map(allIps, func(x netip.Addr, index int) string {
		return x.String()
	})

	success := pingAllHelper(t, allClients, allAddrs)
	t.Logf("before expire: %d successful pings out of %d", success, len(allClients)*len(allIps))

	for _, client := range allClients {
		status, err := client.Status()
		assertNoErr(t, err)

		// Assert that we have the original count - self
		assert.Len(t, status.Peers(), len(MustTestVersions)-1)
	}

	headscale, err := scenario.Headscale()
	assertNoErr(t, err)

	// Duration is chosen arbitrarily, 10m is reported in #1561
	testDuration := 12 * time.Minute
	start := time.Now()
	end := start.Add(testDuration)

	log.Printf("Starting online test from %v to %v", start, end)

	for {
		// Let the test run continuously for X minutes to verify
		// all nodes stay connected and has the expected status over time.
		if end.Before(time.Now()) {
			return
		}

		result, err := headscale.Execute([]string{
			"headscale", "nodes", "list", "--output", "json",
		})
		assertNoErr(t, err)

		var nodes []*v1.Node
		err = json.Unmarshal([]byte(result), &nodes)
		assertNoErr(t, err)

		// Verify that headscale reports the nodes as online
		for _, node := range nodes {
			// All nodes should be online
			assert.Truef(
				t,
				node.GetOnline(),
				"expected %s to have online status in Headscale, marked as offline %s after start",
				node.GetName(),
				time.Since(start),
			)
		}

		// Verify that all nodes report all nodes to be online
		for _, client := range allClients {
			status, err := client.Status()
			assertNoErr(t, err)

			for _, peerKey := range status.Peers() {
				peerStatus := status.Peer[peerKey]

				// .Online is only available from CapVer 16, which
				// is not present in 1.18 which is the lowest we
				// test.
				if strings.Contains(client.Hostname(), "1-18") {
					continue
				}

				// All peers of this nodess are reporting to be
				// connected to the control server
				assert.Truef(
					t,
					peerStatus.Online,
					"expected node %s to be marked as online in %s peer list, marked as offline %s after start",
					peerStatus.HostName,
					client.Hostname(),
					time.Since(start),
				)
			}
		}

		// Check maximum once per second
		time.Sleep(time.Second)
	}
}

// TestPingAllByIPManyUpDown is a variant of the PingAll
// test which will take the tailscale node up and down
// five times ensuring they are able to restablish connectivity.
func TestPingAllByIPManyUpDown(t *testing.T) {
	IntegrationSkip(t)
	t.Parallel()

	scenario, err := NewScenario(dockertestMaxWait())
	assertNoErr(t, err)
	defer scenario.Shutdown()

	// TODO(kradalby): it does not look like the user thing works, only second
	// get created? maybe only when many?
	spec := map[string]int{
		"user1": len(MustTestVersions),
		"user2": len(MustTestVersions),
	}

	headscaleConfig := map[string]string{
		"HEADSCALE_DERP_URLS":                    "",
		"HEADSCALE_DERP_SERVER_ENABLED":          "true",
		"HEADSCALE_DERP_SERVER_REGION_ID":        "999",
		"HEADSCALE_DERP_SERVER_REGION_CODE":      "headscale",
		"HEADSCALE_DERP_SERVER_REGION_NAME":      "Headscale Embedded DERP",
		"HEADSCALE_DERP_SERVER_STUN_LISTEN_ADDR": "0.0.0.0:3478",
		"HEADSCALE_DERP_SERVER_PRIVATE_KEY_PATH": "/tmp/derp.key",

		// Envknob for enabling DERP debug logs
		"DERP_DEBUG_LOGS":        "true",
		"DERP_PROBER_DEBUG_LOGS": "true",
	}

	err = scenario.CreateHeadscaleEnv(spec,
		[]tsic.Option{},
		hsic.WithTestName("pingallbyip"),
		hsic.WithConfigEnv(headscaleConfig),
		hsic.WithTLS(),
		hsic.WithHostnameAsServerURL(),
	)
	assertNoErrHeadscaleEnv(t, err)

	allClients, err := scenario.ListTailscaleClients()
	assertNoErrListClients(t, err)

	allIps, err := scenario.ListTailscaleClientsIPs()
	assertNoErrListClientIPs(t, err)

	err = scenario.WaitForTailscaleSync()
	assertNoErrSync(t, err)

	// assertClientsState(t, allClients)

	allAddrs := lo.Map(allIps, func(x netip.Addr, index int) string {
		return x.String()
	})

	success := pingAllHelper(t, allClients, allAddrs)
	t.Logf("%d successful pings out of %d", success, len(allClients)*len(allIps))

	for run := range 3 {
		t.Logf("Starting DownUpPing run %d", run+1)

		for _, client := range allClients {
			t.Logf("taking down %q", client.Hostname())
			client.Down()
		}

		time.Sleep(5 * time.Second)

		for _, client := range allClients {
			t.Logf("bringing up %q", client.Hostname())
			client.Up()
		}

		time.Sleep(5 * time.Second)

		err = scenario.WaitForTailscaleSync()
		assertNoErrSync(t, err)

		success := pingAllHelper(t, allClients, allAddrs)
		t.Logf("%d successful pings out of %d", success, len(allClients)*len(allIps))
	}
}
