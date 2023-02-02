package integration

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
	"github.com/juanfont/headscale/integration/hsic"
	"github.com/juanfont/headscale/integration/tsic"
	"github.com/rs/zerolog/log"
	"github.com/samber/lo"
	"github.com/stretchr/testify/assert"
)

func TestPingAllByIP(t *testing.T) {
	IntegrationSkip(t)
	t.Parallel()

	scenario, err := NewScenario()
	if err != nil {
		t.Errorf("failed to create scenario: %s", err)
	}

	spec := map[string]int{
		"user1": len(TailscaleVersions),
		"user2": len(TailscaleVersions),
	}

	err = scenario.CreateHeadscaleEnv(spec, []tsic.Option{}, hsic.WithTestName("pingallbyip"))
	if err != nil {
		t.Errorf("failed to create headscale environment: %s", err)
	}

	allClients, err := scenario.ListTailscaleClients()
	if err != nil {
		t.Errorf("failed to get clients: %s", err)
	}

	allIps, err := scenario.ListTailscaleClientsIPs()
	if err != nil {
		t.Errorf("failed to get clients: %s", err)
	}

	err = scenario.WaitForTailscaleSync()
	if err != nil {
		t.Errorf("failed wait for tailscale clients to be in sync: %s", err)
	}

	allAddrs := lo.Map(allIps, func(x netip.Addr, index int) string {
		return x.String()
	})

	success := pingAllHelper(t, allClients, allAddrs)
	t.Logf("%d successful pings out of %d", success, len(allClients)*len(allIps))

	err = scenario.Shutdown()
	if err != nil {
		t.Errorf("failed to tear down scenario: %s", err)
	}
}

func TestAuthKeyLogoutAndRelogin(t *testing.T) {
	IntegrationSkip(t)
	t.Parallel()

	scenario, err := NewScenario()
	if err != nil {
		t.Errorf("failed to create scenario: %s", err)
	}

	spec := map[string]int{
		"user1": len(TailscaleVersions),
		"user2": len(TailscaleVersions),
	}

	err = scenario.CreateHeadscaleEnv(spec, []tsic.Option{}, hsic.WithTestName("pingallbyip"))
	if err != nil {
		t.Errorf("failed to create headscale environment: %s", err)
	}

	allClients, err := scenario.ListTailscaleClients()
	if err != nil {
		t.Errorf("failed to get clients: %s", err)
	}

	err = scenario.WaitForTailscaleSync()
	if err != nil {
		t.Errorf("failed wait for tailscale clients to be in sync: %s", err)
	}

	clientIPs := make(map[TailscaleClient][]netip.Addr)
	for _, client := range allClients {
		ips, err := client.IPs()
		if err != nil {
			t.Errorf("failed to get IPs for client %s: %s", client.Hostname(), err)
		}
		clientIPs[client] = ips
	}

	for _, client := range allClients {
		err := client.Logout()
		if err != nil {
			t.Errorf("failed to logout client %s: %s", client.Hostname(), err)
		}
	}

	scenario.WaitForTailscaleLogout()

	t.Logf("all clients logged out")

	headscale, err := scenario.Headscale()
	if err != nil {
		t.Errorf("failed to get headscale server: %s", err)
	}

	for userName := range spec {
		key, err := scenario.CreatePreAuthKey(userName, true, false)
		if err != nil {
			t.Errorf("failed to create pre-auth key for user %s: %s", userName, err)
		}

		err = scenario.RunTailscaleUp(userName, headscale.GetEndpoint(), key.GetKey())
		if err != nil {
			t.Errorf("failed to run tailscale up for user %s: %s", userName, err)
		}
	}

	err = scenario.WaitForTailscaleSync()
	if err != nil {
		t.Errorf("failed wait for tailscale clients to be in sync: %s", err)
	}

	allClients, err = scenario.ListTailscaleClients()
	if err != nil {
		t.Errorf("failed to get clients: %s", err)
	}

	allIps, err := scenario.ListTailscaleClientsIPs()
	if err != nil {
		t.Errorf("failed to get clients: %s", err)
	}

	allAddrs := lo.Map(allIps, func(x netip.Addr, index int) string {
		return x.String()
	})

	success := pingAllHelper(t, allClients, allAddrs)
	t.Logf("%d successful pings out of %d", success, len(allClients)*len(allIps))

	for _, client := range allClients {
		ips, err := client.IPs()
		if err != nil {
			t.Errorf("failed to get IPs for client %s: %s", client.Hostname(), err)
		}

		// lets check if the IPs are the same
		if len(ips) != len(clientIPs[client]) {
			t.Errorf("IPs changed for client %s", client.Hostname())
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
				t.Errorf(
					"IPs changed for client %s. Used to be %v now %v",
					client.Hostname(),
					clientIPs[client],
					ips,
				)
			}
		}
	}

	t.Logf("all clients IPs are the same")

	err = scenario.Shutdown()
	if err != nil {
		t.Errorf("failed to tear down scenario: %s", err)
	}
}

func TestEphemeral(t *testing.T) {
	IntegrationSkip(t)
	t.Parallel()

	scenario, err := NewScenario()
	if err != nil {
		t.Errorf("failed to create scenario: %s", err)
	}

	spec := map[string]int{
		"user1": len(TailscaleVersions),
		"user2": len(TailscaleVersions),
	}

	headscale, err := scenario.Headscale(hsic.WithTestName("ephemeral"))
	if err != nil {
		t.Errorf("failed to create headscale environment: %s", err)
	}

	for userName, clientCount := range spec {
		err = scenario.CreateUser(userName)
		if err != nil {
			t.Errorf("failed to create user %s: %s", userName, err)
		}

		err = scenario.CreateTailscaleNodesInUser(userName, "all", clientCount, []tsic.Option{}...)
		if err != nil {
			t.Errorf("failed to create tailscale nodes in user %s: %s", userName, err)
		}

		key, err := scenario.CreatePreAuthKey(userName, true, true)
		if err != nil {
			t.Errorf("failed to create pre-auth key for user %s: %s", userName, err)
		}

		err = scenario.RunTailscaleUp(userName, headscale.GetEndpoint(), key.GetKey())
		if err != nil {
			t.Errorf("failed to run tailscale up for user %s: %s", userName, err)
		}
	}

	err = scenario.WaitForTailscaleSync()
	if err != nil {
		t.Errorf("failed wait for tailscale clients to be in sync: %s", err)
	}

	allClients, err := scenario.ListTailscaleClients()
	if err != nil {
		t.Errorf("failed to get clients: %s", err)
	}

	allIps, err := scenario.ListTailscaleClientsIPs()
	if err != nil {
		t.Errorf("failed to get clients: %s", err)
	}

	allAddrs := lo.Map(allIps, func(x netip.Addr, index int) string {
		return x.String()
	})

	success := pingAllHelper(t, allClients, allAddrs)
	t.Logf("%d successful pings out of %d", success, len(allClients)*len(allIps))

	for _, client := range allClients {
		err := client.Logout()
		if err != nil {
			t.Errorf("failed to logout client %s: %s", client.Hostname(), err)
		}
	}

	scenario.WaitForTailscaleLogout()

	t.Logf("all clients logged out")

	for userName := range spec {
		machines, err := headscale.ListMachinesInUser(userName)
		if err != nil {
			log.Error().
				Err(err).
				Str("user", userName).
				Msg("Error listing machines in user")

			return
		}

		if len(machines) != 0 {
			t.Errorf("expected no machines, got %d in user %s", len(machines), userName)
		}
	}

	err = scenario.Shutdown()
	if err != nil {
		t.Errorf("failed to tear down scenario: %s", err)
	}
}

func TestPingAllByHostname(t *testing.T) {
	IntegrationSkip(t)
	t.Parallel()

	scenario, err := NewScenario()
	if err != nil {
		t.Errorf("failed to create scenario: %s", err)
	}

	spec := map[string]int{
		// Omit 1.16.2 (-1) because it does not have the FQDN field
		"user3": len(TailscaleVersions) - 1,
		"user4": len(TailscaleVersions) - 1,
	}

	err = scenario.CreateHeadscaleEnv(spec, []tsic.Option{}, hsic.WithTestName("pingallbyname"))
	if err != nil {
		t.Errorf("failed to create headscale environment: %s", err)
	}

	allClients, err := scenario.ListTailscaleClients()
	if err != nil {
		t.Errorf("failed to get clients: %s", err)
	}

	err = scenario.WaitForTailscaleSync()
	if err != nil {
		t.Errorf("failed wait for tailscale clients to be in sync: %s", err)
	}

	allHostnames, err := scenario.ListTailscaleClientsFQDNs()
	if err != nil {
		t.Errorf("failed to get FQDNs: %s", err)
	}

	success := pingAllHelper(t, allClients, allHostnames)

	t.Logf("%d successful pings out of %d", success, len(allClients)*len(allClients))

	err = scenario.Shutdown()
	if err != nil {
		t.Errorf("failed to tear down scenario: %s", err)
	}
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

	scenario, err := NewScenario()
	if err != nil {
		t.Errorf("failed to create scenario: %s", err)
	}

	spec := map[string]int{
		// Omit 1.16.2 (-1) because it does not have the FQDN field
		"taildrop": len(TailscaleVersions) - 1,
	}

	err = scenario.CreateHeadscaleEnv(spec, []tsic.Option{}, hsic.WithTestName("taildrop"))
	if err != nil {
		t.Errorf("failed to create headscale environment: %s", err)
	}

	allClients, err := scenario.ListTailscaleClients()
	if err != nil {
		t.Errorf("failed to get clients: %s", err)
	}

	err = scenario.WaitForTailscaleSync()
	if err != nil {
		t.Errorf("failed wait for tailscale clients to be in sync: %s", err)
	}

	// This will essentially fetch and cache all the FQDNs
	_, err = scenario.ListTailscaleClientsFQDNs()
	if err != nil {
		t.Errorf("failed to get FQDNs: %s", err)
	}

	for _, client := range allClients {
		command := []string{"touch", fmt.Sprintf("/tmp/file_from_%s", client.Hostname())}

		if _, _, err := client.Execute(command); err != nil {
			t.Errorf("failed to create taildrop file on %s, err: %s", client.Hostname(), err)
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
					t.Errorf(
						"failed to send taildrop file on %s, err: %s",
						client.Hostname(),
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
			t.Errorf("failed to get taildrop file on %s, err: %s", client.Hostname(), err)
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
				if err != nil {
					t.Errorf("failed to execute command to ls taildrop: %s", err)
				}

				log.Printf("Result for %s: %s\n", peer.Hostname(), result)
				if fmt.Sprintf("/tmp/file_from_%s\n", peer.Hostname()) != result {
					t.Errorf(
						"taildrop result is not correct %s, wanted %s",
						result,
						fmt.Sprintf("/tmp/file_from_%s\n", peer.Hostname()),
					)
				}
			})
		}
	}

	err = scenario.Shutdown()
	if err != nil {
		t.Errorf("failed to tear down scenario: %s", err)
	}
}

func TestResolveMagicDNS(t *testing.T) {
	IntegrationSkip(t)
	t.Parallel()

	scenario, err := NewScenario()
	if err != nil {
		t.Errorf("failed to create scenario: %s", err)
	}

	spec := map[string]int{
		// Omit 1.16.2 (-1) because it does not have the FQDN field
		"magicdns1": len(TailscaleVersions) - 1,
		"magicdns2": len(TailscaleVersions) - 1,
	}

	err = scenario.CreateHeadscaleEnv(spec, []tsic.Option{}, hsic.WithTestName("magicdns"))
	if err != nil {
		t.Errorf("failed to create headscale environment: %s", err)
	}

	allClients, err := scenario.ListTailscaleClients()
	if err != nil {
		t.Errorf("failed to get clients: %s", err)
	}

	err = scenario.WaitForTailscaleSync()
	if err != nil {
		t.Errorf("failed wait for tailscale clients to be in sync: %s", err)
	}

	// Poor mans cache
	_, err = scenario.ListTailscaleClientsFQDNs()
	if err != nil {
		t.Errorf("failed to get FQDNs: %s", err)
	}

	_, err = scenario.ListTailscaleClientsIPs()
	if err != nil {
		t.Errorf("failed to get IPs: %s", err)
	}

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
				t.Errorf(
					"failed to execute resolve/ip command %s from %s: %s",
					peerFQDN,
					client.Hostname(),
					err,
				)
			}

			ips, err := peer.IPs()
			if err != nil {
				t.Errorf(
					"failed to get ips for %s: %s",
					peer.Hostname(),
					err,
				)
			}

			for _, ip := range ips {
				if !strings.Contains(result, ip.String()) {
					t.Errorf("ip %s is not found in \n%s\n", ip.String(), result)
				}
			}
		}
	}

	err = scenario.Shutdown()
	if err != nil {
		t.Errorf("failed to tear down scenario: %s", err)
	}
}

func TestExpireNode(t *testing.T) {
	IntegrationSkip(t)
	t.Parallel()

	scenario, err := NewScenario()
	if err != nil {
		t.Errorf("failed to create scenario: %s", err)
	}

	spec := map[string]int{
		"user1": len(TailscaleVersions),
	}

	err = scenario.CreateHeadscaleEnv(spec, []tsic.Option{}, hsic.WithTestName("expirenode"))
	if err != nil {
		t.Errorf("failed to create headscale environment: %s", err)
	}

	allClients, err := scenario.ListTailscaleClients()
	if err != nil {
		t.Errorf("failed to get clients: %s", err)
	}

	allIps, err := scenario.ListTailscaleClientsIPs()
	if err != nil {
		t.Errorf("failed to get clients: %s", err)
	}

	err = scenario.WaitForTailscaleSync()
	if err != nil {
		t.Errorf("failed wait for tailscale clients to be in sync: %s", err)
	}

	allAddrs := lo.Map(allIps, func(x netip.Addr, index int) string {
		return x.String()
	})

	success := pingAllHelper(t, allClients, allAddrs)
	t.Logf("before expire: %d successful pings out of %d", success, len(allClients)*len(allIps))

	for _, client := range allClients {
		status, err := client.Status()
		assert.NoError(t, err)

		// Assert that we have the original count - self
		assert.Len(t, status.Peers(), len(TailscaleVersions)-1)
	}

	headscale, err := scenario.Headscale()
	assert.NoError(t, err)

	// TODO(kradalby): This is Headscale specific and would not play nicely
	// with other implementations of the ControlServer interface
	result, err := headscale.Execute([]string{
		"headscale", "nodes", "expire", "--identifier", "0", "--output", "json",
	})
	assert.NoError(t, err)

	var machine v1.Machine
	err = json.Unmarshal([]byte(result), &machine)
	assert.NoError(t, err)

	time.Sleep(30 * time.Second)

	// Verify that the expired not is no longer present in the Peer list
	// of connected nodes.
	for _, client := range allClients {
		status, err := client.Status()
		assert.NoError(t, err)

		for _, peerKey := range status.Peers() {
			peerStatus := status.Peer[peerKey]

			peerPublicKey := strings.TrimPrefix(peerStatus.PublicKey.String(), "nodekey:")

			assert.NotEqual(t, machine.NodeKey, peerPublicKey)
		}

		if client.Hostname() != machine.Name {
			// Assert that we have the original count - self - expired node
			assert.Len(t, status.Peers(), len(TailscaleVersions)-2)
		}
	}

	err = scenario.Shutdown()
	if err != nil {
		t.Errorf("failed to tear down scenario: %s", err)
	}
}
