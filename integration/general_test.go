package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/juanfont/headscale/integration/hsic"
	"github.com/juanfont/headscale/integration/tsic"
	"github.com/rs/zerolog/log"
	"github.com/samber/lo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"
	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/types/key"
)

func TestPingAllByIP(t *testing.T) {
	IntegrationSkip(t)
	t.Parallel()

	scenario, err := NewScenario(dockertestMaxWait())
	assertNoErr(t, err)
	defer scenario.ShutdownAssertNoPanics(t)

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
	defer scenario.ShutdownAssertNoPanics(t)

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

	for _, https := range []bool{true, false} {
		t.Run(fmt.Sprintf("with-https-%t", https), func(t *testing.T) {
			scenario, err := NewScenario(dockertestMaxWait())
			assertNoErr(t, err)
			defer scenario.ShutdownAssertNoPanics(t)

			spec := map[string]int{
				"user1": len(MustTestVersions),
				"user2": len(MustTestVersions),
			}

			opts := []hsic.Option{hsic.WithTestName("pingallbyip")}
			if https {
				opts = append(opts, []hsic.Option{
					hsic.WithTLS(),
				}...)
			}

			err = scenario.CreateHeadscaleEnv(spec, []tsic.Option{}, opts...)
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

			// if the server is not running with HTTPS, we have to wait a bit before
			// reconnection as the newest Tailscale client has a measure that will only
			// reconnect over HTTPS if they saw a noise connection previously.
			// https://github.com/tailscale/tailscale/commit/1eaad7d3deb0815e8932e913ca1a862afa34db38
			// https://github.com/juanfont/headscale/issues/2164
			if !https {
				time.Sleep(5 * time.Minute)
			}

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
		})
	}
}

func TestEphemeral(t *testing.T) {
	testEphemeralWithOptions(t, hsic.WithTestName("ephemeral"))
}

func TestEphemeralInAlternateTimezone(t *testing.T) {
	testEphemeralWithOptions(
		t,
		hsic.WithTestName("ephemeral-tz"),
		hsic.WithTimezone("America/Los_Angeles"),
	)
}

func testEphemeralWithOptions(t *testing.T, opts ...hsic.Option) {
	IntegrationSkip(t)
	t.Parallel()

	scenario, err := NewScenario(dockertestMaxWait())
	assertNoErr(t, err)
	defer scenario.ShutdownAssertNoPanics(t)

	spec := map[string]int{
		"user1": len(MustTestVersions),
		"user2": len(MustTestVersions),
	}

	headscale, err := scenario.Headscale(opts...)
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

// TestEphemeral2006DeletedTooQuickly verifies that ephemeral nodes are not
// deleted by accident if they are still online and active.
func TestEphemeral2006DeletedTooQuickly(t *testing.T) {
	IntegrationSkip(t)
	t.Parallel()

	scenario, err := NewScenario(dockertestMaxWait())
	assertNoErr(t, err)
	defer scenario.ShutdownAssertNoPanics(t)

	spec := map[string]int{
		"user1": len(MustTestVersions),
		"user2": len(MustTestVersions),
	}

	headscale, err := scenario.Headscale(
		hsic.WithTestName("ephemeral2006"),
		hsic.WithConfigEnv(map[string]string{
			"HEADSCALE_EPHEMERAL_NODE_INACTIVITY_TIMEOUT": "1m6s",
		}),
	)
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

	// All ephemeral nodes should be online and reachable.
	success := pingAllHelper(t, allClients, allAddrs)
	t.Logf("%d successful pings out of %d", success, len(allClients)*len(allIps))

	// Take down all clients, this should start an expiry timer for each.
	for _, client := range allClients {
		err := client.Down()
		if err != nil {
			t.Fatalf("failed to take down client %s: %s", client.Hostname(), err)
		}
	}

	// Wait a bit and bring up the clients again before the expiry
	// time of the ephemeral nodes.
	// Nodes should be able to reconnect and work fine.
	time.Sleep(30 * time.Second)

	for _, client := range allClients {
		err := client.Up()
		if err != nil {
			t.Fatalf("failed to take down client %s: %s", client.Hostname(), err)
		}
	}
	err = scenario.WaitForTailscaleSync()
	assertNoErrSync(t, err)

	success = pingAllHelper(t, allClients, allAddrs)
	t.Logf("%d successful pings out of %d", success, len(allClients)*len(allIps))

	// Take down all clients, this should start an expiry timer for each.
	for _, client := range allClients {
		err := client.Down()
		if err != nil {
			t.Fatalf("failed to take down client %s: %s", client.Hostname(), err)
		}
	}

	// This time wait for all of the nodes to expire and check that they are no longer
	// registered.
	time.Sleep(3 * time.Minute)

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
	defer scenario.ShutdownAssertNoPanics(t)

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

	retry := func(times int, sleepInterval time.Duration, doWork func() error) error {
		var err error
		for attempts := 0; attempts < times; attempts++ {
			err = doWork()
			if err == nil {
				return nil
			}
			time.Sleep(sleepInterval)
		}

		return err
	}

	scenario, err := NewScenario(dockertestMaxWait())
	assertNoErr(t, err)
	defer scenario.ShutdownAssertNoPanics(t)

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

func TestUpdateHostnameFromClient(t *testing.T) {
	IntegrationSkip(t)
	t.Parallel()

	user := "update-hostname-from-client"

	hostnames := map[string]string{
		"1": "user1-host",
		"2": "User2-Host",
		"3": "user3-host",
	}

	scenario, err := NewScenario(dockertestMaxWait())
	assertNoErrf(t, "failed to create scenario: %s", err)
	defer scenario.ShutdownAssertNoPanics(t)

	spec := map[string]int{
		user: 3,
	}

	err = scenario.CreateHeadscaleEnv(spec, []tsic.Option{}, hsic.WithTestName("updatehostname"))
	assertNoErrHeadscaleEnv(t, err)

	allClients, err := scenario.ListTailscaleClients()
	assertNoErrListClients(t, err)

	err = scenario.WaitForTailscaleSync()
	assertNoErrSync(t, err)

	headscale, err := scenario.Headscale()
	assertNoErrGetHeadscale(t, err)

	// update hostnames using the up command
	for _, client := range allClients {
		status, err := client.Status()
		assertNoErr(t, err)

		command := []string{
			"tailscale",
			"set",
			"--hostname=" + hostnames[string(status.Self.ID)],
		}
		_, _, err = client.Execute(command)
		assertNoErrf(t, "failed to set hostname: %s", err)
	}

	err = scenario.WaitForTailscaleSync()
	assertNoErrSync(t, err)

	var nodes []*v1.Node
	err = executeAndUnmarshal(
		headscale,
		[]string{
			"headscale",
			"node",
			"list",
			"--output",
			"json",
		},
		&nodes,
	)

	assertNoErr(t, err)
	assert.Len(t, nodes, 3)

	for _, node := range nodes {
		hostname := hostnames[strconv.FormatUint(node.GetId(), 10)]
		assert.Equal(t, hostname, node.GetName())
		assert.Equal(t, util.ConvertWithFQDNRules(hostname), node.GetGivenName())
	}

	// Rename givenName in nodes
	for _, node := range nodes {
		givenName := fmt.Sprintf("%d-givenname", node.GetId())
		_, err = headscale.Execute(
			[]string{
				"headscale",
				"node",
				"rename",
				givenName,
				"--identifier",
				strconv.FormatUint(node.GetId(), 10),
			})
		assertNoErr(t, err)
	}

	time.Sleep(5 * time.Second)

	// Verify that the clients can see the new hostname, but no givenName
	for _, client := range allClients {
		status, err := client.Status()
		assertNoErr(t, err)

		command := []string{
			"tailscale",
			"set",
			"--hostname=" + hostnames[string(status.Self.ID)] + "NEW",
		}
		_, _, err = client.Execute(command)
		assertNoErrf(t, "failed to set hostname: %s", err)
	}

	err = scenario.WaitForTailscaleSync()
	assertNoErrSync(t, err)

	err = executeAndUnmarshal(
		headscale,
		[]string{
			"headscale",
			"node",
			"list",
			"--output",
			"json",
		},
		&nodes,
	)

	assertNoErr(t, err)
	assert.Len(t, nodes, 3)

	for _, node := range nodes {
		hostname := hostnames[strconv.FormatUint(node.GetId(), 10)]
		givenName := fmt.Sprintf("%d-givenname", node.GetId())
		assert.Equal(t, hostname+"NEW", node.GetName())
		assert.Equal(t, givenName, node.GetGivenName())
	}
}

func TestExpireNode(t *testing.T) {
	IntegrationSkip(t)
	t.Parallel()

	scenario, err := NewScenario(dockertestMaxWait())
	assertNoErr(t, err)
	defer scenario.ShutdownAssertNoPanics(t)

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
	defer scenario.ShutdownAssertNoPanics(t)

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

				// All peers of this nodes are reporting to be
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
	defer scenario.ShutdownAssertNoPanics(t)

	// TODO(kradalby): it does not look like the user thing works, only second
	// get created? maybe only when many?
	spec := map[string]int{
		"user1": len(MustTestVersions),
		"user2": len(MustTestVersions),
	}

	err = scenario.CreateHeadscaleEnv(spec,
		[]tsic.Option{},
		hsic.WithTestName("pingallbyipmany"),
		hsic.WithEmbeddedDERPServerOnly(),
		hsic.WithTLS(),
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

	wg, _ := errgroup.WithContext(context.Background())

	for run := range 3 {
		t.Logf("Starting DownUpPing run %d", run+1)

		for _, client := range allClients {
			c := client
			wg.Go(func() error {
				t.Logf("taking down %q", c.Hostname())
				return c.Down()
			})
		}

		if err := wg.Wait(); err != nil {
			t.Fatalf("failed to take down all nodes: %s", err)
		}

		time.Sleep(5 * time.Second)

		for _, client := range allClients {
			c := client
			wg.Go(func() error {
				t.Logf("bringing up %q", c.Hostname())
				return c.Up()
			})
		}

		if err := wg.Wait(); err != nil {
			t.Fatalf("failed to take down all nodes: %s", err)
		}

		time.Sleep(5 * time.Second)

		err = scenario.WaitForTailscaleSync()
		assertNoErrSync(t, err)

		success := pingAllHelper(t, allClients, allAddrs)
		t.Logf("%d successful pings out of %d", success, len(allClients)*len(allIps))
	}
}

func Test2118DeletingOnlineNodePanics(t *testing.T) {
	IntegrationSkip(t)
	t.Parallel()

	scenario, err := NewScenario(dockertestMaxWait())
	assertNoErr(t, err)
	defer scenario.ShutdownAssertNoPanics(t)

	// TODO(kradalby): it does not look like the user thing works, only second
	// get created? maybe only when many?
	spec := map[string]int{
		"user1": 1,
		"user2": 1,
	}

	err = scenario.CreateHeadscaleEnv(spec,
		[]tsic.Option{},
		hsic.WithTestName("deletenocrash"),
		hsic.WithEmbeddedDERPServerOnly(),
		hsic.WithTLS(),
	)
	assertNoErrHeadscaleEnv(t, err)

	allClients, err := scenario.ListTailscaleClients()
	assertNoErrListClients(t, err)

	allIps, err := scenario.ListTailscaleClientsIPs()
	assertNoErrListClientIPs(t, err)

	err = scenario.WaitForTailscaleSync()
	assertNoErrSync(t, err)

	allAddrs := lo.Map(allIps, func(x netip.Addr, index int) string {
		return x.String()
	})

	success := pingAllHelper(t, allClients, allAddrs)
	t.Logf("%d successful pings out of %d", success, len(allClients)*len(allIps))

	headscale, err := scenario.Headscale()
	assertNoErr(t, err)

	// Test list all nodes after added otherUser
	var nodeList []v1.Node
	err = executeAndUnmarshal(
		headscale,
		[]string{
			"headscale",
			"nodes",
			"list",
			"--output",
			"json",
		},
		&nodeList,
	)
	require.NoError(t, err)
	assert.Len(t, nodeList, 2)
	assert.True(t, nodeList[0].GetOnline())
	assert.True(t, nodeList[1].GetOnline())

	// Delete the first node, which is online
	_, err = headscale.Execute(
		[]string{
			"headscale",
			"nodes",
			"delete",
			"--identifier",
			// Delete the last added machine
			fmt.Sprintf("%d", nodeList[0].GetId()),
			"--output",
			"json",
			"--force",
		},
	)
	require.NoError(t, err)

	time.Sleep(2 * time.Second)

	// Ensure that the node has been deleted, this did not occur due to a panic.
	var nodeListAfter []v1.Node
	err = executeAndUnmarshal(
		headscale,
		[]string{
			"headscale",
			"nodes",
			"list",
			"--output",
			"json",
		},
		&nodeListAfter,
	)
	require.NoError(t, err)
	assert.Len(t, nodeListAfter, 1)
	assert.True(t, nodeListAfter[0].GetOnline())
	assert.Equal(t, nodeList[1].GetId(), nodeListAfter[0].GetId())
}
