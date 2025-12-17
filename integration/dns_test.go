package integration

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/juanfont/headscale/integration/hsic"
	"github.com/juanfont/headscale/integration/tsic"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
)

func TestResolveMagicDNS(t *testing.T) {
	IntegrationSkip(t)

	spec := ScenarioSpec{
		NodesPerUser: len(MustTestVersions),
		Users:        []string{"user1", "user2"},
	}

	scenario, err := NewScenario(spec)
	require.NoError(t, err)
	defer scenario.ShutdownAssertNoPanics(t)

	err = scenario.CreateHeadscaleEnv([]tsic.Option{}, hsic.WithTestName("magicdns"))
	requireNoErrHeadscaleEnv(t, err)

	allClients, err := scenario.ListTailscaleClients()
	requireNoErrListClients(t, err)

	err = scenario.WaitForTailscaleSync()
	requireNoErrSync(t, err)

	// assertClientsState(t, allClients)

	// Poor mans cache
	_, err = scenario.ListTailscaleClientsFQDNs()
	requireNoErrListFQDN(t, err)

	_, err = scenario.ListTailscaleClientsIPs()
	requireNoErrListClientIPs(t, err)

	for _, client := range allClients {
		for _, peer := range allClients {
			// It is safe to ignore this error as we handled it when caching it
			peerFQDN, _ := peer.FQDN()

			assert.Equal(t, peer.Hostname()+".headscale.net.", peerFQDN)

			assert.EventuallyWithT(t, func(ct *assert.CollectT) {
				command := []string{
					"tailscale",
					"ip", peerFQDN,
				}
				result, _, err := client.Execute(command)
				assert.NoError(ct, err, "Failed to execute resolve/ip command %s from %s", peerFQDN, client.Hostname())

				ips, err := peer.IPs()
				assert.NoError(ct, err, "Failed to get IPs for %s", peer.Hostname())

				for _, ip := range ips {
					assert.Contains(ct, result, ip.String(), "IP %s should be found in DNS resolution result from %s to %s", ip.String(), client.Hostname(), peer.Hostname())
				}
			}, 30*time.Second, 2*time.Second)
		}
	}
}

func TestResolveMagicDNSExtraRecordsPath(t *testing.T) {
	IntegrationSkip(t)

	spec := ScenarioSpec{
		NodesPerUser: 1,
		Users:        []string{"user1", "user2"},
	}

	scenario, err := NewScenario(spec)
	require.NoError(t, err)
	defer scenario.ShutdownAssertNoPanics(t)

	const erPath = "/tmp/extra_records.json"

	extraRecords := []tailcfg.DNSRecord{
		{
			Name:  "test.myvpn.example.com",
			Type:  "A",
			Value: "6.6.6.6",
		},
	}
	b, _ := json.Marshal(extraRecords)

	err = scenario.CreateHeadscaleEnv([]tsic.Option{
		tsic.WithDockerEntrypoint([]string{
			"/bin/sh",
			"-c",
			"/bin/sleep 3 ; apk add python3 curl bind-tools ; update-ca-certificates ; tailscaled --tun=tsdev",
		}),
	},
		hsic.WithTestName("extrarecords"),
		hsic.WithConfigEnv(map[string]string{
			// Disable global nameservers to make the test run offline.
			"HEADSCALE_DNS_NAMESERVERS_GLOBAL": "",
			"HEADSCALE_DNS_EXTRA_RECORDS_PATH": erPath,
		}),
		hsic.WithFileInContainer(erPath, b),
		hsic.WithEmbeddedDERPServerOnly(),
		hsic.WithTLS(),
	)
	requireNoErrHeadscaleEnv(t, err)

	allClients, err := scenario.ListTailscaleClients()
	requireNoErrListClients(t, err)

	err = scenario.WaitForTailscaleSync()
	requireNoErrSync(t, err)

	// assertClientsState(t, allClients)

	// Poor mans cache
	_, err = scenario.ListTailscaleClientsFQDNs()
	requireNoErrListFQDN(t, err)

	_, err = scenario.ListTailscaleClientsIPs()
	requireNoErrListClientIPs(t, err)

	for _, client := range allClients {
		assertCommandOutputContains(t, client, []string{"dig", "test.myvpn.example.com"}, "6.6.6.6")
	}

	hs, err := scenario.Headscale()
	require.NoError(t, err)

	// Write the file directly into place from the docker API.
	b0, _ := json.Marshal([]tailcfg.DNSRecord{
		{
			Name:  "docker.myvpn.example.com",
			Type:  "A",
			Value: "2.2.2.2",
		},
	})

	err = hs.WriteFile(erPath, b0)
	require.NoError(t, err)

	for _, client := range allClients {
		assertCommandOutputContains(t, client, []string{"dig", "docker.myvpn.example.com"}, "2.2.2.2")
	}

	// Write a new file and move it to the path to ensure the reload
	// works when a file is moved atomically into place.
	extraRecords = append(extraRecords, tailcfg.DNSRecord{
		Name:  "otherrecord.myvpn.example.com",
		Type:  "A",
		Value: "7.7.7.7",
	})
	b2, _ := json.Marshal(extraRecords)

	err = hs.WriteFile(erPath+"2", b2)
	require.NoError(t, err)
	_, err = hs.Execute([]string{"mv", erPath + "2", erPath})
	require.NoError(t, err)

	for _, client := range allClients {
		assertCommandOutputContains(t, client, []string{"dig", "test.myvpn.example.com"}, "6.6.6.6")
		assertCommandOutputContains(t, client, []string{"dig", "otherrecord.myvpn.example.com"}, "7.7.7.7")
	}

	// Write a new file and copy it to the path to ensure the reload
	// works when a file is copied into place.
	b3, _ := json.Marshal([]tailcfg.DNSRecord{
		{
			Name:  "copy.myvpn.example.com",
			Type:  "A",
			Value: "8.8.8.8",
		},
	})

	err = hs.WriteFile(erPath+"3", b3)
	require.NoError(t, err)
	_, err = hs.Execute([]string{"cp", erPath + "3", erPath})
	require.NoError(t, err)

	for _, client := range allClients {
		assertCommandOutputContains(t, client, []string{"dig", "copy.myvpn.example.com"}, "8.8.8.8")
	}

	// Write in place to ensure pipe like behaviour works
	b4, _ := json.Marshal([]tailcfg.DNSRecord{
		{
			Name:  "docker.myvpn.example.com",
			Type:  "A",
			Value: "9.9.9.9",
		},
	})
	command := []string{"echo", fmt.Sprintf("'%s'", string(b4)), ">", erPath}
	_, err = hs.Execute([]string{"bash", "-c", strings.Join(command, " ")})
	require.NoError(t, err)

	for _, client := range allClients {
		assertCommandOutputContains(t, client, []string{"dig", "docker.myvpn.example.com"}, "9.9.9.9")
	}

	// Delete the file and create a new one to ensure it is picked up again.
	_, err = hs.Execute([]string{"rm", erPath})
	require.NoError(t, err)

	// The same paths should still be available as it is not cleared on delete.
	assert.EventuallyWithT(t, func(ct *assert.CollectT) {
		for _, client := range allClients {
			result, _, err := client.Execute([]string{"dig", "docker.myvpn.example.com"})
			assert.NoError(ct, err)
			assert.Contains(ct, result, "9.9.9.9")
		}
	}, 10*time.Second, 1*time.Second)

	// Write a new file, the backoff mechanism should make the filewatcher pick it up
	// again.
	err = hs.WriteFile(erPath, b3)
	require.NoError(t, err)

	for _, client := range allClients {
		assertCommandOutputContains(t, client, []string{"dig", "copy.myvpn.example.com"}, "8.8.8.8")
	}
}

// TestDNSOverrideLocalBehavior tests issue #2899
// https://github.com/juanfont/headscale/issues/2899
//
// Correct behavior:
// - MagicDNS supersedes override_local_dns
// - When MagicDNS=true: Always send Resolvers (regardless of override_local_dns)
// - When MagicDNS=false:
//   - override_local_dns=true: Send Resolvers
//   - override_local_dns=false/unset: No Resolvers
func TestDNSOverrideLocalBehavior(t *testing.T) {
	IntegrationSkip(t)

	// Test 1: MagicDNS=true, override_local_dns=true
	// Expected: DNS resolvers configured (MagicDNS supersedes)
	t.Run("magic_dns_true_override_true", func(t *testing.T) {
		spec := ScenarioSpec{
			NodesPerUser: 1,
			Users:        []string{"user1"},
		}

		scenario, err := NewScenario(spec)
		require.NoError(t, err)
		defer scenario.ShutdownAssertNoPanics(t)

		err = scenario.CreateHeadscaleEnv(
			[]tsic.Option{},
			hsic.WithTestName("dns-override-true"),
			hsic.WithConfigEnv(map[string]string{
				"HEADSCALE_DNS_MAGIC_DNS":          "true",
				"HEADSCALE_DNS_BASE_DOMAIN":        "example.com",
				"HEADSCALE_DNS_OVERRIDE_LOCAL_DNS": "true",
				"HEADSCALE_DNS_NAMESERVERS_GLOBAL": "8.8.8.8 1.1.1.1",
			}),
		)
		requireNoErrHeadscaleEnv(t, err)

		allClients, err := scenario.ListTailscaleClients()
		requireNoErrListClients(t, err)

		err = scenario.WaitForTailscaleSync()
		requireNoErrSync(t, err)

		for _, client := range allClients {
			assertDNSResolversConfigured(t, client, []string{"8.8.8.8", "1.1.1.1"})
		}
	})

	// Test 2: override_local_dns = false
	// Expected: DNS resolvers should be configured
	t.Run("override_local_dns_false", func(t *testing.T) {
		spec := ScenarioSpec{
			NodesPerUser: 1,
			Users:        []string{"user1"},
		}

		scenario, err := NewScenario(spec)
		require.NoError(t, err)
		defer scenario.ShutdownAssertNoPanics(t)

		err = scenario.CreateHeadscaleEnv(
			[]tsic.Option{},
			hsic.WithTestName("dns-override-false"),
			hsic.WithConfigEnv(map[string]string{
				"HEADSCALE_DNS_MAGIC_DNS":          "true",
				"HEADSCALE_DNS_BASE_DOMAIN":        "example.com",
				"HEADSCALE_DNS_OVERRIDE_LOCAL_DNS": "false",
				"HEADSCALE_DNS_NAMESERVERS_GLOBAL": "8.8.8.8 1.1.1.1",
			}),
		)
		requireNoErrHeadscaleEnv(t, err)

		allClients, err := scenario.ListTailscaleClients()
		requireNoErrListClients(t, err)

		err = scenario.WaitForTailscaleSync()
		requireNoErrSync(t, err)

		for _, client := range allClients {
			assertDNSResolversConfigured(t, client, []string{"8.8.8.8", "1.1.1.1"})
		}
	})

	// Test 3: override_local_dns not set (using default from DefaultConfigEnv)
	// Expected: DNS resolvers should be configured consistently with explicit false
	t.Run("override_local_dns_default", func(t *testing.T) {
		spec := ScenarioSpec{
			NodesPerUser: 1,
			Users:        []string{"user1"},
		}

		scenario, err := NewScenario(spec)
		require.NoError(t, err)
		defer scenario.ShutdownAssertNoPanics(t)

		// Don't set HEADSCALE_DNS_OVERRIDE_LOCAL_DNS, use the default
		err = scenario.CreateHeadscaleEnv(
			[]tsic.Option{},
			hsic.WithTestName("dns-override-default"),
			hsic.WithConfigEnv(map[string]string{
				"HEADSCALE_DNS_MAGIC_DNS":          "true",
				"HEADSCALE_DNS_BASE_DOMAIN":        "example.com",
				"HEADSCALE_DNS_NAMESERVERS_GLOBAL": "8.8.8.8 1.1.1.1",
				// HEADSCALE_DNS_OVERRIDE_LOCAL_DNS intentionally not set
			}),
		)
		requireNoErrHeadscaleEnv(t, err)

		allClients, err := scenario.ListTailscaleClients()
		requireNoErrListClients(t, err)

		err = scenario.WaitForTailscaleSync()
		requireNoErrSync(t, err)

		for _, client := range allClients {
			assertDNSResolversConfigured(t, client, []string{"8.8.8.8", "1.1.1.1"})
		}
	})
}

// assertDNSResolversConfigured checks that the Tailscale client has the expected DNS resolvers configured.
// It uses EventuallyWithT to handle eventual consistency as DNS configuration may take time to propagate.
func assertDNSResolversConfigured(t *testing.T, client TailscaleClient, expectedResolvers []string) {
	t.Helper()

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		// Query DNS status from the client
		// The netmap contains the DNS configuration sent by headscale
		netmap, err := client.Netmap()
		assert.NoError(c, err, "Failed to get netmap from client %s", client.Hostname())

		if netmap == nil {
			assert.Fail(c, "Netmap is nil for client %s", client.Hostname())
			return
		}

		if netmap.DNS.Resolvers == nil {
			assert.Fail(c, "DNS Resolvers is nil for client %s", client.Hostname())
			return
		}

		// Extract resolver IPs from the netmap
		// Resolver.Addr is a string (can be IP or DoH URL)
		var actualResolvers []string
		for _, resolver := range netmap.DNS.Resolvers {
			actualResolvers = append(actualResolvers, resolver.Addr)
		}

		assert.NotEmpty(c, actualResolvers,
			"Client %s should have DNS resolvers configured, but none were found",
			client.Hostname())

		// Check that all expected resolvers are present
		for _, expected := range expectedResolvers {
			assert.Contains(c, actualResolvers, expected,
				"Client %s should have resolver %s configured. Actual resolvers: %v",
				client.Hostname(), expected, actualResolvers)
		}
	}, 30*time.Second, 2*time.Second,
		"DNS resolvers should be configured on client %s with resolvers %v",
		client.Hostname(), expectedResolvers)
}

// TestDNSOverrideLocalWithMagicDNSDisabled tests that when MagicDNS is disabled,
// DNS resolvers should not be pushed to clients regardless of override_local_dns setting.
func TestDNSOverrideLocalWithMagicDNSDisabled(t *testing.T) {
	IntegrationSkip(t)

	spec := ScenarioSpec{
		NodesPerUser: 1,
		Users:        []string{"user1"},
	}

	scenario, err := NewScenario(spec)
	require.NoError(t, err)
	defer scenario.ShutdownAssertNoPanics(t)

	err = scenario.CreateHeadscaleEnv(
		[]tsic.Option{},
		hsic.WithTestName("dns-magicdns-disabled"),
		hsic.WithConfigEnv(map[string]string{
			"HEADSCALE_DNS_MAGIC_DNS":          "false",
			"HEADSCALE_DNS_BASE_DOMAIN":        "example.com",
			"HEADSCALE_DNS_OVERRIDE_LOCAL_DNS": "false",
			"HEADSCALE_DNS_NAMESERVERS_GLOBAL": "8.8.8.8 1.1.1.1",
		}),
	)
	requireNoErrHeadscaleEnv(t, err)

	allClients, err := scenario.ListTailscaleClients()
	requireNoErrListClients(t, err)

	err = scenario.WaitForTailscaleSync()
	requireNoErrSync(t, err)

	for _, client := range allClients {
		// When MagicDNS is disabled, no resolvers should be configured
		assert.EventuallyWithT(t, func(c *assert.CollectT) {
			netmap, err := client.Netmap()
			assert.NoError(c, err, "Failed to get netmap from client %s", client.Hostname())

			if netmap == nil {
				assert.Fail(c, "Netmap is nil for client %s", client.Hostname())
				return
			}

			// When MagicDNS is off, DNS configuration might be nil or empty
			if netmap.DNS.Resolvers != nil {
				assert.Empty(c, netmap.DNS.Resolvers,
					"Client %s should NOT have DNS resolvers when MagicDNS is disabled",
					client.Hostname())
			}
		}, 30*time.Second, 2*time.Second,
			"DNS resolvers should NOT be configured when MagicDNS is disabled on client %s",
			client.Hostname())
	}
}

// This is a Canary test - to be sure that TS client doesn't leak DNS config when it shouldn't.
// Even though both Global Resolver, split DNS & Fallback resolvers are configured, the client should not receive any DNS resolvers
// when override_local_dns is false. (otherwise split DNS is overriding the override_local_dns setting at the client).
// TestDNSSplitWithoutOverride tests that when split DNS is enabled but override_local_dns is false,
// the client should NOT receive global DNS resolvers, but SHOULD receive split DNS routes and fallback resolvers,
// but they should not make it to the hosts' actual DNS configuration.
// This test uses distinct DNS server addresses to identify which configuration field any leaked values came from.
func TestDNSSplitWithoutOverride(t *testing.T) {
	IntegrationSkip(t)

	spec := ScenarioSpec{
		NodesPerUser: 1,
		Users:        []string{"user1"},
	}

	scenario, err := NewScenario(spec)
	require.NoError(t, err)
	defer scenario.ShutdownAssertNoPanics(t)

	// Use distinct DNS server addresses to identify source of any leaked configuration:
	// - Global nameservers: 1.1.1.1, 1.0.0.1 (should NOT appear in client Resolvers)
	// - Fallback resolvers: 9.9.9.9, 149.112.112.112 (SHOULD appear in FallbackResolvers)
	// - Split DNS resolvers: 8.8.8.8, 8.8.4.4 (SHOULD appear in Routes)

	// Create a custom config file with split DNS configuration
	configYAML := []byte(`
noise:
  private_key_path: /tmp/noise_private.key

server_url: http://headscale:8080

prefixes:
  v4: 100.64.0.0/10
  v6: fd7a:115c:a1e0::/48
  allocation: sequential

database:
  type: sqlite3
  sqlite:
    path: /tmp/integration_test_db.sqlite3

dns:
  magic_dns: false
  base_domain: example.com
  override_local_dns: false
  nameservers:
    global:
      - 1.1.1.1
      - 1.0.0.1
    split:
      corp.example.com:
        - 8.8.8.8
      internal.example.com:
        - 8.8.4.4
    split_fallback:
      - 9.9.9.9
      - 149.112.112.112
`)

	err = scenario.CreateHeadscaleEnv(
		[]tsic.Option{
			tsic.WithDockerEntrypoint([]string{
				"/bin/sh",
				"-c",
				"/bin/sleep 3 ; apk add python3 curl bind-tools ; update-ca-certificates ; tailscaled --tun=tsdev",
			}),
		},
		hsic.WithTestName("dns-split-no-override"),
		hsic.WithFileInContainer("/etc/headscale/config.yaml", configYAML),
	)
	requireNoErrHeadscaleEnv(t, err)

	allClients, err := scenario.ListTailscaleClients()
	requireNoErrListClients(t, err)

	err = scenario.WaitForTailscaleSync()
	requireNoErrSync(t, err)

	for _, client := range allClients {
		assert.EventuallyWithT(t, func(c *assert.CollectT) {
			netmap, err := client.Netmap()
			assert.NoError(c, err, "Failed to get netmap from client %s", client.Hostname())

			if netmap == nil {
				assert.Fail(c, "Netmap is nil for client %s", client.Hostname())
				return
			}

			// Critical assertion: Resolvers should be nil or empty when override_local_dns is false
			if len(netmap.DNS.Resolvers) > 0 {
				var leakedResolvers []string
				for _, resolver := range netmap.DNS.Resolvers {
					leakedResolvers = append(leakedResolvers, resolver.Addr)

					// Identify which configuration field this resolver came from
					switch resolver.Addr {
					case "1.1.1.1", "1.0.0.1":
						assert.Fail(c, "Client %s received global nameserver %s in Resolvers field - this should NOT happen when override_local_dns=false. "+
							"This value came from dns.nameservers.global configuration.",
							client.Hostname(), resolver.Addr)
					case "9.9.9.9", "149.112.112.112":
						assert.Fail(c, "Client %s received fallback resolver %s in Resolvers field - this should be in FallbackResolvers, not Resolvers. "+
							"This value came from dns.split_dns_fallback_resolvers configuration.",
							client.Hostname(), resolver.Addr)
					case "8.8.8.8", "8.8.4.4":
						assert.Fail(c, "Client %s received split DNS resolver %s in Resolvers field - this should be in Routes, not Resolvers. "+
							"This value came from dns.nameservers.split configuration.",
							client.Hostname(), resolver.Addr)
					default:
						assert.Fail(c, "Client %s received unexpected resolver %s in Resolvers field",
							client.Hostname(), resolver.Addr)
					}
				}
				assert.Fail(c, "Client %s should NOT have Resolvers configured when override_local_dns=false, but found: %v",
					client.Hostname(), leakedResolvers)
				return
			}

			// FallbackResolvers should be configured with the explicit fallback resolvers
			assert.NotNil(c, netmap.DNS.FallbackResolvers,
				"Client %s should have FallbackResolvers configured for split DNS",
				client.Hostname())

			var actualFallback []string
			for _, resolver := range netmap.DNS.FallbackResolvers {
				actualFallback = append(actualFallback, resolver.Addr)
			}

			expectedFallback := []string{"9.9.9.9", "149.112.112.112"}
			assert.ElementsMatch(c, expectedFallback, actualFallback,
				"Client %s FallbackResolvers mismatch. Expected: %v (from dns.nameservers.split_fallback), Got: %v",
				client.Hostname(), expectedFallback, actualFallback)

			// Routes should be configured with split DNS
			assert.NotNil(c, netmap.DNS.Routes,
				"Client %s should have DNS Routes configured for split DNS",
				client.Hostname())

			// Verify specific split DNS routes
			corpResolvers, hasCorp := netmap.DNS.Routes["corp.example.com"]
			assert.True(c, hasCorp, "Client %s should have route for corp.example.com", client.Hostname())
			if hasCorp {
				assert.Len(c, corpResolvers, 1, "corp.example.com should have 1 resolver")
				assert.Equal(c, "8.8.8.8", corpResolvers[0].Addr,
					"corp.example.com resolver should be 8.8.8.8 (from dns.nameservers.split)")
			}

			internalResolvers, hasInternal := netmap.DNS.Routes["internal.example.com"]
			assert.True(c, hasInternal, "Client %s should have route for internal.example.com", client.Hostname())
			if hasInternal {
				assert.Len(c, internalResolvers, 1, "internal.example.com should have 1 resolver")
				assert.Equal(c, "8.8.4.4", internalResolvers[0].Addr,
					"internal.example.com resolver should be 8.8.4.4 (from dns.nameservers.split)")
			}
		}, 30*time.Second, 2*time.Second,
			"DNS configuration validation failed for client %s",
			client.Hostname())

		// Verify the actual DNS configuration on the client doesn't contain ANY of the configured nameservers
		// Use 'dig' without arguments to query the client's actual DNS server
		assert.EventuallyWithT(t, func(c *assert.CollectT) {
			result, _, err := client.Execute([]string{"dig"})
			assert.NoError(c, err, "Failed to execute dig command on client %s", client.Hostname())

			// NONE of the configured nameservers should appear next to ";; SERVER:" in the dig output
			// Global nameservers (should NOT leak)
			assert.NotContains(c, result, ";; SERVER: 1.1.1.1",
				"Client %s should NOT be using global nameserver 1.1.1.1 when override_local_dns=false",
				client.Hostname())
			assert.NotContains(c, result, ";; SERVER: 1.0.0.1",
				"Client %s should NOT be using global nameserver 1.0.0.1 when override_local_dns=false",
				client.Hostname())

			// Fallback resolvers (should NOT leak to actual DNS configuration)
			assert.NotContains(c, result, ";; SERVER: 9.9.9.9",
				"Client %s should NOT be using fallback resolver 9.9.9.9 as actual DNS server when override_local_dns=false",
				client.Hostname())
			assert.NotContains(c, result, ";; SERVER: 149.112.112.112",
				"Client %s should NOT be using fallback resolver 149.112.112.112 as actual DNS server when override_local_dns=false",
				client.Hostname())

			// Split DNS resolvers (should NOT leak to actual DNS configuration)
			assert.NotContains(c, result, ";; SERVER: 8.8.8.8",
				"Client %s should NOT be using split DNS resolver 8.8.8.8 as actual DNS server when override_local_dns=false",
				client.Hostname())
			assert.NotContains(c, result, ";; SERVER: 8.8.4.4",
				"Client %s should NOT be using split DNS resolver 8.8.4.4 as actual DNS server when override_local_dns=false",
				client.Hostname())
		}, 30*time.Second, 2*time.Second,
			"Client %s should not be using any of headscale's configured DNS servers",
			client.Hostname())
	}
}
