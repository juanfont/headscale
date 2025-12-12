package integration

import (
	"fmt"
	"testing"
	"time"

	"github.com/juanfont/headscale/integration/hsic"
	"github.com/juanfont/headscale/integration/tsic"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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

// TestDNSOverrideLocalConsistency tests that the three ways of setting override_local_dns
// all produce consistent behavior. This is the core test for issue #2899.
func TestDNSOverrideLocalConsistency(t *testing.T) {
	IntegrationSkip(t)

	testCases := []struct {
		name      string
		setEnvVar bool
		value     string
		expectDNS bool
		resolvers []string
	}{
		{
			name:      "explicit_true",
			setEnvVar: true,
			value:     "true",
			expectDNS: true,
			resolvers: []string{"8.8.8.8", "1.1.1.1"},
		},
		{
			name:      "explicit_false",
			setEnvVar: true,
			value:     "false",
			expectDNS: true,
			resolvers: []string{"8.8.8.8", "1.1.1.1"},
		},
		{
			name:      "unset_default",
			setEnvVar: false,
			value:     "",
			expectDNS: true,
			resolvers: []string{"8.8.8.8", "1.1.1.1"},
		},
	}

	for _, tc := range testCases {
		tc := tc // capture range variable
		t.Run(tc.name, func(t *testing.T) {
			spec := ScenarioSpec{
				NodesPerUser: 1,
				Users:        []string{"user1"},
			}

			scenario, err := NewScenario(spec)
			require.NoError(t, err)
			defer scenario.ShutdownAssertNoPanics(t)

			configEnv := map[string]string{
				"HEADSCALE_DNS_MAGIC_DNS":          "true",
				"HEADSCALE_DNS_BASE_DOMAIN":        "example.com",
				"HEADSCALE_DNS_NAMESERVERS_GLOBAL": "8.8.8.8 1.1.1.1",
			}

			if tc.setEnvVar {
				configEnv["HEADSCALE_DNS_OVERRIDE_LOCAL_DNS"] = tc.value
			}

			err = scenario.CreateHeadscaleEnv(
				[]tsic.Option{},
				hsic.WithTestName(fmt.Sprintf("dns-consistency-%s", tc.name)),
				hsic.WithConfigEnv(configEnv),
			)
			requireNoErrHeadscaleEnv(t, err)

			allClients, err := scenario.ListTailscaleClients()
			requireNoErrListClients(t, err)

			err = scenario.WaitForTailscaleSync()
			requireNoErrSync(t, err)

			for _, client := range allClients {
				if tc.expectDNS {
					assertDNSResolversConfigured(t, client, tc.resolvers)
				} else {
					// If we ever need to test that DNS should NOT be configured
					assert.EventuallyWithT(t, func(c *assert.CollectT) {
						netmap, err := client.Netmap()
						assert.NoError(c, err)
						if netmap != nil && netmap.DNS.Resolvers != nil {
							assert.Empty(c, netmap.DNS.Resolvers)
						}
					}, 30*time.Second, 2*time.Second)
				}
			}
		})
	}
}
