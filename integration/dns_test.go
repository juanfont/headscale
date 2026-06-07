package integration

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	policyv2 "github.com/juanfont/headscale/hscontrol/policy/v2"
	"github.com/juanfont/headscale/integration/hsic"
	"github.com/juanfont/headscale/integration/integrationutil"
	"github.com/juanfont/headscale/integration/tsic"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
	"tailscale.com/types/dnstype"
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
			}, integrationutil.StatusReadyTimeout, 2*time.Second)
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

	extraRecords := make([]tailcfg.DNSRecord, 0, 2)
	extraRecords = append(extraRecords, tailcfg.DNSRecord{
		Name:  "test.myvpn.example.com",
		Type:  "A",
		Value: "6.6.6.6",
	})
	b, _ := json.Marshal(extraRecords) //nolint:errchkjson

	err = scenario.CreateHeadscaleEnv([]tsic.Option{
		tsic.WithPackages("python3", "curl", "bind-tools"),
	},
		hsic.WithTestName("extrarecords"),
		hsic.WithConfigEnv(map[string]string{
			// Disable global nameservers to make the test run offline.
			"HEADSCALE_DNS_NAMESERVERS_GLOBAL": "",
			"HEADSCALE_DNS_EXTRA_RECORDS_PATH": erPath,
		}),
		hsic.WithFileInContainer(erPath, b),
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
	b0, _ := json.Marshal([]tailcfg.DNSRecord{ //nolint:errchkjson
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
	b2, _ := json.Marshal(extraRecords) //nolint:errchkjson

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
	b3, _ := json.Marshal([]tailcfg.DNSRecord{ //nolint:errchkjson
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
	b4, _ := json.Marshal([]tailcfg.DNSRecord{ //nolint:errchkjson
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
	}, integrationutil.ScaledTimeout(10*time.Second), 1*time.Second)

	// Write a new file, the backoff mechanism should make the filewatcher pick it up
	// again.
	err = hs.WriteFile(erPath, b3)
	require.NoError(t, err)

	for _, client := range allClients {
		assertCommandOutputContains(t, client, []string{"dig", "copy.myvpn.example.com"}, "8.8.8.8")
	}
}

// hasResolverAddr returns true if any entry in resolvers has the given
// Addr. Used by the integration test to assert presence / absence of
// an override resolver across either Resolvers or FallbackResolvers.
func hasResolverAddr(resolvers []*dnstype.Resolver, addr string) bool {
	for _, r := range resolvers {
		if r != nil && r.Addr == addr {
			return true
		}
	}
	return false
}

// TestPolicyDNSProfiles exercises the policy DNS profiles feature
// end-to-end across two configurations and a hot-reload between them:
//
//	Phase 1 (no policy DNS overrides): both admin and guest clients
//	get the base DNS config from headscale.yaml's `dns:` block.
//
//	Phase 2 (hot reload → add group:admin override): the policy is
//	updated via SetPolicy to add a profile that overrides Resolvers
//	for group:admin. SetPolicy is the same downstream entry point
//	that the file-mode reload path (systemctl reload / SIGHUP) hits,
//	so this exercises the hot-reload propagation mechanism even
//	though the trigger is the API rather than a signal.
//
//	Phase 3 (post-reload): admin's netmap carries the override
//	Resolvers; guest's netmap is unchanged (no override resolver in
//	either Resolvers or FallbackResolvers).
func TestPolicyDNSProfiles(t *testing.T) {
	IntegrationSkip(t)

	const (
		adminUser     = "admin-user"
		guestUser     = "guest-user"
		overrideNS    = "10.99.0.42"
		adminGroup    = "group:admin"
		splitDomain   = "internal.example"
		splitResolver = "10.99.0.99"
	)

	// Initial policy: no dns block. Everyone gets the yaml base.
	initialPolicy := &policyv2.Policy{
		Groups: policyv2.Groups{
			policyv2.Group(adminGroup): []policyv2.Username{
				policyv2.Username(adminUser + "@"),
			},
		},
	}

	spec := ScenarioSpec{
		NodesPerUser: 1,
		Users:        []string{adminUser, guestUser},
		Versions:     []string{"head"},
	}

	scenario, err := NewScenario(spec)
	require.NoError(t, err)
	defer scenario.ShutdownAssertNoPanics(t)

	err = scenario.CreateHeadscaleEnv(
		[]tsic.Option{tsic.WithNetfilter("off")},
		hsic.WithACLPolicy(initialPolicy),
		hsic.WithTestName("dnsreload"),
	)
	requireNoErrHeadscaleEnv(t, err)

	err = scenario.WaitForTailscaleSync()
	requireNoErrSync(t, err)

	adminClients, err := scenario.ListTailscaleClients(adminUser)
	requireNoErrListClients(t, err)
	require.NotEmpty(t, adminClients)
	guestClients, err := scenario.ListTailscaleClients(guestUser)
	requireNoErrListClients(t, err)
	require.NotEmpty(t, guestClients)

	// Phase 1: no policy.dns overrides — neither client should have
	// the override resolver set in Resolvers OR FallbackResolvers.
	for _, client := range append(adminClients, guestClients...) {
		assert.EventuallyWithT(t, func(ct *assert.CollectT) {
			nm, err := client.Netmap()
			if !assert.NoError(ct, err) || !assert.NotNil(ct, nm) || !assert.NotNil(ct, nm.DNS) {
				return
			}
			assert.False(ct, hasResolverAddr(nm.DNS.Resolvers, overrideNS),
				"initial: %s should not have the override in Resolvers yet", client.Hostname())
			assert.False(ct, hasResolverAddr(nm.DNS.FallbackResolvers, overrideNS),
				"initial: %s should not have the override in FallbackResolvers yet", client.Hostname())
		}, integrationutil.StatusReadyTimeout, 1*time.Second)
	}

	// Phase 2: hot-reload the policy to add a group:admin override.
	// The override profile exercises three body fields at once:
	//   Nameservers + OverrideLocalDNS → Resolvers populated on the wire
	//   Split → Routes populated on the wire (split-DNS coverage)
	overrideNSList := []string{overrideNS}
	overrideTrue := true
	splitMap := map[string][]string{splitDomain: {splitResolver}}
	updatedPolicy := &policyv2.Policy{
		Groups: initialPolicy.Groups,
		DNS: policyv2.PolicyDNS{
			{
				Nameservers:      &overrideNSList,
				OverrideLocalDNS: &overrideTrue,
				Split:            &splitMap,
				Groups:           []policyv2.Group{policyv2.Group(adminGroup)},
			},
		},
	}

	headscale, err := scenario.Headscale()
	require.NoError(t, err)
	require.NoError(t, headscale.SetPolicy(updatedPolicy),
		"hot-reloading the policy should succeed")

	// Phase 3: admin now receives the override Resolver; guest is
	// unchanged. EventuallyWithT bounds the wait so the netmap update
	// can propagate to the clients.
	for _, client := range adminClients {
		assert.EventuallyWithT(t, func(ct *assert.CollectT) {
			nm, err := client.Netmap()
			if !assert.NoError(ct, err) || !assert.NotNil(ct, nm) || !assert.NotNil(ct, nm.DNS) {
				return
			}
			if assert.Len(ct, nm.DNS.Resolvers, 1, "admin should have one Resolver after reload") {
				assert.Equal(ct, overrideNS, nm.DNS.Resolvers[0].Addr,
					"admin's Resolvers should be the override after reload")
			}
			if assert.Contains(ct, nm.DNS.Routes, splitDomain,
				"admin's Routes should carry the profile's Split entry") {
				if assert.Len(ct, nm.DNS.Routes[splitDomain], 1) {
					assert.Equal(ct, splitResolver, nm.DNS.Routes[splitDomain][0].Addr,
						"split resolver should be the profile's value")
				}
			}
		}, integrationutil.PolicyPropagationTimeout, 2*time.Second,
			"admin %s should receive override + split DNS after hot-reload", client.Hostname())
	}
	for _, client := range guestClients {
		assert.EventuallyWithT(t, func(ct *assert.CollectT) {
			nm, err := client.Netmap()
			if !assert.NoError(ct, err) || !assert.NotNil(ct, nm) || !assert.NotNil(ct, nm.DNS) {
				return
			}
			assert.False(ct, hasResolverAddr(nm.DNS.Resolvers, overrideNS),
				"guest should not have the override in Resolvers")
			assert.False(ct, hasResolverAddr(nm.DNS.FallbackResolvers, overrideNS),
				"guest should not have the override in FallbackResolvers")
			assert.NotContains(ct, nm.DNS.Routes, splitDomain,
				"guest should not have the admin profile's Split entry")
		}, integrationutil.PolicyPropagationTimeout, 2*time.Second,
			"guest %s should stay on base after hot-reload", client.Hostname())
	}
}
