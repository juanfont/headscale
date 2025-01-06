package integration

import (
	"regexp"
	"testing"

	"github.com/juanfont/headscale/hscontrol/policy"
	"github.com/juanfont/headscale/integration/hsic"
	"github.com/juanfont/headscale/integration/tsic"
	"github.com/stretchr/testify/require"
)

func TestNodeAttrsNextDNS(t *testing.T) {
	IntegrationSkip(t)

	tests := []struct {
		name                string
		policy              policy.ACLPolicy
		wantedResolverRegex map[string]string
	}{
		{
			name: "NextDNS attribute for all",
			policy: policy.ACLPolicy{
				ACLs: []policy.ACL{
					{
						Action:       "accept",
						Sources:      []string{"*"},
						Destinations: []string{"*:*"},
					},
				},
				NodeAttributes: []policy.NodeAttributes{
					{
						Targets:    []string{"*"},
						Attributes: []string{"nextdns:fedcba"},
					},
				},
			},
			wantedResolverRegex: map[string]string{
				"user1": "https://dns\\.nextdns\\.io/fedcba\\?device_ip=.*?\\&device_model=.*?&device_name=.*",
				"user2": "https://dns\\.nextdns\\.io/fedcba\\?device_ip=.*?\\&device_model=.*?&device_name=.*",
			},
		},
		{
			name: "NextDNS attribute for user 1",
			policy: policy.ACLPolicy{
				ACLs: []policy.ACL{
					{
						Action:       "accept",
						Sources:      []string{"*"},
						Destinations: []string{"*:*"},
					},
				},
				NodeAttributes: []policy.NodeAttributes{
					{
						Targets:    []string{"user1"},
						Attributes: []string{"nextdns:fedcba"},
					},
				},
			},
			wantedResolverRegex: map[string]string{
				"user1": "https://dns\\.nextdns\\.io/fedcba\\?device_ip=.*?\\&device_model=.*?&device_name=.*",
				"user2": "https://dns\\.nextdns\\.io/abcdef\\?device_ip=.*?\\&device_model=.*?&device_name=.*",
			},
		},
		{
			name: "NextDNS attribute for no deviceInfo",
			policy: policy.ACLPolicy{
				ACLs: []policy.ACL{
					{
						Action:       "accept",
						Sources:      []string{"*"},
						Destinations: []string{"*:*"},
					},
				},
				NodeAttributes: []policy.NodeAttributes{
					{
						Targets:    []string{"*"},
						Attributes: []string{"nextdns:no-device-info"},
					},
				},
			},
			wantedResolverRegex: map[string]string{
				"user1": "https://dns\\.nextdns\\.io/abcdef",
				"user2": "https://dns\\.nextdns\\.io/abcdef",
			},
		},
	}

	spec := map[string]int{
		"user1": 2,
		"user2": 2,
	}

	for _, testcase := range tests {
		t.Run(testcase.name, func(t *testing.T) {
			scenario, err := NewScenario(dockertestMaxWait())
			require.NoError(t, err)

			scenario.CreateHeadscaleEnv(spec,
				[]tsic.Option{
					tsic.WithSSH(),

					// Alpine containers dont have ip6tables set up, which causes
					// tailscaled to stop configuring the wgengine, causing it
					// to not configure DNS.
					tsic.WithNetfilter("off"),
					tsic.WithDockerEntrypoint([]string{
						"/bin/sh",
						"-c",
						"/bin/sleep 3 ; apk add openssh ; adduser ssh-it-user ; update-ca-certificates ; tailscaled --tun=tsdev",
					}),
					tsic.WithDockerWorkdir("/"),
				},
				hsic.WithACLPolicy(&testcase.policy),
				hsic.WithConfigEnv(map[string]string{
					"HEADSCALE_DNS_NAMESERVERS_GLOBAL": "https://dns.nextdns.io/abcdef",
				}),
			)

			require.NoError(t, err)
			defer scenario.ShutdownAssertNoPanics(t)

			for user, expectedResolver := range testcase.wantedResolverRegex {

				expr, err := regexp.Compile(expectedResolver)
				require.NoError(t, err)

				clients, err := scenario.ListTailscaleClients(user)
				require.NoError(t, err)

				for _, client := range clients {

					output, _, err := client.Execute([]string{
						"tailscale",
						"dns",
						"status",
					})

					require.NoError(t, err)

					if !expr.MatchString(output) {
						t.Logf("unexpected resolver expected: '%s', actual: '%s'", expectedResolver, output)
					}
				}
			}
		})
	}
}
