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
	"tailscale.com/tailcfg"
)

func TestResolveMagicDNS(t *testing.T) {
	IntegrationSkip(t)
	t.Parallel()

	scenario, err := NewScenario(dockertestMaxWait())
	assertNoErr(t, err)
	defer scenario.ShutdownAssertNoPanics(t)

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

			assert.Equal(t, fmt.Sprintf("%s.headscale.net", peer.Hostname()), peerFQDN)

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

func TestResolveMagicDNSExtraRecordsPath(t *testing.T) {
	IntegrationSkip(t)
	t.Parallel()

	scenario, err := NewScenario(dockertestMaxWait())
	assertNoErr(t, err)
	defer scenario.ShutdownAssertNoPanics(t)

	spec := map[string]int{
		"magicdns1": 1,
		"magicdns2": 1,
	}

	const erPath = "/tmp/extra_records.json"

	extraRecords := []tailcfg.DNSRecord{
		{
			Name:  "test.myvpn.example.com",
			Type:  "A",
			Value: "6.6.6.6",
		},
	}
	b, _ := json.Marshal(extraRecords)

	err = scenario.CreateHeadscaleEnv(spec, []tsic.Option{
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
		assertCommandOutputContains(t, client, []string{"dig", "test.myvpn.example.com"}, "6.6.6.6")
	}

	hs, err := scenario.Headscale()
	assertNoErr(t, err)

	// Write the file directly into place from the docker API.
	b0, _ := json.Marshal([]tailcfg.DNSRecord{
		{
			Name:  "docker.myvpn.example.com",
			Type:  "A",
			Value: "2.2.2.2",
		},
	})

	err = hs.WriteFile(erPath, b0)
	assertNoErr(t, err)

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
	assertNoErr(t, err)
	_, err = hs.Execute([]string{"mv", erPath + "2", erPath})
	assertNoErr(t, err)

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
	assertNoErr(t, err)
	_, err = hs.Execute([]string{"cp", erPath + "3", erPath})
	assertNoErr(t, err)

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
	assertNoErr(t, err)

	for _, client := range allClients {
		assertCommandOutputContains(t, client, []string{"dig", "docker.myvpn.example.com"}, "9.9.9.9")
	}

	// Delete the file and create a new one to ensure it is picked up again.
	_, err = hs.Execute([]string{"rm", erPath})
	assertNoErr(t, err)

	time.Sleep(2 * time.Second)

	// The same paths should still be available as it is not cleared on delete.
	for _, client := range allClients {
		assertCommandOutputContains(t, client, []string{"dig", "docker.myvpn.example.com"}, "9.9.9.9")
	}

	// Write a new file, the backoff mechanism should make the filewatcher pick it up
	// again.
	err = hs.WriteFile(erPath, b3)
	assertNoErr(t, err)

	for _, client := range allClients {
		assertCommandOutputContains(t, client, []string{"dig", "copy.myvpn.example.com"}, "8.8.8.8")
	}
}

// TestValidateResolvConf validates that the resolv.conf file
// ends up as expected in our Tailscale containers.
// All the containers are based on Alpine, meaning Tailscale
// will overwrite the resolv.conf file.
// On other platform, Tailscale will integrate with a dns manager
// if available (like systemd-resolved).
func TestValidateResolvConf(t *testing.T) {
	IntegrationSkip(t)

	resolvconf := func(conf string) string {
		return strings.ReplaceAll(`# resolv.conf(5) file generated by tailscale
# For more info, see https://tailscale.com/s/resolvconf-overwrite
# DO NOT EDIT THIS FILE BY HAND -- CHANGES WILL BE OVERWRITTEN
`+conf, "\t", "")
	}

	tests := []struct {
		name                string
		conf                map[string]string
		wantConfCompareFunc func(*testing.T, string)
	}{
		// New config
		{
			name: "no-config",
			conf: map[string]string{
				"HEADSCALE_DNS_BASE_DOMAIN":        "",
				"HEADSCALE_DNS_MAGIC_DNS":          "false",
				"HEADSCALE_DNS_NAMESERVERS_GLOBAL": "",
			},
			wantConfCompareFunc: func(t *testing.T, got string) {
				assert.NotContains(t, got, "100.100.100.100")
			},
		},
		{
			name: "global-only",
			conf: map[string]string{
				"HEADSCALE_DNS_BASE_DOMAIN":        "",
				"HEADSCALE_DNS_MAGIC_DNS":          "false",
				"HEADSCALE_DNS_NAMESERVERS_GLOBAL": "8.8.8.8 1.1.1.1",
			},
			wantConfCompareFunc: func(t *testing.T, got string) {
				want := resolvconf(`
					nameserver 100.100.100.100
				`)
				assert.Equal(t, want, got)
			},
		},
		{
			name: "base-integration-config",
			conf: map[string]string{
				"HEADSCALE_DNS_BASE_DOMAIN": "very-unique-domain.net",
			},
			wantConfCompareFunc: func(t *testing.T, got string) {
				want := resolvconf(`
					nameserver 100.100.100.100
					search very-unique-domain.net
				`)
				assert.Equal(t, want, got)
			},
		},
		{
			name: "base-magic-dns-off",
			conf: map[string]string{
				"HEADSCALE_DNS_MAGIC_DNS":   "false",
				"HEADSCALE_DNS_BASE_DOMAIN": "very-unique-domain.net",
			},
			wantConfCompareFunc: func(t *testing.T, got string) {
				want := resolvconf(`
					nameserver 100.100.100.100
					search very-unique-domain.net
				`)
				assert.Equal(t, want, got)
			},
		},
		{
			name: "base-extra-search-domains",
			conf: map[string]string{
				"HEADSCALE_DNS_SEARCH_DOMAINS": "test1.no test2.no",
				"HEADSCALE_DNS_BASE_DOMAIN":    "with-local-dns.net",
			},
			wantConfCompareFunc: func(t *testing.T, got string) {
				want := resolvconf(`
					nameserver 100.100.100.100
					search with-local-dns.net test1.no test2.no
				`)
				assert.Equal(t, want, got)
			},
		},
		{
			name: "base-nameservers-split",
			conf: map[string]string{
				"HEADSCALE_DNS_NAMESERVERS_SPLIT": `{foo.bar.com: ["1.1.1.1"]}`,
				"HEADSCALE_DNS_BASE_DOMAIN":       "with-local-dns.net",
			},
			wantConfCompareFunc: func(t *testing.T, got string) {
				want := resolvconf(`
					nameserver 100.100.100.100
					search with-local-dns.net
				`)
				assert.Equal(t, want, got)
			},
		},
		{
			name: "base-full-no-magic",
			conf: map[string]string{
				"HEADSCALE_DNS_MAGIC_DNS":          "false",
				"HEADSCALE_DNS_BASE_DOMAIN":        "all-of.it",
				"HEADSCALE_DNS_NAMESERVERS_GLOBAL": `8.8.8.8`,
				"HEADSCALE_DNS_SEARCH_DOMAINS":     "test1.no test2.no",
				// TODO(kradalby): this currently isnt working, need to fix it
				// "HEADSCALE_DNS_NAMESERVERS_SPLIT": `{foo.bar.com: ["1.1.1.1"]}`,
				// "HEADSCALE_DNS_EXTRA_RECORDS":     `[{ name: "prometheus.myvpn.example.com", type: "A", value: "100.64.0.4" }]`,
			},
			wantConfCompareFunc: func(t *testing.T, got string) {
				want := resolvconf(`
					nameserver 100.100.100.100
					search all-of.it test1.no test2.no
				`)
				assert.Equal(t, want, got)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scenario, err := NewScenario(dockertestMaxWait())
			assertNoErr(t, err)
			defer scenario.ShutdownAssertNoPanics(t)

			spec := map[string]int{
				"resolvconf1": 3,
				"resolvconf2": 3,
			}

			err = scenario.CreateHeadscaleEnv(spec, []tsic.Option{}, hsic.WithTestName("resolvconf"), hsic.WithConfigEnv(tt.conf))
			assertNoErrHeadscaleEnv(t, err)

			allClients, err := scenario.ListTailscaleClients()
			assertNoErrListClients(t, err)

			err = scenario.WaitForTailscaleSync()
			assertNoErrSync(t, err)

			// Poor mans cache
			_, err = scenario.ListTailscaleClientsFQDNs()
			assertNoErrListFQDN(t, err)

			_, err = scenario.ListTailscaleClientsIPs()
			assertNoErrListClientIPs(t, err)

			time.Sleep(30 * time.Second)

			for _, client := range allClients {
				b, err := client.ReadFile("/etc/resolv.conf")
				assertNoErr(t, err)

				t.Logf("comparing resolv conf of %s", client.Hostname())
				tt.wantConfCompareFunc(t, string(b))
			}
		})
	}
}
