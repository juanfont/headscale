package config

import (
	"errors"
	"fmt"
	"net/netip"
	"testing"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var errTestSentinel = errors.New("sentinel")

// OK
// server_url: headscale.com, base: clients.headscale.com
// server_url: headscale.com, base: headscale.net
//
// NOT OK
// server_url: server.headscale.com, base: headscale.com.
func TestSafeServerURL(t *testing.T) {
	tests := []struct {
		serverURL, baseDomain,
		wantErr string
	}{
		{
			serverURL:  "https://example.com",
			baseDomain: "example.org",
		},
		{
			serverURL:  "https://headscale.com",
			baseDomain: "headscale.com",
			wantErr:    errServerURLSame.Error(),
		},
		{
			serverURL:  "https://headscale.com",
			baseDomain: "clients.headscale.com",
		},
		{
			serverURL:  "https://headscale.com",
			baseDomain: "clients.subdomain.headscale.com",
		},
		{
			serverURL:  "https://headscale.kristoffer.com",
			baseDomain: "mybase",
		},
		{
			serverURL:  "https://server.headscale.com",
			baseDomain: "headscale.com",
			wantErr:    errServerURLSuffix.Error(),
		},
		{
			serverURL:  "https://server.subdomain.headscale.com",
			baseDomain: "headscale.com",
			wantErr:    errServerURLSuffix.Error(),
		},
		{
			serverURL: "http://foo\x00",
			wantErr:   `parse "http://foo\x00": net/url: invalid control character in URL`,
		},
	}

	for _, tt := range tests {
		testName := fmt.Sprintf("server=%s domain=%s", tt.serverURL, tt.baseDomain)
		t.Run(testName, func(t *testing.T) {
			err := isSafeServerURL(tt.serverURL, tt.baseDomain)
			if tt.wantErr != "" {
				assert.EqualError(t, err, tt.wantErr)

				return
			}

			assert.NoError(t, err)
		})
	}
}

func TestSafeServerURLWithPort(t *testing.T) {
	tests := []struct {
		serverURL, baseDomain,
		wantErr string
	}{
		{
			serverURL:  "https://server.headscale.com:443",
			baseDomain: "headscale.com",
			wantErr:    errServerURLSuffix.Error(),
		},
		{
			serverURL:  "https://server.subdomain.headscale.com:8080",
			baseDomain: "headscale.com",
			wantErr:    errServerURLSuffix.Error(),
		},
		{
			serverURL:  "https://headscale.com:443",
			baseDomain: "headscale.com",
			wantErr:    errServerURLSame.Error(),
		},
		{
			serverURL:  "https://example.com:8080",
			baseDomain: "example.org",
		},
	}

	for _, tt := range tests {
		testName := fmt.Sprintf("server=%s domain=%s", tt.serverURL, tt.baseDomain)
		t.Run(testName, func(t *testing.T) {
			err := isSafeServerURL(tt.serverURL, tt.baseDomain)
			if tt.wantErr != "" {
				assert.EqualError(t, err, tt.wantErr)

				return
			}

			assert.NoError(t, err)
		})
	}
}

// TestNameserverWarningsHideCredentials: a nameserver that does not parse
// is reported without the userinfo it may hold.
func TestNameserverWarningsHideCredentials(t *testing.T) {
	cfg := &types.Config{DNSConfig: types.DNSConfig{Nameservers: types.Nameservers{
		Global: []string{"https://alice:marker-pass@dns.example.com:port"},
		Split:  map[string][]string{"corp.example.com": {"https://marker-user@dns.example.com/%zz"}},
	}}}

	warnings := Warnings(cfg)
	require.Len(t, warnings, 2)

	for _, w := range warnings {
		assert.Contains(t, w, "invalid nameserver")
		assert.NotContains(t, w, "marker")
	}
}

func TestListenersOverlap(t *testing.T) {
	tests := []struct {
		name        string
		aHost       string
		aPort       int
		bHost       string
		bPort       int
		wantOverlap bool
	}{
		{"different-ports", "", 80, "", 443, false},
		{"same-port-wildcard", "", 80, "", 80, true},
		{"wildcard-vs-loopback-same-port", "0.0.0.0", 80, "127.0.0.1", 80, true},
		{"loopback-vs-wildcard-same-port", "127.0.0.1", 80, "0.0.0.0", 80, true},
		{"ipv6-wildcard-vs-numeric", "[::]", 80, "0.0.0.0", 80, true},
		{"different-specific-hosts-same-port", "192.168.1.1", 80, "192.168.1.2", 80, false},
		{"same-specific-host-same-port", "127.0.0.1", 80, "127.0.0.1", 80, true},
		{"same-specific-host-different-port", "127.0.0.1", 80, "127.0.0.1", 81, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := listenersOverlap(tt.aHost, tt.aPort, tt.bHost, tt.bPort)
			assert.Equal(t, tt.wantOverlap, got)
		})
	}
}

// TestValidateListenerCollisions_BlamesParseFailure pins one error per
// malformed address, on its own key, even when paired with a well-formed
// sibling.
func TestValidateListenerCollisions_BlamesParseFailure(t *testing.T) {
	tests := []struct {
		name    string
		bad     string // YAML key whose addr is malformed
		good    string // sibling key with a valid addr
		badAddr string
	}{
		{"bad-listen_addr", "listen_addr", "metrics_listen_addr", "garbage"},
		{"bad-metrics_listen_addr", "metrics_listen_addr", "listen_addr", "no-port"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Decoding rejects these; Go data reaches the rule as is.
			cfg := &types.Config{}
			for _, f := range types.ConfigFields(cfg) {
				switch f.Path {
				case tt.bad:
					f.Value.SetString(tt.badAddr)
				case tt.good:
					f.Value.SetString(":9999")
				}
			}

			var blamed []*types.ConfigError

			for _, e := range types.ConfigErrors(Validate(cfg)) {
				if len(e.Current) > 0 && (e.Current[0].Key == tt.bad || e.Current[0].Key == tt.good) {
					blamed = append(blamed, e)
				}
			}

			require.Len(t, blamed, 1, "expected exactly one parse error")
			assert.Equal(t, tt.bad+" is not a host:port address", blamed[0].Reason)
			require.Len(t, blamed[0].Current, 1)
			assert.Equal(t, tt.bad, blamed[0].Current[0].Key)
			assert.Equal(t, tt.badAddr, blamed[0].Current[0].Value)
		})
	}
}

func TestIsWildcardHost(t *testing.T) {
	wildcards := []string{"", "0.0.0.0", "::", "[::]"}
	for _, h := range wildcards {
		t.Run("wildcard-"+h, func(t *testing.T) {
			assert.True(t, isWildcardHost(h))
		})
	}

	specifics := []string{"127.0.0.1", "192.168.1.1", "::1", "example.com"}
	for _, h := range specifics {
		t.Run("specific-"+h, func(t *testing.T) {
			assert.False(t, isWildcardHost(h))
		})
	}
}

func TestConfigValidator_NilWhenEmpty(t *testing.T) {
	v := &configValidator{}
	assert.False(t, v.HasErrors())
	assert.NoError(t, v.Err())
}

func TestConfigValidator_JoinsWithBlankLine(t *testing.T) {
	v := &configValidator{}
	v.Add(&types.ConfigError{Reason: "first"})
	v.Add(&types.ConfigError{Reason: "second"})

	want := "Fatal config error: first\n" +
		"\n" +
		"Fatal config error: second\n"
	assert.Equal(t, want, v.Err().Error())
}

func TestConfigValidator_JoinedErrorsIs(t *testing.T) {
	v := &configValidator{}
	v.Add(&types.ConfigError{Reason: "first"})
	v.Add(&types.ConfigError{Reason: "second", Cause: errTestSentinel})
	err := v.Err()

	require.ErrorIs(t, err, types.ErrConfig)
	require.ErrorIs(t, err, errTestSentinel)
}

func TestConfigValidator_JoinedErrorsAs(t *testing.T) {
	v := &configValidator{}
	v.Add(&types.ConfigError{Reason: "first"})
	v.Add(&types.ConfigError{Reason: "second"})
	err := v.Err()

	var got *types.ConfigError
	require.ErrorAs(t, err, &got)
	assert.Equal(t, "first", got.Reason)
}

func TestConfigValidator_AddErrSkipsNil(t *testing.T) {
	v := &configValidator{}
	v.AddErr(nil)
	assert.False(t, v.HasErrors())
	assert.NoError(t, v.Err())
}

// TestValidatePrefixesInsideTailscaleRanges: node ranges must lie inside
// the ranges the Tailscale client assumes; a range wholly in the block
// Tailscale reserves for ChromeOS VMs holds no address to hand out.
func TestValidatePrefixesInsideTailscaleRanges(t *testing.T) {
	for _, tt := range []struct {
		name    string
		v4, v6  string // "" leaves the family unset
		wantErr string // "" validates
	}{
		{name: "v4 subnet", v4: "100.64.0.0/24"},
		{name: "v6 subnet", v6: "fd7a:115c:a1e0::/64"},
		{name: "both whole ranges", v4: "100.64.0.0/10", v6: "fd7a:115c:a1e0::/48"},
		{name: "v4 over the ChromeOS block", v4: "100.115.0.0/16"},
		{name: "v4 outside", v4: "10.0.0.0/8", wantErr: "prefixes.v4 is outside 100.64.0.0/10"},
		{name: "v4 wider", v4: "100.0.0.0/8", wantErr: "prefixes.v4 is outside 100.64.0.0/10"},
		{name: "v4 in the ChromeOS block", v4: "100.115.92.0/24", wantErr: "prefixes.v4 is inside 100.115.92.0/23"},
		{name: "v6 outside", v6: "fd00::/48", wantErr: "prefixes.v6 is outside fd7a:115c:a1e0::/48"},
		{name: "v6 wider", v6: "fd7a:115c::/32", wantErr: "prefixes.v6 is outside fd7a:115c:a1e0::/48"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validConfig()
			cfg.Prefixes.V4, cfg.Prefixes.V6 = nil, nil

			if tt.v4 != "" {
				cfg.Prefixes.V4 = new(netip.MustParsePrefix(tt.v4))
			}

			if tt.v6 != "" {
				cfg.Prefixes.V6 = new(netip.MustParsePrefix(tt.v6))
			}

			err := Validate(&cfg)
			if tt.wantErr == "" {
				require.NoError(t, err)

				return
			}

			require.ErrorContains(t, err, tt.wantErr)
			require.ErrorIs(t, err, types.ErrPrefixOutsideTailscaleRanges)
			assert.Len(t, types.ConfigErrors(err), 1, err.Error())
		})
	}
}

func TestValidateRegistrationAuthPageURL(t *testing.T) {
	for _, tt := range []struct {
		name, url, wantErr string
	}{
		{name: "unset validates", url: ""},
		{name: "https", url: "https://portal.example.com/hs-register.html"},
		{name: "http", url: "http://portal.local/p?mode=hs"},
		{name: "relative path", url: "/relative/path", wantErr: "registration.auth_page_url must be an absolute http(s) URL"},
		{name: "javascript scheme", url: "javascript:alert(1)", wantErr: "registration.auth_page_url must be an absolute http(s) URL"},
		{name: "missing scheme", url: "portal.example.com/x.html", wantErr: "registration.auth_page_url must be an absolute http(s) URL"},
		{name: "no host", url: "https:///x.html", wantErr: "registration.auth_page_url must be an absolute http(s) URL"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validConfig()
			cfg.Registration.AuthPageURL = tt.url

			err := Validate(&cfg)
			if tt.wantErr == "" {
				require.NoError(t, err)
			} else {
				require.ErrorContains(t, err, tt.wantErr)
			}
		})
	}
}
