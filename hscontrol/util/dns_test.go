package util

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"tailscale.com/util/dnsname"
	"tailscale.com/util/must"
)

func TestNormaliseHostname(t *testing.T) {
	type args struct {
		name string
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{
			name:    "valid: lowercase user",
			args:    args{name: "valid-user"},
			want:    "valid-user",
			wantErr: false,
		},
		{
			name:    "normalise: capitalized user",
			args:    args{name: "Invalid-CapItaLIzed-user"},
			want:    "invalid-capitalized-user",
			wantErr: false,
		},
		{
			name:    "normalise: email as user",
			args:    args{name: "foo.bar@example.com"},
			want:    "foo.barexample.com",
			wantErr: false,
		},
		{
			name:    "normalise: chars in user name",
			args:    args{name: "super-user+name"},
			want:    "super-username",
			wantErr: false,
		},
		{
			name: "invalid: too long name truncated leaves trailing hyphen",
			args: args{
				name: "super-long-useruseruser-name-that-should-be-a-little-more-than-63-chars",
			},
			want:    "",
			wantErr: true,
		},
		{
			name:    "invalid: emoji stripped leaves trailing hyphen",
			args:    args{name: "hostname-with-💩"},
			want:    "",
			wantErr: true,
		},
		{
			name:    "normalise: multiple emojis stripped",
			args:    args{name: "node-🎉-🚀-test"},
			want:    "node---test",
			wantErr: false,
		},
		{
			name:    "invalid: only emoji becomes empty",
			args:    args{name: "💩"},
			want:    "",
			wantErr: true,
		},
		{
			name:    "invalid: emoji at start leaves leading hyphen",
			args:    args{name: "🚀-rocket-node"},
			want:    "",
			wantErr: true,
		},
		{
			name:    "invalid: emoji at end leaves trailing hyphen",
			args:    args{name: "node-test-🎉"},
			want:    "",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NormaliseHostname(tt.args.name)
			if (err != nil) != tt.wantErr {
				t.Errorf("NormaliseHostname() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("NormaliseHostname() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestValidateHostname(t *testing.T) {
	tests := []struct {
		name          string
		hostname      string
		wantErr       bool
		errorContains string
	}{
		{
			name:     "valid lowercase",
			hostname: "valid-hostname",
			wantErr:  false,
		},
		{
			name:          "uppercase rejected",
			hostname:      "MyHostname",
			wantErr:       true,
			errorContains: "must be lowercase",
		},
		{
			name:          "too short",
			hostname:      "a",
			wantErr:       true,
			errorContains: "too short",
		},
		{
			name:          "too long",
			hostname:      "a" + strings.Repeat("b", 63),
			wantErr:       true,
			errorContains: "too long",
		},
		{
			name:          "emoji rejected",
			hostname:      "hostname-💩",
			wantErr:       true,
			errorContains: "invalid characters",
		},
		{
			name:          "starts with hyphen",
			hostname:      "-hostname",
			wantErr:       true,
			errorContains: "cannot start or end with a hyphen",
		},
		{
			name:          "ends with hyphen",
			hostname:      "hostname-",
			wantErr:       true,
			errorContains: "cannot start or end with a hyphen",
		},
		{
			name:          "starts with dot",
			hostname:      ".hostname",
			wantErr:       true,
			errorContains: "cannot start or end with a dot",
		},
		{
			name:          "ends with dot",
			hostname:      "hostname.",
			wantErr:       true,
			errorContains: "cannot start or end with a dot",
		},
		{
			name:          "special characters",
			hostname:      "host!@#$name",
			wantErr:       true,
			errorContains: "invalid characters",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateHostname(tt.hostname)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateHostname() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr && tt.errorContains != "" {
				if err == nil || !strings.Contains(err.Error(), tt.errorContains) {
					t.Errorf("ValidateHostname() error = %v, should contain %q", err, tt.errorContains)
				}
			}
		})
	}
}

func TestMagicDNSRootDomains100(t *testing.T) {
	domains := GenerateIPv4DNSRootDomain(netip.MustParsePrefix("100.64.0.0/10"))

	assert.Contains(t, domains, must.Get(dnsname.ToFQDN("64.100.in-addr.arpa.")))
	assert.Contains(t, domains, must.Get(dnsname.ToFQDN("100.100.in-addr.arpa.")))
	assert.Contains(t, domains, must.Get(dnsname.ToFQDN("127.100.in-addr.arpa.")))
}

func TestMagicDNSRootDomains172(t *testing.T) {
	domains := GenerateIPv4DNSRootDomain(netip.MustParsePrefix("172.16.0.0/16"))

	assert.Contains(t, domains, must.Get(dnsname.ToFQDN("0.16.172.in-addr.arpa.")))
	assert.Contains(t, domains, must.Get(dnsname.ToFQDN("255.16.172.in-addr.arpa.")))
}

// Happens when netmask is a multiple of 4 bits (sounds likely).
func TestMagicDNSRootDomainsIPv6Single(t *testing.T) {
	domains := GenerateIPv6DNSRootDomain(netip.MustParsePrefix("fd7a:115c:a1e0::/48"))

	assert.Len(t, domains, 1)
	assert.Equal(t, "0.e.1.a.c.5.1.1.a.7.d.f.ip6.arpa.", domains[0].WithTrailingDot())
}

func TestMagicDNSRootDomainsIPv6SingleMultiple(t *testing.T) {
	domains := GenerateIPv6DNSRootDomain(netip.MustParsePrefix("fd7a:115c:a1e0::/50"))

	yieldsRoot := func(dom string) bool {
		for _, candidate := range domains {
			if candidate.WithTrailingDot() == dom {
				return true
			}
		}

		return false
	}

	assert.Len(t, domains, 4)
	assert.True(t, yieldsRoot("0.0.e.1.a.c.5.1.1.a.7.d.f.ip6.arpa."))
	assert.True(t, yieldsRoot("1.0.e.1.a.c.5.1.1.a.7.d.f.ip6.arpa."))
	assert.True(t, yieldsRoot("2.0.e.1.a.c.5.1.1.a.7.d.f.ip6.arpa."))
	assert.True(t, yieldsRoot("3.0.e.1.a.c.5.1.1.a.7.d.f.ip6.arpa."))
}
