package util

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNormalizeToFQDNRules(t *testing.T) {
	type args struct {
		name             string
		stripEmailDomain bool
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{
			name: "normalize simple name",
			args: args{
				name:             "normalize-simple.name",
				stripEmailDomain: false,
			},
			want:    "normalize-simple.name",
			wantErr: false,
		},
		{
			name: "normalize an email",
			args: args{
				name:             "foo.bar@example.com",
				stripEmailDomain: false,
			},
			want:    "foo.bar.example.com",
			wantErr: false,
		},
		{
			name: "normalize an email domain should be removed",
			args: args{
				name:             "foo.bar@example.com",
				stripEmailDomain: true,
			},
			want:    "foo.bar",
			wantErr: false,
		},
		{
			name: "strip enabled no email passed as argument",
			args: args{
				name:             "not-email-and-strip-enabled",
				stripEmailDomain: true,
			},
			want:    "not-email-and-strip-enabled",
			wantErr: false,
		},
		{
			name: "normalize complex email",
			args: args{
				name:             "foo.bar+complex-email@example.com",
				stripEmailDomain: false,
			},
			want:    "foo.bar-complex-email.example.com",
			wantErr: false,
		},
		{
			name: "user name with space",
			args: args{
				name:             "name space",
				stripEmailDomain: false,
			},
			want:    "name-space",
			wantErr: false,
		},
		{
			name: "user with quote",
			args: args{
				name:             "Jamie's iPhone 5",
				stripEmailDomain: false,
			},
			want:    "jamies-iphone-5",
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NormalizeToFQDNRules(tt.args.name, tt.args.stripEmailDomain)
			if (err != nil) != tt.wantErr {
				t.Errorf(
					"NormalizeToFQDNRules() error = %v, wantErr %v",
					err,
					tt.wantErr,
				)

				return
			}
			if got != tt.want {
				t.Errorf("NormalizeToFQDNRules() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCheckForFQDNRules(t *testing.T) {
	type args struct {
		name string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name:    "valid: user",
			args:    args{name: "valid-user"},
			wantErr: false,
		},
		{
			name:    "invalid: capitalized user",
			args:    args{name: "Invalid-CapItaLIzed-user"},
			wantErr: true,
		},
		{
			name:    "invalid: email as user",
			args:    args{name: "foo.bar@example.com"},
			wantErr: true,
		},
		{
			name:    "invalid: chars in user name",
			args:    args{name: "super-user+name"},
			wantErr: true,
		},
		{
			name: "invalid: too long name for user",
			args: args{
				name: "super-long-useruseruser-name-that-should-be-a-little-more-than-63-chars",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := CheckForFQDNRules(tt.args.name); (err != nil) != tt.wantErr {
				t.Errorf("CheckForFQDNRules() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestMagicDNSRootDomains100(t *testing.T) {
	domains := GenerateIPv4DNSRootDomain(netip.MustParsePrefix("100.64.0.0/10"))

	found := false
	for _, domain := range domains {
		if domain == "64.100.in-addr.arpa." {
			found = true

			break
		}
	}
	assert.True(t, found)

	found = false
	for _, domain := range domains {
		if domain == "100.100.in-addr.arpa." {
			found = true

			break
		}
	}
	assert.True(t, found)

	found = false
	for _, domain := range domains {
		if domain == "127.100.in-addr.arpa." {
			found = true

			break
		}
	}
	assert.True(t, found)
}

func TestMagicDNSRootDomains172(t *testing.T) {
	domains := GenerateIPv4DNSRootDomain(netip.MustParsePrefix("172.16.0.0/16"))

	found := false
	for _, domain := range domains {
		if domain == "0.16.172.in-addr.arpa." {
			found = true

			break
		}
	}
	assert.True(t, found)

	found = false
	for _, domain := range domains {
		if domain == "255.16.172.in-addr.arpa." {
			found = true

			break
		}
	}
	assert.True(t, found)
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
