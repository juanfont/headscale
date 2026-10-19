package util

import (
	"net/netip"
	"slices"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/juanfont/headscale/hscontrol/ipset"
)

func TestIPSetAddrIterMaxAddress(t *testing.T) {
	tests := []struct {
		name string
		ips  []string
	}{
		{"IPv4 maximum", []string{"255.255.255.254", "255.255.255.255"}},
		{"IPv6 maximum", []string{
			"ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe",
			"ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
		}},
		{"IPv4 maximum continues to IPv6", []string{
			"255.255.255.255", "2001:db8::1", "2001:db8::2",
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var (
				builder ipset.Builder
				want    []netip.Addr
			)

			for _, s := range tt.ips {
				ip := netip.MustParseAddr(s)
				builder.AddAddr(ip)
				want = append(want, ip)
			}

			set, err := builder.Build()
			if err != nil {
				t.Fatal(err)
			}

			var got []netip.Addr
			for ip := range set.Addrs() {
				got = append(got, ip)
				if len(got) > len(want) {
					break // Bound the regression: Next at the maximum yields an invalid address.
				}
			}

			if !slices.Equal(want, got) {
				t.Errorf("addresses = %v, want %v", got, want)
			}
		})
	}
}

func TestIPSetAddrIterConsumerStop(t *testing.T) {
	var builder ipset.Builder
	builder.AddAddr(netip.MustParseAddr("255.255.255.255"))
	builder.AddAddr(netip.MustParseAddr("2001:db8::1"))

	set, err := builder.Build()
	if err != nil {
		t.Fatal(err)
	}

	calls := 0

	set.Addrs()(func(netip.Addr) bool {
		calls++
		return false
	})

	if calls != 1 {
		t.Errorf("yield called %d times after consumer stopped, want 1", calls)
	}
}

func Test_parseIPSet(t *testing.T) {
	set := func(ips []string, prefixes []string) ipset.Set {
		var builder ipset.Builder

		for _, ip := range ips {
			builder.AddAddr(netip.MustParseAddr(ip))
		}

		for _, pre := range prefixes {
			builder.AddPrefix(netip.MustParsePrefix(pre))
		}

		s, _ := builder.Build()

		return s
	}

	type args struct {
		arg  string
		bits *int
	}

	tests := []struct {
		name    string
		args    args
		want    ipset.Set
		wantErr bool
	}{
		{
			name: "simple ip4",
			args: args{
				arg:  "10.0.0.1",
				bits: nil,
			},
			want: set([]string{
				"10.0.0.1",
			}, []string{}),
			wantErr: false,
		},
		{
			name: "simple ip6",
			args: args{
				arg:  "2001:db8:abcd:1234::2",
				bits: nil,
			},
			want: set([]string{
				"2001:db8:abcd:1234::2",
			}, []string{}),
			wantErr: false,
		},
		{
			name: "wildcard",
			args: args{
				arg:  "*",
				bits: nil,
			},
			want: set([]string{}, []string{
				"0.0.0.0/0",
				"::/0",
			}),
			wantErr: false,
		},
		{
			name: "prefix4",
			args: args{
				arg:  "192.168.0.0/16",
				bits: nil,
			},
			want: set([]string{}, []string{
				"192.168.0.0/16",
			}),
			wantErr: false,
		},
		{
			name: "prefix6",
			args: args{
				arg:  "2001:db8:abcd:1234::/64",
				bits: nil,
			},
			want: set([]string{}, []string{
				"2001:db8:abcd:1234::/64",
			}),
			wantErr: false,
		},
		{
			name: "range4",
			args: args{
				arg:  "192.168.0.0-192.168.255.255",
				bits: nil,
			},
			want: set([]string{}, []string{
				"192.168.0.0/16",
			}),
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseIPSet(tt.args.arg, tt.args.bits)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseIPSet() error = %v, wantErr %v", err, tt.wantErr)

				return
			}

			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("parseIPSet() = (-want +got):\n%s", diff)
			}
		})
	}
}

func TestParseIPSetBoundarySemantics(t *testing.T) {
	for _, tt := range []struct {
		name, input string
		bits        *int
		want        []netip.Prefix
		wantErr     string
	}{
		{"host bits rejected", "192.0.2.1/24", nil, nil, "192.0.2.1/24 contains non-network bits set"},
		{"source bits mask host", "192.0.2.1", new(24), []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}, ""},
		{"source bits ignored on CIDR", "192.0.2.0/24", new(-1), []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}, ""},
		{"invalid source bits", "192.0.2.1", new(33), nil, `invalid CIDR size 33 for IP "192.0.2.1"`},
		{"negative source bits", "::1", new(-1), nil, `invalid CIDR size -1 for IP "::1"`},
		{"range", "192.0.2.1-192.0.2.3", nil, []netip.Prefix{netip.MustParsePrefix("192.0.2.1/32"), netip.MustParsePrefix("192.0.2.2/31")}, ""},
		{"reversed range", "192.0.2.3-192.0.2.1", nil, nil, `invalid IP range "192.0.2.3-192.0.2.1"`},
		{"mixed range", "192.0.2.1-::ffff:192.0.2.2", nil, nil, `invalid IP range "192.0.2.1-::ffff:192.0.2.2"`},
		{"zoned address", "fe80::1%eth0", nil, []netip.Prefix{netip.MustParsePrefix("fe80::1/128")}, ""},
		{"zoned range", "fe80::1%eth0-fe80::2%eth1", nil, []netip.Prefix{netip.MustParsePrefix("fe80::1/128"), netip.MustParsePrefix("fe80::2/128")}, ""},
		{"mapped address", "::ffff:192.0.2.1", nil, []netip.Prefix{netip.MustParsePrefix("::ffff:192.0.2.1/128")}, ""},
		{"invalid address", "not an address", nil, nil, `invalid IP address "not an address"`},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseIPSet(tt.input, tt.bits)
			if tt.wantErr != "" {
				if err == nil || err.Error() != tt.wantErr {
					t.Fatalf("error = %v, want %s", err, tt.wantErr)
				}

				return
			}

			if err != nil {
				t.Fatal(err)
			}

			if diff := cmp.Diff(tt.want, slices.Collect(got.Prefixes()), Comparers...); diff != "" {
				t.Fatal(diff)
			}

			if got.Contains(netip.MustParseAddr("fe80::1%eth0")) {
				t.Fatal("zoned membership must not match")
			}

			if tt.name == "mapped address" && got.Contains(netip.MustParseAddr("192.0.2.1")) {
				t.Fatal("mapped IPv6 must not match native IPv4")
			}
		})
	}
}
