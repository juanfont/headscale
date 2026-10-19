package util

import (
	"net/netip"
	"slices"
	"testing"

	"github.com/google/go-cmp/cmp"
	"go4.org/netipx"
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
				builder netipx.IPSetBuilder
				want    []netip.Addr
			)

			for _, s := range tt.ips {
				ip := netip.MustParseAddr(s)
				builder.Add(ip)
				want = append(want, ip)
			}

			set, err := builder.IPSet()
			if err != nil {
				t.Fatal(err)
			}

			var got []netip.Addr
			for ip := range IPSetAddrIter(set) {
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
	var builder netipx.IPSetBuilder
	builder.Add(netip.MustParseAddr("255.255.255.255"))
	builder.Add(netip.MustParseAddr("2001:db8::1"))

	set, err := builder.IPSet()
	if err != nil {
		t.Fatal(err)
	}

	calls := 0

	IPSetAddrIter(set)(func(netip.Addr) bool {
		calls++
		return false
	})

	if calls != 1 {
		t.Errorf("yield called %d times after consumer stopped, want 1", calls)
	}
}

func Test_parseIPSet(t *testing.T) {
	set := func(ips []string, prefixes []string) *netipx.IPSet {
		var builder netipx.IPSetBuilder

		for _, ip := range ips {
			builder.Add(netip.MustParseAddr(ip))
		}

		for _, pre := range prefixes {
			builder.AddPrefix(netip.MustParsePrefix(pre))
		}

		s, _ := builder.IPSet()

		return s
	}

	type args struct {
		arg  string
		bits *int
	}

	tests := []struct {
		name    string
		args    args
		want    *netipx.IPSet
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
