package util

import (
	"net/netip"
	"testing"

	"github.com/google/go-cmp/cmp"
	"go4.org/netipx"
)

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

// TestParseIPRangeMatchesParseIPSet checks ParseIPRange accepts exactly what
// ParseIPSet does, "*" aside, and denotes the same addresses.
func TestParseIPRangeMatchesParseIPSet(t *testing.T) {
	for _, arg := range []string{
		"10.0.0.1",
		"2001:db8::2",
		"192.168.0.0/16",
		"2001:db8:abcd:1234::/64",
		"192.168.0.0-192.168.255.255",
		"10.0.0.5-10.0.0.9",
		"fd7a::1-fd7a::ff",
		"10.0.0.1/8",
		"10.0.0.9-10.0.0.1",
		"10.0.0.1-fd7a::1",
		"10.0.0.1-10.0.0.2-10.0.0.3",
		"fe80::1%eth0",
		"10.0.0.0/33",
		"not-an-ip",
		"",
	} {
		set, setErr := ParseIPSet(arg, nil)
		r, rangeErr := ParseIPRange(arg)

		if (setErr != nil) != (rangeErr != nil) {
			t.Errorf("%q: ParseIPSet error %v, ParseIPRange error %v", arg, setErr, rangeErr)

			continue
		}

		if setErr != nil {
			continue
		}

		if diff := cmp.Diff(set.Ranges(), []netipx.IPRange{r}, cmp.Comparer(func(a, b netipx.IPRange) bool { return a == b })); diff != "" {
			t.Errorf("%q: (-ParseIPSet +ParseIPRange):\n%s", arg, diff)
		}
	}
}
