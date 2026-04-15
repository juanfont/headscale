package matcher

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
)

func TestMatchFromStrings(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		srcs    []string
		dsts    []string
		wantSrc netip.Addr
		wantDst netip.Addr
		srcIn   bool
		dstIn   bool
	}{
		{
			name:    "basic CIDR match",
			srcs:    []string{"10.0.0.0/8"},
			dsts:    []string{"192.168.1.0/24"},
			wantSrc: netip.MustParseAddr("10.1.2.3"),
			wantDst: netip.MustParseAddr("192.168.1.100"),
			srcIn:   true,
			dstIn:   true,
		},
		{
			name:    "basic CIDR no match",
			srcs:    []string{"10.0.0.0/8"},
			dsts:    []string{"192.168.1.0/24"},
			wantSrc: netip.MustParseAddr("172.16.0.1"),
			wantDst: netip.MustParseAddr("10.0.0.1"),
			srcIn:   false,
			dstIn:   false,
		},
		{
			name:    "wildcard matches everything",
			srcs:    []string{"*"},
			dsts:    []string{"*"},
			wantSrc: netip.MustParseAddr("8.8.8.8"),
			wantDst: netip.MustParseAddr("1.1.1.1"),
			srcIn:   true,
			dstIn:   true,
		},
		{
			name:    "wildcard matches IPv6",
			srcs:    []string{"*"},
			dsts:    []string{"*"},
			wantSrc: netip.MustParseAddr("2001:db8::1"),
			wantDst: netip.MustParseAddr("fd7a:115c:a1e0::1"),
			srcIn:   true,
			dstIn:   true,
		},
		{
			name:    "single IP source",
			srcs:    []string{"100.64.0.1"},
			dsts:    []string{"10.0.0.0/8"},
			wantSrc: netip.MustParseAddr("100.64.0.1"),
			wantDst: netip.MustParseAddr("10.33.0.1"),
			srcIn:   true,
			dstIn:   true,
		},
		{
			name:    "single IP source no match",
			srcs:    []string{"100.64.0.1"},
			dsts:    []string{"10.0.0.0/8"},
			wantSrc: netip.MustParseAddr("100.64.0.2"),
			wantDst: netip.MustParseAddr("10.33.0.1"),
			srcIn:   false,
			dstIn:   true,
		},
		{
			name:    "multiple CIDRs",
			srcs:    []string{"10.0.0.0/8", "172.16.0.0/12"},
			dsts:    []string{"192.168.0.0/16", "100.64.0.0/10"},
			wantSrc: netip.MustParseAddr("172.20.0.1"),
			wantDst: netip.MustParseAddr("100.100.0.1"),
			srcIn:   true,
			dstIn:   true,
		},
		{
			name:    "IPv6 CIDR",
			srcs:    []string{"fd7a:115c:a1e0::/48"},
			dsts:    []string{"2001:db8::/32"},
			wantSrc: netip.MustParseAddr("fd7a:115c:a1e0::1"),
			wantDst: netip.MustParseAddr("2001:db8::1"),
			srcIn:   true,
			dstIn:   true,
		},
		{
			name:    "empty sources and destinations",
			srcs:    []string{},
			dsts:    []string{},
			wantSrc: netip.MustParseAddr("10.0.0.1"),
			wantDst: netip.MustParseAddr("10.0.0.1"),
			srcIn:   false,
			dstIn:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			m := MatchFromStrings(tt.srcs, tt.dsts)
			assert.Equal(t, tt.srcIn, m.SrcsContainsIPs(tt.wantSrc),
				"SrcsContainsIPs(%s)", tt.wantSrc)
			assert.Equal(t, tt.dstIn, m.DestsContainsIP(tt.wantDst),
				"DestsContainsIP(%s)", tt.wantDst)
		})
	}
}

func TestMatchFromFilterRule(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		rule     tailcfg.FilterRule
		checkSrc netip.Addr
		checkDst netip.Addr
		srcMatch bool
		dstMatch bool
	}{
		{
			name: "standard rule with port range",
			rule: tailcfg.FilterRule{
				SrcIPs: []string{"100.64.0.1", "fd7a:115c:a1e0::1"},
				DstPorts: []tailcfg.NetPortRange{
					{IP: "10.33.0.0/16", Ports: tailcfg.PortRange{First: 0, Last: 65535}},
				},
			},
			checkSrc: netip.MustParseAddr("100.64.0.1"),
			checkDst: netip.MustParseAddr("10.33.0.50"),
			srcMatch: true,
			dstMatch: true,
		},
		{
			name: "wildcard destination",
			rule: tailcfg.FilterRule{
				SrcIPs: []string{"10.0.0.0/8"},
				DstPorts: []tailcfg.NetPortRange{
					{IP: "*"},
				},
			},
			checkSrc: netip.MustParseAddr("10.1.1.1"),
			checkDst: netip.MustParseAddr("8.8.8.8"),
			srcMatch: true,
			dstMatch: true,
		},
		{
			name: "multiple DstPorts entries",
			rule: tailcfg.FilterRule{
				SrcIPs: []string{"100.64.0.1"},
				DstPorts: []tailcfg.NetPortRange{
					{IP: "10.33.0.0/16"},
					{IP: "192.168.1.0/24"},
				},
			},
			checkSrc: netip.MustParseAddr("100.64.0.1"),
			checkDst: netip.MustParseAddr("192.168.1.50"),
			srcMatch: true,
			dstMatch: true,
		},
		{
			name: "empty DstPorts",
			rule: tailcfg.FilterRule{
				SrcIPs:   []string{"100.64.0.1"},
				DstPorts: nil,
			},
			checkSrc: netip.MustParseAddr("100.64.0.1"),
			checkDst: netip.MustParseAddr("10.0.0.1"),
			srcMatch: true,
			dstMatch: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			m := MatchFromFilterRule(tt.rule)
			assert.Equal(t, tt.srcMatch, m.SrcsContainsIPs(tt.checkSrc),
				"SrcsContainsIPs(%s)", tt.checkSrc)
			assert.Equal(t, tt.dstMatch, m.DestsContainsIP(tt.checkDst),
				"DestsContainsIP(%s)", tt.checkDst)
		})
	}
}

func TestMatchesFromFilterRules(t *testing.T) {
	t.Parallel()

	rules := []tailcfg.FilterRule{
		{
			SrcIPs:   []string{"10.0.0.0/8"},
			DstPorts: []tailcfg.NetPortRange{{IP: "192.168.1.0/24"}},
		},
		{
			SrcIPs:   []string{"172.16.0.0/12"},
			DstPorts: []tailcfg.NetPortRange{{IP: "10.33.0.0/16"}},
		},
	}

	matches := MatchesFromFilterRules(rules)
	require.Len(t, matches, 2)

	// First matcher: 10.0.0.0/8 -> 192.168.1.0/24
	assert.True(t, matches[0].SrcsContainsIPs(netip.MustParseAddr("10.1.2.3")))
	assert.False(t, matches[0].SrcsContainsIPs(netip.MustParseAddr("172.16.0.1")))
	assert.True(t, matches[0].DestsContainsIP(netip.MustParseAddr("192.168.1.100")))

	// Second matcher: 172.16.0.0/12 -> 10.33.0.0/16
	assert.True(t, matches[1].SrcsContainsIPs(netip.MustParseAddr("172.20.0.1")))
	assert.True(t, matches[1].DestsContainsIP(netip.MustParseAddr("10.33.0.1")))
	assert.False(t, matches[1].DestsContainsIP(netip.MustParseAddr("192.168.1.1")))
}

func TestSrcsOverlapsPrefixes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		srcs     []string
		prefixes []netip.Prefix
		want     bool
	}{
		{
			name:     "exact match",
			srcs:     []string{"10.33.0.0/16"},
			prefixes: []netip.Prefix{netip.MustParsePrefix("10.33.0.0/16")},
			want:     true,
		},
		{
			name:     "parent contains child",
			srcs:     []string{"10.0.0.0/8"},
			prefixes: []netip.Prefix{netip.MustParsePrefix("10.33.0.0/16")},
			want:     true,
		},
		{
			name:     "child overlaps parent",
			srcs:     []string{"10.33.0.0/16"},
			prefixes: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
			want:     true,
		},
		{
			name:     "no overlap",
			srcs:     []string{"10.0.0.0/8"},
			prefixes: []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")},
			want:     false,
		},
		{
			name: "multiple prefixes one overlaps",
			srcs: []string{"10.0.0.0/8"},
			prefixes: []netip.Prefix{
				netip.MustParsePrefix("192.168.1.0/24"),
				netip.MustParsePrefix("10.33.0.0/16"),
			},
			want: true,
		},
		{
			name:     "IPv6 overlap",
			srcs:     []string{"fd7a:115c:a1e0::/48"},
			prefixes: []netip.Prefix{netip.MustParsePrefix("fd7a:115c:a1e0:ab12::/64")},
			want:     true,
		},
		{
			name:     "empty prefixes",
			srcs:     []string{"10.0.0.0/8"},
			prefixes: []netip.Prefix{},
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			m := MatchFromStrings(tt.srcs, nil)
			got := m.SrcsOverlapsPrefixes(tt.prefixes...)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestDestsOverlapsPrefixes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		dsts     []string
		prefixes []netip.Prefix
		want     bool
	}{
		{
			name:     "exact match",
			dsts:     []string{"10.33.0.0/16"},
			prefixes: []netip.Prefix{netip.MustParsePrefix("10.33.0.0/16")},
			want:     true,
		},
		{
			name:     "parent contains child",
			dsts:     []string{"10.0.0.0/8"},
			prefixes: []netip.Prefix{netip.MustParsePrefix("10.33.0.0/16")},
			want:     true,
		},
		{
			name:     "no overlap",
			dsts:     []string{"10.0.0.0/8"},
			prefixes: []netip.Prefix{netip.MustParsePrefix("192.168.0.0/16")},
			want:     false,
		},
		{
			name: "wildcard overlaps everything",
			dsts: []string{"*"},
			prefixes: []netip.Prefix{
				netip.MustParsePrefix("0.0.0.0/0"),
			},
			want: true,
		},
		{
			name:     "wildcard overlaps exit route",
			dsts:     []string{"*"},
			prefixes: []netip.Prefix{netip.MustParsePrefix("::/0")},
			want:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			m := MatchFromStrings(nil, tt.dsts)
			got := m.DestsOverlapsPrefixes(tt.prefixes...)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestDestsIsTheInternet(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		dsts []string
		want bool
	}{
		{
			name: "all IPv4 is the internet",
			dsts: []string{"0.0.0.0/0"},
			want: true,
		},
		{
			name: "all IPv6 is the internet",
			dsts: []string{"::/0"},
			want: true,
		},
		{
			name: "wildcard is the internet",
			dsts: []string{"*"},
			want: true,
		},
		{
			name: "private range is not the internet",
			dsts: []string{"10.0.0.0/8"},
			want: false,
		},
		{
			name: "CGNAT range is not the internet",
			dsts: []string{"100.64.0.0/10"},
			want: false,
		},
		{
			name: "single public IP is not the internet",
			dsts: []string{"8.8.8.8"},
			want: false,
		},
		{
			name: "empty dests is not the internet",
			dsts: []string{},
			want: false,
		},
		{
			name: "multiple private ranges are not the internet",
			dsts: []string{
				"10.0.0.0/8",
				"172.16.0.0/12",
				"192.168.0.0/16",
			},
			want: false,
		},
		{
			name: "all IPv4 combined with subnet is the internet",
			dsts: []string{"0.0.0.0/0", "10.33.0.0/16"},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			m := MatchFromStrings(nil, tt.dsts)
			got := m.DestsIsTheInternet()
			assert.Equal(t, tt.want, got,
				"DestsIsTheInternet() for dsts=%v", tt.dsts)
		})
	}
}

func TestDebugString(t *testing.T) {
	t.Parallel()

	m := MatchFromStrings(
		[]string{"10.0.0.0/8"},
		[]string{"192.168.1.0/24"},
	)

	s := m.DebugString()
	assert.Contains(t, s, "Match:")
	assert.Contains(t, s, "Sources:")
	assert.Contains(t, s, "Destinations:")
	assert.Contains(t, s, "10.0.0.0/8")
	assert.Contains(t, s, "192.168.1.0/24")
}
