package ipset

import (
	"math/rand/v2"
	"net/netip"
	"slices"
	"sync"
	"testing"

	"github.com/gaissmai/iprange"
	"github.com/stretchr/testify/require"
	"go4.org/netipx"
)

func makeSet(tb testing.TB, prefixes ...string) Set {
	tb.Helper()

	var b Builder
	for _, p := range prefixes {
		b.AddPrefix(netip.MustParsePrefix(p))
	}

	s, err := b.Build()
	require.NoError(tb, err)

	return s
}

func wantPrefixes(tb testing.TB, s Set, prefixes ...string) {
	tb.Helper()

	want := slices.Grow([]netip.Prefix(nil), len(prefixes))
	for _, p := range prefixes {
		want = append(want, netip.MustParsePrefix(p))
	}

	require.Equal(tb, want, slices.Collect(s.Prefixes()))
}

func TestSetCoverageAndAlgebra(t *testing.T) {
	empty := Set{}
	require.True(t, empty.IsEmpty())
	require.True(t, empty.ContainsSet(empty))
	require.True(t, empty.Equal(Set{}))
	require.False(t, empty.Overlaps(empty))

	s := makeSet(t, "10.0.0.128/25", "10.0.0.0/25", "2001:db8::/64")
	wantPrefixes(t, s, "10.0.0.0/24", "2001:db8::/64")
	require.True(t, s.ContainsPrefix(netip.MustParsePrefix("10.0.0.99/24")))
	require.False(t, s.ContainsPrefix(netip.MustParsePrefix("10.0.0.0/23")))
	require.True(t, s.OverlapsPrefix(netip.MustParsePrefix("10.0.0.0/23")))
	require.True(t, s.ContainsSet(empty))
	require.False(t, empty.ContainsSet(s))
	require.False(t, s.Overlaps(empty))
	require.False(t, empty.Overlaps(s))
	require.True(t, s.Equal(s.Union(empty)))
	require.True(t, s.Equal(empty.Union(s)))
	require.True(t, s.Intersect(empty).IsEmpty())
	require.True(t, empty.Subtract(s).IsEmpty())
	require.True(t, s.Equal(s.Subtract(empty)))
	require.True(t, s.Subtract(s).IsEmpty())
	require.True(t, All().ContainsSet(s))
	wantPrefixes(t, All(), "0.0.0.0/0", "::/0")

	hole := makeSet(t, "10.0.0.64/26")
	result := s.Subtract(hole)
	wantPrefixes(t, result, "10.0.0.0/26", "10.0.0.128/25", "2001:db8::/64")
	require.False(t, result.Contains(netip.MustParseAddr("10.0.0.100")))
	require.False(t, result.ContainsPrefix(netip.MustParsePrefix("10.0.0.0/24")))
	require.True(t, result.Union(hole).Equal(s))
	require.True(t, s.Intersect(hole).Equal(hole))
	require.True(t, hole.Intersect(s).Equal(hole))
	require.True(t, s.Overlaps(hole))
	require.True(t, hole.Overlaps(s))
	require.False(t, result.Overlaps(hole))

	recursive := makeSet(t, "10.0.0.192/26", "10.0.0.0/26",
		"10.0.0.128/26", "10.0.0.64/26", "10.0.0.1/32")
	wantPrefixes(t, recursive, "10.0.0.0/24")
	require.Nil(t, recursive.multi)
	require.True(t, recursive.single.IsValid())
	require.True(t, recursive.Equal(makeSet(t, "10.0.0.99/24")))
	promoted := recursive.Union(makeSet(t, "2001:db8::/64"))
	require.NotNil(t, promoted.multi)
	require.False(t, promoted.single.IsValid())
	demoted := promoted.Subtract(makeSet(t, "::/0"))
	require.Nil(t, demoted.multi)
	require.True(t, demoted.Equal(recursive))
	require.Nil(t, promoted.Intersect(recursive).multi)
	require.Nil(t, makeSet(t, "10.0.0.0/25").Union(
		makeSet(t, "10.0.0.128/25")).multi)

	// Only the relevant exclusions can affect each disjoint source prefix.
	many := makeSet(t, "10.0.0.0/24", "10.0.2.0/24", "2001:db8::/120")
	exclusions := makeSet(t, "10.0.0.0/25", "10.0.0.192/26",
		"10.0.1.0/24", "10.0.2.0/23", "2001:db8::40/122", "2001:db9::/32")
	wantPrefixes(t, many.Subtract(exclusions), "10.0.0.128/26",
		"2001:db8::/122", "2001:db8::80/121")
}

func TestSetAddressFamilies(t *testing.T) {
	v4 := makeSet(t, "192.0.2.0/24")
	mapped := makeSet(t, "::ffff:192.0.2.0/120")
	require.False(t, v4.Contains(netip.MustParseAddr("::ffff:192.0.2.1")))
	require.False(t, mapped.Contains(netip.MustParseAddr("192.0.2.1")))
	require.False(t, v4.Overlaps(mapped))
	require.False(t, v4.ContainsSet(mapped))
	require.True(t, v4.Intersect(mapped).IsEmpty())
	require.True(t, v4.Subtract(mapped).Equal(v4))

	for _, s := range []Set{{}, v4, mapped, All()} {
		require.False(t, s.Contains(netip.Addr{}))
		require.False(t, s.Contains(netip.MustParseAddr("fe80::1%eth0")))
		require.False(t, s.Contains(netip.MustParseAddr("::ffff:192.0.2.1%eth0")))
		require.False(t, s.ContainsPrefix(netip.Prefix{}))
		require.False(t, s.OverlapsPrefix(netip.Prefix{}))
	}

	var b Builder
	b.AddAddr(netip.MustParseAddr("fe80::1%eth0"))
	s, err := b.Build()
	require.NoError(t, err)
	wantPrefixes(t, s, "fe80::1/128")
	require.True(t, s.Contains(netip.MustParseAddr("fe80::1")))
	require.False(t, s.Contains(netip.MustParseAddr("fe80::1%eth0")))
	b.AddSet(s)
	b.AddSet(v4)
	s, err = b.Build()
	require.NoError(t, err)
	require.False(t, s.Contains(netip.MustParseAddr("fe80::1%eth0")))
	require.True(t, s.Contains(netip.MustParseAddr("fe80::1")))

	r, err := iprange.FromAddrs(netip.MustParseAddr("::ffff:192.0.2.1"),
		netip.MustParseAddr("::ffff:192.0.2.3"))
	require.NoError(t, err)
	b.AddRange(r)
	s, err = b.Build()
	require.NoError(t, err)
	wantPrefixes(t, s, "::ffff:192.0.2.1/128", "::ffff:192.0.2.2/127")
}

func TestBuilderValidationAndReuse(t *testing.T) {
	for _, addInvalid := range []func(*Builder){
		func(b *Builder) { b.AddAddr(netip.Addr{}) },
		func(b *Builder) { b.AddPrefix(netip.Prefix{}) },
		func(b *Builder) { b.AddRange(iprange.IPRange{}) },
	} {
		var b Builder
		b.AddPrefix(netip.MustParsePrefix("10.0.0.0/24"))
		addInvalid(&b)
		b.AddPrefix(netip.MustParsePrefix("::/0"))
		s, err := b.Build()
		require.Error(t, err)
		require.True(t, s.IsEmpty(), "invalid input must not publish partial coverage")
		b.AddAddr(netip.MustParseAddr("192.0.2.1"))
		s, err = b.Build()
		require.NoError(t, err)
		wantPrefixes(t, s, "192.0.2.1/32")
		s, err = b.Build()
		require.NoError(t, err)
		require.True(t, s.IsEmpty())
	}

	addr := netip.MustParseAddr("192.0.2.1")

	require.Zero(t, testing.AllocsPerRun(100, func() {
		var b Builder
		b.AddAddr(addr)

		s, err := b.Build()
		if err != nil || !s.Contains(addr) {
			panic("invalid singleton")
		}
	}))
}

func TestSetImmutability(t *testing.T) {
	a := makeSet(t, "10.0.0.0/25", "10.10.0.0/24", "2001:db8::/64")
	b := makeSet(t, "10.0.0.128/25", "172.16.0.0/16", "2001:db9::/64")
	beforeA, beforeB := slices.Collect(a.Prefixes()), slices.Collect(b.Prefixes())
	copyA := a

	var builder Builder
	builder.AddSet(a)
	first, err := builder.Build()
	require.NoError(t, err)
	builder.AddSet(first)
	builder.AddSet(b)
	second, err := builder.Build()
	require.NoError(t, err)
	require.True(t, second.ContainsPrefix(netip.MustParsePrefix("10.0.0.0/24")))

	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 20 {
				union := a.Union(b)
				if !union.ContainsSet(a) || !union.ContainsSet(b) {
					t.Error("union lost operand coverage")
				}

				if !union.Intersect(a).Equal(a) {
					t.Error("intersection changed operand coverage")
				}

				if union.Subtract(a).Overlaps(a) {
					t.Error("subtraction retained excluded coverage")
				}
			}
		})
	}

	wg.Wait()
	require.Equal(t, beforeA, slices.Collect(a.Prefixes()))
	require.Equal(t, beforeA, slices.Collect(copyA.Prefixes()))
	require.Equal(t, beforeA, slices.Collect(first.Prefixes()))
	require.Equal(t, beforeB, slices.Collect(b.Prefixes()))
}

func TestSetIteration(t *testing.T) {
	var b Builder

	for _, text := range []string{"2001:db8::1-2001:db8::3", "10.0.0.1-10.0.0.3"} {
		r, err := iprange.FromString(text)
		require.NoError(t, err)
		b.AddRange(r)
	}

	s, err := b.Build()
	require.NoError(t, err)
	wantPrefixes(t, s, "10.0.0.1/32", "10.0.0.2/31",
		"2001:db8::1/128", "2001:db8::2/127")

	var ranges []string
	for r := range s.Ranges() {
		ranges = append(ranges, r.String())
	}

	require.Equal(t, []string{"10.0.0.1-10.0.0.3", "2001:db8::1-2001:db8::3"}, ranges)

	var addrs []string
	for addr := range s.Addrs() {
		addrs = append(addrs, addr.String())
	}

	require.Equal(t, []string{
		"10.0.0.1", "10.0.0.2", "10.0.0.3",
		"2001:db8::1", "2001:db8::2", "2001:db8::3",
	}, addrs)

	for _, set := range []Set{{}, makeSet(t, "10.0.0.1/32"), s, All()} {
		wantCalls := 1
		if set.IsEmpty() {
			wantCalls = 0
		}

		calls := 0

		set.Prefixes()(func(netip.Prefix) bool { calls++; return false })
		require.Equal(t, wantCalls, calls)
		calls = 0

		set.Ranges()(func(iprange.IPRange) bool { calls++; return false })
		require.Equal(t, wantCalls, calls)
		calls = 0

		set.Addrs()(func(netip.Addr) bool { calls++; return false })
		require.Equal(t, wantCalls, calls)
	}
}

func TestSetIterationMaximumEndpoints(t *testing.T) {
	for _, prefixes := range [][]string{
		{"255.255.255.255/32"},
		{"ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128"},
		{"255.255.255.254/31", "::/127", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe/127"},
	} {
		s := makeSet(t, prefixes...)

		var want []netip.Addr

		for _, p := range prefixes {
			prefix := netip.MustParsePrefix(p)

			want = append(want, prefix.Addr())
			if prefix.Bits() != prefix.Addr().BitLen() {
				want = append(want, prefix.Addr().Next())
			}
		}

		var got []netip.Addr
		for addr := range s.Addrs() {
			got = append(got, addr)
			if len(got) > len(want) {
				t.Fatal("iterator continued past inclusive maximum endpoint")
			}
		}

		require.Equal(t, want, got)
	}
}

func TestSetDifferential(t *testing.T) {
	rng := rand.New(
		rand.NewPCG(1, 2),
	) // #nosec G404 -- Fixed seed reproduces test fixtures, not security values.

	for range 150 {
		var (
			sets [2]Set
			refs [2]*netipx.IPSet
		)

		for i := range sets {
			var (
				b   Builder
				ref netipx.IPSetBuilder
			)

			for range rng.IntN(65) {
				var addr netip.Addr

				switch rng.IntN(3) {
				case 0:
					addr = netip.AddrFrom4(
						[4]byte{10, 0, 0, byte(rng.IntN(256) & 0xff)},
					)
				case 1:
					addr = netip.AddrFrom16(
						[16]byte{0x20, 1, 0xd, 0xb8, 15: byte(rng.IntN(256) & 0xff)},
					)
				default:
					addr = netip.AddrFrom16(
						[16]byte{
							10: 0xff,
							11: 0xff,
							12: 10,
							15: byte(rng.IntN(256) & 0xff),
						},
					)
				}

				p := netip.PrefixFrom(addr, addr.BitLen()-rng.IntN(7))
				b.AddPrefix(p)
				ref.AddPrefix(p)
			}

			var err error

			sets[i], err = b.Build()
			require.NoError(t, err)
			refs[i], err = ref.IPSet()
			require.NoError(t, err)
			require.True(
				t,
				slices.Equal(refs[i].Prefixes(), slices.Collect(sets[i].Prefixes())),
			)
		}

		a, b := sets[0], sets[1]
		ra, rb := refs[0], refs[1]
		require.Equal(t, ra.Equal(rb), a.Equal(b))
		require.Equal(t, ra.Overlaps(rb), a.Overlaps(b))

		covered := true
		for _, p := range rb.Prefixes() {
			covered = covered && ra.ContainsPrefix(p)
		}

		require.Equal(t, covered, a.ContainsSet(b))

		for _, p := range append(ra.Prefixes(), rb.Prefixes()...) {
			require.Equal(t, ra.Contains(p.Addr()), a.Contains(p.Addr()))
			require.Equal(t, ra.ContainsPrefix(p), a.ContainsPrefix(p))
			require.Equal(t, ra.OverlapsPrefix(p), a.OverlapsPrefix(p))
		}

		for _, op := range []string{"union", "intersect", "subtract"} {
			var ref netipx.IPSetBuilder
			ref.AddSet(ra)

			var got Set

			switch op {
			case "union":
				ref.AddSet(rb)

				got = a.Union(b)
			case "intersect":
				ref.Intersect(rb)
				got = a.Intersect(b)
			case "subtract":
				ref.RemoveSet(rb)

				got = a.Subtract(b)
			}

			want, err := ref.IPSet()
			require.NoError(t, err)
			require.True(
				t,
				slices.Equal(want.Prefixes(), slices.Collect(got.Prefixes())),
				op,
			)

			var ranges []netipx.IPRange

			for r := range got.Ranges() {
				first, last := r.Addrs()
				ranges = append(ranges, netipx.IPRangeFrom(first, last))
			}

			require.True(t, slices.Equal(want.Ranges(), ranges), op)
		}

		require.True(t, slices.Equal(ra.Prefixes(), slices.Collect(a.Prefixes())))
		require.True(t, slices.Equal(rb.Prefixes(), slices.Collect(b.Prefixes())))
	}
}
