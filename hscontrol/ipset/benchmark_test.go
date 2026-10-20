package ipset

import (
	"errors"
	"fmt"
	"net/netip"
	"runtime"
	"slices"
	"testing"

	"github.com/gaissmai/bart"
	"github.com/gaissmai/extnetip"
	"github.com/gaissmai/iprange"
	"github.com/stretchr/testify/require"
	"go4.org/netipx"
)

// All candidates receive the same already-parsed inputs. BART includes validation,
// aggregation and deep cloning where immutable ownership requires it. Its missing
// intersection/subtraction/query guards live here, never in a production backend.
type addressSetInput struct {
	prefixes []netip.Prefix
	ranges   []iprange.IPRange
}

var (
	errBenchmarkInvalidPrefix = errors.New("invalid prefix")
	errBenchmarkInvalidRange  = errors.New("invalid range")

	benchSet        Set
	benchIPSet      *netipx.IPSet
	benchBART       *bart.Lite
	benchBool       bool
	benchUint64     uint64
	benchSetRoots   [2][]Set
	benchIPSetRoots [2][]*netipx.IPSet
	benchBARTRoots  [2][]*bart.Lite
)

func addressSetCorpus(shape string, count int) addressSetInput {
	var input addressSetInput

	for i := range count {
		v6 := shape == "SparseV6" || (i%2 == 1 &&
			(shape == "SparseDual" || shape == "RangesDual"))

		n := uint32(i)
		if shape == "SparseV4" || shape == "SparseV6" || shape == "SparseDual" {
			n *= 256
		}

		addr := netip.AddrFrom4(
			[4]byte{10, byte((n >> 16) & 0xff), byte((n >> 8) & 0xff), byte(n & 0xff)},
		)
		if v6 {
			addr = netip.AddrFrom16([16]byte{
				0x20,
				1,
				0xd,
				0xb8,
				12: byte(
					(n >> 24) & 0xff,
				),
				13: byte((n >> 16) & 0xff),
				14: byte((n >> 8) & 0xff),
				15: byte(n & 0xff),
			})
		}

		bits := addr.BitLen()

		switch shape {
		case "DenseV4":
			// Adjacent /24s recursively aggregate, unlike sparse host inputs.
			addr = netip.AddrFrom4(
				[4]byte{10, byte((i >> 8) & 0xff), byte(i & 0xff), 0},
			)
			bits = 24
		case "OverlapV4":
			bits = 16 + i%17
		case "RangesDual":
			// Three-address intervals leave a one-address gap between neighbors.
			n = uint32(i * 4)
			if v6 {
				addr = netip.AddrFrom16([16]byte{
					0x20,
					1,
					0xd,
					0xb8,
					12: byte(
						(n >> 24) & 0xff,
					),
					13: byte((n >> 16) & 0xff),
					14: byte((n >> 8) & 0xff),
					15: byte(n & 0xff),
				})
			} else {
				addr = netip.AddrFrom4(
					[4]byte{
						10,
						byte((n >> 16) & 0xff),
						byte((n >> 8) & 0xff),
						byte(n & 0xff),
					},
				)
			}

			r, err := iprange.FromAddrs(addr.Next(), addr.Next().Next().Next())
			if err != nil {
				panic(err)
			}

			input.ranges = append(input.ranges, r)

			continue
		}

		input.prefixes = append(input.prefixes, netip.PrefixFrom(addr, bits))
	}

	return input
}

func buildSet(input addressSetInput) (Set, error) {
	var b Builder
	for _, p := range input.prefixes {
		b.AddPrefix(p)
	}

	for _, r := range input.ranges {
		b.AddRange(r)
	}

	return b.Build()
}

func buildIPSet(input addressSetInput) (*netipx.IPSet, error) {
	var b netipx.IPSetBuilder
	for _, p := range input.prefixes {
		b.AddPrefix(p)
	}

	for _, r := range input.ranges {
		first, last := r.Addrs()
		b.AddRange(netipx.IPRangeFrom(first, last))
	}

	return b.IPSet()
}

func buildBART(input addressSetInput) (*bart.Lite, error) {
	table := new(bart.Lite)

	for _, p := range input.prefixes {
		if !p.IsValid() {
			return nil, errBenchmarkInvalidPrefix
		}

		table.Insert(p)
	}

	for _, r := range input.ranges {
		if !r.IsValid() {
			return nil, errBenchmarkInvalidRange
		}

		for p := range r.Prefixes() {
			table.Insert(p)
		}
	}

	table.Aggregate()

	return table, nil
}

func containsBART(table *bart.Lite, addr netip.Addr) bool {
	return addr.IsValid() && addr.Zone() == "" && table.Contains(addr)
}

func unionBART(a, b *bart.Lite) *bart.Lite {
	result := a.Clone()
	result.Union(b)
	result.Aggregate()

	return result
}

func intersectBART(a, b *bart.Lite) *bart.Lite {
	if a.Size() > b.Size() {
		a, b = b, a
	}

	result := new(bart.Lite)

	for p := range a.AllSorted() {
		if b.LookupPrefix(p) {
			result.Insert(p)
			continue
		}

		for q := range b.Subnets(p) {
			result.Insert(q)
		}
	}

	result.Aggregate()

	return result
}

func subtractBART(a, b *bart.Lite) *bart.Lite {
	result := new(bart.Lite)

	var exclusions []iprange.IPRange

	for p := range a.AllSorted() {
		if b.LookupPrefix(p) {
			continue
		}

		exclusions = exclusions[:0]

		for q := range b.Subnets(p) {
			r, _ := iprange.FromAddrs(extnetip.Range(q))
			exclusions = append(exclusions, r)
		}

		if len(exclusions) == 0 {
			result.Insert(p)
			continue
		}

		r, _ := iprange.FromAddrs(extnetip.Range(p))
		for _, remaining := range r.Remove(exclusions) {
			for q := range remaining.Prefixes() {
				result.Insert(q)
			}
		}
	}

	result.Aggregate()

	return result
}

// Hash a transient canonical prefix projection with the same FNV-1a work for
// each candidate. Family is explicit so mapped IPv6 cannot hash as native IPv4.
func hashPrefix(hash uint64, p netip.Prefix) uint64 {
	for _, octet := range p.Addr().As16() {
		hash = (hash ^ uint64(octet)) * 1099511628211
	}

	hash = (hash ^ uint64(p.Addr().BitLen())) * 1099511628211 // #nosec G115 -- Address bit lengths are nonnegative.

	return (hash ^ uint64(p.Bits())) * 1099511628211 // #nosec G115 -- Canonical prefix lengths are nonnegative.
}

func TestAddressSetCandidates(t *testing.T) {
	for _, shape := range []string{
		"SparseV4", "SparseV6", "SparseDual",
		"DenseV4", "OverlapV4", "RangesDual",
	} {
		for _, count := range []int{0, 1, 2, 16, 256, 4096} {
			t.Run(fmt.Sprintf("%s/%d", shape, count), func(t *testing.T) {
				input := addressSetCorpus(shape, count)
				s, err := buildSet(input)
				require.NoError(t, err)
				ref, err := buildIPSet(input)
				require.NoError(t, err)
				raw, err := buildBART(input)
				require.NoError(t, err)
				require.True(
					t,
					slices.Equal(ref.Prefixes(), slices.Collect(s.Prefixes())),
				)
				require.True(
					t,
					slices.Equal(ref.Prefixes(), slices.Collect(raw.AllSorted())),
				)
			})
		}
	}

	var input addressSetInput
	for _, text := range []string{
		"10.0.0.0/25", "10.0.0.128/25",
		"255.255.255.255/32", "::ffff:192.0.2.1/128", "fe80::/64",
		"ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128",
	} {
		input.prefixes = append(input.prefixes, netip.MustParsePrefix(text))
	}

	a, err := buildIPSet(input)
	require.NoError(t, err)
	raw, err := buildBART(input)
	require.NoError(t, err)
	s, err := buildSet(input)
	require.NoError(t, err)

	for _, addr := range []netip.Addr{
		{},
		netip.MustParseAddr("fe80::1%eth0"),
		netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("::ffff:10.0.0.1"),
		netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("::ffff:192.0.2.1"),
		netip.MustParseAddr("255.255.255.255"),
		netip.MustParseAddr("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"),
	} {
		require.Equal(t, a.Contains(addr), containsBART(raw, addr))
		require.Equal(t, a.Contains(addr), s.Contains(addr))
	}

	for _, p := range []netip.Prefix{
		{},
		netip.MustParsePrefix("10.0.0.0/24"),
		netip.MustParsePrefix("10.0.0.0/23"), netip.MustParsePrefix("::/0"),
	} {
		require.Equal(t, a.ContainsPrefix(p), raw.LookupPrefix(p))
		require.Equal(t, a.OverlapsPrefix(p), raw.OverlapsPrefix(p))
	}

	other := addressSetInput{prefixes: []netip.Prefix{
		netip.MustParsePrefix("10.0.0.64/26"), netip.MustParsePrefix("192.0.2.0/24"),
		netip.MustParsePrefix("::/0"),
	}}
	b, err := buildIPSet(other)
	require.NoError(t, err)
	rawB, err := buildBART(other)
	require.NoError(t, err)

	for _, op := range []string{"union", "intersect", "subtract"} {
		var builder netipx.IPSetBuilder
		builder.AddSet(a)

		var result *bart.Lite

		switch op {
		case "union":
			builder.AddSet(b)

			result = unionBART(raw, rawB)
		case "intersect":
			builder.Intersect(b)

			result = intersectBART(raw, rawB)
		case "subtract":
			builder.RemoveSet(b)

			result = subtractBART(raw, rawB)
		}

		want, err := builder.IPSet()
		require.NoError(t, err)
		require.True(
			t,
			slices.Equal(want.Prefixes(), slices.Collect(result.AllSorted())),
			op,
		)
	}

	require.True(t, slices.Equal(a.Prefixes(), slices.Collect(raw.AllSorted())))
	require.True(t, slices.Equal(b.Prefixes(), slices.Collect(rawB.AllSorted())))
}

// BenchmarkAddressSets is the full comparison matrix. Filter subbenchmark names
// for warm samples; run repeated candidates sequentially, never with RunParallel.
func BenchmarkAddressSets(b *testing.B) {
	for _, shape := range []string{
		"SparseV4", "SparseV6", "SparseDual",
		"DenseV4", "OverlapV4", "RangesDual",
	} {
		for _, count := range []int{0, 1, 2, 16, 256, 4096, 16384} {
			if count == 16384 && shape != "SparseDual" {
				continue
			}

			b.Run(fmt.Sprintf("%s/%d", shape, count), func(b *testing.B) {
				input := addressSetCorpus(shape, count)
				benchmarkAddressSets(b, input)
			})
		}
	}
}

//nolint:gocyclo // Separate concrete backend loops avoid benchmark dispatch overhead.
func benchmarkAddressSets(b *testing.B, input addressSetInput) {
	b.Helper()

	s, err := buildSet(input)
	require.NoError(b, err)
	ref, err := buildIPSet(input)
	require.NoError(b, err)
	raw, err := buildBART(input)
	require.NoError(b, err)
	// Fail semantic mismatches before starting any timer.
	require.True(b, slices.Equal(ref.Prefixes(), slices.Collect(s.Prefixes())))
	require.True(b, slices.Equal(ref.Prefixes(), slices.Collect(raw.AllSorted())))

	update := netip.MustParsePrefix("198.51.100.1/32")

	b.Run("Build/IPSet", func(b *testing.B) {
		b.ReportAllocs()

		for b.Loop() {
			var err error

			benchIPSet, err = buildIPSet(input)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("Build/BART", func(b *testing.B) {
		b.ReportAllocs()

		for b.Loop() {
			var err error

			benchBART, err = buildBART(input)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("Build/Set", func(b *testing.B) {
		b.ReportAllocs()

		for b.Loop() {
			var err error

			benchSet, err = buildSet(input)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	misses := []netip.Addr{
		netip.MustParseAddr("203.0.113.1"),
		netip.MustParseAddr("2001:db9::1"),
	}

	var hits []netip.Addr

	prefixes := ref.Prefixes()
	if len(prefixes) > 0 {
		for i := range 64 {
			hits = append(hits, prefixes[i*len(prefixes)/64].Addr())
		}
	}

	for _, name := range []string{"ContainsHit", "ContainsMiss", "ContainsMixed"} {
		queries := misses

		if name != "ContainsMiss" {
			if len(hits) == 0 {
				continue
			}

			queries = hits
			if name == "ContainsMixed" {
				queries = nil
				for i, hit := range hits {
					queries = append(queries, hit, misses[i%2])
				}
			}
		}

		b.Run(name+"/IPSet", func(b *testing.B) {
			b.ReportAllocs()

			i := 0
			for b.Loop() {
				benchBool = ref.Contains(queries[i%len(queries)])
				i++
			}
		})
		b.Run(name+"/BART", func(b *testing.B) {
			b.ReportAllocs()

			i := 0
			for b.Loop() {
				benchBool = containsBART(raw, queries[i%len(queries)])
				i++
			}
		})
		b.Run(name+"/Set", func(b *testing.B) {
			b.ReportAllocs()

			i := 0
			for b.Loop() {
				benchBool = s.Contains(queries[i%len(queries)])
				i++
			}
		})
	}

	for _, name := range []string{"CoverageHit", "CoverageMiss", "OverlapPrefix"} {
		p := update

		if name != "CoverageMiss" {
			if len(prefixes) == 0 {
				continue
			}

			p = prefixes[len(prefixes)/2]
			if name == "OverlapPrefix" && p.Bits() > 0 {
				p = netip.PrefixFrom(p.Addr(), p.Bits()-1)
			}
		}

		b.Run(name+"/IPSet", func(b *testing.B) {
			b.ReportAllocs()

			if name == "OverlapPrefix" {
				for b.Loop() {
					benchBool = ref.OverlapsPrefix(p)
				}
			} else {
				for b.Loop() {
					benchBool = ref.ContainsPrefix(p)
				}
			}
		})
		b.Run(name+"/BART", func(b *testing.B) {
			b.ReportAllocs()

			if name == "OverlapPrefix" {
				for b.Loop() {
					benchBool = raw.OverlapsPrefix(p)
				}
			} else {
				for b.Loop() {
					benchBool = raw.LookupPrefix(p)
				}
			}
		})
		b.Run(name+"/Set", func(b *testing.B) {
			b.ReportAllocs()

			if name == "OverlapPrefix" {
				for b.Loop() {
					benchBool = s.OverlapsPrefix(p)
				}
			} else {
				for b.Loop() {
					benchBool = s.ContainsPrefix(p)
				}
			}
		})
	}

	for _, name := range []string{"Iterate", "Hash"} {
		b.Run(name+"/IPSet", func(b *testing.B) {
			b.ReportAllocs()

			if name == "Hash" {
				for b.Loop() {
					h := uint64(14695981039346656037)
					for _, p := range ref.Prefixes() {
						h = hashPrefix(h, p)
					}

					benchUint64 = h
				}
			} else {
				for b.Loop() {
					var n uint64
					for _, p := range ref.Prefixes() {
						n += uint64(
							p.Bits(),
						) // #nosec G115 -- Canonical prefix lengths are nonnegative.
					}

					benchUint64 = n
				}
			}
		})
		b.Run(name+"/BART", func(b *testing.B) {
			b.ReportAllocs()

			if name == "Hash" {
				for b.Loop() {
					h := uint64(14695981039346656037)
					for p := range raw.AllSorted() {
						h = hashPrefix(h, p)
					}

					benchUint64 = h
				}
			} else {
				for b.Loop() {
					var n uint64
					for p := range raw.AllSorted() {
						n += uint64(
							p.Bits(),
						) // #nosec G115 -- Canonical prefix lengths are nonnegative.
					}

					benchUint64 = n
				}
			}
		})
		b.Run(name+"/Set", func(b *testing.B) {
			b.ReportAllocs()

			if name == "Hash" {
				for b.Loop() {
					h := uint64(14695981039346656037)
					for p := range s.Prefixes() {
						h = hashPrefix(h, p)
					}

					benchUint64 = h
				}
			} else {
				for b.Loop() {
					var n uint64
					for p := range s.Prefixes() {
						n += uint64(
							p.Bits(),
						) // #nosec G115 -- Canonical prefix lengths are nonnegative.
					}

					benchUint64 = n
				}
			}
		})
	}

	b.Run("CloneUpdate/IPSet", func(b *testing.B) {
		b.ReportAllocs()

		for b.Loop() {
			var builder netipx.IPSetBuilder
			builder.AddSet(ref)
			builder.AddPrefix(update)

			var err error

			benchIPSet, err = builder.IPSet()
			if err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("CloneUpdate/BART", func(b *testing.B) {
		b.ReportAllocs()

		for b.Loop() {
			benchBART = raw.Clone()
			benchBART.Insert(update)
			benchBART.Aggregate()
		}
	})
	b.Run("CloneUpdate/Set", func(b *testing.B) {
		b.ReportAllocs()

		for b.Loop() {
			var builder Builder
			builder.AddSet(s)
			builder.AddPrefix(update)

			var err error

			benchSet, err = builder.Build()
			if err != nil {
				b.Fatal(err)
			}
		}
	})
	benchmarkSetAlgebra(b, input)
}

func BenchmarkSetAlgebra(b *testing.B) {
	for _, shape := range []string{"SparseDual", "DenseV4", "RangesDual"} {
		for _, count := range []int{0, 1, 2, 16, 256, 4096} {
			b.Run(fmt.Sprintf("%s/%d", shape, count), func(b *testing.B) {
				benchmarkSetAlgebra(b, addressSetCorpus(shape, count))
			})
		}
	}
}

//nolint:gocyclo // Separate concrete backend loops avoid benchmark dispatch overhead.
func benchmarkSetAlgebra(b *testing.B, input addressSetInput) {
	b.Helper()

	s, err := buildSet(input)
	require.NoError(b, err)
	ref, err := buildIPSet(input)
	require.NoError(b, err)
	raw, err := buildBART(input)
	require.NoError(b, err)
	// Half the source entries overlap, plus one disjoint entry. Equal compares
	// independent equal publications, while EqualShared measures actual sharing.
	other := addressSetInput{
		prefixes: slices.Clone(input.prefixes[:len(input.prefixes)/2]),
		ranges:   slices.Clone(input.ranges[:len(input.ranges)/2]),
	}

	other.prefixes = append(other.prefixes, netip.MustParsePrefix("198.51.100.1/32"))
	for _, name := range []string{"Union", "Intersect", "Subtract", "Overlap", "Equal", "EqualShared"} {
		right := other
		if name == "Equal" || name == "EqualShared" {
			right = input
		}

		sr, err := buildSet(right)
		require.NoError(b, err)
		rr, err := buildIPSet(right)
		require.NoError(b, err)
		br, err := buildBART(right)
		require.NoError(b, err)

		if name == "EqualShared" {
			sr, rr, br = s, ref, raw
		}

		b.Run(name+"/IPSet", func(b *testing.B) {
			b.ReportAllocs()

			switch name {
			case "Equal", "EqualShared":
				for b.Loop() {
					benchBool = ref.Equal(rr)
				}
			case "Overlap":
				for b.Loop() {
					benchBool = ref.Overlaps(rr)
				}
			case "Union":
				for b.Loop() {
					var builder netipx.IPSetBuilder
					builder.AddSet(ref)
					builder.AddSet(rr)

					var err error

					benchIPSet, err = builder.IPSet()
					if err != nil {
						b.Fatal(err)
					}
				}
			case "Intersect":
				for b.Loop() {
					var builder netipx.IPSetBuilder
					builder.AddSet(ref)
					builder.Intersect(rr)

					var err error

					benchIPSet, err = builder.IPSet()
					if err != nil {
						b.Fatal(err)
					}
				}
			case "Subtract":
				for b.Loop() {
					var builder netipx.IPSetBuilder
					builder.AddSet(ref)
					builder.RemoveSet(rr)

					var err error

					benchIPSet, err = builder.IPSet()
					if err != nil {
						b.Fatal(err)
					}
				}
			}
		})
		b.Run(name+"/BART", func(b *testing.B) {
			b.ReportAllocs()

			switch name {
			case "Union":
				for b.Loop() {
					benchBART = unionBART(raw, br)
				}
			case "Intersect":
				for b.Loop() {
					benchBART = intersectBART(raw, br)
				}
			case "Subtract":
				for b.Loop() {
					benchBART = subtractBART(raw, br)
				}
			case "Overlap":
				for b.Loop() {
					benchBool = raw.Overlaps(br)
				}
			case "Equal", "EqualShared":
				for b.Loop() {
					benchBool = raw.Equal(br)
				}
			}
		})
		b.Run(name+"/Set", func(b *testing.B) {
			b.ReportAllocs()

			switch name {
			case "Union":
				for b.Loop() {
					benchSet = s.Union(sr)
				}
			case "Intersect":
				for b.Loop() {
					benchSet = s.Intersect(sr)
				}
			case "Subtract":
				for b.Loop() {
					benchSet = s.Subtract(sr)
				}
			case "Overlap":
				for b.Loop() {
					benchBool = s.Overlaps(sr)
				}
			case "Equal", "EqualShared":
				for b.Loop() {
					benchBool = s.Equal(sr)
				}
			}
		})
	}
}

func BenchmarkSetConstruction(b *testing.B) {
	// Identical resolved inputs and fragment boundaries; no parsing or alias cache
	// differs between shared accumulation and publication of each local fragment.
	for _, count := range []int{1, 16, 256, 4096} {
		input := addressSetCorpus("SparseDual", count)
		for _, strategy := range []string{"SharedBuilder", "LocalBuilders"} {
			b.Run(fmt.Sprintf("%d/%s/IPSet", count, strategy), func(b *testing.B) {
				b.ReportAllocs()

				for b.Loop() {
					var acc netipx.IPSetBuilder

					for group := range slices.Chunk(input.prefixes, 16) {
						if strategy == "SharedBuilder" {
							for _, p := range group {
								acc.AddPrefix(p)
							}
						} else {
							local, err := buildIPSet(addressSetInput{prefixes: group})
							if err != nil {
								b.Fatal(err)
							}

							acc.AddSet(local)
						}
					}

					var err error

					benchIPSet, err = acc.IPSet()
					if err != nil {
						b.Fatal(err)
					}
				}
			})
			b.Run(fmt.Sprintf("%d/%s/BART", count, strategy), func(b *testing.B) {
				b.ReportAllocs()

				for b.Loop() {
					acc := new(bart.Lite)

					for group := range slices.Chunk(input.prefixes, 16) {
						if strategy == "SharedBuilder" {
							for _, p := range group {
								if !p.IsValid() {
									b.Fatal("invalid prefix")
								}

								acc.Insert(p)
							}
						} else {
							local, err := buildBART(addressSetInput{prefixes: group})
							if err != nil {
								b.Fatal(err)
							}

							acc.Union(local)
						}
					}

					acc.Aggregate()
					benchBART = acc
				}
			})
			b.Run(fmt.Sprintf("%d/%s/Set", count, strategy), func(b *testing.B) {
				b.ReportAllocs()

				for b.Loop() {
					var acc Builder

					for group := range slices.Chunk(input.prefixes, 16) {
						if strategy == "SharedBuilder" {
							for _, p := range group {
								acc.AddPrefix(p)
							}
						} else {
							local, err := buildSet(addressSetInput{prefixes: group})
							if err != nil {
								b.Fatal(err)
							}

							acc.AddSet(local)
						}
					}

					var err error

					benchSet, err = acc.Build()
					if err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
}

func heapBytes() int64 {
	var stats runtime.MemStats
	runtime.ReadMemStats(&stats)

	return int64(
		stats.HeapAlloc,
	) // #nosec G115 -- These bounded fixtures retain far less than MaxInt64 bytes.
}

func reportGenerationHeap(b *testing.B, count int, samples [5]int64) {
	b.Helper()
	b.ReportMetric(float64(count), "collections")

	for i, name := range []string{"live-B/set", "update-heap-B/set", "replaced-B/set", "released-B/set"} {
		b.ReportMetric(float64(samples[i+1]-samples[0])/float64(count), name)
	}
}

// BenchmarkAddressSetGenerations measures actual retained heap after GC with
// many live collections. update-heap is the observed heap with both generations
// alive before GC, not an allocator high-water guarantee. Use -benchtime=1x;
// ns/op includes forced GC and is not a construction timing.
func BenchmarkAddressSetGenerations(b *testing.B) {
	for _, shape := range []string{"SparseDual", "DenseV4", "RangesDual"} {
		for _, count := range []int{0, 1, 16, 256, 4096} {
			input := addressSetCorpus(shape, count)

			live := 4096
			if count >= 256 {
				live = 128
			}

			b.Run(fmt.Sprintf("%s/%d/IPSet", shape, count), func(b *testing.B) {
				for b.Loop() {
					benchIPSet, benchBART, benchSet = nil, nil, Set{}

					runtime.GC()

					var samples [5]int64

					samples[0] = heapBytes()
					old := make([]*netipx.IPSet, live)

					benchIPSetRoots[0] = old
					for i := range old {
						var err error

						old[i], err = buildIPSet(input)
						if err != nil {
							b.Fatal(err)
						}
					}

					runtime.GC()

					samples[1] = heapBytes()
					next := make([]*netipx.IPSet, live)

					benchIPSetRoots[1] = next
					for i := range next {
						var builder netipx.IPSetBuilder
						builder.AddSet(old[i])
						builder.AddPrefix(netip.PrefixFrom(netip.IPv6Loopback(), 128))

						var err error

						next[i], err = builder.IPSet()
						if err != nil {
							b.Fatal(err)
						}
					}

					samples[2] = heapBytes()

					runtime.KeepAlive(old)

					benchIPSetRoots[0] = nil

					runtime.GC()

					samples[3] = heapBytes()

					runtime.KeepAlive(next)

					benchIPSetRoots[1] = nil

					runtime.GC()

					samples[4] = heapBytes()
					reportGenerationHeap(b, live, samples)
				}
			})
			b.Run(fmt.Sprintf("%s/%d/BART", shape, count), func(b *testing.B) {
				for b.Loop() {
					benchIPSet, benchBART, benchSet = nil, nil, Set{}

					runtime.GC()

					var samples [5]int64

					samples[0] = heapBytes()
					old := make([]*bart.Lite, live)

					benchBARTRoots[0] = old
					for i := range old {
						var err error

						old[i], err = buildBART(input)
						if err != nil {
							b.Fatal(err)
						}
					}

					runtime.GC()

					samples[1] = heapBytes()
					next := make([]*bart.Lite, live)

					benchBARTRoots[1] = next
					for i := range next {
						next[i] = old[i].Clone()
						next[i].Insert(netip.PrefixFrom(netip.IPv6Loopback(), 128))
						next[i].Aggregate()
					}

					samples[2] = heapBytes()

					runtime.KeepAlive(old)

					benchBARTRoots[0] = nil

					runtime.GC()

					samples[3] = heapBytes()

					runtime.KeepAlive(next)

					benchBARTRoots[1] = nil

					runtime.GC()

					samples[4] = heapBytes()
					reportGenerationHeap(b, live, samples)
				}
			})
			b.Run(fmt.Sprintf("%s/%d/Set", shape, count), func(b *testing.B) {
				for b.Loop() {
					benchIPSet, benchBART, benchSet = nil, nil, Set{}

					runtime.GC()

					var samples [5]int64

					samples[0] = heapBytes()
					old := make([]Set, live)

					benchSetRoots[0] = old
					for i := range old {
						var err error

						old[i], err = buildSet(input)
						if err != nil {
							b.Fatal(err)
						}
					}

					runtime.GC()

					samples[1] = heapBytes()
					next := make([]Set, live)

					benchSetRoots[1] = next
					for i := range next {
						var builder Builder
						builder.AddSet(old[i])
						builder.AddPrefix(netip.PrefixFrom(netip.IPv6Loopback(), 128))

						var err error

						next[i], err = builder.Build()
						if err != nil {
							b.Fatal(err)
						}
					}

					samples[2] = heapBytes()

					runtime.KeepAlive(old)

					benchSetRoots[0] = nil

					runtime.GC()

					samples[3] = heapBytes()

					runtime.KeepAlive(next)

					benchSetRoots[1] = nil

					runtime.GC()

					samples[4] = heapBytes()
					reportGenerationHeap(b, live, samples)
				}
			})
		}
	}
}

// These review cases are separate from the original matrix so its running
// baseline measurements keep the same benchmark names, inputs, and operations.
func interiorAddressSetInput(family, shape string, count int) addressSetInput {
	var input addressSetInput

	for i := range count {
		n := uint32(i*256 + 64)

		addr := netip.AddrFrom4(
			[4]byte{10, byte((n >> 16) & 0xff), byte((n >> 8) & 0xff), byte(n & 0xff)},
		)
		if family == "IPv6" {
			addr = netip.AddrFrom16([16]byte{
				0x20,
				1,
				0xd,
				0xb8,
				12: byte(
					(n >> 24) & 0xff,
				),
				13: byte((n >> 16) & 0xff),
				14: byte((n >> 8) & 0xff),
				15: byte(n & 0xff),
			})
		}

		switch shape {
		case "Sparse":
			input.prefixes = append(
				input.prefixes,
				netip.PrefixFrom(addr, addr.BitLen()),
			)
		case "Prefixes":
			input.prefixes = append(
				input.prefixes,
				netip.PrefixFrom(addr, addr.BitLen()-2),
			)
		case "Ranges":
			r, err := iprange.FromAddrs(addr.Next(), addr.Next().Next().Next())
			if err != nil {
				panic(err)
			}

			input.ranges = append(input.ranges, r)
		default:
			panic("unknown interior fixture shape")
		}
	}

	return input
}

func checkedInteriorCandidates(
	b *testing.B,
	input addressSetInput,
) (Set, *netipx.IPSet, *bart.Lite) {
	b.Helper()

	s, err := buildSet(input)
	require.NoError(b, err)
	ref, err := buildIPSet(input)
	require.NoError(b, err)
	raw, err := buildBART(input)
	require.NoError(b, err)
	require.True(b, slices.Equal(ref.Prefixes(), slices.Collect(s.Prefixes())))
	require.True(b, slices.Equal(ref.Prefixes(), slices.Collect(raw.AllSorted())))

	return s, ref, raw
}

func BenchmarkAddressSetInteriorMisses(b *testing.B) {
	for _, shape := range []string{"Sparse", "Ranges"} {
		for _, family := range []string{"IPv4", "IPv6"} {
			for _, count := range []int{16, 256, 4096} {
				b.Run(
					fmt.Sprintf("%s/%s/%d", shape, family, count),
					func(b *testing.B) {
						input := interiorAddressSetInput(family, shape, count)
						s, ref, raw := checkedInteriorCandidates(b, input)
						ranges := ref.Ranges()
						require.Len(b, ranges, count)
						queries := make([]netip.Addr, 0, count-1)

						for i, r := range ranges[:len(ranges)-1] {
							query := r.To().Next()
							// Each miss lies between live intervals in populated branches.
							require.True(b, r.To().Less(query))
							require.True(b, query.Less(ranges[i+1].From()))
							require.Equal(b, family == "IPv4", query.Is4())
							require.True(b, s.Contains(r.To()))
							require.True(b, ref.Contains(r.To()))
							require.True(b, containsBART(raw, r.To()))
							require.False(b, s.Contains(query))
							require.False(b, ref.Contains(query))
							require.False(b, containsBART(raw, query))
							queries = append(queries, query)
						}

						b.Run("IPSet", func(b *testing.B) {
							b.ReportAllocs()

							i := 0
							for b.Loop() {
								benchBool = ref.Contains(queries[i%len(queries)])
								i++
							}
						})
						b.Run("BART", func(b *testing.B) {
							b.ReportAllocs()

							i := 0
							for b.Loop() {
								benchBool = containsBART(raw, queries[i%len(queries)])
								i++
							}
						})
						b.Run("Set", func(b *testing.B) {
							b.ReportAllocs()

							i := 0
							for b.Loop() {
								benchBool = s.Contains(queries[i%len(queries)])
								i++
							}
						})
					},
				)
			}
		}
	}
}

func BenchmarkAddressSetDisjointOverlap(b *testing.B) {
	for _, shape := range []string{"Sparse", "Ranges"} {
		for _, family := range []string{"IPv4", "IPv6"} {
			for _, count := range []int{256, 4096} {
				b.Run(
					fmt.Sprintf("%s/%s/%d", shape, family, count),
					func(b *testing.B) {
						input := interiorAddressSetInput(family, shape, count)

						var other addressSetInput
						for _, p := range input.prefixes {
							other.prefixes = append(other.prefixes,
								netip.PrefixFrom(p.Addr().Next(), p.Bits()))
						}

						for _, r := range input.ranges {
							_, last := r.Addrs()
							next, err := iprange.FromAddrs(
								last.Next(),
								last.Next().Next().Next(),
							)
							require.NoError(b, err)

							other.ranges = append(other.ranges, next)
						}

						s, ref, raw := checkedInteriorCandidates(b, input)
						sr, rr, br := checkedInteriorCandidates(b, other)
						require.False(b, s.IsEmpty())
						require.False(b, sr.IsEmpty())
						require.Len(b, ref.Ranges(), count)
						require.Len(b, rr.Ranges(), count)
						require.False(b, s.Overlaps(sr))
						require.False(b, ref.Overlaps(rr))
						require.False(b, raw.Overlaps(br))
						b.Run("IPSet", func(b *testing.B) {
							b.ReportAllocs()

							for b.Loop() {
								benchBool = ref.Overlaps(rr)
							}
						})
						b.Run("BART", func(b *testing.B) {
							b.ReportAllocs()

							for b.Loop() {
								benchBool = raw.Overlaps(br)
							}
						})
						b.Run("Set", func(b *testing.B) {
							b.ReportAllocs()

							for b.Loop() {
								benchBool = s.Overlaps(sr)
							}
						})
					},
				)
			}
		}
	}
}

func BenchmarkAddressSetInteriorSubtraction(b *testing.B) {
	for _, shape := range []string{"Prefixes", "Ranges"} {
		for _, family := range []string{"IPv4", "IPv6"} {
			for _, count := range []int{1, 16, 256, 4096} {
				b.Run(
					fmt.Sprintf("%s/%s/%d", shape, family, count),
					func(b *testing.B) {
						prefix := netip.MustParsePrefix("10.0.0.0/8")
						if family == "IPv6" {
							prefix = netip.MustParsePrefix("2001:db8::/96")
						}

						s, ref, raw := checkedInteriorCandidates(b,
							addressSetInput{prefixes: []netip.Prefix{prefix}})
						exclusions := interiorAddressSetInput(family, shape, count)
						sr, rr, br := checkedInteriorCandidates(b, exclusions)
						require.Len(b, rr.Ranges(), count)
						require.True(b, s.ContainsSet(sr))
						require.False(b, sr.ContainsPrefix(prefix))

						var builder netipx.IPSetBuilder
						builder.AddSet(ref)
						builder.RemoveSet(rr)
						want, err := builder.IPSet()
						require.NoError(b, err)

						got, rawResult := s.Subtract(sr), subtractBART(raw, br)
						require.True(
							b,
							slices.Equal(
								want.Prefixes(),
								slices.Collect(got.Prefixes()),
							),
						)
						require.True(
							b,
							slices.Equal(
								want.Prefixes(),
								slices.Collect(rawResult.AllSorted()),
							),
						)
						require.False(b, got.IsEmpty())
						require.False(b, got.Equal(s))
						require.False(b, got.Overlaps(sr))
						require.Greater(b, len(want.Prefixes()), 1)

						first, last := extnetip.Range(prefix)
						require.True(b, got.Contains(first))
						require.True(b, got.Contains(last))

						for _, r := range rr.Ranges() {
							require.True(b, first.Less(r.From()))
							require.True(b, r.To().Less(last))
							require.True(b, got.Contains(r.From().Prev()))
							require.True(b, got.Contains(r.To().Next()))
						}
						// Ownership and canonical source data must survive the validation run.
						require.True(
							b,
							slices.Equal(ref.Prefixes(), slices.Collect(s.Prefixes())),
						)
						require.True(
							b,
							slices.Equal(
								ref.Prefixes(),
								slices.Collect(raw.AllSorted()),
							),
						)
						require.True(
							b,
							slices.Equal(rr.Prefixes(), slices.Collect(sr.Prefixes())),
						)
						require.True(
							b,
							slices.Equal(rr.Prefixes(), slices.Collect(br.AllSorted())),
						)
						b.Run("IPSet", func(b *testing.B) {
							b.ReportAllocs()

							for b.Loop() {
								var builder netipx.IPSetBuilder
								builder.AddSet(ref)
								builder.RemoveSet(rr)

								var err error

								benchIPSet, err = builder.IPSet()
								if err != nil {
									b.Fatal(err)
								}
							}
						})
						b.Run("BART", func(b *testing.B) {
							b.ReportAllocs()

							for b.Loop() {
								benchBART = subtractBART(raw, br)
							}
						})
						b.Run("Set", func(b *testing.B) {
							b.ReportAllocs()

							for b.Loop() {
								benchSet = s.Subtract(sr)
							}
						})
					},
				)
			}
		}
	}
}
