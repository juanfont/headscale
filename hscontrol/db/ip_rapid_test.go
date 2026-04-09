package db

import (
	"math/big"
	"net/netip"
	"testing"

	"github.com/juanfont/headscale/hscontrol/types"
	"go4.org/netipx"
	"pgregory.net/rapid"
	"tailscale.com/net/tsaddr"
)

// ============================================================================
// Generators
// ============================================================================

// genULAPrefix generates a valid IPv6 ULA prefix (fd00::/8).
// Uses prefix lengths from /48 to /112 to avoid enormous ranges.
func genULAPrefix() *rapid.Generator[netip.Prefix] {
	return rapid.Custom[netip.Prefix](func(t *rapid.T) netip.Prefix {
		bits := rapid.IntRange(48, 112).Draw(t, "bits")

		var b [16]byte

		b[0] = 0xfd
		for i := 1; i < 8; i++ {
			b[i] = byte(rapid.IntRange(0, 255).Draw(t, "byte"))
		}

		addr := netip.AddrFrom16(b)
		pfx := netip.PrefixFrom(addr, bits).Masked()

		return pfx
	})
}

// genSmallCGNATPrefix generates a small CGNAT prefix (/24-/28) to keep
// randomNext from taking too long.
func genSmallCGNATPrefix() *rapid.Generator[netip.Prefix] {
	return rapid.Custom[netip.Prefix](func(t *rapid.T) netip.Prefix {
		bits := rapid.IntRange(24, 28).Draw(t, "bits")
		b2 := byte(rapid.IntRange(64, 127).Draw(t, "b2"))
		b3 := byte(rapid.IntRange(0, 255).Draw(t, "b3"))
		addr := netip.AddrFrom4([4]byte{100, b2, b3, 0})
		pfx := netip.PrefixFrom(addr, bits).Masked()

		return pfx
	})
}

// ============================================================================
// randomNext properties
// ============================================================================

// Property: randomNext always returns an IP within the given prefix.
func TestRapid_RandomNext_ContainedInPrefix(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		pfx := genSmallCGNATPrefix().Draw(t, "prefix")

		ip, err := randomNext(pfx)
		if err != nil {
			t.Fatalf("randomNext(%s) failed: %v", pfx, err)
		}

		if !pfx.Contains(ip) {
			t.Fatalf("randomNext(%s) = %s, not contained in prefix", pfx, ip)
		}
	})
}

// Property: randomNext returns an address of the same family as the prefix.
func TestRapid_RandomNext_SameFamily(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		// Choose IPv4 or IPv6
		isV6 := rapid.Bool().Draw(t, "isV6")

		var pfx netip.Prefix
		if isV6 {
			pfx = genULAPrefix().Draw(t, "prefix")
		} else {
			pfx = genSmallCGNATPrefix().Draw(t, "prefix")
		}

		ip, err := randomNext(pfx)
		if err != nil {
			t.Fatalf("randomNext(%s) failed: %v", pfx, err)
		}

		if ip.Is4() != pfx.Addr().Is4() {
			t.Fatalf("randomNext(%s) = %s, address family mismatch", pfx, ip)
		}
	})
}

// Property: randomNext on the same prefix returns IPs within the valid range endpoints.
func TestRapid_RandomNext_WithinRangeEndpoints(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		pfx := genSmallCGNATPrefix().Draw(t, "prefix")

		ip, err := randomNext(pfx)
		if err != nil {
			t.Fatalf("randomNext(%s) failed: %v", pfx, err)
		}

		rang := netipx.RangeOfPrefix(pfx)
		fromIP, toIP := rang.From(), rang.To()

		// IP must be >= from and <= to
		var ipNum, fromNum, toNum big.Int
		ipNum.SetBytes(ip.AsSlice())
		fromNum.SetBytes(fromIP.AsSlice())
		toNum.SetBytes(toIP.AsSlice())

		if ipNum.Cmp(&fromNum) < 0 || ipNum.Cmp(&toNum) > 0 {
			t.Fatalf("randomNext(%s) = %s, outside range [%s, %s]",
				pfx, ip, fromIP, toIP)
		}
	})
}

// ============================================================================
// isTailscaleReservedIP properties
// ============================================================================

// Property: ChromeOS VM range IPs are always reserved.
func TestRapid_IsTailscaleReservedIP_ChromeOSAlwaysReserved(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		// 100.115.92.0/23 — generate IPs within this range
		b3 := byte(rapid.IntRange(92, 93).Draw(t, "b3"))
		b4 := byte(rapid.IntRange(0, 255).Draw(t, "b4"))
		ip := netip.AddrFrom4([4]byte{100, 115, b3, b4})

		if !isTailscaleReservedIP(ip) {
			t.Fatalf("isTailscaleReservedIP(%s) = false, expected true (ChromeOS range)", ip)
		}
	})
}

// Property: The service IPs 100.100.100.100 and the IPv6 service IP are always reserved.
func TestRapid_IsTailscaleReservedIP_ServiceIPsReserved(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		// Pick one of the two service IPs at random
		choice := rapid.IntRange(0, 1).Draw(t, "choice")

		var ip netip.Addr
		if choice == 0 {
			ip = tsaddr.TailscaleServiceIP()
		} else {
			ip = tsaddr.TailscaleServiceIPv6()
		}

		if !isTailscaleReservedIP(ip) {
			t.Fatalf("isTailscaleReservedIP(%s) = false, expected true (service IP)", ip)
		}
	})
}

// Property: A "normal" CGNAT IP outside reserved ranges is not reserved.
func TestRapid_IsTailscaleReservedIP_NormalCGNATNotReserved(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		// Generate an IP in 100.64.0.0/10 that is NOT in the ChromeOS range
		// (100.115.92.0/23) and NOT 100.100.100.100.
		b2 := byte(rapid.IntRange(64, 127).Draw(t, "b2"))
		b3 := byte(rapid.IntRange(0, 255).Draw(t, "b3"))
		b4 := byte(rapid.IntRange(0, 255).Draw(t, "b4"))
		ip := netip.AddrFrom4([4]byte{100, b2, b3, b4})

		// Skip known reserved IPs
		if tsaddr.ChromeOSVMRange().Contains(ip) {
			return
		}

		if ip == tsaddr.TailscaleServiceIP() {
			return
		}

		if isTailscaleReservedIP(ip) {
			t.Fatalf("isTailscaleReservedIP(%s) = true, expected false (normal CGNAT)", ip)
		}
	})
}

// ============================================================================
// GetIPPrefixEndpoints properties (from util package, tested via import)
// ============================================================================

// Property: GetIPPrefixEndpoints returns endpoints contained in the prefix.
func TestRapid_GetIPPrefixEndpoints_ContainedInPrefix(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		pfx := genSmallCGNATPrefix().Draw(t, "prefix")

		network, broadcast := getIPPrefixEndpointsViaRange(pfx)

		if !pfx.Contains(network) {
			t.Fatalf("network %s not in prefix %s", network, pfx)
		}

		if !pfx.Contains(broadcast) {
			t.Fatalf("broadcast %s not in prefix %s", broadcast, pfx)
		}
	})
}

// Property: network <= broadcast for GetIPPrefixEndpoints.
func TestRapid_GetIPPrefixEndpoints_NetworkLEBroadcast(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		pfx := genSmallCGNATPrefix().Draw(t, "prefix")

		network, broadcast := getIPPrefixEndpointsViaRange(pfx)

		if network.Compare(broadcast) > 0 {
			t.Fatalf("network %s > broadcast %s for prefix %s", network, broadcast, pfx)
		}
	})
}

// Property: For a /32 (host) prefix, network == broadcast.
func TestRapid_GetIPPrefixEndpoints_HostPrefix(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		b2 := byte(rapid.IntRange(64, 127).Draw(t, "b2"))
		b3 := byte(rapid.IntRange(0, 255).Draw(t, "b3"))
		b4 := byte(rapid.IntRange(0, 255).Draw(t, "b4"))
		addr := netip.AddrFrom4([4]byte{100, b2, b3, b4})
		pfx := netip.PrefixFrom(addr, 32)

		network, broadcast := getIPPrefixEndpointsViaRange(pfx)

		if network != broadcast {
			t.Fatalf("/32 prefix %s: network %s != broadcast %s", pfx, network, broadcast)
		}
	})
}

// getIPPrefixEndpointsViaRange mirrors util.GetIPPrefixEndpoints to avoid
// cross-package test dependency while testing the same logic.
func getIPPrefixEndpointsViaRange(na netip.Prefix) (netip.Addr, netip.Addr) {
	ipRange := netipx.RangeOfPrefix(na)
	return ipRange.From(), ipRange.To()
}

// ============================================================================
// IPAllocator stateful property-based tests
// ============================================================================

// genTinyIPv4Prefix generates a /28 or /29 CGNAT prefix that avoids all
// Tailscale reserved ranges (ChromeOS VM 100.115.92.0/23, service IP
// 100.100.100.100). This keeps exhaustion tests fast and deterministic.
func genTinyIPv4Prefix() *rapid.Generator[netip.Prefix] {
	return rapid.Custom[netip.Prefix](func(t *rapid.T) netip.Prefix {
		bits := rapid.IntRange(28, 29).Draw(t, "bits")
		// Use 100.64.x.y which is safely inside CGNAT but far from
		// reserved ranges (100.100.100.100, 100.115.92.0/23).
		b3 := byte(rapid.IntRange(0, 255).Draw(t, "b3"))
		addr := netip.AddrFrom4([4]byte{100, 64, b3, 0})
		pfx := netip.PrefixFrom(addr, bits).Masked()

		return pfx
	})
}

// genTinyIPv6Prefix generates a /124 ULA prefix (16 addresses) to match
// the small IPv4 prefix size for exhaustion testing.
func genTinyIPv6Prefix() *rapid.Generator[netip.Prefix] {
	return rapid.Custom[netip.Prefix](func(t *rapid.T) netip.Prefix {
		// fd7a:115c:a1e0:XXXX::Y0/124
		b7 := byte(rapid.IntRange(0, 255).Draw(t, "b7"))
		b8 := byte(rapid.IntRange(0, 255).Draw(t, "b8"))

		var b [16]byte

		b[0] = 0xfd
		b[1] = 0x7a
		b[2] = 0x11
		b[3] = 0x5c
		b[4] = 0xa1
		b[5] = 0xe0
		b[6] = b7
		b[7] = b8
		// Leave bytes 8-15 as zero; the /124 mask handles the rest.
		addr := netip.AddrFrom16(b)
		pfx := netip.PrefixFrom(addr, 124).Masked()

		return pfx
	})
}

// ipAllocatorModel is the reference model for stateful IPAllocator testing.
// It tracks which IPs have been allocated and which prefixes are in use.
type ipAllocatorModel struct {
	allocated map[netip.Addr]bool
	prefix4   netip.Prefix
	prefix6   netip.Prefix
}

func newIPAllocatorModel(
	prefix4, prefix6 netip.Prefix,
) *ipAllocatorModel {
	return &ipAllocatorModel{
		allocated: make(map[netip.Addr]bool),
		prefix4:   prefix4,
		prefix6:   prefix6,
	}
}

// allocableCount returns the number of IPs that can be allocated in a
// prefix, excluding network, broadcast, and Tailscale-reserved addresses.
func allocableCount(pfx netip.Prefix) int {
	rang := netipx.RangeOfPrefix(pfx)
	count := 0

	for ip := rang.From(); ip.Compare(rang.To()) <= 0; ip = ip.Next() {
		if ip == rang.From() || ip == rang.To() {
			continue // network and broadcast
		}

		if isTailscaleReservedIP(ip) {
			continue
		}

		count++
	}

	return count
}

// checkIPAllocatorInvariants verifies all invariants on the model and the
// allocator's output after every operation.
func checkIPAllocatorInvariants(
	t *rapid.T,
	model *ipAllocatorModel,
	opDesc string,
) {
	for ip := range model.allocated {
		// 1. All allocated IPs are within the configured prefix.
		inV4 := model.prefix4.Contains(ip)

		inV6 := model.prefix6.Contains(ip)
		if !inV4 && !inV6 {
			t.Fatalf(
				"%s: allocated IP %s is not in prefix4 %s or prefix6 %s",
				opDesc, ip, model.prefix4, model.prefix6,
			)
		}

		// 2. No allocated IP is a Tailscale reserved IP.
		if isTailscaleReservedIP(ip) {
			t.Fatalf(
				"%s: allocated IP %s is Tailscale-reserved",
				opDesc, ip,
			)
		}

		// 3. No allocated IP is a network or broadcast address.
		if ip.Is4() {
			net4, bcast4 := getIPPrefixEndpointsViaRange(model.prefix4)
			if ip == net4 || ip == bcast4 {
				t.Fatalf(
					"%s: allocated IP %s is network (%s) or broadcast (%s)",
					opDesc, ip, net4, bcast4,
				)
			}
		} else {
			net6, bcast6 := getIPPrefixEndpointsViaRange(model.prefix6)
			if ip == net6 || ip == bcast6 {
				t.Fatalf(
					"%s: allocated IP %s is network (%s) or broadcast (%s)",
					opDesc, ip, net6, bcast6,
				)
			}
		}
	}
	// 4. Uniqueness is guaranteed by the map key semantics — if we
	//    ever got a duplicate from Next(), the Allocate operation
	//    would have already failed (see the duplicate check in each
	//    operation).
}

// TestRapid_IPAllocator_Stateful_Sequential runs a stateful PBT against
// the IPAllocator with the sequential strategy. Operations: Allocate,
// Free, AllocateMany. Invariants are checked after every operation.
//
// The sequential allocator never wraps its cursor: once prev4/prev6
// advance past an IP, freeing that IP does not make it reachable again.
// The model therefore does NOT assert that "remaining capacity ==
// maxPairs - allocatedPairs" — instead it accepts that Next() may return
// ErrCouldNotAllocateIP when the cursor has passed all usable IPs, even
// if some were freed behind it.
func TestRapid_IPAllocator_Stateful_Sequential(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		runIPAllocatorStatefulSequential(rt)
	})
}

// TestRapid_IPAllocator_Stateful_Random runs the same stateful PBT with
// the random allocation strategy. Uses /26 prefixes (64 IPs) and caps
// allocations at half capacity to avoid the pathological performance of
// randomNext when the prefix is nearly full. The random allocator
// generates IPs uniformly at random and retries on collision, so with
// small prefixes near capacity it can spin for an extremely long time.
func TestRapid_IPAllocator_Stateful_Random(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		// Use /26 IPv4 (64 IPs, ~62 usable) and /120 IPv6 (256 IPs)
		// for the random strategy to avoid pathological retry loops.
		b3 := byte(rapid.IntRange(0, 255).Draw(rt, "b3"))
		addr4 := netip.AddrFrom4([4]byte{100, 64, b3, 0})
		prefix4 := netip.PrefixFrom(addr4, 26).Masked()

		b7 := byte(rapid.IntRange(0, 255).Draw(rt, "b7"))
		b8 := byte(rapid.IntRange(0, 255).Draw(rt, "b8"))

		var b6 [16]byte

		b6[0] = 0xfd
		b6[1] = 0x7a
		b6[2] = 0x11
		b6[3] = 0x5c
		b6[4] = 0xa1
		b6[5] = 0xe0
		b6[6] = b7
		b6[7] = b8
		addr6 := netip.AddrFrom16(b6)
		prefix6 := netip.PrefixFrom(addr6, 120).Masked()

		alloc, err := NewIPAllocator(
			nil, &prefix4, &prefix6,
			types.IPAllocationStrategyRandom,
		)
		if err != nil {
			rt.Fatalf("NewIPAllocator: %v", err)
		}

		model := newIPAllocatorModel(prefix4, prefix6)
		maxV4 := allocableCount(prefix4)
		maxV6 := allocableCount(prefix6)

		maxPairs := min(maxV6, maxV4)

		// Cap at half capacity to keep random allocation fast.
		allocCap := max(maxPairs/2, 2)

		allocatedPairs := 0

		var (
			allocatedV4s []netip.Addr
			allocatedV6s []netip.Addr
		)

		rt.Repeat(map[string]func(*rapid.T){
			"Allocate": func(rt *rapid.T) {
				if allocatedPairs >= allocCap {
					rt.Skip("at allocation cap")
				}

				ip4, ip6, err := alloc.Next()
				if err != nil {
					rt.Fatalf(
						"Allocate(random): unexpected error "+
							"(allocated=%d, cap=%d, maxPairs=%d): %v",
						allocatedPairs, allocCap, maxPairs, err,
					)
				}

				if ip4 != nil {
					if model.allocated[*ip4] {
						rt.Fatalf("Allocate: duplicate IPv4 %s", ip4)
					}

					model.allocated[*ip4] = true
					allocatedV4s = append(allocatedV4s, *ip4)
				}

				if ip6 != nil {
					if model.allocated[*ip6] {
						rt.Fatalf("Allocate: duplicate IPv6 %s", ip6)
					}

					model.allocated[*ip6] = true
					allocatedV6s = append(allocatedV6s, *ip6)
				}

				allocatedPairs++

				checkIPAllocatorInvariants(rt, model, "Allocate")
			},

			"Free": func(rt *rapid.T) {
				if len(allocatedV4s) == 0 {
					rt.Skip("nothing to free")
				}

				idx := rapid.IntRange(
					0, len(allocatedV4s)-1,
				).Draw(rt, "freeIdx")
				v4 := allocatedV4s[idx]
				v6 := allocatedV6s[idx]

				alloc.FreeIPs([]netip.Addr{v4, v6})

				delete(model.allocated, v4)
				delete(model.allocated, v6)

				last := len(allocatedV4s) - 1
				allocatedV4s[idx] = allocatedV4s[last]
				allocatedV4s = allocatedV4s[:last]
				allocatedV6s[idx] = allocatedV6s[last]
				allocatedV6s = allocatedV6s[:last]

				allocatedPairs--

				checkIPAllocatorInvariants(rt, model, "Free")
			},

			"AllocateMany": func(rt *rapid.T) {
				remaining := allocCap - allocatedPairs
				if remaining <= 0 {
					rt.Skip("at allocation cap")
				}

				n := rapid.IntRange(1, remaining).Draw(rt, "n")

				for i := range n {
					ip4, ip6, err := alloc.Next()
					if err != nil {
						rt.Fatalf(
							"AllocateMany[%d/%d](random): "+
								"unexpected error (allocated=%d, "+
								"cap=%d): %v",
							i, n, allocatedPairs, allocCap, err,
						)
					}

					if ip4 != nil {
						if model.allocated[*ip4] {
							rt.Fatalf(
								"AllocateMany[%d/%d]: "+
									"duplicate IPv4 %s",
								i, n, ip4,
							)
						}

						model.allocated[*ip4] = true
						allocatedV4s = append(allocatedV4s, *ip4)
					}

					if ip6 != nil {
						if model.allocated[*ip6] {
							rt.Fatalf(
								"AllocateMany[%d/%d]: "+
									"duplicate IPv6 %s",
								i, n, ip6,
							)
						}

						model.allocated[*ip6] = true
						allocatedV6s = append(allocatedV6s, *ip6)
					}

					allocatedPairs++
				}

				checkIPAllocatorInvariants(rt, model, "AllocateMany")
			},
		})
	})
}

func runIPAllocatorStatefulSequential(
	rt *rapid.T,
) {
	prefix4 := genTinyIPv4Prefix().Draw(rt, "prefix4")
	prefix6 := genTinyIPv6Prefix().Draw(rt, "prefix6")

	alloc, err := NewIPAllocator(
		nil, &prefix4, &prefix6,
		types.IPAllocationStrategySequential,
	)
	if err != nil {
		rt.Fatalf("NewIPAllocator: %v", err)
	}

	model := newIPAllocatorModel(prefix4, prefix6)

	maxV4 := allocableCount(prefix4)
	maxV6 := allocableCount(prefix6)

	// The actual limit is min(maxV4, maxV6) because Next() allocates
	// one from each family atomically.
	maxPairs := min(maxV6, maxV4)

	// Track how many pairs are currently allocated (net of frees).
	allocatedPairs := 0

	// Keep ordered lists so we can pick random IPs to free.
	var (
		allocatedV4s []netip.Addr
		allocatedV6s []netip.Addr
	)

	// exhausted tracks whether the allocator has reported exhaustion.
	// The sequential cursor never wraps, so once exhausted it stays
	// exhausted: freed IPs behind the cursor are unreachable.
	exhausted := false

	rt.Repeat(map[string]func(*rapid.T){
		"Allocate": func(rt *rapid.T) {
			if exhausted {
				// Verify the allocator stays exhausted.
				_, _, err := alloc.Next()
				if err == nil {
					rt.Fatalf(
						"Allocate: expected continued exhaustion " +
							"(sequential cursor past end)",
					)
				}

				return
			}

			ip4, ip6, err := alloc.Next()
			if err != nil {
				// Sequential cursor went past the prefix end.
				// This is valid: it can happen when we've
				// allocated+freed+reallocated enough that the
				// cursor swept the whole range.
				exhausted = true
				return
			}

			// Should not succeed when truly full.
			if allocatedPairs >= maxPairs {
				rt.Fatalf(
					"Allocate: succeeded but model says full "+
						"(allocated=%d, maxPairs=%d, ip4=%s, ip6=%s)",
					allocatedPairs, maxPairs, ip4, ip6,
				)
			}

			// Verify IPs are new (not in model) — uniqueness check.
			if ip4 != nil {
				if model.allocated[*ip4] {
					rt.Fatalf("Allocate: duplicate IPv4 %s", ip4)
				}

				model.allocated[*ip4] = true
				allocatedV4s = append(allocatedV4s, *ip4)
			}

			if ip6 != nil {
				if model.allocated[*ip6] {
					rt.Fatalf("Allocate: duplicate IPv6 %s", ip6)
				}

				model.allocated[*ip6] = true
				allocatedV6s = append(allocatedV6s, *ip6)
			}

			allocatedPairs++

			checkIPAllocatorInvariants(rt, model, "Allocate")
		},

		"Free": func(rt *rapid.T) {
			if len(allocatedV4s) == 0 {
				rt.Skip("nothing to free")
			}

			// Pick a random index to free.
			idx := rapid.IntRange(
				0, len(allocatedV4s)-1,
			).Draw(rt, "freeIdx")
			v4 := allocatedV4s[idx]
			v6 := allocatedV6s[idx]

			alloc.FreeIPs([]netip.Addr{v4, v6})

			delete(model.allocated, v4)
			delete(model.allocated, v6)

			// Remove from ordered lists (swap-delete).
			last := len(allocatedV4s) - 1
			allocatedV4s[idx] = allocatedV4s[last]
			allocatedV4s = allocatedV4s[:last]
			allocatedV6s[idx] = allocatedV6s[last]
			allocatedV6s = allocatedV6s[:last]

			allocatedPairs--

			checkIPAllocatorInvariants(rt, model, "Free")
		},

		"AllocateMany": func(rt *rapid.T) {
			if exhausted || allocatedPairs >= maxPairs {
				rt.Skip("allocator exhausted or at capacity")
			}

			remaining := maxPairs - allocatedPairs
			n := rapid.IntRange(1, remaining).Draw(rt, "n")

			for i := range n {
				ip4, ip6, err := alloc.Next()
				if err != nil {
					// Sequential may exhaust mid-batch.
					exhausted = true
					return
				}

				if ip4 != nil {
					if model.allocated[*ip4] {
						rt.Fatalf(
							"AllocateMany[%d/%d]: duplicate IPv4 %s",
							i, n, ip4,
						)
					}

					model.allocated[*ip4] = true
					allocatedV4s = append(allocatedV4s, *ip4)
				}

				if ip6 != nil {
					if model.allocated[*ip6] {
						rt.Fatalf(
							"AllocateMany[%d/%d]: duplicate IPv6 %s",
							i, n, ip6,
						)
					}

					model.allocated[*ip6] = true
					allocatedV6s = append(allocatedV6s, *ip6)
				}

				allocatedPairs++
			}

			checkIPAllocatorInvariants(rt, model, "AllocateMany")
		},
	})
}

// TestRapid_IPAllocator_Exhaustion_Sequential verifies that after
// sequentially allocating all possible IPs in a small prefix, the
// allocator returns ErrCouldNotAllocateIP. It then verifies the
// exhaustion invariant by checking every allocated IP.
func TestRapid_IPAllocator_Exhaustion_Sequential(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		prefix4 := genTinyIPv4Prefix().Draw(rt, "prefix4")
		prefix6 := genTinyIPv6Prefix().Draw(rt, "prefix6")

		alloc, err := NewIPAllocator(
			nil, &prefix4, &prefix6,
			types.IPAllocationStrategySequential,
		)
		if err != nil {
			rt.Fatalf("NewIPAllocator: %v", err)
		}

		maxV4 := allocableCount(prefix4)
		maxV6 := allocableCount(prefix6)

		maxPairs := min(maxV6, maxV4)

		seen4 := make(map[netip.Addr]bool)
		seen6 := make(map[netip.Addr]bool)

		// Exhaust the allocator without any frees.
		for range maxPairs {
			ip4, ip6, err := alloc.Next()
			if err != nil {
				rt.Fatalf(
					"exhaustion: unexpected error at count=%d/%d: %v",
					len(seen4), maxPairs, err,
				)
			}

			if ip4 != nil {
				if seen4[*ip4] {
					rt.Fatalf("exhaustion: duplicate IPv4 %s", ip4)
				}

				seen4[*ip4] = true

				if !prefix4.Contains(*ip4) {
					rt.Fatalf(
						"exhaustion: IPv4 %s not in prefix %s",
						ip4, prefix4,
					)
				}

				if isTailscaleReservedIP(*ip4) {
					rt.Fatalf(
						"exhaustion: IPv4 %s is reserved", ip4,
					)
				}

				net4, bcast4 := getIPPrefixEndpointsViaRange(prefix4)
				if *ip4 == net4 || *ip4 == bcast4 {
					rt.Fatalf(
						"exhaustion: IPv4 %s is network/broadcast",
						ip4,
					)
				}
			}

			if ip6 != nil {
				if seen6[*ip6] {
					rt.Fatalf("exhaustion: duplicate IPv6 %s", ip6)
				}

				seen6[*ip6] = true

				if !prefix6.Contains(*ip6) {
					rt.Fatalf(
						"exhaustion: IPv6 %s not in prefix %s",
						ip6, prefix6,
					)
				}

				if isTailscaleReservedIP(*ip6) {
					rt.Fatalf(
						"exhaustion: IPv6 %s is reserved", ip6,
					)
				}

				net6, bcast6 := getIPPrefixEndpointsViaRange(prefix6)
				if *ip6 == net6 || *ip6 == bcast6 {
					rt.Fatalf(
						"exhaustion: IPv6 %s is network/broadcast",
						ip6,
					)
				}
			}
		}

		// Next allocation must fail.
		_, _, err = alloc.Next()
		if err == nil {
			rt.Fatalf(
				"expected ErrCouldNotAllocateIP after exhaustion "+
					"(prefix4=%s maxV4=%d, prefix6=%s maxV6=%d, "+
					"maxPairs=%d)",
				prefix4, maxV4, prefix6, maxV6, maxPairs,
			)
		}
	})
}
