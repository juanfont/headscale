package db

import (
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/require"
)

// TestIPAllocatorRandomExhaustionReturnsError ensures the random allocation
// strategy terminates when its prefix is exhausted. randomNext only ever
// returns in-prefix addresses, so the allocation loop's exhaustion exit must
// not depend on producing an out-of-prefix candidate; otherwise Next() spins
// forever under the allocator mutex, wedging all registration and IP release.
//
// 100.64.0.0/30 has four addresses: .0 (network) and .3 (broadcast) are
// reserved, leaving .1 and .2. After two allocations the pool is exhausted and
// the third Next() must return ErrCouldNotAllocateIP promptly.
func TestIPAllocatorRandomExhaustionReturnsError(t *testing.T) {
	prefix4 := netip.MustParsePrefix("100.64.0.0/30")

	alloc, err := NewIPAllocator(nil, &prefix4, nil, types.IPAllocationStrategyRandom)
	if err != nil {
		t.Fatalf("NewIPAllocator: %v", err)
	}

	for i := range 2 {
		_, _, err := alloc.Next()
		if err != nil {
			t.Fatalf("Next() #%d unexpectedly failed: %v", i+1, err)
		}
	}

	done := make(chan error, 1)

	go func() {
		_, _, err := alloc.Next()
		done <- err
	}()

	select {
	case err := <-done:
		if !errors.Is(err, ErrCouldNotAllocateIP) {
			t.Fatalf("expected ErrCouldNotAllocateIP on exhausted prefix, got: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Next() on an exhausted random-strategy prefix did not return " +
			"within 2s; it is spinning forever under the allocator mutex")
	}
}

func TestIPAllocatorReservationLifecycle(t *testing.T) {
	for _, prefix := range []string{
		"100.64.0.1/30",
		"fd7a:115c:a1e0::1/126",
		"::ffff:100.64.0.1/126",
		"255.255.255.253/30",
		"ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffd/126",
	} {
		for _, strategy := range []types.IPAllocationStrategy{
			types.IPAllocationStrategySequential, types.IPAllocationStrategyRandom,
		} {
			t.Run(prefix+"/"+string(strategy), func(t *testing.T) {
				p := netip.MustParsePrefix(prefix)

				p4, p6 := &p, (*netip.Prefix)(nil)
				if p.Addr().Is6() {
					p4, p6 = p6, p4
				}

				alloc, err := NewIPAllocator(nil, p4, p6, strategy)
				require.NoError(t, err)

				issued := make([]netip.Addr, 0, 2)

				for range 2 {
					v4, v6, err := alloc.Next()
					require.NoError(t, err)

					ip := v4
					if p.Addr().Is6() {
						require.Nil(t, v4)

						ip = v6
					} else {
						require.Nil(t, v6)
					}

					require.NotNil(t, ip)
					require.NotContains(t, issued, *ip)
					issued = append(issued, *ip)
				}

				first := p.Masked().Addr().Next()
				require.ElementsMatch(t, []netip.Addr{first, first.Next()}, issued)

				prev4, prev6 := alloc.prev4, alloc.prev6
				_, _, err = alloc.Next()
				require.ErrorIs(t, err, ErrCouldNotAllocateIP)
				require.Equal(t, prev4, alloc.prev4)
				require.Equal(t, prev6, alloc.prev6)

				alloc.FreeIPs([]netip.Addr{issued[0], issued[0]})

				v4, v6, err := alloc.Next()
				if strategy == types.IPAllocationStrategySequential {
					require.ErrorIs(t, err, ErrCouldNotAllocateIP)
					return
				}

				require.NoError(t, err)

				ip := v4
				if p.Addr().Is6() {
					ip = v6
				}

				require.Equal(t, issued[0], *ip)

				_, _, err = alloc.Next()
				require.ErrorIs(t, err, ErrCouldNotAllocateIP)
			})
		}
	}
}

func TestIPAllocatorReservedPoolsExhaust(t *testing.T) {
	for _, prefix := range []string{
		"100.64.0.0/31", "100.64.0.1/32",
		"fd7a:115c:a1e0::/127", "fd7a:115c:a1e0::1/128",
		"100.100.100.100/32", "fd7a:115c:a1e0::53/128",
		"100.115.92.0/30",
	} {
		for _, strategy := range []types.IPAllocationStrategy{
			types.IPAllocationStrategySequential, types.IPAllocationStrategyRandom,
		} {
			t.Run(prefix+"/"+string(strategy), func(t *testing.T) {
				p := netip.MustParsePrefix(prefix)

				p4, p6 := &p, (*netip.Prefix)(nil)
				if p.Addr().Is6() {
					p4, p6 = p6, p4
				}

				alloc, err := NewIPAllocator(nil, p4, p6, strategy)
				require.NoError(t, err)
				_, _, err = alloc.Next()
				require.ErrorIs(t, err, ErrCouldNotAllocateIP)
			})
		}
	}
}

func TestRandomNextBounds(t *testing.T) {
	for _, tc := range []struct{ prefix, last string }{
		{"0.0.0.1/30", "0.0.0.3"},
		{"::1/126", "::3"},
		{"::ffff:100.64.0.1/126", "::ffff:100.64.0.3"},
		{"255.255.255.253/30", "255.255.255.255"},
		{"ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffd/126", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"},
		{"255.255.255.255/32", "255.255.255.255"},
		{"ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"},
	} {
		t.Run(tc.prefix, func(t *testing.T) {
			p := netip.MustParsePrefix(tc.prefix)
			for range 32 {
				ip, err := randomNext(p)
				require.NoError(t, err)
				require.True(t, p.Contains(ip), "address %s outside %s", ip, p)
				require.Equal(t, p.Addr().Is4(), ip.Is4())

				if p.IsSingleIP() {
					require.Equal(t, p.Addr(), ip)
				} else {
					// Keep the existing upper-exclusive random starting point.
					require.NotEqual(t, netip.MustParseAddr(tc.last), ip)
				}
			}
		})
	}
}
