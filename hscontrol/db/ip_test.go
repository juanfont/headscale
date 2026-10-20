package db

import (
	"fmt"
	"net/netip"
	"runtime"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go4.org/netipx"
	"tailscale.com/net/tsaddr"
)

var mpp = func(pref string) *netip.Prefix {
	p := netip.MustParsePrefix(pref)
	return &p
}

var na = netip.MustParseAddr

var nap = func(pref string) *netip.Addr {
	n := na(pref)
	return &n
}

func TestIPAllocatorSequential(t *testing.T) {
	tests := []struct {
		name   string
		dbFunc func() *HSDatabase

		prefix4  *netip.Prefix
		prefix6  *netip.Prefix
		getCount int
		want4    []netip.Addr
		want6    []netip.Addr
	}{
		{
			name: "simple",
			dbFunc: func() *HSDatabase {
				return nil
			},

			prefix4: mpp("100.64.0.0/10"),
			prefix6: mpp("fd7a:115c:a1e0::/48"),

			getCount: 1,

			want4: []netip.Addr{
				na("100.64.0.1"),
			},
			want6: []netip.Addr{
				na("fd7a:115c:a1e0::1"),
			},
		},
		{
			name: "simple-v4",
			dbFunc: func() *HSDatabase {
				return nil
			},

			prefix4: mpp("100.64.0.0/10"),

			getCount: 1,

			want4: []netip.Addr{
				na("100.64.0.1"),
			},
		},
		{
			name: "simple-v6",
			dbFunc: func() *HSDatabase {
				return nil
			},

			prefix6: mpp("fd7a:115c:a1e0::/48"),

			getCount: 1,

			want6: []netip.Addr{
				na("fd7a:115c:a1e0::1"),
			},
		},
		{
			name: "simple-with-db",
			dbFunc: func() *HSDatabase {
				db := dbForTest(t)
				user := types.User{Name: ""}
				db.DB.Save(&user)

				db.DB.Save(&types.Node{
					User: &user,
					IPv4: nap("100.64.0.1"),
					IPv6: nap("fd7a:115c:a1e0::1"),
				})

				return db
			},

			prefix4: mpp("100.64.0.0/10"),
			prefix6: mpp("fd7a:115c:a1e0::/48"),

			getCount: 1,

			want4: []netip.Addr{
				na("100.64.0.2"),
			},
			want6: []netip.Addr{
				na("fd7a:115c:a1e0::2"),
			},
		},
		{
			name: "before-after-free-middle-in-db",
			dbFunc: func() *HSDatabase {
				db := dbForTest(t)
				user := types.User{Name: ""}
				db.DB.Save(&user)

				db.DB.Save(&types.Node{
					User: &user,
					IPv4: nap("100.64.0.2"),
					IPv6: nap("fd7a:115c:a1e0::2"),
				})

				return db
			},

			prefix4: mpp("100.64.0.0/10"),
			prefix6: mpp("fd7a:115c:a1e0::/48"),

			getCount: 2,

			want4: []netip.Addr{
				na("100.64.0.1"),
				na("100.64.0.3"),
			},
			want6: []netip.Addr{
				na("fd7a:115c:a1e0::1"),
				na("fd7a:115c:a1e0::3"),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db := tt.dbFunc()

			alloc, _ := NewIPAllocator(
				db,
				tt.prefix4,
				tt.prefix6,
				types.IPAllocationStrategySequential,
			)

			var (
				got4s []netip.Addr
				got6s []netip.Addr
			)

			for range tt.getCount {
				got4, got6, err := alloc.Next()
				if err != nil {
					t.Fatalf("allocating next IP: %s", err)
				}

				if got4 != nil {
					got4s = append(got4s, *got4)
				}

				if got6 != nil {
					got6s = append(got6s, *got6)
				}
			}

			if diff := cmp.Diff(tt.want4, got4s, util.Comparers...); diff != "" {
				t.Errorf("IPAllocator 4s unexpected result (-want +got):\n%s", diff)
			}

			if diff := cmp.Diff(tt.want6, got6s, util.Comparers...); diff != "" {
				t.Errorf("IPAllocator 6s unexpected result (-want +got):\n%s", diff)
			}
		})
	}
}

func TestIPAllocatorRandom(t *testing.T) {
	tests := []struct {
		name   string
		dbFunc func() *HSDatabase

		getCount int

		prefix4 *netip.Prefix
		prefix6 *netip.Prefix
		want4   bool
		want6   bool
	}{
		{
			name: "simple",
			dbFunc: func() *HSDatabase {
				return nil
			},

			prefix4: mpp("100.64.0.0/10"),
			prefix6: mpp("fd7a:115c:a1e0::/48"),

			getCount: 1,

			want4: true,
			want6: true,
		},
		{
			name: "simple-v4",
			dbFunc: func() *HSDatabase {
				return nil
			},

			prefix4: mpp("100.64.0.0/10"),

			getCount: 1,

			want4: true,
			want6: false,
		},
		{
			name: "simple-v6",
			dbFunc: func() *HSDatabase {
				return nil
			},

			prefix6: mpp("fd7a:115c:a1e0::/48"),

			getCount: 1,

			want4: false,
			want6: true,
		},
		{
			name: "generate-lots-of-random",
			dbFunc: func() *HSDatabase {
				return nil
			},

			prefix4: mpp("100.64.0.0/10"),
			prefix6: mpp("fd7a:115c:a1e0::/48"),

			getCount: 1000,

			want4: true,
			want6: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db := tt.dbFunc()

			alloc, _ := NewIPAllocator(db, tt.prefix4, tt.prefix6, types.IPAllocationStrategyRandom)

			for range tt.getCount {
				got4, got6, err := alloc.Next()
				if err != nil {
					t.Fatalf("allocating next IP: %s", err)
				}

				t.Logf("addrs ipv4: %v, ipv6: %v", got4, got6)

				if tt.want4 {
					if got4 == nil {
						t.Fatalf("expected ipv4 addr, got nil")
					}
				}

				if tt.want6 {
					if got6 == nil {
						t.Fatalf("expected ipv4 addr, got nil")
					}
				}
			}
		})
	}
}

func TestBackfillIPAddresses(t *testing.T) {
	fullNodeP := func(i int) *types.Node {
		v4 := fmt.Sprintf("100.64.0.%d", i)
		v6 := fmt.Sprintf("fd7a:115c:a1e0::%d", i)

		return &types.Node{
			IPv4: nap(v4),
			IPv6: nap(v6),
		}
	}
	tests := []struct {
		name   string
		dbFunc func() *HSDatabase

		prefix4 *netip.Prefix
		prefix6 *netip.Prefix
		want    types.Nodes
	}{
		{
			name: "simple-backfill-ipv6",
			dbFunc: func() *HSDatabase {
				db := dbForTest(t)
				user := types.User{Name: ""}
				db.DB.Save(&user)

				db.DB.Save(&types.Node{
					User: &user,
					IPv4: nap("100.64.0.1"),
				})

				return db
			},

			prefix4: mpp("100.64.0.0/10"),
			prefix6: mpp("fd7a:115c:a1e0::/48"),

			want: types.Nodes{
				&types.Node{
					IPv4: nap("100.64.0.1"),
					IPv6: nap("fd7a:115c:a1e0::1"),
				},
			},
		},
		{
			name: "simple-backfill-ipv4",
			dbFunc: func() *HSDatabase {
				db := dbForTest(t)
				user := types.User{Name: ""}
				db.DB.Save(&user)

				db.DB.Save(&types.Node{
					User: &user,
					IPv6: nap("fd7a:115c:a1e0::1"),
				})

				return db
			},

			prefix4: mpp("100.64.0.0/10"),
			prefix6: mpp("fd7a:115c:a1e0::/48"),

			want: types.Nodes{
				&types.Node{
					IPv4: nap("100.64.0.1"),
					IPv6: nap("fd7a:115c:a1e0::1"),
				},
			},
		},
		{
			name: "simple-backfill-remove-ipv6",
			dbFunc: func() *HSDatabase {
				db := dbForTest(t)
				user := types.User{Name: ""}
				db.DB.Save(&user)

				db.DB.Save(&types.Node{
					User: &user,
					IPv4: nap("100.64.0.1"),
					IPv6: nap("fd7a:115c:a1e0::1"),
				})

				return db
			},

			prefix4: mpp("100.64.0.0/10"),

			want: types.Nodes{
				&types.Node{
					IPv4: nap("100.64.0.1"),
				},
			},
		},
		{
			name: "simple-backfill-remove-ipv4",
			dbFunc: func() *HSDatabase {
				db := dbForTest(t)
				user := types.User{Name: ""}
				db.DB.Save(&user)

				db.DB.Save(&types.Node{
					User: &user,
					IPv4: nap("100.64.0.1"),
					IPv6: nap("fd7a:115c:a1e0::1"),
				})

				return db
			},

			prefix6: mpp("fd7a:115c:a1e0::/48"),

			want: types.Nodes{
				&types.Node{
					IPv6: nap("fd7a:115c:a1e0::1"),
				},
			},
		},
		{
			name: "multi-backfill-ipv6",
			dbFunc: func() *HSDatabase {
				db := dbForTest(t)
				user := types.User{Name: ""}
				db.DB.Save(&user)

				db.DB.Save(&types.Node{
					User: &user,
					IPv4: nap("100.64.0.1"),
				})
				db.DB.Save(&types.Node{
					User: &user,
					IPv4: nap("100.64.0.2"),
				})
				db.DB.Save(&types.Node{
					User: &user,
					IPv4: nap("100.64.0.3"),
				})
				db.DB.Save(&types.Node{
					User: &user,
					IPv4: nap("100.64.0.4"),
				})

				return db
			},

			prefix4: mpp("100.64.0.0/10"),
			prefix6: mpp("fd7a:115c:a1e0::/48"),

			want: types.Nodes{
				fullNodeP(1),
				fullNodeP(2),
				fullNodeP(3),
				fullNodeP(4),
			},
		},
	}

	comps := append(util.Comparers, cmpopts.IgnoreFields(types.Node{},
		"ID",
		"User",
		"UserID",
		"Endpoints",
		"Hostinfo",
		"CreatedAt",
		"UpdatedAt",
	))

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db := tt.dbFunc()

			alloc, err := NewIPAllocator(
				db,
				tt.prefix4,
				tt.prefix6,
				types.IPAllocationStrategySequential,
			)
			if err != nil {
				t.Fatalf("failed to set up ip alloc: %s", err)
			}

			logs, err := db.BackfillNodeIPs(alloc)
			if err != nil {
				t.Fatalf("failed to backfill: %s", err)
			}

			t.Logf("backfill log: \n%s", strings.Join(logs, "\n"))

			got, err := db.ListNodes()
			if err != nil {
				t.Fatalf("failed to get nodes: %s", err)
			}

			if diff := cmp.Diff(tt.want, got, comps...); diff != "" {
				t.Errorf("Backfill unexpected result (-want +got):\n%s", diff)
			}
		})
	}
}

func TestIPAllocatorNextNoReservedIPs(t *testing.T) {
	db, err := newSQLiteTestDB()
	require.NoError(t, err)

	defer db.Close()

	alloc, err := NewIPAllocator(
		db,
		new(tsaddr.CGNATRange()),
		new(tsaddr.TailscaleULARange()),
		types.IPAllocationStrategySequential,
	)
	if err != nil {
		t.Fatalf("failed to set up ip alloc: %s", err)
	}

	// Validate that we do not give out 100.100.100.100
	nextQuad100, err := alloc.next(na("100.100.100.99"), new(tsaddr.CGNATRange()))
	require.NoError(t, err)
	assert.Equal(t, na("100.100.100.101"), *nextQuad100)

	// Validate that we do not give out fd7a:115c:a1e0::53
	nextQuad100v6, err := alloc.next(na("fd7a:115c:a1e0::52"), new(tsaddr.TailscaleULARange()))
	require.NoError(t, err)
	assert.Equal(t, na("fd7a:115c:a1e0::54"), *nextQuad100v6)

	// Validate that we do not give out fd7a:115c:a1e0::53
	nextChrome, err := alloc.next(na("100.115.91.255"), new(tsaddr.CGNATRange()))
	t.Logf("chrome: %s", nextChrome.String())
	require.NoError(t, err)
	assert.Equal(t, na("100.115.94.0"), *nextChrome)
}

func TestIPAllocatorDatabaseReservations(t *testing.T) {
	db := dbForTest(t)
	t.Cleanup(func() { require.NoError(t, db.Close()) })
	require.NoError(t, db.DB.Create(&types.Node{
		IPv4: nap("100.64.0.1"),
		IPv6: nap("fd7a:115c:a1e0::1%eth0"),
	}).Error)
	require.NoError(t, db.DB.Create(&types.Node{
		IPv6: nap("::ffff:100.64.0.2"),
	}).Error)

	// Restarting must reload reservations, including zone-stripped IPv6,
	// without treating a mapped IPv6 address as native IPv4.
	for range 2 {
		alloc, err := NewIPAllocator(db, mpp("100.64.0.0/29"),
			mpp("fd7a:115c:a1e0::/125"), types.IPAllocationStrategySequential)
		require.NoError(t, err)
		v4, v6, err := alloc.Next()
		require.NoError(t, err)
		require.Equal(t, na("100.64.0.2"), *v4)
		require.Equal(t, na("fd7a:115c:a1e0::2"), *v6)

		alloc.FreeIPs([]netip.Addr{na("fd7a:115c:a1e0::1%other")})
		v6, err = alloc.allocateNext(new(na("fd7a:115c:a1e0::")), alloc.prefix6)
		require.NoError(t, err)
		require.Equal(t, na("fd7a:115c:a1e0::1"), *v6)
	}

	mapped, err := NewIPAllocator(db, nil, mpp("::ffff:100.64.0.0/125"),
		types.IPAllocationStrategySequential)
	require.NoError(t, err)
	_, v6, err := mapped.Next()
	require.NoError(t, err)
	require.Equal(t, na("::ffff:100.64.0.1"), *v6)
	_, v6, err = mapped.Next()
	require.NoError(t, err)
	require.Equal(t, na("::ffff:100.64.0.3"), *v6)
}

func TestIPAllocatorInvalidInputs(t *testing.T) {
	for _, column := range []string{"ipv4", "ipv6"} {
		t.Run(column, func(t *testing.T) {
			db := dbForTest(t)
			t.Cleanup(func() { require.NoError(t, db.Close()) })

			node := types.Node{}
			require.NoError(t, db.DB.Create(&node).Error)
			require.NoError(
				t,
				db.DB.Model(&node).UpdateColumn(column, "bad address").Error,
			)
			alloc, err := NewIPAllocator(db, mpp("100.64.0.0/29"), nil,
				types.IPAllocationStrategySequential)
			require.ErrorContains(t, err, "parsing IP address from database:")
			require.Nil(t, alloc)
		})
	}

	for _, v6 := range []bool{false, true} {
		t.Run(fmt.Sprintf("invalid-prefix-v6=%t", v6), func(t *testing.T) {
			p4, p6 := new(netip.Prefix), (*netip.Prefix)(nil)
			if v6 {
				p4, p6 = p6, p4
			}

			alloc, err := NewIPAllocator(
				nil,
				p4,
				p6,
				types.IPAllocationStrategySequential,
			)
			require.Error(t, err)
			require.Nil(t, alloc)
		})
	}

	t.Run("invalid-release", func(t *testing.T) {
		alloc, err := NewIPAllocator(nil, mpp("100.64.0.0/29"), nil,
			types.IPAllocationStrategySequential)
		require.NoError(t, err)
		alloc.FreeIPs([]netip.Addr{{}})

		var legacy netipx.IPSetBuilder
		legacy.Remove(netip.Addr{})

		for attempt := range 2 {
			_, legacyErr := legacy.IPSet()
			v4, v6, err := alloc.Next()
			require.Nil(t, v6)

			if attempt == 0 {
				require.Error(t, legacyErr)
				require.Error(t, err)
				require.Nil(t, v4)
			} else {
				require.NoError(t, legacyErr)
				require.NoError(t, err)
				require.NotNil(t, v4)
				require.Equal(t, na("100.64.0.1"), *v4)
			}
		}
	})
}

func TestIPAllocatorPartialFailureKeepsReservation(t *testing.T) {
	alloc, err := NewIPAllocator(nil, mpp("100.64.0.0/29"),
		mpp("fd7a:115c:a1e0::/128"), types.IPAllocationStrategySequential)
	require.NoError(t, err)
	v4, v6, err := alloc.Next()
	require.ErrorIs(t, err, ErrCouldNotAllocateIP)
	require.ErrorContains(t, err, "allocating IPv6 address:")
	require.Nil(t, v4)
	require.Nil(t, v6)
	require.Equal(t, na("100.64.0.1"), alloc.prev4)
	require.Equal(t, na("fd7a:115c:a1e0::"), alloc.prev6)

	v4, err = alloc.allocateNext(new(na("100.64.0.0")), alloc.prefix4)
	require.NoError(t, err)
	require.Equal(t, na("100.64.0.2"), *v4)
}

func TestBackfillIPFailureKeepsReservation(t *testing.T) {
	db := dbForTest(t)
	t.Cleanup(func() { require.NoError(t, db.Close()) })

	node := types.Node{}
	require.NoError(t, db.DB.Create(&node).Error)
	alloc, err := NewIPAllocator(db, mpp("100.64.0.0/29"), nil,
		types.IPAllocationStrategySequential)
	require.NoError(t, err)
	require.NoError(t, db.DB.Exec(`CREATE TRIGGER reject_ip_update
		BEFORE UPDATE OF ipv4 ON nodes BEGIN
		SELECT RAISE(ABORT, 'reject IP update'); END`).Error)

	_, err = db.BackfillNodeIPs(alloc)
	require.ErrorContains(t, err, "reject IP update")

	var persisted types.Node
	require.NoError(t, db.DB.First(&persisted, node.ID).Error)
	require.Nil(t, persisted.IPv4)

	v4, err := alloc.allocateNext(new(na("100.64.0.0")), alloc.prefix4)
	require.NoError(t, err)
	require.Equal(t, na("100.64.0.2"), *v4)

	// A restart discards reservations that never reached the database.
	restarted, err := NewIPAllocator(db, alloc.prefix4, nil,
		types.IPAllocationStrategySequential)
	require.NoError(t, err)
	v4, _, err = restarted.Next()
	require.NoError(t, err)
	require.Equal(t, na("100.64.0.1"), *v4)
}

func TestIPAllocatorSequentialAllocationCost(t *testing.T) {
	alloc, err := NewIPAllocator(nil, mpp("100.64.0.0/16"), nil,
		types.IPAllocationStrategySequential)
	require.NoError(t, err)

	allocations := testing.AllocsPerRun(1000, func() {
		_, _, err := alloc.Next()
		if err != nil {
			t.Fatal(err)
		}
	})
	// Returning the address needs one allocation; rebuilding the ownership
	// collection on every allocation must not add recurring allocations.
	require.LessOrEqual(t, allocations, float64(1))
}

func BenchmarkIPAllocator(b *testing.B) {
	for _, tc := range []struct {
		name     string
		prefix   string
		strategy types.IPAllocationStrategy
		count    int
	}{
		{"dense-sequential", "100.64.0.0/16", types.IPAllocationStrategySequential, 4096},
		{"fragmented-random", "100.64.0.0/16", types.IPAllocationStrategyRandom, 4096},
		{
			"fill-to-nearly-full-random",
			"100.64.0.0/24",
			types.IPAllocationStrategyRandom,
			253,
		},
	} {
		b.Run(tc.name, func(b *testing.B) {
			prefix := netip.MustParsePrefix(tc.prefix)

			b.ReportAllocs()

			for b.Loop() {
				alloc, err := NewIPAllocator(nil, &prefix, nil, tc.strategy)
				if err != nil {
					b.Fatal(err)
				}

				for range tc.count {
					_, _, err := alloc.Next()
					if err != nil {
						b.Fatal(err)
					}
				}
			}

			b.ReportMetric(float64(tc.count), "addresses/op")
			b.ReportMetric(
				float64(b.Elapsed().Nanoseconds())/float64(b.N*tc.count),
				"ns/address",
			)
		})
	}

	b.Run("nearly-full-random", func(b *testing.B) {
		alloc, err := NewIPAllocator(nil, mpp("100.64.0.0/24"), nil,
			types.IPAllocationStrategyRandom)
		if err != nil {
			b.Fatal(err)
		}

		for range 253 {
			_, _, err := alloc.Next()
			if err != nil {
				b.Fatal(err)
			}
		}

		b.ReportAllocs()
		// Loop excludes prefill; each allocation starts with one usable address free.
		for b.Loop() {
			v4, _, err := alloc.Next()
			if err != nil {
				b.Fatal(err)
			}

			alloc.FreeIPs([]netip.Addr{*v4})
		}
	})

	b.Run("concurrent-random", func(b *testing.B) {
		alloc, err := NewIPAllocator(nil, mpp("100.64.0.0/16"), nil,
			types.IPAllocationStrategyRandom)
		if err != nil {
			b.Fatal(err)
		}

		b.ReportAllocs()
		b.ResetTimer()
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				v4, _, err := alloc.Next()
				if err != nil {
					b.Error(err)
					return
				}

				alloc.FreeIPs([]netip.Addr{*v4})
			}
		})
	})
}

func BenchmarkIPAllocatorRetainedMemory(b *testing.B) {
	for _, strategy := range []types.IPAllocationStrategy{
		types.IPAllocationStrategySequential, types.IPAllocationStrategyRandom,
	} {
		b.Run(string(strategy), func(b *testing.B) {
			const (
				populations = 16
				addresses   = 4096
			)

			var retained float64

			for b.Loop() {
				var (
					allocators    [populations]*IPAllocator
					before, after runtime.MemStats
				)

				runtime.GC()
				runtime.ReadMemStats(&before)

				for j := range allocators {
					alloc, err := NewIPAllocator(
						nil,
						mpp("100.64.0.0/16"),
						nil,
						strategy,
					)
					if err != nil {
						b.Fatal(err)
					}

					for range addresses {
						_, _, err := alloc.Next()
						if err != nil {
							b.Fatal(err)
						}
					}

					allocators[j] = alloc
				}

				runtime.GC()
				runtime.ReadMemStats(&after)
				runtime.KeepAlive(allocators)

				retained += float64(after.HeapAlloc) - float64(before.HeapAlloc)
			}

			b.ReportMetric(retained/float64(b.N*populations),
				"retained-B/allocator")
			b.ReportMetric(addresses, "addresses/allocator")
			b.ReportMetric(0, "ns/op")
		})
	}
}
