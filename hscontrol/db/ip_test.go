package db

import (
	"database/sql"
	"net/netip"
	"os"
	"testing"

	"github.com/davecgh/go-spew/spew"
	"github.com/google/go-cmp/cmp"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
)

func TestIPAllocator(t *testing.T) {
	mpp := func(pref string) *netip.Prefix {
		p := netip.MustParsePrefix(pref)
		return &p
	}
	na := func(pref string) netip.Addr {
		return netip.MustParseAddr(pref)
	}
	newDb := func() *HSDatabase {
		tmpDir, err := os.MkdirTemp("", "headscale-db-test-*")
		if err != nil {
			t.Fatalf("creating temp dir: %s", err)
		}
		db, _ = NewHeadscaleDatabase(
			types.DatabaseConfig{
				Type: "sqlite3",
				Sqlite: types.SqliteConfig{
					Path: tmpDir + "/headscale_test.db",
				},
			},
			"",
		)

		return db
	}

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
				db := newDb()

				db.DB.Save(&types.Node{
					IPv4DatabaseField: sql.NullString{
						Valid:  true,
						String: "100.64.0.1",
					},
					IPv6DatabaseField: sql.NullString{
						Valid:  true,
						String: "fd7a:115c:a1e0::1",
					},
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
				db := newDb()

				db.DB.Save(&types.Node{
					IPv4DatabaseField: sql.NullString{
						Valid:  true,
						String: "100.64.0.2",
					},
					IPv6DatabaseField: sql.NullString{
						Valid:  true,
						String: "fd7a:115c:a1e0::2",
					},
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

			alloc, _ := NewIPAllocator(db, tt.prefix4, tt.prefix6)

			spew.Dump(alloc)

			var got4s []netip.Addr
			var got6s []netip.Addr

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
