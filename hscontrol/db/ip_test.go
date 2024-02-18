package db

import (
	"net/netip"
	"os"
	"testing"

	"github.com/davecgh/go-spew/spew"
	"github.com/google/go-cmp/cmp"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
)

func TestIPAllocator(t *testing.T) {
	mpp := func(pref string) netip.Prefix {
		return netip.MustParsePrefix(pref)
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

		prefix4  netip.Prefix
		prefix6  netip.Prefix
		getCount int
		want     []types.NodeAddresses
	}{
		{
			name: "simple",
			dbFunc: func() *HSDatabase {
				return nil
			},

			prefix4: mpp("100.64.0.0/10"),
			prefix6: mpp("fd7a:115c:a1e0::/48"),

			getCount: 1,

			want: []types.NodeAddresses{
				{
					na("100.64.0.1"),
					na("fd7a:115c:a1e0::1"),
				},
			},
		},
		{
			name: "simple-with-db",
			dbFunc: func() *HSDatabase {
				db := newDb()

				db.DB.Save(&types.Node{
					IPAddresses: types.NodeAddresses{
						na("100.64.0.1"),
						na("fd7a:115c:a1e0::1"),
					},
				})

				return db
			},

			prefix4: mpp("100.64.0.0/10"),
			prefix6: mpp("fd7a:115c:a1e0::/48"),

			getCount: 1,

			want: []types.NodeAddresses{
				{
					na("100.64.0.2"),
					na("fd7a:115c:a1e0::2"),
				},
			},
		},
		{
			name: "before-after-free-middle-in-db",
			dbFunc: func() *HSDatabase {
				db := newDb()

				db.DB.Save(&types.Node{
					IPAddresses: types.NodeAddresses{
						na("100.64.0.2"),
						na("fd7a:115c:a1e0::2"),
					},
				})

				return db
			},

			prefix4: mpp("100.64.0.0/10"),
			prefix6: mpp("fd7a:115c:a1e0::/48"),

			getCount: 2,

			want: []types.NodeAddresses{
				{
					na("100.64.0.1"),
					na("fd7a:115c:a1e0::1"),
				},
				{
					na("100.64.0.3"),
					na("fd7a:115c:a1e0::3"),
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db := tt.dbFunc()

			alloc, _ := NewIPAllocator(db, tt.prefix4, tt.prefix6)

			spew.Dump(alloc)

			t.Logf("prefixes: %q, %q", tt.prefix4.String(), tt.prefix6.String())

			var got []types.NodeAddresses

			for range tt.getCount {
				gotSet, err := alloc.Next()
				if err != nil {
					t.Fatalf("allocating next IP: %s", err)
				}

				got = append(got, gotSet)
			}
			if diff := cmp.Diff(tt.want, got, util.Comparers...); diff != "" {
				t.Errorf("IPAllocator unexpected result (-want +got):\n%s", diff)
			}
		})
	}
}
