package db

import (
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"gorm.io/gorm"
)

func TestMigrations(t *testing.T) {
	ipp := func(p string) types.IPPrefix {
		return types.IPPrefix(netip.MustParsePrefix(p))
	}
	r := func(id uint64, p string, a, e, i bool) types.Route {
		return types.Route{
			NodeID:     id,
			Prefix:     ipp(p),
			Advertised: a,
			Enabled:    e,
			IsPrimary:  i,
		}
	}
	tests := []struct {
		dbPath   string
		wantFunc func(*testing.T, *HSDatabase)
		wantErr  string
	}{
		{
			dbPath: "testdata/0-22-3-to-0-23-0-routes-are-dropped-2063.sqlite",
			wantFunc: func(t *testing.T, h *HSDatabase) {
				routes, err := Read(h.DB, func(rx *gorm.DB) (types.Routes, error) {
					return GetRoutes(rx)
				})
				assert.NoError(t, err)

				assert.Len(t, routes, 10)
				want := types.Routes{
					r(1, "0.0.0.0/0", true, true, false),
					r(1, "::/0", true, true, false),
					r(1, "10.9.110.0/24", true, true, true),
					r(26, "172.100.100.0/24", true, true, true),
					r(26, "172.100.100.0/24", true, false, false),
					r(31, "0.0.0.0/0", true, true, false),
					r(31, "0.0.0.0/0", true, false, false),
					r(31, "::/0", true, true, false),
					r(31, "::/0", true, false, false),
					r(32, "192.168.0.24/32", true, true, true),
				}
				if diff := cmp.Diff(want, routes, cmpopts.IgnoreFields(types.Route{}, "Model", "Node"), cmp.Comparer(func(x, y types.IPPrefix) bool {
					return x == y
				})); diff != "" {
					t.Errorf("TestMigrations() mismatch (-want +got):\n%s", diff)
				}
			},
		},
		{
			dbPath: "testdata/0-22-3-to-0-23-0-routes-fail-foreign-key-2076.sqlite",
			wantFunc: func(t *testing.T, h *HSDatabase) {
				routes, err := Read(h.DB, func(rx *gorm.DB) (types.Routes, error) {
					return GetRoutes(rx)
				})
				assert.NoError(t, err)

				assert.Len(t, routes, 4)
				want := types.Routes{
					// These routes exists, but have no nodes associated with them
					// when the migration starts.
					// r(1, "0.0.0.0/0", true, true, false),
					// r(1, "::/0", true, true, false),
					// r(3, "0.0.0.0/0", true, true, false),
					// r(3, "::/0", true, true, false),
					// r(5, "0.0.0.0/0", true, true, false),
					// r(5, "::/0", true, true, false),
					// r(6, "0.0.0.0/0", true, true, false),
					// r(6, "::/0", true, true, false),
					// r(6, "10.0.0.0/8", true, false, false),
					// r(7, "0.0.0.0/0", true, true, false),
					// r(7, "::/0", true, true, false),
					// r(7, "10.0.0.0/8", true, false, false),
					// r(9, "0.0.0.0/0", true, true, false),
					// r(9, "::/0", true, true, false),
					// r(9, "10.0.0.0/8", true, true, false),
					// r(11, "0.0.0.0/0", true, true, false),
					// r(11, "::/0", true, true, false),
					// r(11, "10.0.0.0/8", true, true, true),
					// r(12, "0.0.0.0/0", true, true, false),
					// r(12, "::/0", true, true, false),
					// r(12, "10.0.0.0/8", true, false, false),
					//
					// These nodes exists, so routes should be kept.
					r(13, "10.0.0.0/8", true, false, false),
					r(13, "0.0.0.0/0", true, true, false),
					r(13, "::/0", true, true, false),
					r(13, "10.18.80.2/32", true, true, true),
				}
				if diff := cmp.Diff(want, routes, cmpopts.IgnoreFields(types.Route{}, "Model", "Node"), cmp.Comparer(func(x, y types.IPPrefix) bool {
					return x == y
				})); diff != "" {
					t.Errorf("TestMigrations() mismatch (-want +got):\n%s", diff)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.dbPath, func(t *testing.T) {
			dbPath, err := testCopyOfDatabase(tt.dbPath)
			if err != nil {
				t.Fatalf("copying db for test: %s", err)
			}

			hsdb, err := NewHeadscaleDatabase(types.DatabaseConfig{
				Type: "sqlite3",
				Sqlite: types.SqliteConfig{
					Path: dbPath,
				},
			}, "")
			if err != nil && tt.wantErr != err.Error() {
				t.Errorf("TestMigrations() unexpected error = %v, wantErr %v", err, tt.wantErr)
			}

			if tt.wantFunc != nil {
				tt.wantFunc(t, hsdb)
			}
		})
	}
}

func testCopyOfDatabase(src string) (string, error) {
	sourceFileStat, err := os.Stat(src)
	if err != nil {
		return "", err
	}

	if !sourceFileStat.Mode().IsRegular() {
		return "", fmt.Errorf("%s is not a regular file", src)
	}

	source, err := os.Open(src)
	if err != nil {
		return "", err
	}
	defer source.Close()

	tmpDir, err := os.MkdirTemp("", "hsdb-test-*")
	if err != nil {
		return "", err
	}

	fn := filepath.Base(src)
	dst := filepath.Join(tmpDir, fn)

	destination, err := os.Create(dst)
	if err != nil {
		return "", err
	}
	defer destination.Close()
	_, err = io.Copy(destination, source)
	return dst, err
}
