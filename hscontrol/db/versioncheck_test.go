package db

import (
	"fmt"
	"testing"

	"github.com/glebarez/sqlite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

func TestParseVersion(t *testing.T) {
	tests := []struct {
		input   string
		want    semver
		wantErr bool
	}{
		{input: "v0.25.0", want: semver{0, 25, 0}},
		{input: "0.25.0", want: semver{0, 25, 0}},
		{input: "v0.25.1", want: semver{0, 25, 1}},
		{input: "v1.0.0", want: semver{1, 0, 0}},
		{input: "v0.28.3", want: semver{0, 28, 3}},
		// Pre-release suffixes stripped
		{input: "v0.25.0-beta.1", want: semver{0, 25, 0}},
		{input: "v0.25.0-rc1", want: semver{0, 25, 0}},
		// Build metadata stripped
		{input: "v0.25.0+build123", want: semver{0, 25, 0}},
		{input: "v0.25.0-beta.1+build123", want: semver{0, 25, 0}},
		// Invalid inputs
		{input: "", wantErr: true},
		{input: "dev", wantErr: true},
		{input: "vfoo.bar.baz", wantErr: true},
		{input: "v1.2", wantErr: true},
		{input: "v1", wantErr: true},
		{input: "not-a-version", wantErr: true},
		{input: "v1.2.3.4", wantErr: true},
		{input: "(devel)", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := parseVersion(tt.input)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.want, got)
			}
		})
	}
}

func TestSemverString(t *testing.T) {
	s := semver{0, 28, 3}
	assert.Equal(t, "v0.28.3", s.String())
}

func TestIsDev(t *testing.T) {
	assert.True(t, isDev(""))
	assert.True(t, isDev("dev"))
	assert.True(t, isDev("(devel)"))
	assert.False(t, isDev("v0.28.0"))
	assert.False(t, isDev("0.28.0"))
}

// versionTestDB creates an in-memory SQLite database with the
// database_versions table already bootstrapped.
func versionTestDB(t *testing.T) *gorm.DB {
	t.Helper()

	db, err := gorm.Open(sqlite.Open("file::memory:"), &gorm.Config{})
	require.NoError(t, err)

	err = ensureDatabaseVersionTable(db)
	require.NoError(t, err)

	return db
}

func TestSetAndGetDatabaseVersion(t *testing.T) {
	db := versionTestDB(t)

	// Initially empty
	v, err := getDatabaseVersion(db)
	require.NoError(t, err)
	assert.Empty(t, v)

	// Set a version
	err = setDatabaseVersion(db, "v0.27.0")
	require.NoError(t, err)

	v, err = getDatabaseVersion(db)
	require.NoError(t, err)
	assert.Equal(t, "v0.27.0", v)

	// Update the version (upsert)
	err = setDatabaseVersion(db, "v0.28.0")
	require.NoError(t, err)

	v, err = getDatabaseVersion(db)
	require.NoError(t, err)
	assert.Equal(t, "v0.28.0", v)
}

func TestEnsureDatabaseVersionTableIdempotent(t *testing.T) {
	db, err := gorm.Open(sqlite.Open("file::memory:"), &gorm.Config{})
	require.NoError(t, err)

	// Call twice — should not error
	err = ensureDatabaseVersionTable(db)
	require.NoError(t, err)

	err = ensureDatabaseVersionTable(db)
	require.NoError(t, err)
}

// TestCheckVersionUpgradePathDirect tests the version comparison logic
// by directly seeding the database, bypassing types.GetVersionInfo()
// (which returns "dev" in test environments and cannot be overridden).
func TestCheckVersionUpgradePathDirect(t *testing.T) {
	tests := []struct {
		name           string
		storedVersion  string // empty means no row stored
		currentVersion string
		wantErr        bool
		errContains    string
	}{
		// Fresh database (no stored version)
		{
			name:           "fresh db allows any version",
			storedVersion:  "",
			currentVersion: "v0.28.0",
		},

		// Stored is dev
		{
			name:           "real version over dev db",
			storedVersion:  "dev",
			currentVersion: "v0.28.0",
		},
		{
			name:           "devel version in db",
			storedVersion:  "(devel)",
			currentVersion: "v0.28.0",
		},

		// Same version
		{
			name:           "same version",
			storedVersion:  "v0.27.0",
			currentVersion: "v0.27.0",
		},

		// Patch changes within same minor
		{
			name:           "patch upgrade",
			storedVersion:  "v0.27.0",
			currentVersion: "v0.27.3",
		},
		{
			name:           "patch downgrade within same minor",
			storedVersion:  "v0.27.3",
			currentVersion: "v0.27.0",
		},

		// Single minor upgrade
		{
			name:           "single minor upgrade",
			storedVersion:  "v0.27.0",
			currentVersion: "v0.28.0",
		},
		{
			name:           "single minor upgrade with different patches",
			storedVersion:  "v0.27.3",
			currentVersion: "v0.28.1",
		},

		// Multi-minor upgrade (blocked)
		{
			name:           "two minor versions ahead",
			storedVersion:  "v0.25.0",
			currentVersion: "v0.27.0",
			wantErr:        true,
			errContains:    "latest v0.26.x",
		},
		{
			name:           "three minor versions ahead",
			storedVersion:  "v0.25.0",
			currentVersion: "v0.28.0",
			wantErr:        true,
			errContains:    "latest v0.26.x",
		},

		// Minor downgrades (blocked)
		{
			name:           "single minor downgrade",
			storedVersion:  "v0.28.0",
			currentVersion: "v0.27.0",
			wantErr:        true,
			errContains:    "downgrading",
		},
		{
			name:           "multi minor downgrade",
			storedVersion:  "v0.28.0",
			currentVersion: "v0.25.0",
			wantErr:        true,
			errContains:    "downgrading",
		},

		// Major version mismatch
		{
			name:           "major version upgrade",
			storedVersion:  "v0.28.0",
			currentVersion: "v1.0.0",
			wantErr:        true,
			errContains:    "major version",
		},
		{
			name:           "major version downgrade",
			storedVersion:  "v1.0.0",
			currentVersion: "v0.28.0",
			wantErr:        true,
			errContains:    "major version",
		},

		// Pre-release versions
		{
			name:           "pre-release single minor upgrade",
			storedVersion:  "v0.27.0",
			currentVersion: "v0.28.0-beta.1",
		},
		{
			name:           "pre-release multi minor upgrade blocked",
			storedVersion:  "v0.25.0",
			currentVersion: "v0.27.0-rc1",
			wantErr:        true,
			errContains:    "latest v0.26.x",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db := versionTestDB(t)

			// Seed the stored version if provided
			if tt.storedVersion != "" {
				err := setDatabaseVersion(db, tt.storedVersion)
				require.NoError(t, err)
			}

			err := checkVersionUpgradePathFromVersions(db, tt.currentVersion)
			if tt.wantErr {
				require.Error(t, err)

				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// checkVersionUpgradePathFromVersions is a test helper that runs the
// version comparison logic with a specific currentVersion string,
// bypassing types.GetVersionInfo(). It replicates the logic from
// checkVersionUpgradePath but accepts the version as a parameter.
func checkVersionUpgradePathFromVersions(db *gorm.DB, currentVersion string) error {
	if isDev(currentVersion) {
		return nil
	}

	storedVersion, err := getDatabaseVersion(db)
	if err != nil {
		return err
	}

	if storedVersion == "" {
		return nil
	}

	if isDev(storedVersion) {
		return nil
	}

	current, err := parseVersion(currentVersion)
	if err != nil {
		return err
	}

	stored, err := parseVersion(storedVersion)
	if err != nil {
		return err
	}

	if current.Major != stored.Major {
		return errVersionMajorChange
	}

	minorDiff := current.Minor - stored.Minor

	switch {
	case minorDiff == 0:
		return nil
	case minorDiff == 1:
		return nil
	case minorDiff > 1:
		return fmt.Errorf(
			"please upgrade to the latest v%d.%d.x release first: %w",
			stored.Major, stored.Minor+1,
			errVersionUpgrade,
		)
	default:
		return fmt.Errorf("downgrading: %w", errVersionDowngrade)
	}
}
