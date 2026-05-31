package db

import (
	"fmt"
	"testing"
	"time"

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

func TestPseudoVersionTime(t *testing.T) {
	parseTS := func(s string) time.Time {
		t.Helper()

		ts, err := time.Parse(pseudoVersionTimeLayout, s)
		require.NoError(t, err)

		return ts
	}

	tests := []struct {
		name     string
		input    string
		wantOK   bool
		wantTime time.Time
	}{
		// Accept: all three Go pseudo-version shapes.
		{
			name:     "no ancestor tag (v0.0.0 base)",
			input:    "v0.0.0-20260522092201-58a85b68b3d9",
			wantOK:   true,
			wantTime: parseTS("20260522092201"),
		},
		{
			name:     "ancestor is pre-release tag",
			input:    "v0.29.0-beta.1.0.20260522092201-58a85b68b3d9",
			wantOK:   true,
			wantTime: parseTS("20260522092201"),
		},
		{
			name:     "ancestor is release tag",
			input:    "v0.29.1-0.20260522092201-58a85b68b3d9",
			wantOK:   true,
			wantTime: parseTS("20260522092201"),
		},
		{
			name:     "earliest realistic Go module date",
			input:    "v0.0.0-20180101000000-000000000000",
			wantOK:   true,
			wantTime: parseTS("20180101000000"),
		},

		// Reject: real release tags must not look like pseudo-versions.
		{name: "release tag", input: "v0.29.0"},
		{name: "pre-release tag", input: "v0.29.0-beta.1"},
		{name: "rc tag", input: "v0.29.0-rc1"},
		{name: "tag with build metadata", input: "v0.29.0+build123"},

		// Reject: literals handled elsewhere.
		{name: "empty", input: ""},
		{name: "dev literal", input: "dev"},
		{name: "devel literal", input: "(devel)"},

		// Reject: malformed hash.
		{name: "hash too short", input: "v0.0.0-20260522092201-58a85b6"},
		{name: "hash too long", input: "v0.0.0-20260522092201-58a85b68b3d9aa"},
		{name: "hash uppercase hex", input: "v0.0.0-20260522092201-58A85B68B3D9"},
		{name: "hash non-hex", input: "v0.0.0-20260522092201-zzzzzzzzzzzz"},

		// Reject: malformed timestamp.
		{name: "timestamp too short", input: "v0.0.0-2026052209220-58a85b68b3d9"},
		{name: "timestamp too long", input: "v0.0.0-202605220922010-58a85b68b3d9"},
		{name: "invalid month", input: "v0.0.0-20261322092201-58a85b68b3d9"},
		{name: "invalid day", input: "v0.0.0-20260230092201-58a85b68b3d9"},
		{name: "invalid hour", input: "v0.0.0-20260522252201-58a85b68b3d9"},
		{name: "invalid minute", input: "v0.0.0-20260522096001-58a85b68b3d9"},
		{name: "invalid second", input: "v0.0.0-20260522092260-58a85b68b3d9"},
		{name: "leap day on non-leap year", input: "v0.0.0-20230229000000-58a85b68b3d9"},

		// Reject: missing components.
		{name: "missing date and hash", input: "v0.0.0-"},
		{name: "missing hash", input: "v0.0.0-20260522092201-"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := pseudoVersionTime(tt.input)
			assert.Equal(t, tt.wantOK, ok)

			if tt.wantOK {
				assert.True(t, got.Equal(tt.wantTime),
					"want %s, got %s", tt.wantTime, got)
			}
		})
	}
}

func TestIsDev(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		// Existing literals.
		{name: "empty", input: "", want: true},
		{name: "dev", input: "dev", want: true},
		{name: "devel", input: "(devel)", want: true},
		{name: "release tag", input: "v0.28.0", want: false},
		{name: "release tag no v", input: "0.28.0", want: false},
		{name: "pre-release tag", input: "v0.29.0-beta.1", want: false},

		// Go module pseudo-versions — all three shapes Go emits per
		// golang.org/ref/mod#pseudo-versions. Untagged commits
		// (such as main-sha docker builds) must be treated as dev
		// so they neither poison database_versions nor trip the
		// upgrade-path guard.
		{
			name:  "pseudo v0.0.0 base",
			input: "v0.0.0-20260522092201-58a85b68b3d9",
			want:  true,
		},
		{
			name:  "pseudo from pre-release ancestor",
			input: "v0.29.0-beta.1.0.20260522092201-58a85b68b3d9",
			want:  true,
		},
		{
			name:  "pseudo from release ancestor",
			input: "v0.29.1-0.20260522092201-58a85b68b3d9",
			want:  true,
		},

		// Malformed pseudo-version lookalikes must NOT be treated
		// as dev — they fall through to the semver parser.
		{
			name:  "malformed timestamp not dev",
			input: "v0.0.0-20261322092201-58a85b68b3d9",
			want:  false,
		},
		{
			name:  "hash wrong length not dev",
			input: "v0.0.0-20260522092201-58a85b6",
			want:  false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, isDev(tt.input))
		})
	}
}

// TestCheckVersionUpgradePath_StoredPseudoVersion exercises the
// upgrade path when database_versions holds a Go module pseudo-version
// written by an untagged main-sha build. Without dev handling, the
// stored pseudo-version parses as v0.0.0 and the next real release
// trips the multi-minor guard.
func TestCheckVersionUpgradePath_StoredPseudoVersion(t *testing.T) {
	tests := []struct {
		name           string
		stored         string
		currentVersion string
	}{
		{
			name:           "v0.0.0 base pseudo to real release",
			stored:         "v0.0.0-20260520093041-e4e742c776ee",
			currentVersion: "v0.29.0-beta.1",
		},
		{
			name:           "pseudo from pre-release ancestor",
			stored:         "v0.29.0-beta.1.0.20260520093041-e4e742c776ee",
			currentVersion: "v0.29.0",
		},
		{
			name:           "pseudo from release ancestor",
			stored:         "v0.28.1-0.20260520093041-e4e742c776ee",
			currentVersion: "v0.29.0",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db := versionTestDB(t)
			require.NoError(t, setDatabaseVersion(db, tt.stored))
			err := checkVersionUpgradePathFromVersions(db, tt.currentVersion)
			assert.NoError(t, err)
		})
	}
}

// TestCheckVersionUpgradePath_CurrentPseudoDoesNotPoison locks the
// contract that a main-sha (pseudo-version) binary must preserve the
// stored real release so the next real release can upgrade cleanly.
// Mirrors the gating in db.go around setDatabaseVersion.
func TestCheckVersionUpgradePath_CurrentPseudoDoesNotPoison(t *testing.T) {
	db := versionTestDB(t)
	require.NoError(t, setDatabaseVersion(db, "v0.28.0"))

	current := "v0.0.0-20260522092201-58a85b68b3d9"
	err := checkVersionUpgradePathFromVersions(db, current)
	require.NoError(t, err)

	// Mirror db.go: only write the current version when !isDev.
	if !isDev(current) {
		require.NoError(t, setDatabaseVersion(db, current))
	}

	stored, err := getDatabaseVersion(db)
	require.NoError(t, err)
	assert.Equal(t, "v0.28.0", stored,
		"pseudo-version run must not overwrite stored release")
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
