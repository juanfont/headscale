package db

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/rs/zerolog/log"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

var errVersionUpgrade = errors.New("version upgrade not supported")

var errVersionDowngrade = errors.New("version downgrade not supported")

var errVersionMajorChange = errors.New("major version change not supported")

var errVersionParse = errors.New("cannot parse version")

var errVersionFormat = errors.New(
	"version does not follow semver major.minor.patch format",
)

// DatabaseVersion tracks the headscale version that last
// successfully started against this database.
// It is a single-row table (ID is always 1).
type DatabaseVersion struct {
	ID        uint   `gorm:"primaryKey"`
	Version   string `gorm:"not null"`
	UpdatedAt time.Time
}

// semver holds parsed major.minor.patch components.
type semver struct {
	Major int
	Minor int
	Patch int
}

func (s semver) String() string {
	return fmt.Sprintf("v%d.%d.%d", s.Major, s.Minor, s.Patch)
}

// parseVersion parses a version string like "v0.25.0", "0.25.1",
// "v0.25.0-beta.1", or "v0.25.0-rc1+build123" into its major, minor,
// patch components. Pre-release and build metadata suffixes are stripped.
func parseVersion(s string) (semver, error) {
	if s == "" || s == "dev" {
		return semver{}, fmt.Errorf("%q: %w", s, errVersionParse)
	}

	v := strings.TrimPrefix(s, "v")

	// Strip pre-release suffix (everything after first '-')
	// and build metadata (everything after first '+').
	if idx := strings.IndexAny(v, "-+"); idx != -1 {
		v = v[:idx]
	}

	parts := strings.Split(v, ".")
	if len(parts) != 3 {
		return semver{}, fmt.Errorf("%q: %w", s, errVersionFormat)
	}

	var out [3]int

	names := [...]string{"major", "minor", "patch"}

	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil {
			return semver{}, fmt.Errorf("invalid %s version in %q: %w", names[i], s, err)
		}

		out[i] = n
	}

	return semver{Major: out[0], Minor: out[1], Patch: out[2]}, nil
}

// ensureDatabaseVersionTable creates the database_versions table if it
// does not already exist. Uses [gorm.DB.AutoMigrate] to handle dialect
// differences between SQLite (datetime) and PostgreSQL (timestamp).
// This runs before gormigrate migrations.
func ensureDatabaseVersionTable(db *gorm.DB) error {
	err := db.AutoMigrate(&DatabaseVersion{})
	if err != nil {
		return fmt.Errorf("creating database version table: %w", err)
	}

	return nil
}

// getDatabaseVersion reads the stored version from the database.
// Returns an empty string if no version has been stored yet.
func getDatabaseVersion(db *gorm.DB) (string, error) {
	var version string

	result := db.Raw("SELECT version FROM database_versions WHERE id = 1").Scan(&version)
	if result.Error != nil {
		return "", fmt.Errorf("reading database version: %w", result.Error)
	}

	if result.RowsAffected == 0 {
		return "", nil
	}

	return version, nil
}

// setDatabaseVersion upserts the version row in the database.
func setDatabaseVersion(db *gorm.DB, version string) error {
	now := time.Now().UTC()

	err := db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "id"}},
		DoUpdates: clause.AssignmentColumns([]string{"version", "updated_at"}),
	}).Create(&DatabaseVersion{ID: 1, Version: version, UpdatedAt: now}).Error
	if err != nil {
		return fmt.Errorf("upserting database version: %w", err)
	}

	return nil
}

// pseudoVersionTimeLayout is Go's pseudo-version timestamp layout
// (golang.org/ref/mod#pseudo-versions): UTC yyyymmddhhmmss.
const pseudoVersionTimeLayout = "20060102150405"

// pseudoVersionSuffix matches the trailing "<sep><14 digits>-<12
// lowercase hex>" of a Go module pseudo-version. The base form
// (vX.0.0-<date>-<hash>) uses "-" before the timestamp; the
// pre-release-ancestor and release-ancestor forms
// (vX.Y.Z-pre.0.<date>-<hash> and vX.Y.(Z+1)-0.<date>-<hash>) use "."
// because the digit-only "0" marker precedes the timestamp.
var pseudoVersionSuffix = regexp.MustCompile(`[-.](\d{14})-[0-9a-f]{12}$`)

// pseudoVersionTime returns the embedded commit time when v is a
// syntactically and semantically valid Go module pseudo-version. The
// timestamp must parse as a real UTC time; lookalikes with malformed
// dates (e.g. month 13, day 30 in February) are rejected.
func pseudoVersionTime(v string) (time.Time, bool) {
	m := pseudoVersionSuffix.FindStringSubmatch(v)
	if m == nil {
		return time.Time{}, false
	}

	t, err := time.Parse(pseudoVersionTimeLayout, m[1])
	if err != nil {
		return time.Time{}, false
	}

	return t, true
}

// isDev reports whether a version string represents a development build
// that should skip version checking. Go module pseudo-versions (used by
// untagged main-sha builds, where runtime/debug.BuildInfo falls back to
// vX.Y.Z-<timestamp>-<commit>) are treated as dev to avoid poisoning
// database_versions with synthetic baselines.
func isDev(version string) bool {
	if version == "" || version == "dev" || version == "(devel)" {
		return true
	}

	_, ok := pseudoVersionTime(version)

	return ok
}

// checkVersionUpgradePath verifies that the running headscale version
// is compatible with the version that last used this database.
//
// Rules:
//   - If the running binary has no version ("dev" or empty), warn and skip.
//   - If no version is stored in the database, allow (first run with this feature).
//   - If the stored version is "dev", allow (previous run was unversioned).
//   - Same minor version: always allowed (patch changes in either direction).
//   - Single minor version upgrade (stored.minor+1 == current.minor): allowed.
//   - Multi-minor upgrade or any minor downgrade: blocked with a fatal error.
func checkVersionUpgradePath(db *gorm.DB) error {
	err := ensureDatabaseVersionTable(db)
	if err != nil {
		return err
	}

	currentVersion := types.GetVersionInfo().Version

	// Running binary has no real version — skip the check but
	// preserve whatever version is already stored.
	if isDev(currentVersion) {
		storedVersion, err := getDatabaseVersion(db)
		if err != nil {
			return err
		}

		if storedVersion != "" && !isDev(storedVersion) {
			log.Warn().
				Str("database_version", storedVersion).
				Msg("running a development build of headscale without a version number, " +
					"database version check is skipped, the stored database version is preserved")
		}

		return nil
	}

	storedVersion, err := getDatabaseVersion(db)
	if err != nil {
		return err
	}

	// No stored version — first run with this feature. Allow startup;
	// the version will be stored after migrations succeed.
	if storedVersion == "" {
		return nil
	}

	// Previous run was an unversioned build — no meaningful comparison.
	if isDev(storedVersion) {
		return nil
	}

	current, err := parseVersion(currentVersion)
	if err != nil {
		return fmt.Errorf("parsing current version: %w", err)
	}

	stored, err := parseVersion(storedVersion)
	if err != nil {
		return fmt.Errorf("parsing stored database version: %w", err)
	}

	if current.Major != stored.Major {
		return fmt.Errorf(
			"headscale version %s cannot be used with a database last used by %s: %w",
			currentVersion, storedVersion, errVersionMajorChange,
		)
	}

	minorDiff := current.Minor - stored.Minor

	switch {
	case minorDiff == 0:
		// Same minor version — patch changes are always fine.
		return nil

	case minorDiff == 1:
		// Single minor version upgrade — allowed.
		return nil

	case minorDiff > 1:
		// Multi-minor upgrade — blocked.
		return fmt.Errorf(
			"headscale version %s cannot be used with a database last used by %s, "+
				"upgrading more than one minor version at a time is not supported, "+
				"please upgrade to the latest v%d.%d.x release first, then to %s, "+
				"release page: https://github.com/juanfont/headscale/releases: %w",
			currentVersion, storedVersion,
			stored.Major, stored.Minor+1,
			current.String(),
			errVersionUpgrade,
		)

	default:
		// minorDiff < 0 — any minor downgrade is blocked.
		return fmt.Errorf(
			"headscale version %s cannot be used with a database last used by %s, "+
				"downgrading to a previous minor version is not supported, "+
				"release page: https://github.com/juanfont/headscale/releases: %w",
			currentVersion, storedVersion,
			errVersionDowngrade,
		)
	}
}
