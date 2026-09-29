package db

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// ErrGroupsNotStored is returned when groups just created cannot all be read
// back.
var ErrGroupsNotStored = errors.New("groups were not stored")

// gormDialectSQLite is the name gorm reports for the SQLite dialect.
const gormDialectSQLite = "sqlite"

// groupsDDLSQLite and userGroupsDDLSQLite match schema.sql byte-for-byte (the
// squibble digest is the SQLite source of truth). user_groups.source is not
// CHECK-constrained so a new membership source does not need a table rebuild.
const (
	groupsDDLSQLite = `CREATE TABLE groups(
  id integer PRIMARY KEY AUTOINCREMENT,
  name text NOT NULL,

  created_at datetime,
  updated_at datetime
)`
	userGroupsDDLSQLite = `CREATE TABLE user_groups(
  user_id integer NOT NULL,
  group_id integer NOT NULL,
  source text NOT NULL,
  created_at datetime,

  PRIMARY KEY(user_id, group_id, source),
  CONSTRAINT fk_user_groups_user FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
  CONSTRAINT fk_user_groups_group FOREIGN KEY(group_id) REFERENCES groups(id) ON DELETE CASCADE
)`
)

// groupsDDLPostgres and userGroupsDDLPostgres are the Postgres forms of the
// SQLite DDL; InitSchema and the migration share them.
const (
	groupsDDLPostgres = `CREATE TABLE groups(
  id bigserial PRIMARY KEY,
  name text NOT NULL,

  created_at timestamptz,
  updated_at timestamptz
)`
	userGroupsDDLPostgres = `CREATE TABLE user_groups(
  user_id bigint NOT NULL,
  group_id bigint NOT NULL,
  source text NOT NULL,
  created_at timestamptz,

  PRIMARY KEY(user_id, group_id, source),
  CONSTRAINT fk_user_groups_user FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
  CONSTRAINT fk_user_groups_group FOREIGN KEY(group_id) REFERENCES groups(id) ON DELETE CASCADE
)`
)

// groupIndexes are created with the tables. The group_id index serves the
// cascade from groups and lookups of a group's members.
var groupIndexes = []string{
	`CREATE UNIQUE INDEX idx_groups_name ON groups(name)`,
	`CREATE INDEX idx_user_groups_group_id ON user_groups(group_id)`,
}

// ensureGroupsTables creates the groups and user_groups tables and their
// indexes in one transaction, and is a no-op once they exist.
func ensureGroupsTables(tx *gorm.DB) error {
	if tx.Migrator().HasTable(&types.UserGroup{}) {
		return nil
	}

	return tx.Transaction(createGroupsTables)
}

func createGroupsTables(tx *gorm.DB) error {
	ddl := []string{groupsDDLSQLite, userGroupsDDLSQLite}
	if tx.Name() != gormDialectSQLite {
		ddl = []string{groupsDDLPostgres, userGroupsDDLPostgres}
	}

	for _, stmt := range append(ddl, groupIndexes...) {
		err := tx.Exec(stmt).Error
		if err != nil {
			return fmt.Errorf("creating groups tables: %w", err)
		}
	}

	return nil
}

// preloadUserGroups eager-loads a user's memberships and their groups at the
// given association path ("" for a query on users itself).
func preloadUserGroups(tx *gorm.DB, path string) *gorm.DB {
	if path != "" {
		path += "."
	}

	return tx.Preload(path + "Memberships.Group")
}

// SetUserGroups makes groups, a list of qualified group names (see
// [types.QualifyGroupName]), the complete set of the user's memberships from
// source. Memberships from other sources are left untouched. Unknown groups
// are created. It reports whether the user's memberships from source changed.
func SetUserGroups(
	tx *gorm.DB,
	uid types.UserID,
	source types.GroupSource,
	groups []string,
) (bool, error) {
	groups = slices.Clone(groups)
	slices.Sort(groups)
	groups = slices.Compact(groups)

	// Serialise concurrent syncs for the same user, such as two logins at
	// once, so each replaces the other's set instead of merging with it.
	// SQLite already serialises writers and has no row locks.
	if tx.Name() != gormDialectSQLite {
		err := tx.Clauses(clause.Locking{Strength: clause.LockingStrengthUpdate}).
			Select("id").
			First(&types.User{}, uint(uid)).Error
		if err != nil {
			return false, fmt.Errorf("locking user: %w", err)
		}
	}

	var current []string

	err := tx.Model(&types.UserGroup{}).
		Joins("JOIN groups ON groups.id = user_groups.group_id").
		Where("user_groups.user_id = ? AND user_groups.source = ?", uid, source).
		Pluck("groups.name", &current).Error
	if err != nil {
		return false, fmt.Errorf("loading group memberships: %w", err)
	}

	// Sorted here rather than by the database, whose collation need not
	// match Go's byte order.
	slices.Sort(current)

	if slices.Equal(current, groups) {
		return false, nil
	}

	groupIDs, err := ensureGroups(tx, groups)
	if err != nil {
		return false, err
	}

	remove := tx.Where("user_id = ? AND source = ?", uid, source)
	if len(groupIDs) > 0 {
		remove = remove.Where("group_id NOT IN ?", groupIDs)
	}

	err = remove.Delete(&types.UserGroup{}).Error
	if err != nil {
		return false, fmt.Errorf("removing group memberships: %w", err)
	}

	if len(groupIDs) == 0 {
		return true, nil
	}

	now := time.Now().UTC()

	memberships := make([]types.UserGroup, 0, len(groupIDs))
	for _, gid := range groupIDs {
		memberships = append(memberships, types.UserGroup{
			UserID:    uint(uid),
			GroupID:   gid,
			Source:    source,
			CreatedAt: now,
		})
	}

	err = tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&memberships).Error
	if err != nil {
		return false, fmt.Errorf("adding group memberships: %w", err)
	}

	return true, nil
}

// ensureGroups creates any of names that do not exist and returns the ids of
// all of them.
func ensureGroups(tx *gorm.DB, names []string) ([]uint, error) {
	if len(names) == 0 {
		return nil, nil
	}

	now := time.Now().UTC()

	rows := make([]types.Group, 0, len(names))
	for _, name := range names {
		rows = append(rows, types.Group{Name: name, CreatedAt: now, UpdatedAt: now})
	}

	err := tx.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "name"}},
		DoNothing: true,
	}).Create(&rows).Error
	if err != nil {
		return nil, fmt.Errorf("creating groups: %w", err)
	}

	var ids []uint

	err = tx.Model(&types.Group{}).Where("name IN ?", names).Pluck("id", &ids).Error
	if err != nil {
		return nil, fmt.Errorf("loading group ids: %w", err)
	}

	if len(ids) != len(names) {
		return nil, fmt.Errorf("%w: read back %d of %d", ErrGroupsNotStored, len(ids), len(names))
	}

	return ids, nil
}

// PruneGroupMemberships removes memberships from source whose group is not
// qualified with keepDomain, or all of source's memberships when keepDomain
// is empty. It runs at startup so that disabling group sync, or changing its
// domain, revokes the affected memberships immediately instead of at each
// user's next login. It returns the number of memberships removed.
func PruneGroupMemberships(tx *gorm.DB, source types.GroupSource, keepDomain string) (int64, error) {
	remove := tx.Where("source = ?", source)

	if keepDomain != "" {
		suffix := "@" + types.FoldGroupName(keepDomain)

		var stale []uint

		var groups []types.Group

		err := tx.Find(&groups).Error
		if err != nil {
			return 0, fmt.Errorf("loading groups: %w", err)
		}

		for _, g := range groups {
			if !strings.HasSuffix(g.Name, suffix) {
				stale = append(stale, g.ID)
			}
		}

		if len(stale) == 0 {
			return 0, nil
		}

		remove = remove.Where("group_id IN ?", stale)
	}

	res := remove.Delete(&types.UserGroup{})
	if res.Error != nil {
		return 0, fmt.Errorf("pruning group memberships: %w", res.Error)
	}

	return res.RowsAffected, nil
}
