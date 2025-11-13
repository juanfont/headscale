package db

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"
	"slices"
	"strconv"
	"time"

	"github.com/glebarez/sqlite"
	"github.com/go-gormigrate/gormigrate/v2"
	"github.com/juanfont/headscale/hscontrol/db/sqliteconfig"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/rs/zerolog/log"
	"github.com/tailscale/squibble"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
	"gorm.io/gorm/schema"
	"tailscale.com/net/tsaddr"
	"zgo.at/zcache/v2"
)

//go:embed schema.sql
var dbSchema string

func init() {
	schema.RegisterSerializer("text", TextSerialiser{})
}

var errDatabaseNotSupported = errors.New("database type not supported")

var errForeignKeyConstraintsViolated = errors.New("foreign key constraints violated")

const (
	maxIdleConns       = 100
	maxOpenConns       = 100
	contextTimeoutSecs = 10
)

// KV is a key-value store in a psql table. For future use...
// TODO(kradalby): Is this used for anything?
type KV struct {
	Key   string
	Value string
}

type HSDatabase struct {
	DB       *gorm.DB
	cfg      *types.DatabaseConfig
	regCache *zcache.Cache[types.RegistrationID, types.RegisterNode]

	baseDomain string
}

// TODO(kradalby): assemble this struct from toptions or something typed
// rather than arguments.
func NewHeadscaleDatabase(
	cfg types.DatabaseConfig,
	baseDomain string,
	regCache *zcache.Cache[types.RegistrationID, types.RegisterNode],
) (*HSDatabase, error) {
	dbConn, err := openDB(cfg)
	if err != nil {
		return nil, err
	}

	migrations := gormigrate.New(
		dbConn,
		gormigrate.DefaultOptions,
		[]*gormigrate.Migration{
			// New migrations must be added as transactions at the end of this list.
			// Migrations start from v0.25.0. If upgrading from v0.24.x or earlier,
			// you must first upgrade to v0.25.1 before upgrading to this version.

			// v0.25.0
			{
				// Add a constraint to routes ensuring they cannot exist without a node.
				ID: "202501221827",
				Migrate: func(tx *gorm.DB) error {
					// Remove any invalid routes associated with a node that does not exist.
					if tx.Migrator().HasTable(&types.Route{}) && tx.Migrator().HasTable(&types.Node{}) {
						err := tx.Exec("delete from routes where node_id not in (select id from nodes)").Error
						if err != nil {
							return err
						}
					}

					// Remove any invalid routes without a node_id.
					if tx.Migrator().HasTable(&types.Route{}) {
						err := tx.Exec("delete from routes where node_id is null").Error
						if err != nil {
							return err
						}
					}

					err := tx.AutoMigrate(&types.Route{})
					if err != nil {
						return fmt.Errorf("automigrating types.Route: %w", err)
					}

					return nil
				},
				Rollback: func(db *gorm.DB) error { return nil },
			},
			// Add back constraint so you cannot delete preauth keys that
			// is still used by a node.
			{
				ID: "202501311657",
				Migrate: func(tx *gorm.DB) error {
					err := tx.AutoMigrate(&types.PreAuthKey{})
					if err != nil {
						return fmt.Errorf("automigrating types.PreAuthKey: %w", err)
					}
					err = tx.AutoMigrate(&types.Node{})
					if err != nil {
						return fmt.Errorf("automigrating types.Node: %w", err)
					}

					return nil
				},
				Rollback: func(db *gorm.DB) error { return nil },
			},
			// Ensure there are no nodes referring to a deleted preauthkey.
			{
				ID: "202502070949",
				Migrate: func(tx *gorm.DB) error {
					if tx.Migrator().HasTable(&types.PreAuthKey{}) {
						err := tx.Exec(`
UPDATE nodes
SET auth_key_id = NULL
WHERE auth_key_id IS NOT NULL
AND auth_key_id NOT IN (
    SELECT id FROM pre_auth_keys
);
							`).Error
						if err != nil {
							return fmt.Errorf("setting auth_key to null on nodes with non-existing keys: %w", err)
						}
					}

					return nil
				},
				Rollback: func(db *gorm.DB) error { return nil },
			},
			// v0.26.0
			// Migrate all routes from the Route table to the new field ApprovedRoutes
			// in the Node table. Then drop the Route table.
			{
				ID: "202502131714",
				Migrate: func(tx *gorm.DB) error {
					if !tx.Migrator().HasColumn(&types.Node{}, "approved_routes") {
						err := tx.Migrator().AddColumn(&types.Node{}, "approved_routes")
						if err != nil {
							return fmt.Errorf("adding column types.Node: %w", err)
						}
					}

					nodeRoutes := map[uint64][]netip.Prefix{}

					var routes []types.Route
					err = tx.Find(&routes).Error
					if err != nil {
						return fmt.Errorf("fetching routes: %w", err)
					}

					for _, route := range routes {
						if route.Enabled {
							nodeRoutes[route.NodeID] = append(nodeRoutes[route.NodeID], route.Prefix)
						}
					}

					for nodeID, routes := range nodeRoutes {
						tsaddr.SortPrefixes(routes)
						routes = slices.Compact(routes)

						data, err := json.Marshal(routes)

						err = tx.Model(&types.Node{}).Where("id = ?", nodeID).Update("approved_routes", data).Error
						if err != nil {
							return fmt.Errorf("saving approved routes to new column: %w", err)
						}
					}

					// Drop the old table.
					_ = tx.Migrator().DropTable(&types.Route{})

					return nil
				},
				Rollback: func(db *gorm.DB) error { return nil },
			},
			{
				ID: "202502171819",
				Migrate: func(tx *gorm.DB) error {
					// This migration originally removed the last_seen column
					// from the node table, but it was added back in
					// 202505091439.
					return nil
				},
				Rollback: func(db *gorm.DB) error { return nil },
			},
			// Add back last_seen column to node table.
			{
				ID: "202505091439",
				Migrate: func(tx *gorm.DB) error {
					// Add back last_seen column to node table if it does not exist.
					// This is a workaround for the fact that the last_seen column
					// was removed in the 202502171819 migration, but only for some
					// beta testers.
					if !tx.Migrator().HasColumn(&types.Node{}, "last_seen") {
						_ = tx.Migrator().AddColumn(&types.Node{}, "last_seen")
					}

					return nil
				},
				Rollback: func(db *gorm.DB) error { return nil },
			},
			// Fix the provider identifier for users that have a double slash in the
			// provider identifier.
			{
				ID: "202505141324",
				Migrate: func(tx *gorm.DB) error {
					users, err := ListUsers(tx)
					if err != nil {
						return fmt.Errorf("listing users: %w", err)
					}

					for _, user := range users {
						user.ProviderIdentifier.String = types.CleanIdentifier(user.ProviderIdentifier.String)

						err := tx.Save(user).Error
						if err != nil {
							return fmt.Errorf("saving user: %w", err)
						}
					}

					return nil
				},
				Rollback: func(db *gorm.DB) error { return nil },
			},
			// v0.27.0
			// Schema migration to ensure all tables match the expected schema.
			// This migration recreates all tables to match the exact structure in schema.sql,
			// preserving all data during the process.
			// Only SQLite will be migrated for consistency.
			{
				ID: "202507021200",
				Migrate: func(tx *gorm.DB) error {
					// Only run on SQLite
					if cfg.Type != types.DatabaseSqlite {
						log.Info().Msg("Skipping schema migration on non-SQLite database")
						return nil
					}

					log.Info().Msg("Starting schema recreation with table renaming")

					// Rename existing tables to _old versions
					tablesToRename := []string{"users", "pre_auth_keys", "api_keys", "nodes", "policies"}

					// Check if routes table exists and drop it (should have been migrated already)
					var routesExists bool
					err := tx.Raw("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='routes'").Row().Scan(&routesExists)
					if err == nil && routesExists {
						log.Info().Msg("Dropping leftover routes table")
						if err := tx.Exec("DROP TABLE routes").Error; err != nil {
							return fmt.Errorf("dropping routes table: %w", err)
						}
					}

					// Drop all indexes first to avoid conflicts
					indexesToDrop := []string{
						"idx_users_deleted_at",
						"idx_provider_identifier",
						"idx_name_provider_identifier",
						"idx_name_no_provider_identifier",
						"idx_api_keys_prefix",
						"idx_policies_deleted_at",
					}

					for _, index := range indexesToDrop {
						_ = tx.Exec("DROP INDEX IF EXISTS " + index).Error
					}

					for _, table := range tablesToRename {
						// Check if table exists before renaming
						var exists bool
						err := tx.Raw("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?", table).Row().Scan(&exists)
						if err != nil {
							return fmt.Errorf("checking if table %s exists: %w", table, err)
						}

						if exists {
							// Drop old table if it exists from previous failed migration
							_ = tx.Exec("DROP TABLE IF EXISTS " + table + "_old").Error

							// Rename current table to _old
							if err := tx.Exec("ALTER TABLE " + table + " RENAME TO " + table + "_old").Error; err != nil {
								return fmt.Errorf("renaming table %s to %s_old: %w", table, table, err)
							}
						}
					}

					// Create new tables with correct schema
					tableCreationSQL := []string{
						`CREATE TABLE users(
  id integer PRIMARY KEY AUTOINCREMENT,
  name text,
  display_name text,
  email text,
  provider_identifier text,
  provider text,
  profile_pic_url text,
  created_at datetime,
  updated_at datetime,
  deleted_at datetime
)`,
						`CREATE TABLE pre_auth_keys(
  id integer PRIMARY KEY AUTOINCREMENT,
  key text,
  user_id integer,
  reusable numeric,
  ephemeral numeric DEFAULT false,
  used numeric DEFAULT false,
  tags text,
  expiration datetime,
  created_at datetime,
  CONSTRAINT fk_pre_auth_keys_user FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE SET NULL
)`,
						`CREATE TABLE api_keys(
  id integer PRIMARY KEY AUTOINCREMENT,
  prefix text,
  hash blob,
  expiration datetime,
  last_seen datetime,
  created_at datetime
)`,
						`CREATE TABLE nodes(
  id integer PRIMARY KEY AUTOINCREMENT,
  machine_key text,
  node_key text,
  disco_key text,
  endpoints text,
  host_info text,
  ipv4 text,
  ipv6 text,
  hostname text,
  given_name varchar(63),
  user_id integer,
  register_method text,
  forced_tags text,
  auth_key_id integer,
  last_seen datetime,
  expiry datetime,
  approved_routes text,
  created_at datetime,
  updated_at datetime,
  deleted_at datetime,
  CONSTRAINT fk_nodes_user FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
  CONSTRAINT fk_nodes_auth_key FOREIGN KEY(auth_key_id) REFERENCES pre_auth_keys(id)
)`,
						`CREATE TABLE policies(
  id integer PRIMARY KEY AUTOINCREMENT,
  data text,
  created_at datetime,
  updated_at datetime,
  deleted_at datetime
)`,
					}

					for _, createSQL := range tableCreationSQL {
						if err := tx.Exec(createSQL).Error; err != nil {
							return fmt.Errorf("creating new table: %w", err)
						}
					}

					// Copy data directly using SQL
					dataCopySQL := []string{
						`INSERT INTO users (id, name, display_name, email, provider_identifier, provider, profile_pic_url, created_at, updated_at, deleted_at)
             SELECT id, name, display_name, email, provider_identifier, provider, profile_pic_url, created_at, updated_at, deleted_at
             FROM users_old`,

						`INSERT INTO pre_auth_keys (id, key, user_id, reusable, ephemeral, used, tags, expiration, created_at)
             SELECT id, key, user_id, reusable, ephemeral, used, tags, expiration, created_at
             FROM pre_auth_keys_old`,

						`INSERT INTO api_keys (id, prefix, hash, expiration, last_seen, created_at)
             SELECT id, prefix, hash, expiration, last_seen, created_at
             FROM api_keys_old`,

						`INSERT INTO nodes (id, machine_key, node_key, disco_key, endpoints, host_info, ipv4, ipv6, hostname, given_name, user_id, register_method, forced_tags, auth_key_id, last_seen, expiry, approved_routes, created_at, updated_at, deleted_at)
             SELECT id, machine_key, node_key, disco_key, endpoints, host_info, ipv4, ipv6, hostname, given_name, user_id, register_method, forced_tags, auth_key_id, last_seen, expiry, approved_routes, created_at, updated_at, deleted_at
             FROM nodes_old`,

						`INSERT INTO policies (id, data, created_at, updated_at, deleted_at)
             SELECT id, data, created_at, updated_at, deleted_at
             FROM policies_old`,
					}

					for _, copySQL := range dataCopySQL {
						if err := tx.Exec(copySQL).Error; err != nil {
							return fmt.Errorf("copying data: %w", err)
						}
					}

					// Create indexes
					indexes := []string{
						"CREATE INDEX idx_users_deleted_at ON users(deleted_at)",
						`CREATE UNIQUE INDEX idx_provider_identifier ON users(
  provider_identifier
) WHERE provider_identifier IS NOT NULL`,
						`CREATE UNIQUE INDEX idx_name_provider_identifier ON users(
  name,
  provider_identifier
)`,
						`CREATE UNIQUE INDEX idx_name_no_provider_identifier ON users(
  name
) WHERE provider_identifier IS NULL`,
						"CREATE UNIQUE INDEX idx_api_keys_prefix ON api_keys(prefix)",
						"CREATE INDEX idx_policies_deleted_at ON policies(deleted_at)",
					}

					for _, indexSQL := range indexes {
						if err := tx.Exec(indexSQL).Error; err != nil {
							return fmt.Errorf("creating index: %w", err)
						}
					}

					// Drop old tables only after everything succeeds
					for _, table := range tablesToRename {
						if err := tx.Exec("DROP TABLE IF EXISTS " + table + "_old").Error; err != nil {
							log.Warn().Str("table", table+"_old").Err(err).Msg("Failed to drop old table, but migration succeeded")
						}
					}

					log.Info().Msg("Schema recreation completed successfully")

					return nil
				},
				Rollback: func(db *gorm.DB) error { return nil },
			},
			// v0.27.1
			{
				// Drop all tables that are no longer in use and has existed.
				// They potentially still present from broken migrations in the past.
				ID: "202510311551",
				Migrate: func(tx *gorm.DB) error {
					for _, oldTable := range []string{"namespaces", "machines", "shared_machines", "kvs", "pre_auth_key_acl_tags", "routes"} {
						err := tx.Migrator().DropTable(oldTable)
						if err != nil {
							log.Trace().Str("table", oldTable).
								Err(err).
								Msg("Error dropping old table, continuing...")
						}
					}

					return nil
				},
				Rollback: func(tx *gorm.DB) error {
					return nil
				},
			},
			{
				// Drop all indices that are no longer in use and has existed.
				// They potentially still present from broken migrations in the past.
				// They should all be cleaned up by the db engine, but we are a bit
				// conservative to ensure all our previous mess is cleaned up.
				ID: "202511101554-drop-old-idx",
				Migrate: func(tx *gorm.DB) error {
					for _, oldIdx := range []struct{ name, table string }{
						{"idx_namespaces_deleted_at", "namespaces"},
						{"idx_routes_deleted_at", "routes"},
						{"idx_shared_machines_deleted_at", "shared_machines"},
					} {
						err := tx.Migrator().DropIndex(oldIdx.table, oldIdx.name)
						if err != nil {
							log.Trace().
								Str("index", oldIdx.name).
								Str("table", oldIdx.table).
								Err(err).
								Msg("Error dropping old index, continuing...")
						}
					}

					return nil
				},
				Rollback: func(tx *gorm.DB) error {
					return nil
				},
			},

			// Migrations **above** this points will be REMOVED in version **0.29.0**
			// This is to clean up a lot of old migrations that is seldom used
			// and carries a lot of technical debt.
			// Any new migrations should be added after the comment below and follow
			// the rules it sets out.

			// From this point, the following rules must be followed:
			// - NEVER use gorm.AutoMigrate, write the exact migration steps needed
			// - AutoMigrate depends on the struct staying exactly the same, which it won't over time.
			// - Never write migrations that requires foreign keys to be disabled.

			{
				// Add columns for prefix and hash for pre auth keys, implementing
				// them with the same security model as api keys.
				ID: "202511011637-preauthkey-bcrypt",
				Migrate: func(tx *gorm.DB) error {
					// Check and add prefix column if it doesn't exist
					if !tx.Migrator().HasColumn(&types.PreAuthKey{}, "prefix") {
						err := tx.Migrator().AddColumn(&types.PreAuthKey{}, "prefix")
						if err != nil {
							return fmt.Errorf("adding prefix column: %w", err)
						}
					}

					// Check and add hash column if it doesn't exist
					if !tx.Migrator().HasColumn(&types.PreAuthKey{}, "hash") {
						err := tx.Migrator().AddColumn(&types.PreAuthKey{}, "hash")
						if err != nil {
							return fmt.Errorf("adding hash column: %w", err)
						}
					}

					// Create partial unique index to allow multiple legacy keys (NULL/empty prefix)
					// while enforcing uniqueness for new bcrypt-based keys
					err := tx.Exec("CREATE UNIQUE INDEX IF NOT EXISTS idx_pre_auth_keys_prefix ON pre_auth_keys(prefix) WHERE prefix IS NOT NULL AND prefix != ''").Error
					if err != nil {
						return fmt.Errorf("creating prefix index: %w", err)
					}

					return nil
				},
				Rollback: func(db *gorm.DB) error { return nil },
			},
			{
				ID: "202511122344-remove-newline-index",
				Migrate: func(tx *gorm.DB) error {
					// Reformat multi-line indexes to single-line for consistency
					// This migration drops and recreates the three user identity indexes
					// to match the single-line format expected by schema validation

					// Drop existing multi-line indexes
					dropIndexes := []string{
						`DROP INDEX IF EXISTS idx_provider_identifier`,
						`DROP INDEX IF EXISTS idx_name_provider_identifier`,
						`DROP INDEX IF EXISTS idx_name_no_provider_identifier`,
					}

					for _, dropSQL := range dropIndexes {
						err := tx.Exec(dropSQL).Error
						if err != nil {
							return fmt.Errorf("dropping index: %w", err)
						}
					}

					// Recreate indexes in single-line format
					createIndexes := []string{
						`CREATE UNIQUE INDEX idx_provider_identifier ON users(provider_identifier) WHERE provider_identifier IS NOT NULL`,
						`CREATE UNIQUE INDEX idx_name_provider_identifier ON users(name, provider_identifier)`,
						`CREATE UNIQUE INDEX idx_name_no_provider_identifier ON users(name) WHERE provider_identifier IS NULL`,
					}

					for _, createSQL := range createIndexes {
						err := tx.Exec(createSQL).Error
						if err != nil {
							return fmt.Errorf("creating index: %w", err)
						}
					}

					return nil
				},
				Rollback: func(db *gorm.DB) error { return nil },
			},
		},
	)

	migrations.InitSchema(func(tx *gorm.DB) error {
		// Create all tables using AutoMigrate
		err := tx.AutoMigrate(
			&types.User{},
			&types.PreAuthKey{},
			&types.APIKey{},
			&types.Node{},
			&types.Policy{},
		)
		if err != nil {
			return err
		}

		// Drop all indexes (both GORM-created and potentially pre-existing ones)
		// to ensure we can recreate them in the correct format
		dropIndexes := []string{
			`DROP INDEX IF EXISTS "idx_users_deleted_at"`,
			`DROP INDEX IF EXISTS "idx_api_keys_prefix"`,
			`DROP INDEX IF EXISTS "idx_policies_deleted_at"`,
			`DROP INDEX IF EXISTS "idx_provider_identifier"`,
			`DROP INDEX IF EXISTS "idx_name_provider_identifier"`,
			`DROP INDEX IF EXISTS "idx_name_no_provider_identifier"`,
			`DROP INDEX IF EXISTS "idx_pre_auth_keys_prefix"`,
		}

		for _, dropSQL := range dropIndexes {
			err := tx.Exec(dropSQL).Error
			if err != nil {
				return err
			}
		}

		// Recreate indexes without backticks to match schema.sql format
		indexes := []string{
			`CREATE INDEX idx_users_deleted_at ON users(deleted_at)`,
			`CREATE UNIQUE INDEX idx_api_keys_prefix ON api_keys(prefix)`,
			`CREATE INDEX idx_policies_deleted_at ON policies(deleted_at)`,
			`CREATE UNIQUE INDEX idx_provider_identifier ON users(provider_identifier) WHERE provider_identifier IS NOT NULL`,
			`CREATE UNIQUE INDEX idx_name_provider_identifier ON users(name, provider_identifier)`,
			`CREATE UNIQUE INDEX idx_name_no_provider_identifier ON users(name) WHERE provider_identifier IS NULL`,
			`CREATE UNIQUE INDEX idx_pre_auth_keys_prefix ON pre_auth_keys(prefix) WHERE prefix IS NOT NULL AND prefix != ''`,
		}

		for _, indexSQL := range indexes {
			err := tx.Exec(indexSQL).Error
			if err != nil {
				return err
			}
		}

		return nil
	})

	if err := runMigrations(cfg, dbConn, migrations); err != nil {
		return nil, fmt.Errorf("migration failed: %w", err)
	}

	// Validate that the schema ends up in the expected state.
	// This is currently only done on sqlite as squibble does not
	// support Postgres and we use our sqlite schema as our source of
	// truth.
	if cfg.Type == types.DatabaseSqlite {
		sqlConn, err := dbConn.DB()
		if err != nil {
			return nil, fmt.Errorf("getting DB from gorm: %w", err)
		}

		// or else it blocks...
		sqlConn.SetMaxIdleConns(maxIdleConns)
		sqlConn.SetMaxOpenConns(maxOpenConns)
		defer sqlConn.SetMaxIdleConns(1)
		defer sqlConn.SetMaxOpenConns(1)

		ctx, cancel := context.WithTimeout(context.Background(), contextTimeoutSecs*time.Second)
		defer cancel()

		opts := squibble.DigestOptions{
			IgnoreTables: []string{
				// Litestream tables, these are inserted by
				// litestream and not part of our schema
				// https://litestream.io/how-it-works
				"_litestream_lock",
				"_litestream_seq",
			},
		}

		if err := squibble.Validate(ctx, sqlConn, dbSchema, &opts); err != nil {
			return nil, fmt.Errorf("validating schema: %w", err)
		}
	}

	db := HSDatabase{
		DB:       dbConn,
		cfg:      &cfg,
		regCache: regCache,

		baseDomain: baseDomain,
	}

	return &db, err
}

func openDB(cfg types.DatabaseConfig) (*gorm.DB, error) {
	// TODO(kradalby): Integrate this with zerolog
	var dbLogger logger.Interface
	if cfg.Debug {
		dbLogger = util.NewDBLogWrapper(&log.Logger, cfg.Gorm.SlowThreshold, cfg.Gorm.SkipErrRecordNotFound, cfg.Gorm.ParameterizedQueries)
	} else {
		dbLogger = logger.Default.LogMode(logger.Silent)
	}

	switch cfg.Type {
	case types.DatabaseSqlite:
		dir := filepath.Dir(cfg.Sqlite.Path)
		err := util.EnsureDir(dir)
		if err != nil {
			return nil, fmt.Errorf("creating directory for sqlite: %w", err)
		}

		log.Info().
			Str("database", types.DatabaseSqlite).
			Str("path", cfg.Sqlite.Path).
			Msg("Opening database")

		// Build SQLite configuration with pragmas set at connection time
		sqliteConfig := sqliteconfig.Default(cfg.Sqlite.Path)
		if cfg.Sqlite.WriteAheadLog {
			sqliteConfig.JournalMode = sqliteconfig.JournalModeWAL
			sqliteConfig.WALAutocheckpoint = cfg.Sqlite.WALAutoCheckPoint
		}

		connectionURL, err := sqliteConfig.ToURL()
		if err != nil {
			return nil, fmt.Errorf("building sqlite connection URL: %w", err)
		}

		db, err := gorm.Open(
			sqlite.Open(connectionURL),
			&gorm.Config{
				PrepareStmt: cfg.Gorm.PrepareStmt,
				Logger:      dbLogger,
			},
		)

		// The pure Go SQLite library does not handle locking in
		// the same way as the C based one and we can't use the gorm
		// connection pool as of 2022/02/23.
		sqlDB, _ := db.DB()
		sqlDB.SetMaxIdleConns(1)
		sqlDB.SetMaxOpenConns(1)
		sqlDB.SetConnMaxIdleTime(time.Hour)

		return db, err

	case types.DatabasePostgres:
		dbString := fmt.Sprintf(
			"host=%s dbname=%s user=%s",
			cfg.Postgres.Host,
			cfg.Postgres.Name,
			cfg.Postgres.User,
		)

		log.Info().
			Str("database", types.DatabasePostgres).
			Str("path", dbString).
			Msg("Opening database")

		if sslEnabled, err := strconv.ParseBool(cfg.Postgres.Ssl); err == nil {
			if !sslEnabled {
				dbString += " sslmode=disable"
			}
		} else {
			dbString += " sslmode=" + cfg.Postgres.Ssl
		}

		if cfg.Postgres.Port != 0 {
			dbString += fmt.Sprintf(" port=%d", cfg.Postgres.Port)
		}

		if cfg.Postgres.Pass != "" {
			dbString += " password=" + cfg.Postgres.Pass
		}

		db, err := gorm.Open(postgres.Open(dbString), &gorm.Config{
			Logger: dbLogger,
		})
		if err != nil {
			return nil, err
		}

		sqlDB, _ := db.DB()
		sqlDB.SetMaxIdleConns(cfg.Postgres.MaxIdleConnections)
		sqlDB.SetMaxOpenConns(cfg.Postgres.MaxOpenConnections)
		sqlDB.SetConnMaxIdleTime(
			time.Duration(cfg.Postgres.ConnMaxIdleTimeSecs) * time.Second,
		)

		return db, nil
	}

	return nil, fmt.Errorf(
		"database of type %s is not supported: %w",
		cfg.Type,
		errDatabaseNotSupported,
	)
}

func runMigrations(cfg types.DatabaseConfig, dbConn *gorm.DB, migrations *gormigrate.Gormigrate) error {
	if cfg.Type == types.DatabaseSqlite {
		// SQLite: Run migrations step-by-step, only disabling foreign keys when necessary

		// List of migration IDs that require foreign keys to be disabled
		// These are migrations that perform complex schema changes that GORM cannot handle safely with FK enabled
		// NO NEW MIGRATIONS SHOULD BE ADDED HERE. ALL NEW MIGRATIONS MUST RUN WITH FOREIGN KEYS ENABLED.
		migrationsRequiringFKDisabled := map[string]bool{
			"202501221827": true, // Route table automigration with FK constraint issues
			"202501311657": true, // PreAuthKey table automigration with FK constraint issues
			// Add other migration IDs here as they are identified to need FK disabled
		}

		// Get the current foreign key status
		var fkOriginallyEnabled int
		if err := dbConn.Raw("PRAGMA foreign_keys").Scan(&fkOriginallyEnabled).Error; err != nil {
			return fmt.Errorf("checking foreign key status: %w", err)
		}

		// Get all migration IDs in order from the actual migration definitions
		// Only IDs that are in the migrationsRequiringFKDisabled map will be processed with FK disabled
		// any other new migrations are ran after.
		migrationIDs := []string{
			// v0.25.0
			"202501221827",
			"202501311657",
			"202502070949",

			// v0.26.0
			"202502131714",
			"202502171819",
			"202505091439",
			"202505141324",

			// As of 2025-07-02, no new IDs should be added here.
			// They will be ran by the migrations.Migrate() call below.
		}

		for _, migrationID := range migrationIDs {
			log.Trace().Caller().Str("migration_id", migrationID).Msg("Running migration")
			needsFKDisabled := migrationsRequiringFKDisabled[migrationID]

			if needsFKDisabled {
				// Disable foreign keys for this migration
				if err := dbConn.Exec("PRAGMA foreign_keys = OFF").Error; err != nil {
					return fmt.Errorf("disabling foreign keys for migration %s: %w", migrationID, err)
				}
			} else {
				// Ensure foreign keys are enabled for this migration
				if err := dbConn.Exec("PRAGMA foreign_keys = ON").Error; err != nil {
					return fmt.Errorf("enabling foreign keys for migration %s: %w", migrationID, err)
				}
			}

			// Run up to this specific migration (will only run the next pending migration)
			if err := migrations.MigrateTo(migrationID); err != nil {
				return fmt.Errorf("running migration %s: %w", migrationID, err)
			}
		}

		if err := dbConn.Exec("PRAGMA foreign_keys = ON").Error; err != nil {
			return fmt.Errorf("restoring foreign keys: %w", err)
		}

		// Run the rest of the migrations
		if err := migrations.Migrate(); err != nil {
			return err
		}

		// Check for constraint violations at the end
		type constraintViolation struct {
			Table           string
			RowID           int
			Parent          string
			ConstraintIndex int
		}

		var violatedConstraints []constraintViolation

		rows, err := dbConn.Raw("PRAGMA foreign_key_check").Rows()
		if err != nil {
			return err
		}

		for rows.Next() {
			var violation constraintViolation
			if err := rows.Scan(&violation.Table, &violation.RowID, &violation.Parent, &violation.ConstraintIndex); err != nil {
				return err
			}

			violatedConstraints = append(violatedConstraints, violation)
		}
		_ = rows.Close()

		if len(violatedConstraints) > 0 {
			for _, violation := range violatedConstraints {
				log.Error().
					Str("table", violation.Table).
					Int("row_id", violation.RowID).
					Str("parent", violation.Parent).
					Msg("Foreign key constraint violated")
			}

			return errForeignKeyConstraintsViolated
		}
	} else {
		// PostgreSQL can run all migrations in one block - no foreign key issues
		if err := migrations.Migrate(); err != nil {
			return err
		}
	}

	return nil
}

func (hsdb *HSDatabase) PingDB(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	sqlDB, err := hsdb.DB.DB()
	if err != nil {
		return err
	}

	return sqlDB.PingContext(ctx)
}

func (hsdb *HSDatabase) Close() error {
	db, err := hsdb.DB.DB()
	if err != nil {
		return err
	}

	if hsdb.cfg.Type == types.DatabaseSqlite && hsdb.cfg.Sqlite.WriteAheadLog {
		db.Exec("VACUUM")
	}

	return db.Close()
}

func (hsdb *HSDatabase) Read(fn func(rx *gorm.DB) error) error {
	rx := hsdb.DB.Begin()
	defer rx.Rollback()
	return fn(rx)
}

func Read[T any](db *gorm.DB, fn func(rx *gorm.DB) (T, error)) (T, error) {
	rx := db.Begin()
	defer rx.Rollback()
	ret, err := fn(rx)
	if err != nil {
		var no T
		return no, err
	}

	return ret, nil
}

func (hsdb *HSDatabase) Write(fn func(tx *gorm.DB) error) error {
	tx := hsdb.DB.Begin()
	defer tx.Rollback()
	if err := fn(tx); err != nil {
		return err
	}

	return tx.Commit().Error
}

func Write[T any](db *gorm.DB, fn func(tx *gorm.DB) (T, error)) (T, error) {
	tx := db.Begin()
	defer tx.Rollback()
	ret, err := fn(tx)
	if err != nil {
		var no T
		return no, err
	}

	return ret, tx.Commit().Error
}
