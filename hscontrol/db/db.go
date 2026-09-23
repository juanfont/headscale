package db

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"path/filepath"
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
)

//go:embed schema.sql
var dbSchema string

func init() {
	schema.RegisterSerializer("text", TextSerialiser{})
}

var errDatabaseNotSupported = errors.New("database type not supported")

var errForeignKeyConstraintsViolated = errors.New("foreign key constraints violated")

const (
	maxIdleConns   = 100
	maxOpenConns   = 100
	contextTimeout = 10 * time.Second
)

type HSDatabase struct {
	DB  *gorm.DB
	cfg *types.Config
}

// NewHeadscaleDatabase creates a new database connection and runs migrations.
//
//nolint:gocyclo // migration closures inflate the count; each is linear
func NewHeadscaleDatabase(cfg *types.Config) (*HSDatabase, error) {
	dbConn, err := openDB(cfg.Database)
	if err != nil {
		return nil, err
	}

	err = checkMinimumMigration(dbConn)
	if err != nil {
		return nil, fmt.Errorf("version check: %w", err)
	}

	err = checkVersionUpgradePath(dbConn)
	if err != nil {
		return nil, fmt.Errorf("version check: %w", err)
	}

	migrations := gormigrate.New(
		dbConn,
		gormigrate.DefaultOptions,
		[]*gormigrate.Migration{
			// New migrations must be added as transactions at the end of this list.
			// Migrations start from v0.29.0; older databases are rejected by
			// checkMinimumMigration and must upgrade to the latest 0.29.x first.
			//
			// Rules:
			// - NEVER use gorm.AutoMigrate, write the exact migration steps needed
			// - AutoMigrate depends on the struct staying exactly the same, which it won't over time.
			// - Never write migrations that requires foreign keys to be disabled.
			// - ALL errors in migrations must be handled properly.
			{
				// Recover user_id on untagged nodes detached by the earlier
				// version of 202602201200-clear-tagged-node-user-id, which
				// treated tags='null' as tagged and cleared the user. This
				// repairs databases that already upgraded to 0.29.0; databases
				// that took the fixed migration find nothing to repair.
				// Recovery is best-effort: the owner is re-derived from the
				// node's pre-auth key, so nodes registered via CLI/OIDC (no
				// pre-auth key) cannot be recovered and must be reassigned
				// manually.
				// Fixes: https://github.com/juanfont/headscale/issues/3323
				ID: "202606181200-recover-null-tags-node-user-id",
				Migrate: func(tx *gorm.DB) error {
					err := tx.Exec(`
UPDATE nodes
SET user_id = (
	SELECT pak.user_id FROM pre_auth_keys pak WHERE pak.id = nodes.auth_key_id
)
WHERE user_id IS NULL
	AND auth_key_id IS NOT NULL
	AND (tags IS NULL OR tags = '' OR tags = '[]' OR tags = 'null');
						`).Error
					if err != nil {
						return fmt.Errorf("recovering user_id on untagged nodes: %w", err)
					}

					return nil
				},
				Rollback: func(db *gorm.DB) error { return nil },
			},
			{
				// Add an optional owning user to API keys so the v2 API can
				// create user-owned (untagged) auth keys, mirroring Tailscale's
				// "key owned by the creating identity".
				ID: "202606191500-api-key-user-id",
				Migrate: func(tx *gorm.DB) error {
					if !tx.Migrator().HasColumn(&types.APIKey{}, "user_id") {
						err := tx.Migrator().AddColumn(&types.APIKey{}, "user_id")
						if err != nil {
							return fmt.Errorf("adding user_id to api_keys: %w", err)
						}
					}

					return nil
				},
				Rollback: func(db *gorm.DB) error { return nil },
			},
			{
				// Add a free-text description to pre-auth keys, set via the
				// v2 keys API.
				ID: "202606191501-pre-auth-key-description",
				Migrate: func(tx *gorm.DB) error {
					if !tx.Migrator().HasColumn(&types.PreAuthKey{}, "description") {
						err := tx.Migrator().AddColumn(&types.PreAuthKey{}, "description")
						if err != nil {
							return fmt.Errorf("adding description to pre_auth_keys: %w", err)
						}
					}

					return nil
				},
				Rollback: func(db *gorm.DB) error { return nil },
			},
			{
				// Add a revoked timestamp to pre-auth keys. The v2 API's DELETE
				// soft-revokes a key (set revoked = now) rather than destroying
				// it; the row is reaped later by the background collector.
				ID: "202606201200-pre-auth-key-revoked",
				Migrate: func(tx *gorm.DB) error {
					if !tx.Migrator().HasColumn(&types.PreAuthKey{}, "revoked") {
						err := tx.Migrator().AddColumn(&types.PreAuthKey{}, "revoked")
						if err != nil {
							return fmt.Errorf("adding revoked to pre_auth_keys: %w", err)
						}
					}

					return nil
				},
				Rollback: func(db *gorm.DB) error { return nil },
			},
			{
				// Add the OAuth client + access token tables backing the v2 API's
				// OAuth client-credentials flow. They mirror the api_keys /
				// pre_auth_keys security model: a public id/prefix plus an Argon2id
				// hash of the secret.
				//
				// SQLite uses explicit DDL that matches schema.sql byte-for-byte
				// (the squibble digest is the SQLite source of truth). Postgres,
				// which has no digest and rejects SQLite-isms like AUTOINCREMENT,
				// uses dialect-aware AutoMigrate, mirroring InitSchema's fresh-DB
				// table creation so an existing Postgres deployment can upgrade.
				ID: "202606211200-oauth-clients-and-tokens",
				Migrate: func(tx *gorm.DB) error {
					if tx.Migrator().HasTable(&types.OAuthClient{}) &&
						tx.Migrator().HasTable(&types.OAuthAccessToken{}) {
						return nil
					}

					if tx.Name() != "sqlite" {
						return tx.AutoMigrate(&types.OAuthClient{}, &types.OAuthAccessToken{})
					}

					if !tx.Migrator().HasTable(&types.OAuthClient{}) {
						err := tx.Exec(`CREATE TABLE oauth_clients(
  id integer PRIMARY KEY AUTOINCREMENT,
  client_id text,
  secret_hash blob,
  scopes text,
  tags text,
  description text,
  user_id integer,
  created_at datetime,
  revoked datetime
)`).Error
						if err != nil {
							return fmt.Errorf("creating oauth_clients table: %w", err)
						}

						err = tx.Exec(`CREATE UNIQUE INDEX idx_oauth_clients_client_id ON oauth_clients(client_id)`).Error
						if err != nil {
							return fmt.Errorf("creating oauth_clients index: %w", err)
						}
					}

					if !tx.Migrator().HasTable(&types.OAuthAccessToken{}) {
						err := tx.Exec(`CREATE TABLE oauth_access_tokens(
  id integer PRIMARY KEY AUTOINCREMENT,
  prefix text,
  hash blob,
  client_id text,
  scopes text,
  tags text,
  expiration datetime,
  created_at datetime
)`).Error
						if err != nil {
							return fmt.Errorf("creating oauth_access_tokens table: %w", err)
						}

						err = tx.Exec(`CREATE UNIQUE INDEX idx_oauth_access_tokens_prefix ON oauth_access_tokens(prefix)`).Error
						if err != nil {
							return fmt.Errorf("creating oauth_access_tokens index: %w", err)
						}
					}

					return nil
				},
				Rollback: func(db *gorm.DB) error { return nil },
			},
			{
				// Clear stale key expiry on tagged nodes. A tagged node is
				// owned by its tags and never expires (KB 1068), but a buggy
				// handleLogout stamped a past expiry on it, leaving it
				// permanently Expired and unable to re-authenticate. The
				// buggy writer is fixed, so this only repairs rows written
				// before the upgrade; a fixed server cannot recreate them.
				// Match the tagged-node predicate of 0.29's
				// clear-tagged-node-user-id migration (a nil tags slice
				// marshals to 'null', so exclude it).
				// Fixes: https://github.com/juanfont/headscale/issues/3371
				ID: "202607241200-clear-tagged-node-expiry",
				Migrate: func(tx *gorm.DB) error {
					err := tx.Exec(`
UPDATE nodes
SET expiry = NULL
WHERE tags IS NOT NULL AND tags != '[]' AND tags != '' AND tags != 'null'
	AND expiry IS NOT NULL;
						`).Error
					if err != nil {
						return fmt.Errorf("clearing expiry on tagged nodes: %w", err)
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
			&types.OAuthClient{},
			&types.OAuthAccessToken{},
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
			`DROP INDEX IF EXISTS "idx_oauth_clients_client_id"`,
			`DROP INDEX IF EXISTS "idx_oauth_access_tokens_prefix"`,
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
			`CREATE UNIQUE INDEX idx_oauth_clients_client_id ON oauth_clients(client_id)`,
			`CREATE UNIQUE INDEX idx_oauth_access_tokens_prefix ON oauth_access_tokens(prefix)`,
		}

		for _, indexSQL := range indexes {
			err := tx.Exec(indexSQL).Error
			if err != nil {
				return err
			}
		}

		return nil
	})

	err = runMigrations(cfg.Database, dbConn, migrations)
	if err != nil {
		return nil, fmt.Errorf("migration failed: %w", err)
	}

	// Store the current version in the database after migrations succeed.
	// Dev builds skip this to preserve the stored version for the next
	// real versioned binary.
	currentVersion := types.GetVersionInfo().Version
	if !isDev(currentVersion) {
		err = setDatabaseVersion(dbConn, currentVersion)
		if err != nil {
			return nil, fmt.Errorf(
				"storing database version: %w",
				err,
			)
		}
	}

	// Validate that the schema ends up in the expected state.
	// This is currently only done on sqlite as squibble does not
	// support Postgres and we use our sqlite schema as our source of
	// truth.
	if cfg.Database.Type == types.DatabaseSqlite {
		sqlConn, err := dbConn.DB()
		if err != nil {
			return nil, fmt.Errorf("getting DB from gorm: %w", err)
		}

		// or else it blocks...
		sqlConn.SetMaxIdleConns(maxIdleConns)

		sqlConn.SetMaxOpenConns(maxOpenConns)
		defer sqlConn.SetMaxIdleConns(1)
		defer sqlConn.SetMaxOpenConns(1)

		ctx, cancel := context.WithTimeout(context.Background(), contextTimeout)
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

		if err := squibble.Validate(ctx, sqlConn, dbSchema, &opts); err != nil { //nolint:noinlineerr
			return nil, fmt.Errorf("validating schema: %w", err)
		}
	}

	db := HSDatabase{
		DB:  dbConn,
		cfg: cfg,
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

		if sslEnabled, err := strconv.ParseBool(cfg.Postgres.Ssl); err == nil { //nolint:noinlineerr
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
		if err := migrations.Migrate(); err != nil { //nolint:noinlineerr
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
		defer rows.Close()

		for rows.Next() {
			var violation constraintViolation

			err := rows.Scan(&violation.Table, &violation.RowID, &violation.Parent, &violation.ConstraintIndex)
			if err != nil {
				return err
			}

			violatedConstraints = append(violatedConstraints, violation)
		}

		if err := rows.Err(); err != nil { //nolint:noinlineerr
			return err
		}

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
		err := migrations.Migrate()
		if err != nil {
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

	if hsdb.cfg.Database.Type == types.DatabaseSqlite && hsdb.cfg.Database.Sqlite.WriteAheadLog {
		db.Exec("VACUUM") //nolint:errcheck,noctx
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

	err := fn(tx)
	if err != nil {
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
