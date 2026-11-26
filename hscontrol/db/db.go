package db

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/glebarez/sqlite"
	"github.com/go-gormigrate/gormigrate/v2"
	"github.com/juanfont/headscale/hscontrol/db/sqliteconfig"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/juanfont/headscale/hscontrol/util/zlog/zf"
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

const contextTimeout = 10 * time.Second

type HSDatabase struct {
	DB  *gorm.DB
	cfg *types.Config
	// asIs is a database opened by OpenAsIs, which Close leaves as it is.
	asIs bool
	// othersOpen is a database of OpenAsIs that another process has open.
	othersOpen bool
}

// NewHeadscaleDatabase creates a new database connection and runs migrations.
//
//nolint:gocyclo // migration closures inflate the count; each is linear
func NewHeadscaleDatabase(cfg *types.Config) (*HSDatabase, error) {
	dbConn, err := openDB(cfg.Database, cfg.SQLitePath())
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

	migrations := gormigrate.New(dbConn, gormigrate.DefaultOptions, migrationList())

	migrations.InitSchema(func(tx *gorm.DB) error {
		// Credentials use the migration's explicit DDL (AutoMigrate cannot
		// express its CHECK constraints), created before Node so the
		// nodes.auth_key_id foreign key to credentials(id) can be created.
		err := tx.AutoMigrate(&types.User{})
		if err != nil {
			return err
		}

		err = ensureCredentialsTable(tx)
		if err != nil {
			return err
		}

		err = tx.AutoMigrate(&types.Node{}, &types.Policy{})
		if err != nil {
			return err
		}

		// Drop all indexes (both GORM-created and potentially pre-existing ones)
		// to ensure we can recreate them in the correct format
		dropIndexes := []string{
			`DROP INDEX IF EXISTS "idx_users_deleted_at"`,
			`DROP INDEX IF EXISTS "idx_policies_deleted_at"`,
			`DROP INDEX IF EXISTS "idx_provider_identifier"`,
			`DROP INDEX IF EXISTS "idx_name_provider_identifier"`,
			`DROP INDEX IF EXISTS "idx_name_no_provider_identifier"`,
			`DROP INDEX IF EXISTS "idx_nodes_auth_key_id"`,
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
			`CREATE INDEX idx_policies_deleted_at ON policies(deleted_at)`,
			`CREATE UNIQUE INDEX idx_provider_identifier ON users(provider_identifier) WHERE provider_identifier IS NOT NULL`,
			`CREATE UNIQUE INDEX idx_name_provider_identifier ON users(name, provider_identifier)`,
			`CREATE UNIQUE INDEX idx_name_no_provider_identifier ON users(name) WHERE provider_identifier IS NULL`,
			`CREATE INDEX idx_nodes_auth_key_id ON nodes(auth_key_id)`,
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
	if cfg.Database.IsSQLite() {
		sqlConn, err := dbConn.DB()
		if err != nil {
			return nil, fmt.Errorf("getting DB from gorm: %w", err)
		}

		ctx, cancel := context.WithTimeout(context.Background(), contextTimeout)
		defer cancel()

		// squibble nests queries. Without WAL a second connection would
		// hang: its opening pragmas write, and the write waits for the
		// first connection's read.
		conn, err := sqlConn.Conn(ctx)
		if err != nil {
			return nil, fmt.Errorf("getting connection for schema validation: %w", err)
		}
		defer conn.Close()

		opts := squibble.DigestOptions{
			IgnoreTables: []string{
				// Litestream tables, these are inserted by
				// litestream and not part of our schema
				// https://litestream.io/how-it-works
				"_litestream_lock",
				"_litestream_seq",
			},
		}

		if err := squibble.Validate(ctx, conn, dbSchema, &opts); err != nil { //nolint:noinlineerr
			return nil, fmt.Errorf("validating schema: %w", err)
		}
	}

	db := HSDatabase{
		DB:  dbConn,
		cfg: cfg,
	}

	return &db, err
}

// The errors of [OpenAsIs] for a database it does not open.
var (
	ErrDatabaseMissing = errors.New("the database does not exist")
	ErrNotHeadscale    = errors.New("this is not a Headscale database")
	ErrSchemaOlder     = errors.New("the database's schema is older than this headscale's")
	ErrSchemaUnknown   = errors.New("the database has a migration that this headscale does not know")
	// ErrInUse is a database that another connection has open, such as a
	// server's, which a write would change under it.
	ErrInUse = errors.New("another program has the database open")
	// ErrNeedsRecovery is a database that a read-only open cannot read as
	// a server would find it: a write a crash left half done, which only a
	// writer can roll back or index.
	ErrNeedsRecovery = errors.New("the database holds a write that was not finished, which only a writer can recover")
)

// VersionError is a database that a headscale of another minor version
// last opened: the server refuses it, and its schema and rules are that
// version's.
type VersionError struct{ Stored, Current string }

func (e *VersionError) Error() string {
	return "the database was last opened by headscale " + e.Stored + ", and this is " + e.Current
}

// releasedMigrations are the migrations that releases up to v0.29 ran,
// which this build no longer lists: a database that went through them
// records them.
var releasedMigrations = []string{
	"202312101416",
	"202312101430",
	"202402151347",
	"2024041121742",
	"202406021630",
	"202407191627",
	"202408181235",
	"202409271400",
	"202412131220",
	"202501221827",
	"202501311657",
	"202502070949",
	"202502131714",
	"202502171819",
	"202505091439",
	"202505141324",
	"202505211519-node-user-optional-tags",
	"202505231615-preauthkey-user-optional-tags-user",
	"202507021200",
	"202510311551",
	"202511011637-preauthkey-bcrypt",
	"202511101554-drop-old-idx",
	"202511122344-remove-newline-index",
	"202511131445-node-forced-tags-to-tags",
	"202601121700-migrate-hostinfo-request-tags",
	"202602201200-clear-tagged-node-user-id",
	"202605221435-clear-zero-time-node-expiry",
}

// OpenAsIs opens the database cfg names as it is, for a tool that works on
// the database of a stopped server: it runs no migration, writes no
// version, creates no directory or table, and changes no setting that
// SQLite keeps in the file. With readOnly the database is not written: a
// read-only SQLite open, a read-only transaction on PostgreSQL; a SQLite
// database that needs a writer to recover is ErrNeedsRecovery. A write on
// SQLite is ErrInUse when another process has the database open with the
// write-ahead log, as a server does from its start to its end. Refused:
// a database with a migration this build does not know or without one it
// lists, and one a headscale of another minor version last opened.
func OpenAsIs(cfg *types.Config, readOnly bool) (*HSDatabase, error) {
	silent := &gorm.Config{Logger: logger.Default.LogMode(logger.Silent), TranslateError: true}

	var (
		db  *gorm.DB
		err error
	)

	switch {
	case cfg.Database.IsSQLite():
		path := cfg.SQLitePath()

		_, err = os.Stat(path)
		if errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("%s: %w", path, ErrDatabaseMissing)
		}

		c := sqliteconfig.ReadOnly(path)
		if !readOnly {
			// No journal mode, auto vacuum or synchronous: each is kept in
			// the file or changes it, and the server sets them when it starts.
			c = &sqliteconfig.Config{Path: path, BusyTimeout: sqliteconfig.DefaultBusyTimeout, WALAutocheckpoint: -1, ForeignKeys: true, TxLock: sqliteconfig.TxLockImmediate}
		}

		u, err := c.ToURL()
		if err != nil {
			return nil, fmt.Errorf("building sqlite connection URL: %w", err)
		}

		// mode=rw opens the file only if it is there; ReadOnly has mode=ro.
		// The connection is an ordinary one: in exclusive locking mode it
		// would take the write-ahead log for itself and, closing, check it
		// into the file and remove it under a server that has it open.
		if !readOnly {
			u += "&mode=rw"
		}

		db, err = gorm.Open(sqlite.Open(u), silent)
		if err != nil {
			return nil, sqliteAsIs(err, readOnly)
		}

		sqlDB, err := db.DB()
		if err != nil {
			return nil, err
		}

		sqlDB.SetMaxOpenConns(1)

	case cfg.Database.Type == types.DatabasePostgres:
		pg := cfg.Database.Postgres

		pass, err := types.ResolveSecret("database.postgres.pass", string(pg.Pass))
		if err != nil {
			return nil, err
		}

		pg.Pass = types.Secret(pass)

		dsn, err := url.Parse(pg.DSN())
		if err != nil {
			return nil, err
		}

		if readOnly {
			q := dsn.Query()
			q.Set("default_transaction_read_only", "on")
			dsn.RawQuery = q.Encode()
		}

		db, err = gorm.Open(postgres.Open(dsn.String()), silent)
		if err != nil {
			return nil, err
		}

	default:
		return nil, fmt.Errorf("database of type %s is not supported: %w", cfg.Database.Type, errDatabaseNotSupported)
	}

	hsdb := &HSDatabase{DB: db, cfg: cfg, asIs: true}

	// The first read takes the locks and finds what a crash left; a check
	// of a table that hides its error must not come first.
	first := "SELECT count(*) FROM pg_catalog.pg_tables"
	if cfg.Database.IsSQLite() {
		first = "SELECT count(*) FROM sqlite_master"
	}

	err = db.Exec(first).Error
	if err == nil && cfg.Database.IsSQLite() {
		// After the first read, which opened the -shm of this connection:
		// another process that has the database open holds it too.
		held, herr := othersHoldWAL(cfg.SQLitePath())

		switch {
		case herr != nil:
			err = fmt.Errorf("asking whether another program has the database open: %w", herr)
		case held && !readOnly:
			err = fmt.Errorf("%w: another process holds its write-ahead log", ErrInUse)
		}

		hsdb.othersOpen = held
	}

	if err == nil {
		err = checkSchema(db)
	}

	if err != nil {
		_ = hsdb.Close()

		if cfg.Database.IsSQLite() {
			return nil, sqliteAsIs(err, readOnly)
		}

		return nil, err
	}

	return hsdb, nil
}

// sqliteAsIs is err of a SQLite database opened as it is, said by what it
// means for the tool: busy is another connection that holds the database,
// and a read-only open that SQLite cannot use is a database to recover.
func sqliteAsIs(err error, readOnly bool) error {
	switch code := sqliteCode(err); {
	case code == sqliteBusy:
		return fmt.Errorf("%w: %w", ErrInUse, err)
	case readOnly && (code == sqliteReadOnly || code == sqliteCantOpen):
		return fmt.Errorf("%w: %w", ErrNeedsRecovery, err)
	case code == sqliteNotADB:
		return fmt.Errorf("%w: it is not a SQLite file", ErrNotHeadscale)
	}

	return err
}

// OtherSessions is how many other sessions have the database open: on
// PostgreSQL, the sessions of other clients, which a server on another
// host is one of and cannot be told from; 0 on SQLite, which a write of
// OpenAsIs holds for itself.
func (hsdb *HSDatabase) OtherSessions() (int, error) {
	if hsdb.cfg.Database.Type != types.DatabasePostgres {
		return 0, nil
	}

	var n int

	err := hsdb.DB.Raw("SELECT count(*) FROM pg_stat_activity WHERE datname = current_database() AND pid <> pg_backend_pid()").Scan(&n).Error

	return n, err
}

// OthersOpen reports whether another process had the SQLite database open
// with the write-ahead log when OpenAsIs opened it for a read, such as a
// server: what is stored may then not be what is in force. A write of
// OpenAsIs is refused then.
func (hsdb *HSDatabase) OthersOpen() bool { return hsdb.othersOpen }

// The primary result codes of SQLite that OpenAsIs tells apart.
const (
	sqliteBusy     = 5
	sqliteReadOnly = 8
	sqliteCantOpen = 14
	sqliteNotADB   = 26
)

// sqliteCode is the primary result code of a SQLite error, 0 for another.
func sqliteCode(err error) int {
	var e interface{ Code() int }
	if errors.As(err, &e) {
		return e.Code() & 0xff
	}

	return 0
}

// checkSchema holds that db is a database of this build: every migration
// it lists recorded, none recorded that neither it nor a release before
// it ran, and last opened by this minor version, as the server's start
// requires. A database with no record of migrations is not Headscale's.
func checkSchema(db *gorm.DB) error {
	err := checkMinimumMigration(db)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrSchemaOlder, err)
	}

	if !db.Migrator().HasTable("migrations") {
		return fmt.Errorf("%w: it has no migrations table", ErrNotHeadscale)
	}

	var ids []string

	err = db.Table("migrations").Pluck("id", &ids).Error
	if err != nil {
		return fmt.Errorf("reading migrations: %w", err)
	}

	if len(ids) == 0 {
		return fmt.Errorf("%w: it records no migration", ErrNotHeadscale)
	}

	known := migrationList()

	for _, m := range known {
		if !slices.Contains(ids, m.ID) {
			return fmt.Errorf("%w: it lacks the migration %s", ErrSchemaOlder, m.ID)
		}
	}

	for _, id := range ids {
		listed := slices.ContainsFunc(known, func(m *gormigrate.Migration) bool { return m.ID == id })
		if id != "SCHEMA_INIT" && !listed && !slices.Contains(releasedMigrations, id) {
			return fmt.Errorf("%w: %s", ErrSchemaUnknown, id)
		}
	}

	return checkVersion(db)
}

// checkVersion is the rule of the server's start on the stored version,
// read as it is: a database of a release is opened only by its minor
// version. A development build on either side is not compared, as the
// server does not, and a database with no version table has none stored.
func checkVersion(db *gorm.DB) error {
	current := types.GetVersionInfo().Version
	if isDev(current) || !db.Migrator().HasTable("database_versions") {
		return nil
	}

	stored, err := getDatabaseVersion(db)
	if err != nil || stored == "" || isDev(stored) {
		return err
	}

	c, err := parseVersion(current)
	if err != nil {
		return fmt.Errorf("parsing current version: %w", err)
	}

	s, err := parseVersion(stored)
	if err != nil {
		return fmt.Errorf("parsing stored database version: %w", err)
	}

	if c.Major != s.Major || c.Minor != s.Minor {
		return &VersionError{Stored: stored, Current: current}
	}

	return nil
}

// migrationList is every migration of this build, in order. Its IDs are the
// schema this build knows.
//
//nolint:gocyclo,maintidx // migration closures inflate the count; each is linear
func migrationList() []*gormigrate.Migration {
	return []*gormigrate.Migration{
		// New migrations must be added as transactions at the end of this list.
		// Migrations start from v0.29.0; older databases are rejected by
		// checkMinimumMigration and must upgrade one minor release at a time
		// to the latest 0.29.x first.
		//
		// Rules:
		// - NEVER use gorm.AutoMigrate, write the exact migration steps needed
		// - AutoMigrate depends on the struct staying exactly the same, which it won't over time.
		// - Never write migrations that requires foreign keys to be disabled.
		// - ALL errors in migrations must be handled properly.
		// Shipped in 0.29.1.
		// TODO(kradalby): remove in 0.31, which upgrades only from 0.30.
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
		// 0.30 development: columns and tables that 202609231300 reads.
		// TODO(kradalby): remove in 0.31 with the credentials migration.
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
		// Shipped in 0.29.3.
		// TODO(kradalby): remove in 0.31, which upgrades only from 0.30.
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
		// 0.30: unified credentials table (InitSchema keeps ensureCredentialsTable).
		// TODO(kradalby): remove in 0.31 with the credentials migration.
		{
			// Create the unified credentials table; the next migration
			// backfills it. Explicit DDL for both dialects (no AutoMigrate).
			ID:       "202609231200-create-credentials",
			Migrate:  ensureCredentialsTable,
			Rollback: func(db *gorm.DB) error { return nil },
		},
		{
			// Move every credential into the unified table and drop the
			// per-kind tables (see migrateToCredentials).
			ID: "202609231300-migrate-to-credentials",
			Migrate: func(tx *gorm.DB) error {
				// Already migrated (e.g. fresh DB via InitSchema): nothing to do.
				if !tx.Migrator().HasTable("pre_auth_keys") &&
					!tx.Migrator().HasTable("api_keys") {
					return nil
				}

				return tx.Transaction(migrateToCredentials)
			},
			Rollback: func(db *gorm.DB) error { return nil },
		},
		{
			// Records which approved routes only auto-approval granted. It
			// starts empty: the current policy cannot tell which earlier
			// approvals were automatic, so all of them stay as an admin's.
			ID: "202610211200-node-auto-approved-routes",
			Migrate: func(tx *gorm.DB) error {
				return tx.Transaction(func(tx *gorm.DB) error {
					return tx.Exec(`ALTER TABLE nodes ADD COLUMN auto_approved_routes text`).Error
				})
			},
			Rollback: func(db *gorm.DB) error { return nil },
		},
		{
			// Store a node's ephemeral flag on the node, taken from the
			// key it references, so a login with another key keeps it.
			ID: "202610211300-node-ephemeral",
			Migrate: func(tx *gorm.DB) error {
				// The column and backfill commit together, before gormigrate
				// records the migration; a stop in between leaves both done.
				if tx.Migrator().HasColumn(&types.Node{}, "ephemeral") {
					return nil
				}

				return tx.Transaction(func(tx *gorm.DB) error {
					colType := "numeric"
					if tx.Name() != sqlite.DriverName {
						colType = "boolean"
					}

					err := tx.Exec(`ALTER TABLE nodes ADD COLUMN ephemeral ` + colType + ` DEFAULT false`).Error
					if err != nil {
						return fmt.Errorf("adding ephemeral to nodes: %w", err)
					}

					err = tx.Exec(`
UPDATE nodes SET ephemeral = true
WHERE auth_key_id IN (
SELECT id FROM credentials WHERE kind = ? AND ephemeral = true
);
						`, types.CredentialPreAuthKey).Error
					if err != nil {
						return fmt.Errorf("backfilling ephemeral on nodes: %w", err)
					}

					return nil
				})
			},
			Rollback: func(db *gorm.DB) error { return nil },
		},
		{
			// Mark the auth keys an OAuth access token makes. A database
			// that got the credentials table from the DDL above already
			// has the column; no released version made keys from tokens,
			// so existing rows stay false.
			ID: "202610221200-credential-created-by-token",
			Migrate: func(tx *gorm.DB) error {
				return tx.Transaction(func(tx *gorm.DB) error {
					if tx.Migrator().HasColumn(&types.Credential{}, "created_by_token") {
						return nil
					}

					colType := "numeric"
					if tx.Name() != sqlite.DriverName {
						colType = "boolean"
					}

					err := tx.Exec(`ALTER TABLE credentials ADD COLUMN created_by_token ` + colType + ` DEFAULT false`).Error
					if err != nil {
						return fmt.Errorf("adding created_by_token to credentials: %w", err)
					}

					return nil
				})
			},
			Rollback: func(db *gorm.DB) error { return nil },
		},
		{
			// The source IP of each node's latest authenticated control
			// connection. Existing rows stay NULL until the node next connects.
			ID: "202611041200-node-last-control-address",
			Migrate: func(tx *gorm.DB) error {
				return tx.Transaction(func(tx *gorm.DB) error {
					if tx.Migrator().HasColumn(&types.Node{}, "last_control_address") {
						return nil
					}

					return tx.Exec(`ALTER TABLE nodes ADD COLUMN last_control_address text`).Error
				})
			},
			Rollback: func(db *gorm.DB) error { return nil },
		},
		{
			// Key expiry becomes a switch beside the expiry time, as on
			// Tailscale. Tagged nodes had expiry turned off by clearing the
			// time; the switch now says so, so they still never expire. A
			// tagged node with a stored time got it from an admin or a
			// logout and expired by it, so its key expiry stays on.
			ID: "202611171200-node-key-expiry-disabled",
			Migrate: func(tx *gorm.DB) error {
				return tx.Transaction(func(tx *gorm.DB) error {
					if tx.Migrator().HasColumn(&types.Node{}, "key_expiry_disabled") {
						return nil
					}

					colType := "numeric"
					if tx.Name() != sqlite.DriverName {
						colType = "boolean"
					}

					err := tx.Exec(`ALTER TABLE nodes ADD COLUMN key_expiry_disabled ` + colType + ` DEFAULT false`).Error
					if err != nil {
						return fmt.Errorf("adding key_expiry_disabled to nodes: %w", err)
					}

					// The tagged-node predicate of 202607241200-clear-tagged-node-expiry.
					err = tx.Exec(`
UPDATE nodes SET key_expiry_disabled = true
WHERE tags IS NOT NULL AND tags != '[]' AND tags != '' AND tags != 'null'
	AND expiry IS NULL;
						`).Error
					if err != nil {
						return fmt.Errorf("disabling key expiry on tagged nodes: %w", err)
					}

					return nil
				})
			},
			Rollback: func(db *gorm.DB) error { return nil },
		},
		{
			// Who made a node or a credential, apart from its owner: a
			// tagged node keeps the user who registered it, and a key one
			// user made for another can say so. Nothing records it today,
			// so existing rows stay NULL. A user delete nulls it (no
			// foreign key: nodes come from AutoMigrate on a fresh
			// database, which would not add one).
			ID: "202611201200-created-by-user",
			Migrate: func(tx *gorm.DB) error {
				return tx.Transaction(func(tx *gorm.DB) error {
					colType := "integer"
					if tx.Name() != sqlite.DriverName {
						colType = "bigint"
					}

					for _, table := range []any{&types.Node{}, &types.Credential{}} {
						if tx.Migrator().HasColumn(table, "created_by_user_id") {
							continue
						}

						stmt := &gorm.Statement{DB: tx}

						err := stmt.Parse(table)
						if err != nil {
							return fmt.Errorf("reading the table of %T: %w", table, err)
						}

						err = tx.Exec(`ALTER TABLE ` + stmt.Table + ` ADD COLUMN created_by_user_id ` + colType).Error
						if err != nil {
							return fmt.Errorf("adding created_by_user_id to %s: %w", stmt.Table, err)
						}
					}

					return nil
				})
			},
			Rollback: func(db *gorm.DB) error { return nil },
		},
		{
			// When a node first joined with an auth key. Nothing recorded
			// it, so existing rows stay NULL: a node's creation time is not
			// when the key it now refers to was first used, and the used
			// flag keeps meaning what it meant.
			ID:       "202611252300-credential-first-used",
			Migrate:  addCredentialFirstUsed,
			Rollback: func(db *gorm.DB) error { return nil },
		},
	}
}

// addCredentialFirstUsed adds credentials.first_used.
func addCredentialFirstUsed(tx *gorm.DB) error {
	return tx.Transaction(func(tx *gorm.DB) error {
		if tx.Migrator().HasColumn(&types.Credential{}, "first_used") {
			return nil
		}

		colType := "datetime"
		if tx.Name() != sqlite.DriverName {
			colType = "timestamptz"
		}

		err := tx.Exec(`ALTER TABLE credentials ADD COLUMN first_used ` + colType).Error
		if err != nil {
			return fmt.Errorf("adding first_used to credentials: %w", err)
		}

		return nil
	})
}

// openDB opens the database cfg names; sqlitePath is database.sqlite.path
// resolved.
func openDB(cfg types.DatabaseConfig, sqlitePath string) (*gorm.DB, error) {
	// TODO(kradalby): Integrate this with zerolog
	var dbLogger logger.Interface
	if cfg.Debug {
		dbLogger = util.NewDBLogWrapper(&log.Logger, time.Duration(cfg.Gorm.SlowThreshold)*time.Millisecond, cfg.Gorm.SkipErrRecordNotFound, cfg.Gorm.ParameterizedQueries)
	} else {
		dbLogger = logger.Default.LogMode(logger.Silent)
	}

	switch {
	case cfg.IsSQLite():
		dir := filepath.Dir(sqlitePath)

		err := util.EnsureDir(dir)
		if err != nil {
			return nil, fmt.Errorf("creating directory for sqlite: %w", err)
		}

		log.Info().
			Str("database", string(types.DatabaseSqlite)).
			Str("path", sqlitePath).
			Msg("Opening database")

		// Build SQLite configuration with pragmas set at connection time
		sqliteConfig := sqliteconfig.Default(sqlitePath)
		if cfg.Sqlite.WriteAheadLog {
			sqliteConfig.WALAutocheckpoint = cfg.Sqlite.WALAutoCheckPoint
		} else {
			// The journal mode persists in the file, so leaving it unset keeps
			// a database an earlier run put in WAL mode there. FULL is SQLite's
			// default for a rollback journal; NORMAL can corrupt it on power loss.
			sqliteConfig.JournalMode = sqliteconfig.JournalModeDelete
			sqliteConfig.Synchronous = sqliteconfig.SynchronousFull
		}

		connectionURL, err := sqliteConfig.ToURL()
		if err != nil {
			return nil, fmt.Errorf("building sqlite connection URL: %w", err)
		}

		// No PrepareStmt: its cache can wait on the one connection a transaction holds.
		// An outside query can publish a pending cached statement while waiting
		// for that connection. If the transaction requests the same statement,
		// it waits for preparation, deadlocking both callers. The regression
		// test TestSQLiteSameQueryInAndOutsideTransaction covers this ordering.
		db, err := gorm.Open(
			sqlite.Open(connectionURL),
			&gorm.Config{
				Logger: dbLogger,
				// Callers match gorm.ErrDuplicatedKey, not driver text.
				TranslateError: true,
			},
		)
		if err != nil {
			return nil, err
		}

		// The pure Go SQLite library does not handle locking in
		// the same way as the C based one and we can't use the gorm
		// connection pool as of 2022/02/23.
		sqlDB, err := db.DB()
		if err != nil {
			return nil, err
		}

		sqlDB.SetMaxIdleConns(1)
		sqlDB.SetMaxOpenConns(1)
		sqlDB.SetConnMaxIdleTime(time.Hour)

		return db, nil

	case cfg.Type == types.DatabasePostgres:
		// Log the DSN without the password.
		pg := cfg.Postgres
		pg.Pass = ""

		log.Info().
			Str(zf.Database, string(types.DatabasePostgres)).
			Str(zf.Path, pg.DSN()).
			Msg("Opening database")

		pass, err := types.ResolveSecret("database.postgres.pass", string(cfg.Postgres.Pass))
		if err != nil {
			return nil, err
		}

		pg.Pass = types.Secret(pass)

		db, err := gorm.Open(postgres.Open(pg.DSN()), &gorm.Config{
			Logger:         dbLogger,
			TranslateError: true,
		})
		if err != nil {
			return nil, err
		}

		sqlDB, err := db.DB()
		if err != nil {
			return nil, err
		}

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
	if cfg.IsSQLite() {
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

	if hsdb.cfg.Database.IsSQLite() && hsdb.cfg.Database.Sqlite.WriteAheadLog && !hsdb.asIs {
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
