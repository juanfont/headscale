package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/glebarez/sqlite"
	"github.com/go-gormigrate/gormigrate/v2"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/rs/zerolog/log"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
	"gorm.io/gorm/schema"
	"tailscale.com/util/set"
	"zgo.at/zcache/v2"
)

func init() {
	schema.RegisterSerializer("text", TextSerialiser{})
}

var errDatabaseNotSupported = errors.New("database type not supported")

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
			// The initial migration here is quite messy, completely out of order and
			// has no versioning and is the tech debt of not having versioned migrations
			// prior to this point. This first migration is all DB changes to bring a DB
			// up to 0.23.0.
			{
				ID: "202312101416",
				Migrate: func(tx *gorm.DB) error {
					if cfg.Type == types.DatabasePostgres {
						tx.Exec(`create extension if not exists "uuid-ossp";`)
					}

					_ = tx.Migrator().RenameTable("namespaces", "users")

					// the big rename from Machine to Node
					_ = tx.Migrator().RenameTable("machines", "nodes")
					_ = tx.Migrator().
						RenameColumn(&types.Route{}, "machine_id", "node_id")

					err = tx.AutoMigrate(types.User{})
					if err != nil {
						return err
					}

					_ = tx.Migrator().
						RenameColumn(&types.Node{}, "namespace_id", "user_id")
					_ = tx.Migrator().
						RenameColumn(&types.PreAuthKey{}, "namespace_id", "user_id")

					_ = tx.Migrator().
						RenameColumn(&types.Node{}, "ip_address", "ip_addresses")
					_ = tx.Migrator().RenameColumn(&types.Node{}, "name", "hostname")

					// GivenName is used as the primary source of DNS names, make sure
					// the field is populated and normalized if it was not when the
					// node was registered.
					_ = tx.Migrator().
						RenameColumn(&types.Node{}, "nickname", "given_name")

					dbConn.Model(&types.Node{}).Where("auth_key_id = ?", 0).Update("auth_key_id", nil)
					// If the Node table has a column for registered,
					// find all occourences of "false" and drop them. Then
					// remove the column.
					if tx.Migrator().HasColumn(&types.Node{}, "registered") {
						log.Info().
							Msg(`Database has legacy "registered" column in node, removing...`)

						nodes := types.Nodes{}
						if err := tx.Not("registered").Find(&nodes).Error; err != nil {
							log.Error().Err(err).Msg("Error accessing db")
						}

						for _, node := range nodes {
							log.Info().
								Str("node", node.Hostname).
								Str("machine_key", node.MachineKey.ShortString()).
								Msg("Deleting unregistered node")
							if err := tx.Delete(&types.Node{}, node.ID).Error; err != nil {
								log.Error().
									Err(err).
									Str("node", node.Hostname).
									Str("machine_key", node.MachineKey.ShortString()).
									Msg("Error deleting unregistered node")
							}
						}

						err := tx.Migrator().DropColumn(&types.Node{}, "registered")
						if err != nil {
							log.Error().Err(err).Msg("Error dropping registered column")
						}
					}

					// Remove any invalid routes associated with a node that does not exist.
					if tx.Migrator().HasTable(&types.Route{}) && tx.Migrator().HasTable(&types.Node{}) {
						err := tx.Exec("delete from routes where node_id not in (select id from nodes)").Error
						if err != nil {
							return err
						}
					}
					err = tx.AutoMigrate(&types.Route{})
					if err != nil {
						return err
					}

					err = tx.AutoMigrate(&types.Node{})
					if err != nil {
						return err
					}

					// Ensure all keys have correct prefixes
					// https://github.com/tailscale/tailscale/blob/main/types/key/node.go#L35
					type result struct {
						ID         uint64
						MachineKey string
						NodeKey    string
						DiscoKey   string
					}
					var results []result
					err = tx.Raw("SELECT id, node_key, machine_key, disco_key FROM nodes").
						Find(&results).
						Error
					if err != nil {
						return err
					}

					for _, node := range results {
						mKey := node.MachineKey
						if !strings.HasPrefix(node.MachineKey, "mkey:") {
							mKey = "mkey:" + node.MachineKey
						}
						nKey := node.NodeKey
						if !strings.HasPrefix(node.NodeKey, "nodekey:") {
							nKey = "nodekey:" + node.NodeKey
						}

						dKey := node.DiscoKey
						if !strings.HasPrefix(node.DiscoKey, "discokey:") {
							dKey = "discokey:" + node.DiscoKey
						}

						err := tx.Exec(
							"UPDATE nodes SET machine_key = @mKey, node_key = @nKey, disco_key = @dKey WHERE ID = @id",
							sql.Named("mKey", mKey),
							sql.Named("nKey", nKey),
							sql.Named("dKey", dKey),
							sql.Named("id", node.ID),
						).Error
						if err != nil {
							return err
						}
					}

					if tx.Migrator().HasColumn(&types.Node{}, "enabled_routes") {
						log.Info().
							Msgf("Database has legacy enabled_routes column in node, migrating...")

						type NodeAux struct {
							ID            uint64
							EnabledRoutes []netip.Prefix `gorm:"serializer:json"`
						}

						nodesAux := []NodeAux{}
						err := tx.Table("nodes").
							Select("id, enabled_routes").
							Scan(&nodesAux).
							Error
						if err != nil {
							log.Fatal().Err(err).Msg("Error accessing db")
						}
						for _, node := range nodesAux {
							for _, prefix := range node.EnabledRoutes {
								if err != nil {
									log.Error().
										Err(err).
										Str("enabled_route", prefix.String()).
										Msg("Error parsing enabled_route")

									continue
								}

								err = tx.Preload("Node").
									Where("node_id = ? AND prefix = ?", node.ID, prefix).
									First(&types.Route{}).
									Error
								if err == nil {
									log.Info().
										Str("enabled_route", prefix.String()).
										Msg("Route already migrated to new table, skipping")

									continue
								}

								route := types.Route{
									NodeID:     node.ID,
									Advertised: true,
									Enabled:    true,
									Prefix:     prefix,
								}
								if err := tx.Create(&route).Error; err != nil {
									log.Error().Err(err).Msg("Error creating route")
								} else {
									log.Info().
										Uint64("node_id", route.NodeID).
										Str("prefix", prefix.String()).
										Msg("Route migrated")
								}
							}
						}

						err = tx.Migrator().DropColumn(&types.Node{}, "enabled_routes")
						if err != nil {
							log.Error().
								Err(err).
								Msg("Error dropping enabled_routes column")
						}
					}

					if tx.Migrator().HasColumn(&types.Node{}, "given_name") {
						nodes := types.Nodes{}
						if err := tx.Find(&nodes).Error; err != nil {
							log.Error().Err(err).Msg("Error accessing db")
						}

						for item, node := range nodes {
							if node.GivenName == "" {
								if err != nil {
									log.Error().
										Caller().
										Str("hostname", node.Hostname).
										Err(err).
										Msg("Failed to normalize node hostname in DB migration")
								}

								err = tx.Model(nodes[item]).Updates(types.Node{
									GivenName: node.Hostname,
								}).Error
								if err != nil {
									log.Error().
										Caller().
										Str("hostname", node.Hostname).
										Err(err).
										Msg("Failed to save normalized node name in DB migration")
								}
							}
						}
					}

					err = tx.AutoMigrate(&KV{})
					if err != nil {
						return err
					}

					err = tx.AutoMigrate(&types.PreAuthKey{})
					if err != nil {
						return err
					}

					type preAuthKeyACLTag struct {
						ID           uint64 `gorm:"primary_key"`
						PreAuthKeyID uint64
						Tag          string
					}
					err = tx.AutoMigrate(&preAuthKeyACLTag{})
					if err != nil {
						return err
					}

					_ = tx.Migrator().DropTable("shared_machines")

					err = tx.AutoMigrate(&types.APIKey{})
					if err != nil {
						return err
					}

					return nil
				},
				Rollback: func(tx *gorm.DB) error {
					return nil
				},
			},
			{
				// drop key-value table, it is not used, and has not contained
				// useful data for a long time or ever.
				ID: "202312101430",
				Migrate: func(tx *gorm.DB) error {
					return tx.Migrator().DropTable("kvs")
				},
				Rollback: func(tx *gorm.DB) error {
					return nil
				},
			},
			{
				// remove last_successful_update from node table,
				// no longer used.
				ID: "202402151347",
				Migrate: func(tx *gorm.DB) error {
					_ = tx.Migrator().DropColumn(&types.Node{}, "last_successful_update")
					return nil
				},
				Rollback: func(tx *gorm.DB) error {
					return nil
				},
			},
			{
				// Replace column with IP address list with dedicated
				// IP v4 and v6 column.
				// Note that previously, the list _could_ contain more
				// than two addresses, which should not really happen.
				// In that case, the first occurrence of each type will
				// be kept.
				ID: "2024041121742",
				Migrate: func(tx *gorm.DB) error {
					_ = tx.Migrator().AddColumn(&types.Node{}, "ipv4")
					_ = tx.Migrator().AddColumn(&types.Node{}, "ipv6")

					type node struct {
						ID        uint64 `gorm:"column:id"`
						Addresses string `gorm:"column:ip_addresses"`
					}

					var nodes []node

					_ = tx.Raw("SELECT id, ip_addresses FROM nodes").Scan(&nodes).Error

					for _, node := range nodes {
						addrs := strings.Split(node.Addresses, ",")

						if len(addrs) == 0 {
							return fmt.Errorf("no addresses found for node(%d)", node.ID)
						}

						var v4 *netip.Addr
						var v6 *netip.Addr

						for _, addrStr := range addrs {
							addr, err := netip.ParseAddr(addrStr)
							if err != nil {
								return fmt.Errorf("parsing IP for node(%d) from database: %w", node.ID, err)
							}

							if addr.Is4() && v4 == nil {
								v4 = &addr
							}

							if addr.Is6() && v6 == nil {
								v6 = &addr
							}
						}

						if v4 != nil {
							err = tx.Model(&types.Node{}).Where("id = ?", node.ID).Update("ipv4", v4.String()).Error
							if err != nil {
								return fmt.Errorf("saving ip addresses to new columns: %w", err)
							}
						}

						if v6 != nil {
							err = tx.Model(&types.Node{}).Where("id = ?", node.ID).Update("ipv6", v6.String()).Error
							if err != nil {
								return fmt.Errorf("saving ip addresses to new columns: %w", err)
							}
						}
					}

					_ = tx.Migrator().DropColumn(&types.Node{}, "ip_addresses")

					return nil
				},
				Rollback: func(tx *gorm.DB) error {
					return nil
				},
			},
			{
				ID: "202406021630",
				Migrate: func(tx *gorm.DB) error {
					err := tx.AutoMigrate(&types.Policy{})
					if err != nil {
						return err
					}

					return nil
				},
				Rollback: func(db *gorm.DB) error { return nil },
			},
			// denormalise the ACL tags for preauth keys back onto
			// the preauth key table. We dont normalise or reuse and
			// it is just a bunch of work for extra work.
			{
				ID: "202409271400",
				Migrate: func(tx *gorm.DB) error {
					preauthkeyTags := map[uint64]set.Set[string]{}

					type preAuthKeyACLTag struct {
						ID           uint64 `gorm:"primary_key"`
						PreAuthKeyID uint64
						Tag          string
					}

					var aclTags []preAuthKeyACLTag
					if err := tx.Find(&aclTags).Error; err != nil {
						return err
					}

					// Store the current tags.
					for _, tag := range aclTags {
						if preauthkeyTags[tag.PreAuthKeyID] == nil {
							preauthkeyTags[tag.PreAuthKeyID] = set.SetOf([]string{tag.Tag})
						} else {
							preauthkeyTags[tag.PreAuthKeyID].Add(tag.Tag)
						}
					}

					// Add tags column and restore the tags.
					_ = tx.Migrator().AddColumn(&types.PreAuthKey{}, "tags")
					for keyID, tags := range preauthkeyTags {
						s := tags.Slice()
						j, err := json.Marshal(s)
						if err != nil {
							return err
						}
						if err := tx.Model(&types.PreAuthKey{}).Where("id = ?", keyID).Update("tags", string(j)).Error; err != nil {
							return err
						}
					}

					// Drop the old table.
					_ = tx.Migrator().DropTable(&preAuthKeyACLTag{})
					return nil
				},
				Rollback: func(db *gorm.DB) error { return nil },
			},
			{
				// Pick up new user fields used for OIDC and to
				// populate the user with more interesting information.
				ID: "202407191627",
				Migrate: func(tx *gorm.DB) error {
					// Fix an issue where the automigration in GORM expected a constraint to
					// exists that didnt, and add the one it wanted.
					// Fixes https://github.com/juanfont/headscale/issues/2351
					if cfg.Type == types.DatabasePostgres {
						err := tx.Exec(`
BEGIN;
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'uni_users_name'
    ) THEN
        ALTER TABLE users ADD CONSTRAINT uni_users_name UNIQUE (name);
    END IF;
END $$;

DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'users_name_key'
    ) THEN
        ALTER TABLE users DROP CONSTRAINT users_name_key;
    END IF;
END $$;
COMMIT;
`).Error
						if err != nil {
							return fmt.Errorf("failed to rename constraint: %w", err)
						}
					}

					err := tx.AutoMigrate(&types.User{})
					if err != nil {
						return err
					}

					return nil
				},
				Rollback: func(db *gorm.DB) error { return nil },
			},
			{
				// The unique constraint of Name has been dropped
				// in favour of a unique together of name and
				// provider identity.
				ID: "202408181235",
				Migrate: func(tx *gorm.DB) error {
					err := tx.AutoMigrate(&types.User{})
					if err != nil {
						return err
					}

					// Set up indexes and unique constraints outside of GORM, it does not support
					// conditional unique constraints.
					// This ensures the following:
					// - A user name and provider_identifier is unique
					// - A provider_identifier is unique
					// - A user name is unique if there is no provider_identifier is not set
					for _, idx := range []string{
						"DROP INDEX IF EXISTS idx_provider_identifier",
						"DROP INDEX IF EXISTS idx_name_provider_identifier",
						"CREATE UNIQUE INDEX IF NOT EXISTS idx_provider_identifier ON users (provider_identifier) WHERE provider_identifier IS NOT NULL;",
						"CREATE UNIQUE INDEX IF NOT EXISTS idx_name_provider_identifier ON users (name,provider_identifier);",
						"CREATE UNIQUE INDEX IF NOT EXISTS idx_name_no_provider_identifier ON users (name) WHERE provider_identifier IS NULL;",
					} {
						err = tx.Exec(idx).Error
						if err != nil {
							return fmt.Errorf("creating username index: %w", err)
						}
					}

					return nil
				},
				Rollback: func(db *gorm.DB) error { return nil },
			},
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

					err := tx.AutoMigrate(&types.Route{})
					if err != nil {
						return err
					}

					return nil
				},
				Rollback: func(db *gorm.DB) error { return nil },
			},
		},
	)

	if err := runMigrations(cfg, dbConn, migrations); err != nil {
		log.Fatal().Err(err).Msgf("Migration failed: %v", err)
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

		db, err := gorm.Open(
			sqlite.Open(cfg.Sqlite.Path),
			&gorm.Config{
				PrepareStmt: cfg.Gorm.PrepareStmt,
				Logger:      dbLogger,
			},
		)

		if err := db.Exec(`
			PRAGMA foreign_keys=ON;
			PRAGMA busy_timeout=10000;
			PRAGMA auto_vacuum=INCREMENTAL;
			PRAGMA synchronous=NORMAL;
			`).Error; err != nil {
			return nil, fmt.Errorf("enabling foreign keys: %w", err)
		}

		if cfg.Sqlite.WriteAheadLog {
			if err := db.Exec(fmt.Sprintf(`
				PRAGMA journal_mode=WAL;
				PRAGMA wal_autocheckpoint=%d;
				`, cfg.Sqlite.WALAutoCheckPoint)).Error; err != nil {
				return nil, fmt.Errorf("setting WAL mode: %w", err)
			}
		}

		// The pure Go SQLite library does not handle locking in
		// the same way as the C based one and we cant use the gorm
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
			dbString += fmt.Sprintf(" sslmode=%s", cfg.Postgres.Ssl)
		}

		if cfg.Postgres.Port != 0 {
			dbString += fmt.Sprintf(" port=%d", cfg.Postgres.Port)
		}

		if cfg.Postgres.Pass != "" {
			dbString += fmt.Sprintf(" password=%s", cfg.Postgres.Pass)
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
	// Turn off foreign keys for the duration of the migration if using sqllite to
	// prevent data loss due to the way the GORM migrator handles certain schema
	// changes.
	if cfg.Type == types.DatabaseSqlite {
		var fkEnabled int
		if err := dbConn.Raw("PRAGMA foreign_keys").Scan(&fkEnabled).Error; err != nil {
			return fmt.Errorf("checking foreign key status: %w", err)
		}
		if fkEnabled == 1 {
			if err := dbConn.Exec("PRAGMA foreign_keys = OFF").Error; err != nil {
				return fmt.Errorf("disabling foreign keys: %w", err)
			}
			defer dbConn.Exec("PRAGMA foreign_keys = ON")
		}
	}

	if err := migrations.Migrate(); err != nil {
		return err
	}

	// Since we disabled foreign keys for the migration, we need to check for
	// constraint violations manually at the end of the migration.
	if cfg.Type == types.DatabaseSqlite {
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

			return fmt.Errorf("foreign key constraints violated")
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
