package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/glebarez/sqlite"
	"github.com/go-gormigrate/gormigrate/v2"
	"github.com/rs/zerolog/log"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
)

var errDatabaseNotSupported = errors.New("database type not supported")

// KV is a key-value store in a psql table. For future use...
// TODO(kradalby): Is this used for anything?
type KV struct {
	Key   string
	Value string
}

type HSDatabase struct {
	DB *gorm.DB

	baseDomain string
}

// TODO(kradalby): assemble this struct from toptions or something typed
// rather than arguments.
func NewHeadscaleDatabase(
	cfg types.DatabaseConfig,
	baseDomain string,
) (*HSDatabase, error) {
	dbConn, err := openDB(cfg)
	if err != nil {
		return nil, err
	}

	migrations := gormigrate.New(
		dbConn,
		gormigrate.DefaultOptions,
		[]*gormigrate.Migration{
			// New migrations should be added as transactions at the end of this list.
			// The initial commit here is quite messy, completely out of order and
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
							EnabledRoutes types.IPPrefixes
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
									Where("node_id = ? AND prefix = ?", node.ID, types.IPPrefix(prefix)).
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
									Prefix:     types.IPPrefix(prefix),
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
								normalizedHostname, err := util.NormalizeToFQDNRulesConfigFromViper(
									node.Hostname,
								)
								if err != nil {
									log.Error().
										Caller().
										Str("hostname", node.Hostname).
										Err(err).
										Msg("Failed to normalize node hostname in DB migration")
								}

								err = tx.Model(nodes[item]).Updates(types.Node{
									GivenName: normalizedHostname,
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

					err = tx.AutoMigrate(&types.PreAuthKeyACLTag{})
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
					err := tx.Migrator().DropColumn(&types.Node{}, "last_successful_update")
					if err != nil && strings.Contains(err.Error(), `of relation "nodes" does not exist`) {
						return nil
					} else {
						return err
					}

					return err
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
				// In that case, the first occurence of each type will
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
		},
	)

	if err = migrations.Migrate(); err != nil {
		log.Fatal().Err(err).Msgf("Migration failed: %v", err)
	}

	db := HSDatabase{
		DB: dbConn,

		baseDomain: baseDomain,
	}

	return &db, err
}

func openDB(cfg types.DatabaseConfig) (*gorm.DB, error) {
	// TODO(kradalby): Integrate this with zerolog
	var dbLogger logger.Interface
	if cfg.Debug {
		dbLogger = logger.Default
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
			sqlite.Open(cfg.Sqlite.Path+"?_synchronous=1&_journal_mode=WAL"),
			&gorm.Config{
				Logger: dbLogger,
			},
		)

		db.Exec("PRAGMA foreign_keys=ON")

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
