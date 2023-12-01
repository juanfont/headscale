package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/glebarez/sqlite"
	"github.com/juanfont/headscale/hscontrol/notifier"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/rs/zerolog/log"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

const (
	dbVersion = "1"
	Postgres  = "postgres"
	Sqlite    = "sqlite3"
)

var (
	errValueNotFound        = errors.New("not found")
	errDatabaseNotSupported = errors.New("database type not supported")
)

// KV is a key-value store in a psql table. For future use...
// TODO(kradalby): Is this used for anything?
type KV struct {
	Key   string
	Value string
}

type HSDatabase struct {
	db       *gorm.DB
	notifier *notifier.Notifier

	mu sync.RWMutex

	ipAllocationMutex sync.Mutex

	ipPrefixes []netip.Prefix
	baseDomain string
}

// TODO(kradalby): assemble this struct from toptions or something typed
// rather than arguments.
func NewHeadscaleDatabase(
	dbType, connectionAddr string,
	debug bool,
	notifier *notifier.Notifier,
	ipPrefixes []netip.Prefix,
	baseDomain string,
) (*HSDatabase, error) {
	dbConn, err := openDB(dbType, connectionAddr, debug)
	if err != nil {
		return nil, err
	}

	db := HSDatabase{
		db:       dbConn,
		notifier: notifier,

		ipPrefixes: ipPrefixes,
		baseDomain: baseDomain,
	}

	log.Debug().Msgf("database %#v", dbConn)

	if dbType == Postgres {
		dbConn.Exec(`create extension if not exists "uuid-ossp";`)
	}

	_ = dbConn.Migrator().RenameTable("namespaces", "users")

	// the big rename from Machine to Node
	_ = dbConn.Migrator().RenameTable("machines", "nodes")
	_ = dbConn.Migrator().RenameColumn(&types.Route{}, "machine_id", "node_id")

	err = dbConn.AutoMigrate(types.User{})
	if err != nil {
		return nil, err
	}

	_ = dbConn.Migrator().RenameColumn(&types.Node{}, "namespace_id", "user_id")
	_ = dbConn.Migrator().RenameColumn(&types.PreAuthKey{}, "namespace_id", "user_id")

	_ = dbConn.Migrator().RenameColumn(&types.Node{}, "ip_address", "ip_addresses")
	_ = dbConn.Migrator().RenameColumn(&types.Node{}, "name", "hostname")

	// GivenName is used as the primary source of DNS names, make sure
	// the field is populated and normalized if it was not when the
	// node was registered.
	_ = dbConn.Migrator().RenameColumn(&types.Node{}, "nickname", "given_name")

	// If the Node table has a column for registered,
	// find all occourences of "false" and drop them. Then
	// remove the column.
	if dbConn.Migrator().HasColumn(&types.Node{}, "registered") {
		log.Info().
			Msg(`Database has legacy "registered" column in node, removing...`)

		nodes := types.Nodes{}
		if err := dbConn.Not("registered").Find(&nodes).Error; err != nil {
			log.Error().Err(err).Msg("Error accessing db")
		}

		for _, node := range nodes {
			log.Info().
				Str("node", node.Hostname).
				Str("machine_key", node.MachineKey.ShortString()).
				Msg("Deleting unregistered node")
			if err := dbConn.Delete(&types.Node{}, node.ID).Error; err != nil {
				log.Error().
					Err(err).
					Str("node", node.Hostname).
					Str("machine_key", node.MachineKey.ShortString()).
					Msg("Error deleting unregistered node")
			}
		}

		err := dbConn.Migrator().DropColumn(&types.Node{}, "registered")
		if err != nil {
			log.Error().Err(err).Msg("Error dropping registered column")
		}
	}

	err = dbConn.AutoMigrate(&types.Route{})
	if err != nil {
		return nil, err
	}

	err = dbConn.AutoMigrate(&types.Node{})
	if err != nil {
		return nil, err
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
	err = db.db.Raw("SELECT id, node_key, machine_key, disco_key FROM nodes").Find(&results).Error
	if err != nil {
		return nil, err
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

		err := db.db.Exec(
			"UPDATE nodes SET machine_key = @mKey, node_key = @nKey, disco_key = @dKey WHERE ID = @id",
			sql.Named("mKey", mKey),
			sql.Named("nKey", nKey),
			sql.Named("dKey", dKey),
			sql.Named("id", node.ID),
		).Error
		if err != nil {
			return nil, err
		}
	}

	if dbConn.Migrator().HasColumn(&types.Node{}, "enabled_routes") {
		log.Info().Msgf("Database has legacy enabled_routes column in node, migrating...")

		type NodeAux struct {
			ID            uint64
			EnabledRoutes types.IPPrefixes
		}

		nodesAux := []NodeAux{}
		err := dbConn.Table("nodes").Select("id, enabled_routes").Scan(&nodesAux).Error
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

				err = dbConn.Preload("Node").
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
				if err := dbConn.Create(&route).Error; err != nil {
					log.Error().Err(err).Msg("Error creating route")
				} else {
					log.Info().
						Uint64("node_id", route.NodeID).
						Str("prefix", prefix.String()).
						Msg("Route migrated")
				}
			}
		}

		err = dbConn.Migrator().DropColumn(&types.Node{}, "enabled_routes")
		if err != nil {
			log.Error().Err(err).Msg("Error dropping enabled_routes column")
		}
	}

	if dbConn.Migrator().HasColumn(&types.Node{}, "given_name") {
		nodes := types.Nodes{}
		if err := dbConn.Find(&nodes).Error; err != nil {
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

				err = db.RenameNode(nodes[item], normalizedHostname)
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

	err = dbConn.AutoMigrate(&KV{})
	if err != nil {
		return nil, err
	}

	err = dbConn.AutoMigrate(&types.PreAuthKey{})
	if err != nil {
		return nil, err
	}

	err = dbConn.AutoMigrate(&types.PreAuthKeyACLTag{})
	if err != nil {
		return nil, err
	}

	_ = dbConn.Migrator().DropTable("shared_machines")

	err = dbConn.AutoMigrate(&types.APIKey{})
	if err != nil {
		return nil, err
	}

	// TODO(kradalby): is this needed?
	err = db.setValue("db_version", dbVersion)

	return &db, err
}

func openDB(dbType, connectionAddr string, debug bool) (*gorm.DB, error) {
	log.Debug().Str("type", dbType).Str("connection", connectionAddr).Msg("opening database")

	var dbLogger logger.Interface
	if debug {
		dbLogger = logger.Default
	} else {
		dbLogger = logger.Default.LogMode(logger.Silent)
	}

	switch dbType {
	case Sqlite:
		db, err := gorm.Open(
			sqlite.Open(connectionAddr+"?_synchronous=1&_journal_mode=WAL"),
			&gorm.Config{
				DisableForeignKeyConstraintWhenMigrating: true,
				Logger:                                   dbLogger,
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

	case Postgres:
		return gorm.Open(postgres.Open(connectionAddr), &gorm.Config{
			DisableForeignKeyConstraintWhenMigrating: true,
			Logger:                                   dbLogger,
		})
	}

	return nil, fmt.Errorf(
		"database of type %s is not supported: %w",
		dbType,
		errDatabaseNotSupported,
	)
}

// getValue returns the value for the given key in KV.
func (hsdb *HSDatabase) getValue(key string) (string, error) {
	var row KV
	if result := hsdb.db.First(&row, "key = ?", key); errors.Is(
		result.Error,
		gorm.ErrRecordNotFound,
	) {
		return "", errValueNotFound
	}

	return row.Value, nil
}

// setValue sets value for the given key in KV.
func (hsdb *HSDatabase) setValue(key string, value string) error {
	keyValue := KV{
		Key:   key,
		Value: value,
	}

	if _, err := hsdb.getValue(key); err == nil {
		hsdb.db.Model(&keyValue).Where("key = ?", key).Update("value", value)

		return nil
	}

	if err := hsdb.db.Create(keyValue).Error; err != nil {
		return fmt.Errorf("failed to create key value pair in the database: %w", err)
	}

	return nil
}

func (hsdb *HSDatabase) PingDB(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	sqlDB, err := hsdb.db.DB()
	if err != nil {
		return err
	}

	return sqlDB.PingContext(ctx)
}

func (hsdb *HSDatabase) Close() error {
	db, err := hsdb.db.DB()
	if err != nil {
		return err
	}

	return db.Close()
}
