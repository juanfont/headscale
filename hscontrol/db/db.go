package db

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"time"

	"github.com/glebarez/sqlite"
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
	db               *gorm.DB
	notifyStateChan  chan<- struct{}
	notifyPolicyChan chan<- struct{}

	ipAllocationMutex sync.Mutex

	ipPrefixes       []netip.Prefix
	baseDomain       string
	stripEmailDomain bool
}

// TODO(kradalby): assemble this struct from toptions or something typed
// rather than arguments.
func NewHeadscaleDatabase(
	dbType, connectionAddr string,
	stripEmailDomain, debug bool,
	notifyStateChan chan<- struct{},
	notifyPolicyChan chan<- struct{},
	ipPrefixes []netip.Prefix,
	baseDomain string,
) (*HSDatabase, error) {
	dbConn, err := openDB(dbType, connectionAddr, debug)
	if err != nil {
		return nil, err
	}

	db := HSDatabase{
		db:               dbConn,
		notifyStateChan:  notifyStateChan,
		notifyPolicyChan: notifyPolicyChan,

		ipPrefixes:       ipPrefixes,
		baseDomain:       baseDomain,
		stripEmailDomain: stripEmailDomain,
	}

	log.Debug().Msgf("database %#v", dbConn)

	if dbType == Postgres {
		dbConn.Exec(`create extension if not exists "uuid-ossp";`)
	}

	_ = dbConn.Migrator().RenameTable("namespaces", "users")

	err = dbConn.AutoMigrate(types.User{})
	if err != nil {
		return nil, err
	}

	_ = dbConn.Migrator().RenameColumn(&types.Machine{}, "namespace_id", "user_id")
	_ = dbConn.Migrator().RenameColumn(&types.PreAuthKey{}, "namespace_id", "user_id")

	_ = dbConn.Migrator().RenameColumn(&types.Machine{}, "ip_address", "ip_addresses")
	_ = dbConn.Migrator().RenameColumn(&types.Machine{}, "name", "hostname")

	// GivenName is used as the primary source of DNS names, make sure
	// the field is populated and normalized if it was not when the
	// machine was registered.
	_ = dbConn.Migrator().RenameColumn(&types.Machine{}, "nickname", "given_name")

	// If the Machine table has a column for registered,
	// find all occourences of "false" and drop them. Then
	// remove the column.
	if dbConn.Migrator().HasColumn(&types.Machine{}, "registered") {
		log.Info().
			Msg(`Database has legacy "registered" column in machine, removing...`)

		machines := types.Machines{}
		if err := dbConn.Not("registered").Find(&machines).Error; err != nil {
			log.Error().Err(err).Msg("Error accessing db")
		}

		for _, machine := range machines {
			log.Info().
				Str("machine", machine.Hostname).
				Str("machine_key", machine.MachineKey).
				Msg("Deleting unregistered machine")
			if err := dbConn.Delete(&types.Machine{}, machine.ID).Error; err != nil {
				log.Error().
					Err(err).
					Str("machine", machine.Hostname).
					Str("machine_key", machine.MachineKey).
					Msg("Error deleting unregistered machine")
			}
		}

		err := dbConn.Migrator().DropColumn(&types.Machine{}, "registered")
		if err != nil {
			log.Error().Err(err).Msg("Error dropping registered column")
		}
	}

	err = dbConn.AutoMigrate(&types.Route{})
	if err != nil {
		return nil, err
	}

	if dbConn.Migrator().HasColumn(&types.Machine{}, "enabled_routes") {
		log.Info().Msgf("Database has legacy enabled_routes column in machine, migrating...")

		type MachineAux struct {
			ID            uint64
			EnabledRoutes types.IPPrefixes
		}

		machinesAux := []MachineAux{}
		err := dbConn.Table("machines").Select("id, enabled_routes").Scan(&machinesAux).Error
		if err != nil {
			log.Fatal().Err(err).Msg("Error accessing db")
		}
		for _, machine := range machinesAux {
			for _, prefix := range machine.EnabledRoutes {
				if err != nil {
					log.Error().
						Err(err).
						Str("enabled_route", prefix.String()).
						Msg("Error parsing enabled_route")

					continue
				}

				err = dbConn.Preload("Machine").
					Where("machine_id = ? AND prefix = ?", machine.ID, types.IPPrefix(prefix)).
					First(&types.Route{}).
					Error
				if err == nil {
					log.Info().
						Str("enabled_route", prefix.String()).
						Msg("Route already migrated to new table, skipping")

					continue
				}

				route := types.Route{
					MachineID:  machine.ID,
					Advertised: true,
					Enabled:    true,
					Prefix:     types.IPPrefix(prefix),
				}
				if err := dbConn.Create(&route).Error; err != nil {
					log.Error().Err(err).Msg("Error creating route")
				} else {
					log.Info().
						Uint64("machine_id", route.MachineID).
						Str("prefix", prefix.String()).
						Msg("Route migrated")
				}
			}
		}

		err = dbConn.Migrator().DropColumn(&types.Machine{}, "enabled_routes")
		if err != nil {
			log.Error().Err(err).Msg("Error dropping enabled_routes column")
		}
	}

	err = dbConn.AutoMigrate(&types.Machine{})
	if err != nil {
		return nil, err
	}

	if dbConn.Migrator().HasColumn(&types.Machine{}, "given_name") {
		machines := types.Machines{}
		if err := dbConn.Find(&machines).Error; err != nil {
			log.Error().Err(err).Msg("Error accessing db")
		}

		for item, machine := range machines {
			if machine.GivenName == "" {
				normalizedHostname, err := util.NormalizeToFQDNRules(
					machine.Hostname,
					stripEmailDomain,
				)
				if err != nil {
					log.Error().
						Caller().
						Str("hostname", machine.Hostname).
						Err(err).
						Msg("Failed to normalize machine hostname in DB migration")
				}

				err = db.RenameMachine(&machines[item], normalizedHostname)
				if err != nil {
					log.Error().
						Caller().
						Str("hostname", machine.Hostname).
						Err(err).
						Msg("Failed to save normalized machine name in DB migration")
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

func (hsdb *HSDatabase) notifyStateChange() {
	hsdb.notifyStateChan <- struct{}{}
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
