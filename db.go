package headscale

import (
	"context"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/glebarez/sqlite"
	"github.com/rs/zerolog/log"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
	"tailscale.com/tailcfg"
)

const (
	dbVersion = "1"

	errValueNotFound     = Error("not found")
	ErrCannotParsePrefix = Error("cannot parse prefix")
)

// KV is a key-value store in a psql table. For future use...
type KV struct {
	Key   string
	Value string
}

func (h *Headscale) initDB() error {
	db, err := h.openDB()
	if err != nil {
		return err
	}
	h.db = db

	if h.dbType == Postgres {
		db.Exec(`create extension if not exists "uuid-ossp";`)
	}

	_ = db.Migrator().RenameTable("namespaces", "users")

	err = db.AutoMigrate(&User{})
	if err != nil {
		return err
	}

	_ = db.Migrator().RenameColumn(&Machine{}, "ip_address", "ip_addresses")
	_ = db.Migrator().RenameColumn(&Machine{}, "name", "hostname")

	// GivenName is used as the primary source of DNS names, make sure
	// the field is populated and normalized if it was not when the
	// machine was registered.
	_ = db.Migrator().RenameColumn(&Machine{}, "nickname", "given_name")

	// If the Machine table has a column for registered,
	// find all occourences of "false" and drop them. Then
	// remove the column.
	if db.Migrator().HasColumn(&Machine{}, "registered") {
		log.Info().
			Msg(`Database has legacy "registered" column in machine, removing...`)

		machines := Machines{}
		if err := h.db.Not("registered").Find(&machines).Error; err != nil {
			log.Error().Err(err).Msg("Error accessing db")
		}

		for _, machine := range machines {
			log.Info().
				Str("machine", machine.Hostname).
				Str("machine_key", machine.MachineKey).
				Msg("Deleting unregistered machine")
			if err := h.db.Delete(&Machine{}, machine.ID).Error; err != nil {
				log.Error().
					Err(err).
					Str("machine", machine.Hostname).
					Str("machine_key", machine.MachineKey).
					Msg("Error deleting unregistered machine")
			}
		}

		err := db.Migrator().DropColumn(&Machine{}, "registered")
		if err != nil {
			log.Error().Err(err).Msg("Error dropping registered column")
		}
	}

	err = db.AutoMigrate(&Route{})
	if err != nil {
		return err
	}

	if db.Migrator().HasColumn(&Machine{}, "enabled_routes") {
		log.Info().Msgf("Database has legacy enabled_routes column in machine, migrating...")

		type MachineAux struct {
			ID            uint64
			EnabledRoutes IPPrefixes
		}

		machinesAux := []MachineAux{}
		err := db.Table("machines").Select("id, enabled_routes").Scan(&machinesAux).Error
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

				err = db.Preload("Machine").
					Where("machine_id = ? AND prefix = ?", machine.ID, IPPrefix(prefix)).
					First(&Route{}).
					Error
				if err == nil {
					log.Info().
						Str("enabled_route", prefix.String()).
						Msg("Route already migrated to new table, skipping")

					continue
				}

				route := Route{
					MachineID:  machine.ID,
					Advertised: true,
					Enabled:    true,
					Prefix:     IPPrefix(prefix),
				}
				if err := h.db.Create(&route).Error; err != nil {
					log.Error().Err(err).Msg("Error creating route")
				} else {
					log.Info().
						Uint64("machine_id", route.MachineID).
						Str("prefix", prefix.String()).
						Msg("Route migrated")
				}
			}
		}

		err = db.Migrator().DropColumn(&Machine{}, "enabled_routes")
		if err != nil {
			log.Error().Err(err).Msg("Error dropping enabled_routes column")
		}
	}

	err = db.AutoMigrate(&Machine{})
	if err != nil {
		return err
	}

	if db.Migrator().HasColumn(&Machine{}, "given_name") {
		machines := Machines{}
		if err := h.db.Find(&machines).Error; err != nil {
			log.Error().Err(err).Msg("Error accessing db")
		}

		for item, machine := range machines {
			if machine.GivenName == "" {
				normalizedHostname, err := NormalizeToFQDNRules(
					machine.Hostname,
					h.cfg.OIDC.StripEmaildomain,
				)
				if err != nil {
					log.Error().
						Caller().
						Str("hostname", machine.Hostname).
						Err(err).
						Msg("Failed to normalize machine hostname in DB migration")
				}

				err = h.RenameMachine(&machines[item], normalizedHostname)
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

	err = db.AutoMigrate(&KV{})
	if err != nil {
		return err
	}

	err = db.AutoMigrate(&PreAuthKey{})
	if err != nil {
		return err
	}

	err = db.AutoMigrate(&PreAuthKeyACLTag{})
	if err != nil {
		return err
	}

	_ = db.Migrator().DropTable("shared_machines")

	err = db.AutoMigrate(&APIKey{})
	if err != nil {
		return err
	}

	err = h.setValue("db_version", dbVersion)

	return err
}

func (h *Headscale) openDB() (*gorm.DB, error) {
	var db *gorm.DB
	var err error

	var log logger.Interface
	if h.dbDebug {
		log = logger.Default
	} else {
		log = logger.Default.LogMode(logger.Silent)
	}

	switch h.dbType {
	case Sqlite:
		db, err = gorm.Open(
			sqlite.Open(h.dbString+"?_synchronous=1&_journal_mode=WAL"),
			&gorm.Config{
				DisableForeignKeyConstraintWhenMigrating: true,
				Logger:                                   log,
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

	case Postgres:
		db, err = gorm.Open(postgres.Open(h.dbString), &gorm.Config{
			DisableForeignKeyConstraintWhenMigrating: true,
			Logger:                                   log,
		})
	}

	if err != nil {
		return nil, err
	}

	return db, nil
}

// getValue returns the value for the given key in KV.
func (h *Headscale) getValue(key string) (string, error) {
	var row KV
	if result := h.db.First(&row, "key = ?", key); errors.Is(
		result.Error,
		gorm.ErrRecordNotFound,
	) {
		return "", errValueNotFound
	}

	return row.Value, nil
}

// setValue sets value for the given key in KV.
func (h *Headscale) setValue(key string, value string) error {
	keyValue := KV{
		Key:   key,
		Value: value,
	}

	if _, err := h.getValue(key); err == nil {
		h.db.Model(&keyValue).Where("key = ?", key).Update("value", value)

		return nil
	}

	if err := h.db.Create(keyValue).Error; err != nil {
		return fmt.Errorf("failed to create key value pair in the database: %w", err)
	}

	return nil
}

func (h *Headscale) pingDB(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	db, err := h.db.DB()
	if err != nil {
		return err
	}

	return db.PingContext(ctx)
}

// This is a "wrapper" type around tailscales
// Hostinfo to allow us to add database "serialization"
// methods. This allows us to use a typed values throughout
// the code and not have to marshal/unmarshal and error
// check all over the code.
type HostInfo tailcfg.Hostinfo

func (hi *HostInfo) Scan(destination interface{}) error {
	switch value := destination.(type) {
	case []byte:
		return json.Unmarshal(value, hi)

	case string:
		return json.Unmarshal([]byte(value), hi)

	default:
		return fmt.Errorf("%w: unexpected data type %T", ErrMachineAddressesInvalid, destination)
	}
}

// Value return json value, implement driver.Valuer interface.
func (hi HostInfo) Value() (driver.Value, error) {
	bytes, err := json.Marshal(hi)

	return string(bytes), err
}

type IPPrefix netip.Prefix

func (i *IPPrefix) Scan(destination interface{}) error {
	switch value := destination.(type) {
	case string:
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return err
		}
		*i = IPPrefix(prefix)

		return nil
	default:
		return fmt.Errorf("%w: unexpected data type %T", ErrCannotParsePrefix, destination)
	}
}

// Value return json value, implement driver.Valuer interface.
func (i IPPrefix) Value() (driver.Value, error) {
	prefixStr := netip.Prefix(i).String()

	return prefixStr, nil
}

type IPPrefixes []netip.Prefix

func (i *IPPrefixes) Scan(destination interface{}) error {
	switch value := destination.(type) {
	case []byte:
		return json.Unmarshal(value, i)

	case string:
		return json.Unmarshal([]byte(value), i)

	default:
		return fmt.Errorf("%w: unexpected data type %T", ErrMachineAddressesInvalid, destination)
	}
}

// Value return json value, implement driver.Valuer interface.
func (i IPPrefixes) Value() (driver.Value, error) {
	bytes, err := json.Marshal(i)

	return string(bytes), err
}

type StringList []string

func (i *StringList) Scan(destination interface{}) error {
	switch value := destination.(type) {
	case []byte:
		return json.Unmarshal(value, i)

	case string:
		return json.Unmarshal([]byte(value), i)

	default:
		return fmt.Errorf("%w: unexpected data type %T", ErrMachineAddressesInvalid, destination)
	}
}

// Value return json value, implement driver.Valuer interface.
func (i StringList) Value() (driver.Value, error) {
	bytes, err := json.Marshal(i)

	return string(bytes), err
}
