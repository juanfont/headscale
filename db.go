package headscale

import (
	"errors"

	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

const (
	dbVersion        = "1"
	errValueNotFound = Error("not found")
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
		db.Exec("create extension if not exists \"uuid-ossp\";")
	}
	err = db.AutoMigrate(&Machine{})
	if err != nil {
		return err
	}
	err = db.AutoMigrate(&KV{})
	if err != nil {
		return err
	}
	err = db.AutoMigrate(&Namespace{})
	if err != nil {
		return err
	}
	err = db.AutoMigrate(&PreAuthKey{})
	if err != nil {
		return err
	}

	err = db.AutoMigrate(&SharedMachine{})
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
		db, err = gorm.Open(sqlite.Open(h.dbString), &gorm.Config{
			DisableForeignKeyConstraintWhenMigrating: true,
			Logger:                                   log,
		})
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

	h.db.Create(keyValue)

	return nil
}
