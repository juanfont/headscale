package headscale

import (
	"errors"

	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

const dbVersion = "1"

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

	if h.dbType == "postgres" {
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

	err = h.setValue("db_version", dbVersion)
	return err
}

func (h *Headscale) openDB() (*gorm.DB, error) {
	var db *gorm.DB
	var err error
	switch h.dbType {
	case "sqlite3":
		db, err = gorm.Open(sqlite.Open(h.dbString), &gorm.Config{
			DisableForeignKeyConstraintWhenMigrating: true,
		})
	case "postgres":
		db, err = gorm.Open(postgres.Open(h.dbString), &gorm.Config{
			DisableForeignKeyConstraintWhenMigrating: true,
		})
	}

	if err != nil {
		return nil, err
	}
	if h.dbDebug {
		db.Debug()
	}
	return db, nil
}

func (h *Headscale) getValue(key string) (string, error) {
	var row KV
	if result := h.db.First(&row, "key = ?", key); errors.Is(result.Error, gorm.ErrRecordNotFound) {
		return "", errors.New("not found")
	}
	return row.Value, nil
}

func (h *Headscale) setValue(key string, value string) error {
	kv := KV{
		Key:   key,
		Value: value,
	}

	_, err := h.getValue(key)
	if err == nil {
		h.db.Model(&kv).Where("key = ?", key).Update("value", value)
		return nil
	}

	h.db.Create(kv)
	return nil
}
