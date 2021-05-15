package headscale

import (
	"errors"

	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/postgres" // sql driver
	_ "github.com/jinzhu/gorm/dialects/sqlite"   // sql driver
)

const dbVersion = "1"

// KV is a key-value store in a psql table. For future use...
type KV struct {
	Key   string
	Value string
}

func (h *Headscale) initDB() error {
	db, err := gorm.Open(h.dbType, h.dbString)
	if err != nil {
		return err
	}
	if h.dbType == "postgres" {
		db.Exec("create extension if not exists \"uuid-ossp\";")
	}
	db.AutoMigrate(&Machine{})
	db.AutoMigrate(&KV{})
	db.AutoMigrate(&Namespace{})
	db.AutoMigrate(&PreAuthKey{})
	db.Close()

	err = h.setValue("db_version", dbVersion)
	return err
}

func (h *Headscale) db() (*gorm.DB, error) {
	db, err := gorm.Open(h.dbType, h.dbString)
	if err != nil {
		return nil, err
	}
	if h.dbDebug {
		db.LogMode(true)
	}
	return db, nil
}

func (h *Headscale) getValue(key string) (string, error) {
	db, err := h.db()
	if err != nil {
		return "", err
	}
	defer db.Close()
	var row KV
	if db.First(&row, "key = ?", key).RecordNotFound() {
		return "", errors.New("not found")
	}
	return row.Value, nil
}

func (h *Headscale) setValue(key string, value string) error {
	kv := KV{
		Key:   key,
		Value: value,
	}
	db, err := h.db()
	if err != nil {
		return err
	}
	defer db.Close()
	_, err = h.getValue(key)
	if err == nil {
		db.Model(&kv).Where("key = ?", key).Update("value", value)
		return nil
	}

	db.Create(kv)
	return nil
}
