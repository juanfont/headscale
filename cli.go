package headscale

import (
	"errors"
	"log"

	"gorm.io/gorm"
	"tailscale.com/wgengine/wgcfg"
)

// RegisterMachine is executed from the CLI to register a new Machine using its MachineKey
func (h *Headscale) RegisterMachine(key string, namespace string) (*Machine, error) {
	ns, err := h.GetNamespace(namespace)
	if err != nil {
		return nil, err
	}
	mKey, err := wgcfg.ParseHexKey(key)
	if err != nil {
		return nil, err
	}
	db, err := h.db()
	if err != nil {
		log.Printf("Cannot open DB: %s", err)
		return nil, err
	}
	m := Machine{}
	if result := db.First(&m, "machine_key = ?", mKey.HexString()); errors.Is(result.Error, gorm.ErrRecordNotFound) {
		return nil, errors.New("Machine not found")
	}

	if m.isAlreadyRegistered() {
		return nil, errors.New("Machine already registered")
	}

	ip, err := h.getAvailableIP()
	if err != nil {
		return nil, err
	}
	m.IPAddress = ip.String()
	m.NamespaceID = ns.ID
	m.Registered = true
	m.RegisterMethod = "cli"
	db.Save(&m)
	return &m, nil
}
