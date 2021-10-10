package headscale

import (
	"errors"

	"gorm.io/gorm"
	"tailscale.com/types/wgkey"
)

// RegisterMachine is executed from the CLI to register a new Machine using its MachineKey
func (h *Headscale) RegisterMachine(key string, namespace string) (*Machine, error) {
	ns, err := h.GetNamespace(namespace)
	if err != nil {
		return nil, err
	}
	mKey, err := wgkey.ParseHex(key)
	if err != nil {
		return nil, err
	}

	m := Machine{}
	if result := h.db.First(&m, "machine_key = ?", mKey.HexString()); errors.Is(result.Error, gorm.ErrRecordNotFound) {
		return nil, errors.New("Machine not found")
	}

	h.updateMachineExpiry(&m) // update the machine's expiry before bailing if its already registered

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
	h.db.Save(&m)

	return &m, nil
}
