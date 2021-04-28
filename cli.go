package headscale

import (
	"fmt"
	"log"

	"tailscale.com/wgengine/wgcfg"
)

// RegisterMachine is executed from the CLI to register a new Machine using its MachineKey
func (h *Headscale) RegisterMachine(key string, namespace string) error {
	ns, err := h.GetNamespace(namespace)
	if err != nil {
		return err
	}
	mKey, err := wgcfg.ParseHexKey(key)
	if err != nil {
		log.Printf("Cannot parse client key: %s", err)
		return err
	}
	db, err := h.db()
	if err != nil {
		log.Printf("Cannot open DB: %s", err)
		return err
	}
	defer db.Close()
	m := Machine{}
	if db.First(&m, "machine_key = ?", mKey.HexString()).RecordNotFound() {
		log.Printf("Cannot find machine with machine key: %s", mKey.Base64())
		return err
	}

	if m.isAlreadyRegistered() {
		fmt.Println("This machine already registered")
		return nil
	}

	ip, err := h.getAvailableIP()
	if err != nil {
		log.Println(err)
		return err
	}
	m.IPAddress = ip.String()
	m.NamespaceID = ns.ID
	m.Registered = true
	db.Save(&m)
	fmt.Println("Machine registered 🎉")
	return nil
}
