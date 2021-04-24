package headscale

import (
	"encoding/json"
	"fmt"
	"log"

	"github.com/jinzhu/gorm/dialects/postgres"
	"inet.af/netaddr"
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

// ListNodeRoutes prints the subnet routes advertised by a node (identified by
// namespace and node name)
func (h *Headscale) ListNodeRoutes(namespace string, nodeName string) error {
	m, err := h.GetMachine(namespace, nodeName)
	if err != nil {
		return err
	}

	hi, err := m.GetHostInfo()
	if err != nil {
		return err
	}
	fmt.Println(hi.RoutableIPs)
	return nil
}

// EnableNodeRoute enables a subnet route advertised by a node (identified by
// namespace and node name)
func (h *Headscale) EnableNodeRoute(namespace string, nodeName string, routeStr string) error {
	m, err := h.GetMachine(namespace, nodeName)
	if err != nil {
		return err
	}
	hi, err := m.GetHostInfo()
	if err != nil {
		return err
	}
	route, err := netaddr.ParseIPPrefix(routeStr)
	if err != nil {
		return err
	}

	for _, rIP := range hi.RoutableIPs {
		if rIP == route {
			db, err := h.db()
			if err != nil {
				log.Printf("Cannot open DB: %s", err)
				return err
			}
			defer db.Close()
			routes, _ := json.Marshal([]string{routeStr}) // TODO: only one for the time being, so overwriting the rest
			m.EnabledRoutes = postgres.Jsonb{RawMessage: json.RawMessage(routes)}
			db.Save(&m)
			db.Close()

			peers, _ := h.getPeers(*m)
			h.pollMu.Lock()
			for _, p := range *peers {
				if pUp, ok := h.clientsPolling[uint64(p.ID)]; ok {
					pUp <- []byte{}
				}
			}
			h.pollMu.Unlock()
			return nil
		}
	}
	return fmt.Errorf("Could not find routable range")

}
