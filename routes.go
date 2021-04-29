package headscale

import (
	"encoding/json"
	"errors"
	"log"

	"github.com/jinzhu/gorm/dialects/postgres"
	"inet.af/netaddr"
)

// GetNodeRoutes returns the subnet routes advertised by a node (identified by
// namespace and node name)
func (h *Headscale) GetNodeRoutes(namespace string, nodeName string) (*[]netaddr.IPPrefix, error) {
	m, err := h.GetMachine(namespace, nodeName)
	if err != nil {
		return nil, err
	}

	hi, err := m.GetHostInfo()
	if err != nil {
		return nil, err
	}
	return &hi.RoutableIPs, nil
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

	return errors.New("could not find routable range")
}
