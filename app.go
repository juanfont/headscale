package headscale

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sync"

	"github.com/gin-gonic/gin"
	"github.com/jinzhu/gorm/dialects/postgres"
	"inet.af/netaddr"
	"tailscale.com/tailcfg"
	"tailscale.com/wgengine/wgcfg"
)

// Config contains the initial Headscale configuration
type Config struct {
	ServerURL      string
	Addr           string
	PrivateKeyPath string
	DerpMap        *tailcfg.DERPMap

	DBhost string
	DBport int
	DBname string
	DBuser string
	DBpass string
}

// Headscale represents the base app of the service
type Headscale struct {
	cfg        Config
	dbString   string
	publicKey  *wgcfg.Key
	privateKey *wgcfg.PrivateKey

	pollMu         sync.Mutex
	clientsPolling map[uint64]chan []byte // this is by all means a hackity hack
}

// NewHeadscale returns the Headscale app
func NewHeadscale(cfg Config) (*Headscale, error) {
	content, err := os.ReadFile(cfg.PrivateKeyPath)
	if err != nil {
		return nil, err
	}
	privKey, err := wgcfg.ParsePrivateKey(string(content))
	if err != nil {
		return nil, err
	}
	pubKey := privKey.Public()
	h := Headscale{
		cfg: cfg,
		dbString: fmt.Sprintf("host=%s port=%d dbname=%s user=%s password=%s sslmode=disable", cfg.DBhost,
			cfg.DBport, cfg.DBname, cfg.DBuser, cfg.DBpass),
		privateKey: privKey,
		publicKey:  &pubKey,
	}
	err = h.initDB()
	if err != nil {
		return nil, err
	}
	h.clientsPolling = make(map[uint64]chan []byte)
	return &h, nil
}

// Serve launches a GIN server with the Headscale API
func (h *Headscale) Serve() error {
	r := gin.Default()
	r.GET("/key", h.KeyHandler)
	r.GET("/register", h.RegisterWebAPI)
	r.POST("/machine/:id/map", h.PollNetMapHandler)
	r.POST("/machine/:id", h.RegistrationHandler)
	err := r.Run(h.cfg.Addr)
	return err
}

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
				} else {
				}
			}
			h.pollMu.Unlock()
			return nil
		}
	}
	return fmt.Errorf("Could not find routable range")

}

func eqCIDRs(a, b []netaddr.IPPrefix) bool {
	if len(a) != len(b) || ((a == nil) != (b == nil)) {
		return false
	}
	for i, v := range a {
		if v != b[i] {
			return false
		}
	}
	return true
}
