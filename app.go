package headscale

import (
	"fmt"
	"os"
	"sync"

	"github.com/gin-gonic/gin"
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
