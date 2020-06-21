package headscale

import (
	"fmt"
	"io/ioutil"

	"github.com/gin-gonic/gin"

	"github.com/tailscale/wireguard-go/wgcfg"
)

type Config struct {
	ServerURL      string
	Addr           string
	PrivateKeyPath string

	DBhost string
	DBport int
	DBname string
	DBuser string
	DBpass string
}

type Headscale struct {
	cfg        Config
	dbString   string
	publicKey  *wgcfg.Key
	privateKey *wgcfg.PrivateKey
}

func NewHeadscale(cfg Config) (*Headscale, error) {
	content, err := ioutil.ReadFile(cfg.PrivateKeyPath)
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
	return &h, nil
}

func (h *Headscale) Serve() error {
	r := gin.Default()
	r.GET("/key", h.KeyHandler)
	r.GET("/register", h.RegisterWebAPI)
	r.POST("/machine/:id/map", h.PollNetMapHandler)
	r.POST("/machine/:id", h.RegistrationHandler)
	err := r.Run(h.cfg.Addr)
	return err
}
