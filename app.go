package headscale

import (
	"fmt"
	"io/ioutil"
	"log"

	"github.com/gin-gonic/gin"
	"tailscale.com/tailcfg"
	"tailscale.com/wgengine/wgcfg"
)

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

	// r.LoadHTMLFiles("./frontend/build/index.html")
	// r.Use(static.Serve("/", static.LocalFile("./frontend/build", true)))
	err := r.Run(h.cfg.Addr)
	return err
}

func (h *Headscale) RegisterMachine(key string) error {
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
	m.Registered = true
	db.Save(&m)
	fmt.Println("Machine registered 🎉")
	return nil
}
