package headscale

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/acme/autocert"
	"gorm.io/gorm"
	"inet.af/netaddr"
	"tailscale.com/tailcfg"
	"tailscale.com/types/wgkey"
)

// Config contains the initial Headscale configuration
type Config struct {
	ServerURL                      string
	Addr                           string
	PrivateKeyPath                 string
	DerpMap                        *tailcfg.DERPMap
	EphemeralNodeInactivityTimeout time.Duration
	IPPrefix                       netaddr.IPPrefix

	DBtype string
	DBpath string
	DBhost string
	DBport int
	DBname string
	DBuser string
	DBpass string

	TLSLetsEncryptListen        string
	TLSLetsEncryptHostname      string
	TLSLetsEncryptCacheDir      string
	TLSLetsEncryptChallengeType string

	TLSCertPath string
	TLSKeyPath  string
}

// Headscale represents the base app of the service
type Headscale struct {
	cfg        Config
	db         *gorm.DB
	dbString   string
	dbType     string
	dbDebug    bool
	publicKey  *wgkey.Key
	privateKey *wgkey.Private

	aclPolicy *ACLPolicy
	aclRules  *[]tailcfg.FilterRule

	pollMu         sync.Mutex
	clientsPolling map[uint64]chan []byte // this is by all means a hackity hack
}

// NewHeadscale returns the Headscale app
func NewHeadscale(cfg Config) (*Headscale, error) {
	content, err := os.ReadFile(cfg.PrivateKeyPath)
	if err != nil {
		return nil, err
	}
	privKey, err := wgkey.ParsePrivate(string(content))
	if err != nil {
		return nil, err
	}
	pubKey := privKey.Public()

	var dbString string
	switch cfg.DBtype {
	case "postgres":
		dbString = fmt.Sprintf("host=%s port=%d dbname=%s user=%s password=%s sslmode=disable", cfg.DBhost,
			cfg.DBport, cfg.DBname, cfg.DBuser, cfg.DBpass)
	case "sqlite3":
		dbString = cfg.DBpath
	default:
		return nil, errors.New("unsupported DB")
	}

	h := Headscale{
		cfg:        cfg,
		dbType:     cfg.DBtype,
		dbString:   dbString,
		privateKey: privKey,
		publicKey:  &pubKey,
		aclRules:   &tailcfg.FilterAllowAll, // default allowall
	}

	err = h.initDB()
	if err != nil {
		return nil, err
	}

	h.clientsPolling = make(map[uint64]chan []byte)
	return &h, nil
}

// Redirect to our TLS url
func (h *Headscale) redirect(w http.ResponseWriter, req *http.Request) {
	target := h.cfg.ServerURL + req.URL.RequestURI()
	http.Redirect(w, req, target, http.StatusFound)
}

// ExpireEphemeralNodes deletes ephemeral machine records that have not been
// seen for longer than h.cfg.EphemeralNodeInactivityTimeout
func (h *Headscale) ExpireEphemeralNodes(milliSeconds int64) {
	ticker := time.NewTicker(time.Duration(milliSeconds) * time.Millisecond)
	for range ticker.C {
		h.expireEphemeralNodesWorker()
	}
}

func (h *Headscale) expireEphemeralNodesWorker() {
	namespaces, err := h.ListNamespaces()
	if err != nil {
		log.Printf("Error listing namespaces: %s", err)
		return
	}
	for _, ns := range *namespaces {
		machines, err := h.ListMachinesInNamespace(ns.Name)
		if err != nil {
			log.Printf("Error listing machines in namespace %s: %s", ns.Name, err)
			return
		}
		for _, m := range *machines {
			if m.AuthKey != nil && m.LastSeen != nil && m.AuthKey.Ephemeral && time.Now().After(m.LastSeen.Add(h.cfg.EphemeralNodeInactivityTimeout)) {
				log.Printf("[%s] Ephemeral client removed from database\n", m.Name)
				err = h.db.Unscoped().Delete(m).Error
				if err != nil {
					log.Printf("[%s] 🤮 Cannot delete ephemeral machine from the database: %s", m.Name, err)
				}
			}
		}
	}
}

// WatchForKVUpdates checks the KV DB table for requests to perform tailnet upgrades
// This is a way to communitate the CLI with the headscale server
func (h *Headscale) watchForKVUpdates(milliSeconds int64) {
	ticker := time.NewTicker(time.Duration(milliSeconds) * time.Millisecond)
	for range ticker.C {
		h.watchForKVUpdatesWorker()
	}
}

func (h *Headscale) watchForKVUpdatesWorker() {
	h.checkForNamespacesPendingUpdates()
	// more functions will come here in the future
}

// Serve launches a GIN server with the Headscale API
func (h *Headscale) Serve() error {
	r := gin.Default()
	r.GET("/key", h.KeyHandler)
	r.GET("/register", h.RegisterWebAPI)
	r.POST("/machine/:id/map", h.PollNetMapHandler)
	r.POST("/machine/:id", h.RegistrationHandler)
	var err error

	go h.watchForKVUpdates(5000)

	if h.cfg.TLSLetsEncryptHostname != "" {
		if !strings.HasPrefix(h.cfg.ServerURL, "https://") {
			log.Println("WARNING: listening with TLS but ServerURL does not start with https://")
		}

		m := autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(h.cfg.TLSLetsEncryptHostname),
			Cache:      autocert.DirCache(h.cfg.TLSLetsEncryptCacheDir),
		}
		s := &http.Server{
			Addr:      h.cfg.Addr,
			TLSConfig: m.TLSConfig(),
			Handler:   r,
		}
		if h.cfg.TLSLetsEncryptChallengeType == "TLS-ALPN-01" {
			// Configuration via autocert with TLS-ALPN-01 (https://tools.ietf.org/html/rfc8737)
			// The RFC requires that the validation is done on port 443; in other words, headscale
			// must be reachable on port 443.
			err = s.ListenAndServeTLS("", "")
		} else if h.cfg.TLSLetsEncryptChallengeType == "HTTP-01" {
			// Configuration via autocert with HTTP-01. This requires listening on
			// port 80 for the certificate validation in addition to the headscale
			// service, which can be configured to run on any other port.
			go func() {
				log.Fatal(http.ListenAndServe(h.cfg.TLSLetsEncryptListen, m.HTTPHandler(http.HandlerFunc(h.redirect))))
			}()
			err = s.ListenAndServeTLS("", "")
		} else {
			return errors.New("unknown value for TLSLetsEncryptChallengeType")
		}
	} else if h.cfg.TLSCertPath == "" {
		if !strings.HasPrefix(h.cfg.ServerURL, "http://") {
			log.Println("WARNING: listening without TLS but ServerURL does not start with http://")
		}
		err = r.Run(h.cfg.Addr)
	} else {
		if !strings.HasPrefix(h.cfg.ServerURL, "https://") {
			log.Println("WARNING: listening with TLS but ServerURL does not start with https://")
		}
		err = r.RunTLS(h.cfg.Addr, h.cfg.TLSCertPath, h.cfg.TLSKeyPath)
	}
	return err
}
