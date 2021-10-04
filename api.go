package headscale

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/gin-gonic/gin"
	"github.com/klauspost/compress/zstd"
	"gorm.io/gorm"
	"tailscale.com/tailcfg"
	"tailscale.com/types/wgkey"
)

// KeyHandler provides the Headscale pub key
// Listens in /key
func (h *Headscale) KeyHandler(c *gin.Context) {
	c.Data(200, "text/plain; charset=utf-8", []byte(h.publicKey.HexString()))
}

// RegisterWebAPI shows a simple message in the browser to point to the CLI
// Listens in /register
func (h *Headscale) RegisterWebAPI(c *gin.Context) {
	mKeyStr := c.Query("key")
	if mKeyStr == "" {
		c.String(http.StatusBadRequest, "Wrong params")
		return
	}

	c.Data(http.StatusOK, "text/html; charset=utf-8", []byte(fmt.Sprintf(`
	<html>
	<body>
	<h1>headscale</h1>
	<p>
		Run the command below in the headscale server to add this machine to your network:
	</p>

	<p>
		<code>
			<b>headscale -n NAMESPACE nodes register %s</b>
		</code>
	</p>

	</body>
	</html>

	`, mKeyStr)))
}

// RegistrationHandler handles the actual registration process of a machine
// Endpoint /machine/:id
func (h *Headscale) RegistrationHandler(c *gin.Context) {
	body, _ := io.ReadAll(c.Request.Body)
	mKeyStr := c.Param("id")
	mKey, err := wgkey.ParseHex(mKeyStr)
	if err != nil {
		log.Error().
			Str("handler", "Registration").
			Err(err).
			Msg("Cannot parse machine key")
		machineRegistrations.WithLabelValues("unkown", "web", "error", "unknown").Inc()
		c.String(http.StatusInternalServerError, "Sad!")
		return
	}
	req := tailcfg.RegisterRequest{}
	err = decode(body, &req, &mKey, h.privateKey)
	if err != nil {
		log.Error().
			Str("handler", "Registration").
			Err(err).
			Msg("Cannot decode message")
		machineRegistrations.WithLabelValues("unkown", "web", "error", "unknown").Inc()
		c.String(http.StatusInternalServerError, "Very sad!")
		return
	}

	now := time.Now().UTC()
	var m Machine
	if result := h.db.Preload("Namespace").First(&m, "machine_key = ?", mKey.HexString()); errors.Is(result.Error, gorm.ErrRecordNotFound) {
		log.Info().Str("machine", req.Hostinfo.Hostname).Msg("New machine")
		m = Machine{
			Expiry:               &req.Expiry,
			MachineKey:           mKey.HexString(),
			Name:                 req.Hostinfo.Hostname,
			NodeKey:              wgkey.Key(req.NodeKey).HexString(),
			LastSuccessfulUpdate: &now,
		}
		if err := h.db.Create(&m).Error; err != nil {
			log.Error().
				Str("handler", "Registration").
				Err(err).
				Msg("Could not create row")
			machineRegistrations.WithLabelValues("unkown", "web", "error", m.Namespace.Name).Inc()
			return
		}
	}

	if !m.Registered && req.Auth.AuthKey != "" {
		h.handleAuthKey(c, h.db, mKey, req, m)
		return
	}

	resp := tailcfg.RegisterResponse{}

	// We have the updated key!
	if m.NodeKey == wgkey.Key(req.NodeKey).HexString() {
		if m.Registered {
			log.Debug().
				Str("handler", "Registration").
				Str("machine", m.Name).
				Msg("Client is registered and we have the current NodeKey. All clear to /map")

			resp.AuthURL = ""
			resp.MachineAuthorized = true
			resp.User = *m.Namespace.toUser()
			respBody, err := encode(resp, &mKey, h.privateKey)
			if err != nil {
				log.Error().
					Str("handler", "Registration").
					Err(err).
					Msg("Cannot encode message")
				machineRegistrations.WithLabelValues("update", "web", "error", m.Namespace.Name).Inc()
				c.String(http.StatusInternalServerError, "")
				return
			}
			machineRegistrations.WithLabelValues("update", "web", "success", m.Namespace.Name).Inc()
			c.Data(200, "application/json; charset=utf-8", respBody)
			return
		}

		log.Debug().
			Str("handler", "Registration").
			Str("machine", m.Name).
			Msg("Not registered and not NodeKey rotation. Sending a authurl to register")
		resp.AuthURL = fmt.Sprintf("%s/register?key=%s",
			h.cfg.ServerURL, mKey.HexString())
		respBody, err := encode(resp, &mKey, h.privateKey)
		if err != nil {
			log.Error().
				Str("handler", "Registration").
				Err(err).
				Msg("Cannot encode message")
			machineRegistrations.WithLabelValues("new", "web", "error", m.Namespace.Name).Inc()
			c.String(http.StatusInternalServerError, "")
			return
		}
		machineRegistrations.WithLabelValues("new", "web", "success", m.Namespace.Name).Inc()
		c.Data(200, "application/json; charset=utf-8", respBody)
		return
	}

	// The NodeKey we have matches OldNodeKey, which means this is a refresh after an key expiration
	if m.NodeKey == wgkey.Key(req.OldNodeKey).HexString() {
		log.Debug().
			Str("handler", "Registration").
			Str("machine", m.Name).
			Msg("We have the OldNodeKey in the database. This is a key refresh")
		m.NodeKey = wgkey.Key(req.NodeKey).HexString()
		h.db.Save(&m)

		resp.AuthURL = ""
		resp.User = *m.Namespace.toUser()
		respBody, err := encode(resp, &mKey, h.privateKey)
		if err != nil {
			log.Error().
				Str("handler", "Registration").
				Err(err).
				Msg("Cannot encode message")
			c.String(http.StatusInternalServerError, "Extremely sad!")
			return
		}
		c.Data(200, "application/json; charset=utf-8", respBody)
		return
	}

	// We arrive here after a client is restarted without finalizing the authentication flow or
	// when headscale is stopped in the middle of the auth process.
	if m.Registered {
		log.Debug().
			Str("handler", "Registration").
			Str("machine", m.Name).
			Msg("The node is sending us a new NodeKey, but machine is registered. All clear for /map")
		resp.AuthURL = ""
		resp.MachineAuthorized = true
		resp.User = *m.Namespace.toUser()
		respBody, err := encode(resp, &mKey, h.privateKey)
		if err != nil {
			log.Error().
				Str("handler", "Registration").
				Err(err).
				Msg("Cannot encode message")
			c.String(http.StatusInternalServerError, "")
			return
		}
		c.Data(200, "application/json; charset=utf-8", respBody)
		return
	}

	log.Debug().
		Str("handler", "Registration").
		Str("machine", m.Name).
		Msg("The node is sending us a new NodeKey, sending auth url")
	resp.AuthURL = fmt.Sprintf("%s/register?key=%s",
		h.cfg.ServerURL, mKey.HexString())
	respBody, err := encode(resp, &mKey, h.privateKey)
	if err != nil {
		log.Error().
			Str("handler", "Registration").
			Err(err).
			Msg("Cannot encode message")
		c.String(http.StatusInternalServerError, "")
		return
	}
	c.Data(200, "application/json; charset=utf-8", respBody)
}

func (h *Headscale) getMapResponse(mKey wgkey.Key, req tailcfg.MapRequest, m *Machine) ([]byte, error) {
	log.Trace().
		Str("func", "getMapResponse").
		Str("machine", req.Hostinfo.Hostname).
		Msg("Creating Map response")
	node, err := m.toNode(true)
	if err != nil {
		log.Error().
			Str("func", "getMapResponse").
			Err(err).
			Msg("Cannot convert to node")
		return nil, err
	}

	peers, err := h.getPeers(m)
	if err != nil {
		log.Error().
			Str("func", "getMapResponse").
			Err(err).
			Msg("Cannot fetch peers")
		return nil, err
	}

	profile := tailcfg.UserProfile{
		ID:          tailcfg.UserID(m.NamespaceID),
		LoginName:   m.Namespace.Name,
		DisplayName: m.Namespace.Name,
	}

	nodePeers, err := peers.toNodes(true)
	if err != nil {
		log.Error().
			Str("func", "getMapResponse").
			Err(err).
			Msg("Failed to convert peers to Tailscale nodes")
		return nil, err
	}

	var dnsConfig *tailcfg.DNSConfig
	if h.cfg.DNSConfig != nil && h.cfg.DNSConfig.Proxied { // if MagicDNS is enabled
		// TODO(juanfont): We should not be regenerating this all the time
		// And we should only send the domains of the peers (this own namespace + those from the shared peers)
		namespaces, err := h.ListNamespaces()
		if err != nil {
			return nil, err
		}
		dnsConfig = h.cfg.DNSConfig.Clone()
		for _, ns := range *namespaces {
			dnsConfig.Domains = append(dnsConfig.Domains, fmt.Sprintf("%s.%s", ns.Name, h.cfg.BaseDomain))
		}
	} else {
		dnsConfig = h.cfg.DNSConfig
	}

	resp := tailcfg.MapResponse{
		KeepAlive:    false,
		Node:         node,
		Peers:        nodePeers,
		DNSConfig:    dnsConfig,
		Domain:       h.cfg.BaseDomain,
		PacketFilter: *h.aclRules,
		DERPMap:      h.cfg.DerpMap,

		// TODO(juanfont): We should send the profiles of all the peers (this own namespace + those from the shared peers)
		UserProfiles: []tailcfg.UserProfile{profile},
	}
	log.Trace().
		Str("func", "getMapResponse").
		Str("machine", req.Hostinfo.Hostname).
		Interface("payload", resp).
		Msgf("Generated map response: %s", tailMapResponseToString(resp))

	var respBody []byte
	if req.Compress == "zstd" {
		src, _ := json.Marshal(resp)

		encoder, _ := zstd.NewWriter(nil)
		srcCompressed := encoder.EncodeAll(src, nil)
		respBody, err = encodeMsg(srcCompressed, &mKey, h.privateKey)
		if err != nil {
			return nil, err
		}
	} else {
		respBody, err = encode(resp, &mKey, h.privateKey)
		if err != nil {
			return nil, err
		}
	}
	// declare the incoming size on the first 4 bytes
	data := make([]byte, 4)
	binary.LittleEndian.PutUint32(data, uint32(len(respBody)))
	data = append(data, respBody...)
	return data, nil
}

func (h *Headscale) getMapKeepAliveResponse(mKey wgkey.Key, req tailcfg.MapRequest, m *Machine) ([]byte, error) {
	resp := tailcfg.MapResponse{
		KeepAlive: true,
	}
	var respBody []byte
	var err error
	if req.Compress == "zstd" {
		src, _ := json.Marshal(resp)
		encoder, _ := zstd.NewWriter(nil)
		srcCompressed := encoder.EncodeAll(src, nil)
		respBody, err = encodeMsg(srcCompressed, &mKey, h.privateKey)
		if err != nil {
			return nil, err
		}
	} else {
		respBody, err = encode(resp, &mKey, h.privateKey)
		if err != nil {
			return nil, err
		}
	}
	data := make([]byte, 4)
	binary.LittleEndian.PutUint32(data, uint32(len(respBody)))
	data = append(data, respBody...)
	return data, nil
}

func (h *Headscale) handleAuthKey(c *gin.Context, db *gorm.DB, idKey wgkey.Key, req tailcfg.RegisterRequest, m Machine) {
	log.Debug().
		Str("func", "handleAuthKey").
		Str("machine", req.Hostinfo.Hostname).
		Msgf("Processing auth key for %s", req.Hostinfo.Hostname)
	resp := tailcfg.RegisterResponse{}
	pak, err := h.checkKeyValidity(req.Auth.AuthKey)
	if err != nil {
		log.Error().
			Str("func", "handleAuthKey").
			Str("machine", m.Name).
			Err(err).
			Msg("Failed authentication via AuthKey")
		resp.MachineAuthorized = false
		respBody, err := encode(resp, &idKey, h.privateKey)
		if err != nil {
			log.Error().
				Str("func", "handleAuthKey").
				Str("machine", m.Name).
				Err(err).
				Msg("Cannot encode message")
			c.String(http.StatusInternalServerError, "")
			machineRegistrations.WithLabelValues("new", "authkey", "error", m.Namespace.Name).Inc()
			return
		}
		c.Data(401, "application/json; charset=utf-8", respBody)
		log.Error().
			Str("func", "handleAuthKey").
			Str("machine", m.Name).
			Msg("Failed authentication via AuthKey")
		machineRegistrations.WithLabelValues("new", "authkey", "error", m.Namespace.Name).Inc()
		return
	}

	log.Debug().
		Str("func", "handleAuthKey").
		Str("machine", m.Name).
		Msg("Authentication key was valid, proceeding to acquire an IP address")
	ip, err := h.getAvailableIP()
	if err != nil {
		log.Error().
			Str("func", "handleAuthKey").
			Str("machine", m.Name).
			Msg("Failed to find an available IP")
		machineRegistrations.WithLabelValues("new", "authkey", "error", m.Namespace.Name).Inc()
		return
	}
	log.Info().
		Str("func", "handleAuthKey").
		Str("machine", m.Name).
		Str("ip", ip.String()).
		Msgf("Assigning %s to %s", ip, m.Name)

	m.AuthKeyID = uint(pak.ID)
	m.IPAddress = ip.String()
	m.NamespaceID = pak.NamespaceID
	m.NodeKey = wgkey.Key(req.NodeKey).HexString() // we update it just in case
	m.Registered = true
	m.RegisterMethod = "authKey"
	db.Save(&m)

	resp.MachineAuthorized = true
	resp.User = *pak.Namespace.toUser()
	respBody, err := encode(resp, &idKey, h.privateKey)
	if err != nil {
		log.Error().
			Str("func", "handleAuthKey").
			Str("machine", m.Name).
			Err(err).
			Msg("Cannot encode message")
		machineRegistrations.WithLabelValues("new", "authkey", "error", m.Namespace.Name).Inc()
		c.String(http.StatusInternalServerError, "Extremely sad!")
		return
	}
	machineRegistrations.WithLabelValues("new", "authkey", "success", m.Namespace.Name).Inc()
	c.Data(200, "application/json; charset=utf-8", respBody)
	log.Info().
		Str("func", "handleAuthKey").
		Str("machine", m.Name).
		Str("ip", ip.String()).
		Msg("Successfully authenticated via AuthKey")
}
