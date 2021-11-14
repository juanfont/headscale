package headscale

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/klauspost/compress/zstd"
	"github.com/rs/zerolog/log"
	"gorm.io/gorm"
	"tailscale.com/tailcfg"
	"tailscale.com/types/wgkey"
)

const RESERVED_RESPONSE_HEADER_SIZE = 4

// KeyHandler provides the Headscale pub key
// Listens in /key.
func (h *Headscale) KeyHandler(c *gin.Context) {
	c.Data(http.StatusOK, "text/plain; charset=utf-8", []byte(h.publicKey.HexString()))
}

// RegisterWebAPI shows a simple message in the browser to point to the CLI
// Listens in /register.
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
			<b>headscale -n NAMESPACE nodes register --key %s</b>
		</code>
	</p>

	</body>
	</html>

	`, mKeyStr)))
}

// RegistrationHandler handles the actual registration process of a machine
// Endpoint /machine/:id.
func (h *Headscale) RegistrationHandler(c *gin.Context) {
	body, _ := io.ReadAll(c.Request.Body)
	mKeyStr := c.Param("id")
	mKey, err := wgkey.ParseHex(mKeyStr)
	if err != nil {
		log.Error().
			Str("handler", "Registration").
			Err(err).
			Msg("Cannot parse machine key")
		machineRegistrations.WithLabelValues("unknown", "web", "error", "unknown").Inc()
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
		machineRegistrations.WithLabelValues("unknown", "web", "error", "unknown").Inc()
		c.String(http.StatusInternalServerError, "Very sad!")

		return
	}

	now := time.Now().UTC()
	m, err := h.GetMachineByMachineKey(mKey.HexString())
	if errors.Is(err, gorm.ErrRecordNotFound) {
		log.Info().Str("machine", req.Hostinfo.Hostname).Msg("New machine")
		newMachine := Machine{
			Expiry:     &time.Time{},
			MachineKey: mKey.HexString(),
			Name:       req.Hostinfo.Hostname,
		}
		if err := h.db.Create(&newMachine).Error; err != nil {
			log.Error().
				Str("handler", "Registration").
				Err(err).
				Msg("Could not create row")
			machineRegistrations.WithLabelValues("unknown", "web", "error", m.Namespace.Name).
				Inc()

			return
		}
		m = &newMachine
	}

	if !m.Registered && req.Auth.AuthKey != "" {
		h.handleAuthKey(c, h.db, mKey, req, *m)

		return
	}

	resp := tailcfg.RegisterResponse{}

	// We have the updated key!
	if m.NodeKey == wgkey.Key(req.NodeKey).HexString() {
		// The client sends an Expiry in the past if the client is requesting to expire the key (aka logout)
		//   https://github.com/tailscale/tailscale/blob/main/tailcfg/tailcfg.go#L648
		if !req.Expiry.IsZero() && req.Expiry.UTC().Before(now) {
			log.Info().
				Str("handler", "Registration").
				Str("machine", m.Name).
				Msg("Client requested logout")

			m.Expiry = &req.Expiry // save the expiry so that the machine is marked as expired
			h.db.Save(&m)

			resp.AuthURL = ""
			resp.MachineAuthorized = false
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
			c.Data(http.StatusOK, "application/json; charset=utf-8", respBody)

			return
		}

		if m.Registered && m.Expiry.UTC().After(now) {
			// The machine registration is valid, respond with redirect to /map
			log.Debug().
				Str("handler", "Registration").
				Str("machine", m.Name).
				Msg("Client is registered and we have the current NodeKey. All clear to /map")

			resp.AuthURL = ""
			resp.MachineAuthorized = true
			resp.User = *m.Namespace.toUser()
			resp.Login = *m.Namespace.toLogin()

			respBody, err := encode(resp, &mKey, h.privateKey)
			if err != nil {
				log.Error().
					Str("handler", "Registration").
					Err(err).
					Msg("Cannot encode message")
				machineRegistrations.WithLabelValues("update", "web", "error", m.Namespace.Name).
					Inc()
				c.String(http.StatusInternalServerError, "")

				return
			}
			machineRegistrations.WithLabelValues("update", "web", "success", m.Namespace.Name).
				Inc()
			c.Data(http.StatusOK, "application/json; charset=utf-8", respBody)

			return
		}

		// The client has registered before, but has expired
		log.Debug().
			Str("handler", "Registration").
			Str("machine", m.Name).
			Msg("Machine registration has expired. Sending a authurl to register")

		if h.cfg.OIDC.Issuer != "" {
			resp.AuthURL = fmt.Sprintf("%s/oidc/register/%s",
				strings.TrimSuffix(h.cfg.ServerURL, "/"), mKey.HexString())
		} else {
			resp.AuthURL = fmt.Sprintf("%s/register?key=%s",
				strings.TrimSuffix(h.cfg.ServerURL, "/"), mKey.HexString())
		}

		// When a client connects, it may request a specific expiry time in its
		// RegisterRequest (https://github.com/tailscale/tailscale/blob/main/tailcfg/tailcfg.go#L634)
		// RequestedExpiry is used to store the clients requested expiry time since the authentication flow is broken
		// into two steps (which cant pass arbitrary data between them easily) and needs to be
		// retrieved again after the user has authenticated. After the authentication flow
		// completes, RequestedExpiry is copied into Expiry.
		m.RequestedExpiry = &req.Expiry

		h.db.Save(&m)

		respBody, err := encode(resp, &mKey, h.privateKey)
		if err != nil {
			log.Error().
				Str("handler", "Registration").
				Err(err).
				Msg("Cannot encode message")
			machineRegistrations.WithLabelValues("new", "web", "error", m.Namespace.Name).
				Inc()
			c.String(http.StatusInternalServerError, "")

			return
		}
		machineRegistrations.WithLabelValues("new", "web", "success", m.Namespace.Name).
			Inc()
		c.Data(http.StatusOK, "application/json; charset=utf-8", respBody)

		return
	}

	// The NodeKey we have matches OldNodeKey, which means this is a refresh after a key expiration
	if m.NodeKey == wgkey.Key(req.OldNodeKey).HexString() && m.Expiry.UTC().After(now) {
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
		c.Data(http.StatusOK, "application/json; charset=utf-8", respBody)

		return
	}

	// The machine registration is new, redirect the client to the registration URL
	log.Debug().
		Str("handler", "Registration").
		Str("machine", m.Name).
		Msg("The node is sending us a new NodeKey, sending auth url")
	if h.cfg.OIDC.Issuer != "" {
		resp.AuthURL = fmt.Sprintf(
			"%s/oidc/register/%s",
			strings.TrimSuffix(h.cfg.ServerURL, "/"),
			mKey.HexString(),
		)
	} else {
		resp.AuthURL = fmt.Sprintf("%s/register?key=%s",
			strings.TrimSuffix(h.cfg.ServerURL, "/"), mKey.HexString())
	}

	// save the requested expiry time for retrieval later in the authentication flow
	m.RequestedExpiry = &req.Expiry
	m.NodeKey = wgkey.Key(req.NodeKey).HexString() // save the NodeKey
	h.db.Save(&m)

	respBody, err := encode(resp, &mKey, h.privateKey)
	if err != nil {
		log.Error().
			Str("handler", "Registration").
			Err(err).
			Msg("Cannot encode message")
		c.String(http.StatusInternalServerError, "")

		return
	}
	c.Data(http.StatusOK, "application/json; charset=utf-8", respBody)
}

func (h *Headscale) getMapResponse(
	mKey wgkey.Key,
	req tailcfg.MapRequest,
	m *Machine,
) ([]byte, error) {
	log.Trace().
		Str("func", "getMapResponse").
		Str("machine", req.Hostinfo.Hostname).
		Msg("Creating Map response")
	node, err := m.toNode(h.cfg.BaseDomain, h.cfg.DNSConfig, true)
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

	profiles := getMapResponseUserProfiles(*m, peers)

	nodePeers, err := peers.toNodes(h.cfg.BaseDomain, h.cfg.DNSConfig, true)
	if err != nil {
		log.Error().
			Str("func", "getMapResponse").
			Err(err).
			Msg("Failed to convert peers to Tailscale nodes")

		return nil, err
	}

	dnsConfig := getMapResponseDNSConfig(
		h.cfg.DNSConfig,
		h.cfg.BaseDomain,
		*m,
		peers,
	)

	resp := tailcfg.MapResponse{
		KeepAlive:    false,
		Node:         node,
		Peers:        nodePeers,
		DNSConfig:    dnsConfig,
		Domain:       h.cfg.BaseDomain,
		PacketFilter: h.aclRules,
		DERPMap:      h.DERPMap,
		UserProfiles: profiles,
	}

	log.Trace().
		Str("func", "getMapResponse").
		Str("machine", req.Hostinfo.Hostname).
		// Interface("payload", resp).
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
	data := make([]byte, RESERVED_RESPONSE_HEADER_SIZE)
	binary.LittleEndian.PutUint32(data, uint32(len(respBody)))
	data = append(data, respBody...)

	return data, nil
}

func (h *Headscale) getMapKeepAliveResponse(
	mKey wgkey.Key,
	req tailcfg.MapRequest,
) ([]byte, error) {
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
	data := make([]byte, RESERVED_RESPONSE_HEADER_SIZE)
	binary.LittleEndian.PutUint32(data, uint32(len(respBody)))
	data = append(data, respBody...)

	return data, nil
}

func (h *Headscale) handleAuthKey(
	c *gin.Context,
	db *gorm.DB,
	idKey wgkey.Key,
	req tailcfg.RegisterRequest,
	m Machine,
) {
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
			machineRegistrations.WithLabelValues("new", "authkey", "error", m.Namespace.Name).
				Inc()

			return
		}
		c.Data(http.StatusUnauthorized, "application/json; charset=utf-8", respBody)
		log.Error().
			Str("func", "handleAuthKey").
			Str("machine", m.Name).
			Msg("Failed authentication via AuthKey")
		machineRegistrations.WithLabelValues("new", "authkey", "error", m.Namespace.Name).
			Inc()

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
		machineRegistrations.WithLabelValues("new", "authkey", "error", m.Namespace.Name).
			Inc()

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

	pak.Used = true
	db.Save(&pak)

	resp.MachineAuthorized = true
	resp.User = *pak.Namespace.toUser()
	respBody, err := encode(resp, &idKey, h.privateKey)
	if err != nil {
		log.Error().
			Str("func", "handleAuthKey").
			Str("machine", m.Name).
			Err(err).
			Msg("Cannot encode message")
		machineRegistrations.WithLabelValues("new", "authkey", "error", m.Namespace.Name).
			Inc()
		c.String(http.StatusInternalServerError, "Extremely sad!")

		return
	}
	machineRegistrations.WithLabelValues("new", "authkey", "success", m.Namespace.Name).
		Inc()
	c.Data(http.StatusOK, "application/json; charset=utf-8", respBody)
	log.Info().
		Str("func", "handleAuthKey").
		Str("machine", m.Name).
		Str("ip", ip.String()).
		Msg("Successfully authenticated via AuthKey")
}
