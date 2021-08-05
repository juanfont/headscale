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
	"gorm.io/datatypes"
	"gorm.io/gorm"
	"inet.af/netaddr"
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

	// spew.Dump(c.Params)

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
		c.String(http.StatusInternalServerError, "Very sad!")
		return
	}

	var m Machine
	if result := h.db.Preload("Namespace").First(&m, "machine_key = ?", mKey.HexString()); errors.Is(result.Error, gorm.ErrRecordNotFound) {
		log.Info().Str("machine", req.Hostinfo.Hostname).Msg("New machine")
		m = Machine{
			Expiry:     &req.Expiry,
			MachineKey: mKey.HexString(),
			Name:       req.Hostinfo.Hostname,
			NodeKey:    wgkey.Key(req.NodeKey).HexString(),
		}
		if err := h.db.Create(&m).Error; err != nil {
			log.Error().
				Str("handler", "Registration").
				Err(err).
				Msg("Could not create row")
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
				c.String(http.StatusInternalServerError, "")
				return
			}
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
			c.String(http.StatusInternalServerError, "")
			return
		}
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

// PollNetMapHandler takes care of /machine/:id/map
//
// This is the busiest endpoint, as it keeps the HTTP long poll that updates
// the clients when something in the network changes.
//
// The clients POST stuff like HostInfo and their Endpoints here, but
// only after their first request (marked with the ReadOnly field).
//
// At this moment the updates are sent in a quite horrendous way, but they kinda work.
func (h *Headscale) PollNetMapHandler(c *gin.Context) {
	log.Trace().
		Str("handler", "PollNetMap").
		Str("id", c.Param("id")).
		Msg("PollNetMapHandler called")
	body, _ := io.ReadAll(c.Request.Body)
	mKeyStr := c.Param("id")
	mKey, err := wgkey.ParseHex(mKeyStr)
	if err != nil {
		log.Error().
			Str("handler", "PollNetMap").
			Err(err).
			Msg("Cannot parse client key")
		c.String(http.StatusBadRequest, "")
		return
	}
	req := tailcfg.MapRequest{}
	err = decode(body, &req, &mKey, h.privateKey)
	if err != nil {
		log.Error().
			Str("handler", "PollNetMap").
			Err(err).
			Msg("Cannot decode message")
		c.String(http.StatusBadRequest, "")
		return
	}

	var m Machine
	if result := h.db.Preload("Namespace").First(&m, "machine_key = ?", mKey.HexString()); errors.Is(result.Error, gorm.ErrRecordNotFound) {
		log.Warn().
			Str("handler", "PollNetMap").
			Msgf("Ignoring request, cannot find machine with key %s", mKey.HexString())
		c.String(http.StatusUnauthorized, "")
		return
	}
	log.Trace().
		Str("handler", "PollNetMap").
		Str("id", c.Param("id")).
		Str("machine", m.Name).
		Msg("Found machine in database")

	hostinfo, _ := json.Marshal(req.Hostinfo)
	m.Name = req.Hostinfo.Hostname
	m.HostInfo = datatypes.JSON(hostinfo)
	m.DiscoKey = wgkey.Key(req.DiscoKey).HexString()
	now := time.Now().UTC()

	// From Tailscale client:
	//
	// ReadOnly is whether the client just wants to fetch the MapResponse,
	// without updating their Endpoints. The Endpoints field will be ignored and
	// LastSeen will not be updated and peers will not be notified of changes.
	//
	// The intended use is for clients to discover the DERP map at start-up
	// before their first real endpoint update.
	if !req.ReadOnly {
		endpoints, _ := json.Marshal(req.Endpoints)
		m.Endpoints = datatypes.JSON(endpoints)
		m.LastSeen = &now
	}
	h.db.Save(&m)

	update := make(chan []byte, 1)

	pollData := make(chan []byte, 1)
	defer close(pollData)

	cancelKeepAlive := make(chan []byte, 1)
	defer close(cancelKeepAlive)

	log.Trace().
		Str("handler", "PollNetMap").
		Str("id", c.Param("id")).
		Str("machine", m.Name).
		Msg("Locking poll mutex")
	h.clientsPolling.Store(m.ID, update)
	log.Trace().
		Str("handler", "PollNetMap").
		Str("id", c.Param("id")).
		Str("machine", m.Name).
		Msg("Unlocking poll mutex")

	data, err := h.getMapResponse(mKey, req, m)
	if err != nil {
		log.Error().
			Str("handler", "PollNetMap").
			Str("id", c.Param("id")).
			Str("machine", m.Name).
			Err(err).
			Msg("Failed to get Map response")
		c.String(http.StatusInternalServerError, ":(")
		return
	}

	// We update our peers if the client is not sending ReadOnly in the MapRequest
	// so we don't distribute its initial request (it comes with
	// empty endpoints to peers)

	// Details on the protocol can be found in https://github.com/tailscale/tailscale/blob/main/tailcfg/tailcfg.go#L696
	log.Debug().
		Str("handler", "PollNetMap").
		Str("id", c.Param("id")).
		Str("machine", m.Name).
		Bool("readOnly", req.ReadOnly).
		Bool("omitPeers", req.OmitPeers).
		Bool("stream", req.Stream).
		Msg("Client map request processed")

	if req.ReadOnly {
		log.Info().
			Str("handler", "PollNetMap").
			Str("machine", m.Name).
			Msg("Client is starting up. Asking for DERP map")
		c.Data(200, "application/json; charset=utf-8", *data)
		return
	}
	if req.OmitPeers && !req.Stream {
		log.Info().
			Str("handler", "PollNetMap").
			Str("machine", m.Name).
			Msg("Client sent endpoint update and is ok with a response without peer list")
		c.Data(200, "application/json; charset=utf-8", *data)
		return
	} else if req.OmitPeers && req.Stream {
		log.Warn().
			Str("handler", "PollNetMap").
			Str("machine", m.Name).
			Msg("Ignoring request, don't know how to handle it")
		c.String(http.StatusBadRequest, "")
		return
	}

	log.Info().
		Str("handler", "PollNetMap").
		Str("machine", m.Name).
		Msg("Client is ready to access the tailnet")
	log.Info().
		Str("handler", "PollNetMap").
		Str("machine", m.Name).
		Msg("Sending initial map")
	pollData <- *data

	log.Info().
		Str("handler", "PollNetMap").
		Str("machine", m.Name).
		Msg("Notifying peers")
	peers, _ := h.getPeers(m)
	for _, p := range *peers {
		pUp, ok := h.clientsPolling.Load(uint64(p.ID))
		if ok {
			log.Info().
				Str("handler", "PollNetMap").
				Str("machine", m.Name).
				Str("peer", m.Name).
				Str("address", p.Addresses[0].String()).
				Msgf("Notifying peer %s (%s)", p.Name, p.Addresses[0])
			pUp.(chan []byte) <- []byte{}
		} else {
			log.Info().
				Str("handler", "PollNetMap").
				Str("machine", m.Name).
				Str("peer", m.Name).
				Msgf("Peer %s does not appear to be polling", p.Name)
		}
	}

	go h.keepAlive(cancelKeepAlive, pollData, mKey, req, m)

	c.Stream(func(w io.Writer) bool {
		select {
		case data := <-pollData:
			log.Trace().
				Str("handler", "PollNetMap").
				Str("machine", m.Name).
				Int("bytes", len(data)).
				Msg("Sending data")
			_, err := w.Write(data)
			if err != nil {
				log.Error().
					Str("handler", "PollNetMap").
					Str("machine", m.Name).
					Err(err).
					Msg("Cannot write data")
			}
			now := time.Now().UTC()
			m.LastSeen = &now
			h.db.Save(&m)
			return true

		case <-update:
			log.Debug().
				Str("handler", "PollNetMap").
				Str("machine", m.Name).
				Msg("Received a request for update")
			data, err := h.getMapResponse(mKey, req, m)
			if err != nil {
				log.Error().
					Str("handler", "PollNetMap").
					Str("machine", m.Name).
					Err(err).
					Msg("Could not get the map update")
			}
			_, err = w.Write(*data)
			if err != nil {
				log.Error().
					Str("handler", "PollNetMap").
					Str("machine", m.Name).
					Err(err).
					Msg("Could not write the map response")
			}
			return true

		case <-c.Request.Context().Done():
			log.Info().
				Str("handler", "PollNetMap").
				Str("machine", m.Name).
				Msg("The client has closed the connection")
			now := time.Now().UTC()
			m.LastSeen = &now
			h.db.Save(&m)
			cancelKeepAlive <- []byte{}
			h.clientsPolling.Delete(m.ID)
			close(update)
			return false

		}
	})
}

func (h *Headscale) keepAlive(cancel chan []byte, pollData chan []byte, mKey wgkey.Key, req tailcfg.MapRequest, m Machine) {
	for {
		select {
		case <-cancel:
			return

		default:
			h.pollMu.Lock()
			data, err := h.getMapKeepAliveResponse(mKey, req, m)
			if err != nil {
				log.Error().
					Str("func", "keepAlive").
					Err(err).
					Msg("Error generating the keep alive msg")
				return
			}
			log.Debug().
				Str("func", "keepAlive").
				Str("machine", m.Name).
				Msg("Sending keepalive")
			pollData <- *data
			h.pollMu.Unlock()
			time.Sleep(60 * time.Second)
		}
	}
}

func (h *Headscale) getMapResponse(mKey wgkey.Key, req tailcfg.MapRequest, m Machine) (*[]byte, error) {
	log.Trace().
		Str("func", "getMapResponse").
		Str("machine", req.Hostinfo.Hostname).
		Msg("Creating Map response")
	node, err := m.toNode()
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

	resp := tailcfg.MapResponse{
		KeepAlive:    false,
		Node:         node,
		Peers:        *peers,
		DNS:          []netaddr.IP{},
		SearchPaths:  []string{},
		Domain:       "headscale.net",
		PacketFilter: *h.aclRules,
		DERPMap:      h.cfg.DerpMap,
		UserProfiles: []tailcfg.UserProfile{profile},
	}

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
	// spew.Dump(resp)
	// declare the incoming size on the first 4 bytes
	data := make([]byte, 4)
	binary.LittleEndian.PutUint32(data, uint32(len(respBody)))
	data = append(data, respBody...)
	return &data, nil
}

func (h *Headscale) getMapKeepAliveResponse(mKey wgkey.Key, req tailcfg.MapRequest, m Machine) (*[]byte, error) {
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
	return &data, nil
}

func (h *Headscale) handleAuthKey(c *gin.Context, db *gorm.DB, idKey wgkey.Key, req tailcfg.RegisterRequest, m Machine) {
	log.Debug().
		Str("func", "handleAuthKey").
		Str("machine", req.Hostinfo.Hostname).
		Msgf("Processing auth key for %s", req.Hostinfo.Hostname)
	resp := tailcfg.RegisterResponse{}
	pak, err := h.checkKeyValidity(req.Auth.AuthKey)
	if err != nil {
		resp.MachineAuthorized = false
		respBody, err := encode(resp, &idKey, h.privateKey)
		if err != nil {
			log.Error().
				Str("func", "handleAuthKey").
				Str("machine", m.Name).
				Err(err).
				Msg("Cannot encode message")
			c.String(http.StatusInternalServerError, "")
			return
		}
		c.Data(200, "application/json; charset=utf-8", respBody)
		log.Error().
			Str("func", "handleAuthKey").
			Str("machine", m.Name).
			Msg("Failed authentication via AuthKey")
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
		return
	}
	log.Info().
		Str("func", "handleAuthKey").
		Str("machine", m.Name).
		Str("ip", ip.String()).
		Msgf("Assining %s to %s", ip, m.Name)

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
		c.String(http.StatusInternalServerError, "Extremely sad!")
		return
	}
	c.Data(200, "application/json; charset=utf-8", respBody)
	log.Info().
		Str("func", "handleAuthKey").
		Str("machine", m.Name).
		Str("ip", ip.String()).
		Msg("Successfully authenticated via AuthKey")
}
