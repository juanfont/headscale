package headscale

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jinzhu/gorm"
	"github.com/klauspost/compress/zstd"
	"gorm.io/datatypes"
	"inet.af/netaddr"
	"tailscale.com/tailcfg"
	"tailscale.com/wgengine/wgcfg"
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
			<b>headscale -n NAMESPACE node register %s</b>
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
	mKey, err := wgcfg.ParseHexKey(mKeyStr)
	if err != nil {
		log.Printf("Cannot parse machine key: %s", err)
		c.String(http.StatusInternalServerError, "Sad!")
		return
	}
	req := tailcfg.RegisterRequest{}
	err = decode(body, &req, &mKey, h.privateKey)
	if err != nil {
		log.Printf("Cannot decode message: %s", err)
		c.String(http.StatusInternalServerError, "Very sad!")
		return
	}

	db, err := h.db()
	if err != nil {
		log.Printf("Cannot open DB: %s", err)
		c.String(http.StatusInternalServerError, ":(")
		return
	}
	defer db.Close()

	var m Machine
	if db.First(&m, "machine_key = ?", mKey.HexString()).RecordNotFound() {
		log.Println("New Machine!")
		m = Machine{
			Expiry:     &req.Expiry,
			MachineKey: mKey.HexString(),
			Name:       req.Hostinfo.Hostname,
			NodeKey:    wgcfg.Key(req.NodeKey).HexString(),
		}
		if err := db.Create(&m).Error; err != nil {
			log.Printf("Could not create row: %s", err)
			return
		}
	}

	if !m.Registered && req.Auth.AuthKey != "" {
		h.handleAuthKey(c, db, mKey, req, m)
		return
	}

	resp := tailcfg.RegisterResponse{}

	// We have the updated key!
	if m.NodeKey == wgcfg.Key(req.NodeKey).HexString() {
		if m.Registered {
			log.Printf("[%s] Client is registered and we have the current NodeKey. All clear to /map", m.Name)
			resp.AuthURL = ""
			resp.MachineAuthorized = true
			resp.User = *m.Namespace.toUser()
			respBody, err := encode(resp, &mKey, h.privateKey)
			if err != nil {
				log.Printf("Cannot encode message: %s", err)
				c.String(http.StatusInternalServerError, "")
				return
			}
			c.Data(200, "application/json; charset=utf-8", respBody)
			return
		}

		log.Printf("[%s] Not registered and not NodeKey rotation. Sending a authurl to register", m.Name)
		resp.AuthURL = fmt.Sprintf("%s/register?key=%s",
			h.cfg.ServerURL, mKey.HexString())
		respBody, err := encode(resp, &mKey, h.privateKey)
		if err != nil {
			log.Printf("Cannot encode message: %s", err)
			c.String(http.StatusInternalServerError, "")
			return
		}
		c.Data(200, "application/json; charset=utf-8", respBody)
		return
	}

	// The NodeKey we have matches OldNodeKey, which means this is a refresh after an key expiration
	if m.NodeKey == wgcfg.Key(req.OldNodeKey).HexString() {
		log.Printf("[%s] We have the OldNodeKey in the database. This is a key refresh", m.Name)
		m.NodeKey = wgcfg.Key(req.NodeKey).HexString()
		db.Save(&m)

		resp.AuthURL = ""
		resp.User = *m.Namespace.toUser()
		respBody, err := encode(resp, &mKey, h.privateKey)
		if err != nil {
			log.Printf("Cannot encode message: %s", err)
			c.String(http.StatusInternalServerError, "Extremely sad!")
			return
		}
		c.Data(200, "application/json; charset=utf-8", respBody)
		return
	}

	// We arrive here after a client is restarted without finalizing the authentication flow or
	// when headscale is stopped in the middle of the auth process.
	if m.Registered {
		log.Printf("[%s] The node is sending us a new NodeKey, but machine is registered. All clear for /map", m.Name)
		resp.AuthURL = ""
		resp.MachineAuthorized = true
		resp.User = *m.Namespace.toUser()
		respBody, err := encode(resp, &mKey, h.privateKey)
		if err != nil {
			log.Printf("Cannot encode message: %s", err)
			c.String(http.StatusInternalServerError, "")
			return
		}
		c.Data(200, "application/json; charset=utf-8", respBody)
		return
	}
	log.Printf("[%s] The node is sending us a new NodeKey, sending auth url", m.Name)
	resp.AuthURL = fmt.Sprintf("%s/register?key=%s",
		h.cfg.ServerURL, mKey.HexString())
	respBody, err := encode(resp, &mKey, h.privateKey)
	if err != nil {
		log.Printf("Cannot encode message: %s", err)
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
	body, _ := io.ReadAll(c.Request.Body)
	mKeyStr := c.Param("id")
	mKey, err := wgcfg.ParseHexKey(mKeyStr)
	if err != nil {
		log.Printf("Cannot parse client key: %s", err)
		return
	}
	req := tailcfg.MapRequest{}
	err = decode(body, &req, &mKey, h.privateKey)
	if err != nil {
		log.Printf("Cannot decode message: %s", err)
		return
	}

	db, err := h.db()
	if err != nil {
		log.Printf("Cannot open DB: %s", err)
		return
	}
	defer db.Close()
	var m Machine
	if db.First(&m, "machine_key = ?", mKey.HexString()).RecordNotFound() {
		log.Printf("Ignoring request, cannot find machine with key %s", mKey.HexString())
		return
	}

	hostinfo, _ := json.Marshal(req.Hostinfo)
	m.Name = req.Hostinfo.Hostname
	m.HostInfo = datatypes.JSON(hostinfo)
	m.DiscoKey = wgcfg.Key(req.DiscoKey).HexString()
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
	db.Save(&m)

	pollData := make(chan []byte, 1)
	update := make(chan []byte, 1)
	cancelKeepAlive := make(chan []byte, 1)
	defer close(pollData)
	defer close(cancelKeepAlive)
	h.pollMu.Lock()
	h.clientsPolling[m.ID] = update
	h.pollMu.Unlock()

	data, err := h.getMapResponse(mKey, req, m)
	if err != nil {
		c.String(http.StatusInternalServerError, ":(")
		return
	}

	// We update our peers if the client is not sending ReadOnly in the MapRequest
	// so we don't distribute its initial request (it comes with
	// empty endpoints to peers)

	// Details on the protocol can be found in https://github.com/tailscale/tailscale/blob/main/tailcfg/tailcfg.go#L696
	log.Printf("[%s] ReadOnly=%t   OmitPeers=%t    Stream=%t", m.Name, req.ReadOnly, req.OmitPeers, req.Stream)

	if req.ReadOnly {
		log.Printf("[%s] Client is starting up. Asking for DERP map", m.Name)
		c.Data(200, "application/json; charset=utf-8", *data)
		return
	}
	if req.OmitPeers && !req.Stream {
		log.Printf("[%s] Client sent endpoint update and is ok with a response without peer list", m.Name)
		c.Data(200, "application/json; charset=utf-8", *data)
		return
	} else if req.OmitPeers && req.Stream {
		log.Printf("[%s] Warning, ignoring request, don't know how to handle it", m.Name)
		c.String(http.StatusBadRequest, "")
		return
	}

	log.Printf("[%s] Client is ready to access the tailnet", m.Name)
	log.Printf("[%s] Sending initial map", m.Name)
	pollData <- *data

	log.Printf("[%s] Notifying peers", m.Name)
	peers, _ := h.getPeers(m)
	h.pollMu.Lock()
	for _, p := range *peers {
		pUp, ok := h.clientsPolling[uint64(p.ID)]
		if ok {
			log.Printf("[%s] Notifying peer %s (%s)", m.Name, p.Name, p.Addresses[0])
			pUp <- []byte{}
		} else {
			log.Printf("[%s] Peer %s does not appear to be polling", m.Name, p.Name)
		}
	}
	h.pollMu.Unlock()

	go h.keepAlive(cancelKeepAlive, pollData, mKey, req, m)

	c.Stream(func(w io.Writer) bool {
		select {
		case data := <-pollData:
			log.Printf("[%s] Sending data (%d bytes)", m.Name, len(data))
			_, err := w.Write(data)
			if err != nil {
				log.Printf("[%s] 🤮 Cannot write data: %s", m.Name, err)
			}
			now := time.Now().UTC()
			m.LastSeen = &now
			db.Save(&m)
			return true

		case <-update:
			log.Printf("[%s] Received a request for update", m.Name)
			data, err := h.getMapResponse(mKey, req, m)
			if err != nil {
				log.Printf("[%s] Could not get the map update: %s", m.Name, err)
			}
			_, err = w.Write(*data)
			if err != nil {
				log.Printf("[%s] Could not write the map response: %s", m.Name, err)
			}
			return true

		case <-c.Request.Context().Done():
			h.pollMu.Lock()
			log.Printf("[%s] The client has closed the connection", m.Name)
			now := time.Now().UTC()
			m.LastSeen = &now
			db.Save(&m)
			cancelKeepAlive <- []byte{}
			delete(h.clientsPolling, m.ID)
			close(update)
			h.pollMu.Unlock()
			return false

		}
	})
}

func (h *Headscale) keepAlive(cancel chan []byte, pollData chan []byte, mKey wgcfg.Key, req tailcfg.MapRequest, m Machine) {
	for {
		select {
		case <-cancel:
			return

		default:
			h.pollMu.Lock()
			data, err := h.getMapKeepAliveResponse(mKey, req, m)
			if err != nil {
				log.Printf("Error generating the keep alive msg: %s", err)
				return
			}
			log.Printf("[%s] Sending keepalive", m.Name)
			pollData <- *data
			h.pollMu.Unlock()
			time.Sleep(60 * time.Second)
		}
	}
}

func (h *Headscale) getMapResponse(mKey wgcfg.Key, req tailcfg.MapRequest, m Machine) (*[]byte, error) {
	node, err := m.toNode()
	if err != nil {
		log.Printf("Cannot convert to node: %s", err)
		return nil, err
	}
	peers, err := h.getPeers(m)
	if err != nil {
		log.Printf("Cannot fetch peers: %s", err)
		return nil, err
	}
	resp := tailcfg.MapResponse{
		KeepAlive:    false,
		Node:         node,
		Peers:        *peers,
		DNS:          []netaddr.IP{},
		SearchPaths:  []string{},
		Domain:       "foobar@example.com",
		PacketFilter: tailcfg.FilterAllowAll,
		DERPMap:      h.cfg.DerpMap,
		UserProfiles: []tailcfg.UserProfile{},
		Roles:        []tailcfg.Role{},
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

func (h *Headscale) getMapKeepAliveResponse(mKey wgcfg.Key, req tailcfg.MapRequest, m Machine) (*[]byte, error) {
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

func (h *Headscale) handleAuthKey(c *gin.Context, db *gorm.DB, idKey wgcfg.Key, req tailcfg.RegisterRequest, m Machine) {
	resp := tailcfg.RegisterResponse{}
	pak, err := h.checkKeyValidity(req.Auth.AuthKey)
	if err != nil {
		resp.MachineAuthorized = false
		respBody, err := encode(resp, &idKey, h.privateKey)
		if err != nil {
			log.Printf("Cannot encode message: %s", err)
			c.String(http.StatusInternalServerError, "")
			return
		}
		c.Data(200, "application/json; charset=utf-8", respBody)
		log.Printf("[%s] Failed authentication via AuthKey", m.Name)
		return
	}
	ip, err := h.getAvailableIP()
	if err != nil {
		log.Println(err)
		return
	}

	m.AuthKeyID = uint(pak.ID)
	m.IPAddress = ip.String()
	m.NamespaceID = pak.NamespaceID
	m.NodeKey = wgcfg.Key(req.NodeKey).HexString() // we update it just in case
	m.Registered = true
	m.RegisterMethod = "authKey"
	db.Save(&m)

	resp.MachineAuthorized = true
	resp.User = *pak.Namespace.toUser()
	respBody, err := encode(resp, &idKey, h.privateKey)
	if err != nil {
		log.Printf("Cannot encode message: %s", err)
		c.String(http.StatusInternalServerError, "Extremely sad!")
		return
	}
	c.Data(200, "application/json; charset=utf-8", respBody)
	log.Printf("[%s] Successfully authenticated via AuthKey", m.Name)
}
