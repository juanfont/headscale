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
	resp := tailcfg.RegisterResponse{}

	if db.First(&m, "machine_key = ?", mKey.HexString()).RecordNotFound() {
		log.Println("New Machine!")
		h.handleNewServer(c, db, mKey, req)
		return
	}

	// We do have the updated key!
	if m.NodeKey == wgcfg.Key(req.NodeKey).HexString() {
		if m.Registered {
			log.Printf("[%s] Client is registered and we have the current key. All clear to /map\n", m.Name)
			resp.AuthURL = ""
			resp.User = *m.Namespace.toUser()
			resp.MachineAuthorized = true
			respBody, err := encode(resp, &mKey, h.privateKey)
			if err != nil {
				log.Printf("Cannot encode message: %s", err)
				c.String(http.StatusInternalServerError, "Extremely sad!")
				return
			}
			c.Data(200, "application/json; charset=utf-8", respBody)
			return
		}

		log.Println("Hey! Not registered. Not asking for key rotation. Send a passive-aggressive authurl to register")
		resp.AuthURL = fmt.Sprintf("%s/register?key=%s",
			h.cfg.ServerURL, mKey.HexString())
		respBody, err := encode(resp, &mKey, h.privateKey)
		if err != nil {
			log.Printf("Cannot encode message: %s", err)
			c.String(http.StatusInternalServerError, "Extremely sad!")
			return
		}
		c.Data(200, "application/json; charset=utf-8", respBody)
		return

	}

	// We dont have the updated key in the DB. Lets try with the old one.
	if m.NodeKey == wgcfg.Key(req.OldNodeKey).HexString() {
		log.Println("Key rotation!")
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

	log.Println("We dont know anything about the new key. WTF")
	// spew.Dump(req)
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
	defer close(update)
	defer close(cancelKeepAlive)
	h.pollMu.Lock()
	h.clientsPolling[m.ID] = update
	h.pollMu.Unlock()

	data, err := h.getMapResponse(mKey, req, m)
	if err != nil {
		c.String(http.StatusInternalServerError, ":(")
		return
	}

	log.Printf("[%s] sending initial map", m.Name)
	pollData <- *data

	// We update our peers if the client is not sending ReadOnly in the MapRequest
	// so we don't distribute its initial request (it comes with
	// empty endpoints to peers)
	if !req.ReadOnly {
		peers, _ := h.getPeers(m)
		h.pollMu.Lock()
		for _, p := range *peers {
			log.Printf("[%s] notifying peer %s (%s)", m.Name, p.Name, p.Addresses[0])
			if pUp, ok := h.clientsPolling[uint64(p.ID)]; ok {
				pUp <- []byte{}
			} else {
				log.Printf("[%s] Peer %s does not appear to be polling", m.Name, p.Name)
			}
		}
		h.pollMu.Unlock()
	}

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
				log.Printf("[%s] 🤮 Cannot get the poll response: %s", m.Name, err)
			}
			_, err = w.Write(*data)
			if err != nil {
				log.Printf("[%s] 🤮 Cannot write the poll response: %s", m.Name, err)
			}
			return true

		case <-c.Request.Context().Done():
			log.Printf("[%s] 😥 The client has closed the connection", m.Name)
			now := time.Now().UTC()
			m.LastSeen = &now
			db.Save(&m)
			h.pollMu.Lock()
			cancelKeepAlive <- []byte{}
			delete(h.clientsPolling, m.ID)
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

func (h *Headscale) handleNewServer(c *gin.Context, db *gorm.DB, idKey wgcfg.Key, req tailcfg.RegisterRequest) {
	m := Machine{
		MachineKey: idKey.HexString(),
		NodeKey:    wgcfg.Key(req.NodeKey).HexString(),
		Expiry:     &req.Expiry,
		Name:       req.Hostinfo.Hostname,
	}
	if err := db.Create(&m).Error; err != nil {
		log.Printf("Could not create row: %s", err)
		return
	}

	resp := tailcfg.RegisterResponse{}

	if req.Auth.AuthKey != "" {
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
			return
		}
		ip, err := h.getAvailableIP()
		if err != nil {
			log.Println(err)
			return
		}

		m.IPAddress = ip.String()
		m.NamespaceID = pak.NamespaceID
		m.AuthKeyID = uint(pak.ID)
		m.RegisterMethod = "authKey"
		m.Registered = true
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
		return
	}

	resp.AuthURL = fmt.Sprintf("%s/register?key=%s",
		h.cfg.ServerURL, idKey.HexString())

	respBody, err := encode(resp, &idKey, h.privateKey)
	if err != nil {
		log.Printf("Cannot encode message: %s", err)
		c.String(http.StatusInternalServerError, "Extremely sad!")
		return
	}
	c.Data(200, "application/json; charset=utf-8", respBody)
}
