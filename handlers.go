package headscale

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jinzhu/gorm"
	"github.com/jinzhu/gorm/dialects/postgres"
	"github.com/klauspost/compress/zstd"
	"github.com/tailscale/wireguard-go/wgcfg"
	"tailscale.com/tailcfg"
)

func (h *Headscale) KeyHandler(c *gin.Context) {
	c.Data(200, "text/plain; charset=utf-8", []byte(h.publicKey.HexString()))
}

func (h *Headscale) RegistrationHandler(c *gin.Context) {
	body, _ := ioutil.ReadAll(c.Request.Body)
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
			log.Println("Registered and we have the updated key! Lets move to map")
			resp.AuthURL = ""
			respBody, err := encode(resp, &mKey, h.privateKey)
			if err != nil {
				log.Printf("Cannot encode message: %s", err)
				c.String(http.StatusInternalServerError, "Extremely sad!")
				return
			}
			c.Data(200, "application/json; charset=utf-8", respBody)
			return
		}

		log.Println("Hey! Not registered. Not asking for key rotation. Send a passive-agressive authurl to register")
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
}

func (h *Headscale) PollNetMapHandler(c *gin.Context) {
	body, _ := ioutil.ReadAll(c.Request.Body)
	mKeyStr := c.Param("id")
	mKey, err := wgcfg.ParseHexKey(mKeyStr)
	if err != nil {
		log.Printf("Cannot parse client key: %s", err)
		c.String(http.StatusOK, "Sad!")
		return
	}
	req := tailcfg.MapRequest{}
	err = decode(body, &req, &mKey, h.privateKey)
	if err != nil {
		log.Printf("Cannot decode message: %s", err)
		c.String(http.StatusOK, "Very sad!")
		// return
	}

	db, err := h.db()
	if err != nil {
		log.Printf("Cannot open DB: %s", err)
		c.String(http.StatusInternalServerError, ":(")
		return
	}
	var m Machine
	if db.First(&m, "machine_key = ?", mKey.HexString()).RecordNotFound() {
		log.Printf("Cannot encode message: %s", err)
		c.String(http.StatusOK, "Extremely sad!")
		return
	}

	endpoints, _ := json.Marshal(req.Endpoints)
	hostinfo, _ := json.Marshal(req.Hostinfo)
	m.Endpoints = postgres.Jsonb{RawMessage: json.RawMessage(endpoints)}
	m.HostInfo = postgres.Jsonb{RawMessage: json.RawMessage(hostinfo)}
	now := time.Now().UTC()
	m.LastSeen = &now
	db.Save(&m)
	db.Close()

	chanStream := make(chan []byte, 1)
	go func() {
		defer close(chanStream)

		data, err := h.getMapResponse(mKey, req, m)
		if err != nil {
			c.String(http.StatusInternalServerError, ":(")
			return
		}

		//send initial dump
		chanStream <- *data
		for {

			data, err := h.getMapKeepAliveResponse(mKey, req, m)
			if err != nil {
				c.String(http.StatusInternalServerError, ":(")
				return
			}
			chanStream <- *data
			// keep the node entertained
			time.Sleep(time.Second * 180)
			break
		}

	}()
	c.Stream(func(w io.Writer) bool {
		if msg, ok := <-chanStream; ok {
			log.Printf("🦀 Sending data to %s: %d bytes", c.Request.RemoteAddr, len(msg))
			w.Write(msg)
			return true
		} else {
			log.Printf("🦄 Closing connection to %s", c.Request.RemoteAddr)
			c.AbortWithStatus(200)
			return false
		}
	})

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
		DNS:          []wgcfg.IP{},
		SearchPaths:  []string{},
		Domain:       "foobar@example.com",
		PacketFilter: tailcfg.FilterAllowAll,
		DERPMap:      &tailcfg.DERPMap{},
		UserProfiles: []tailcfg.UserProfile{},
		Roles:        []tailcfg.Role{}}

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

// RegisterWebAPI attaches the machine to a user or team.
// Currently this is a rather temp implementation, as it just registers it.
func (h *Headscale) RegisterWebAPI(c *gin.Context) {
	mKeyStr := c.Query("key")
	if mKeyStr == "" {
		c.String(http.StatusBadRequest, "Wrong params")
		return
	}
	mKey, err := wgcfg.ParseHexKey(mKeyStr)
	if err != nil {
		log.Printf("Cannot parse client key: %s", err)
		c.String(http.StatusInternalServerError, "Sad!")
		return
	}
	db, err := h.db()
	if err != nil {
		log.Printf("Cannot open DB: %s", err)
		c.String(http.StatusInternalServerError, ":(")
		return
	}
	defer db.Close()
	m := Machine{}
	if db.First(&m, "machine_key = ?", mKey.HexString()).RecordNotFound() {
		log.Printf("Cannot find machine with machine key: %s", mKey.Base64())
		c.String(http.StatusNotFound, "Sad!")
		return
	}

	if !m.isAlreadyRegistered() {
		ip, err := h.getAvailableIP()
		if err != nil {
			log.Println(err)
			c.String(http.StatusInternalServerError, "Upsy dupsy")
			return
		}
		m.IPAddress = ip.String()
		m.Registered = true // very naive 😱
		db.Save(&m)

		c.JSON(http.StatusOK, gin.H{"msg": "Ook"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"msg": "Eek"})
}

func (h *Headscale) handleNewServer(c *gin.Context, db *gorm.DB, idKey wgcfg.Key, req tailcfg.RegisterRequest) {
	mNew := Machine{
		MachineKey: idKey.HexString(),
		NodeKey:    wgcfg.Key(req.NodeKey).HexString(),
		Expiry:     &req.Expiry,
	}
	if err := db.Create(&mNew).Error; err != nil {
		log.Printf("Could not create row: %s", err)
		return
	}
	resp := tailcfg.RegisterResponse{
		AuthURL: fmt.Sprintf("%s/register?key=%s",
			h.cfg.ServerURL, idKey.HexString()),
	}

	respBody, err := encode(resp, &idKey, h.privateKey)
	if err != nil {
		log.Printf("Cannot encode message: %s", err)
		c.String(http.StatusInternalServerError, "Extremely sad!")
		return
	}
	c.Data(200, "application/json; charset=utf-8", respBody)
}
