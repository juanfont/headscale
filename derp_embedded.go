package headscale

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
	"tailscale.com/derp"
	"tailscale.com/net/stun"
	"tailscale.com/types/key"
)

// fastStartHeader is the header (with value "1") that signals to the HTTP
// server that the DERP HTTP client does not want the HTTP 101 response
// headers and it will begin writing & reading the DERP protocol immediately
// following its HTTP request.
const fastStartHeader = "Derp-Fast-Start"

var (
	dnsCache     atomic.Value // of []byte
	bootstrapDNS = "derp.tailscale.com"
)

type EmbeddedDerpServer struct {
	tailscaleDerp *derp.Server
}

func (h *Headscale) NewEmbeddedDerpServer() (*EmbeddedDerpServer, error) {
	s := derp.NewServer(key.NodePrivate(*h.privateKey), log.Info().Msgf)
	return &EmbeddedDerpServer{s}, nil

}

func (h *Headscale) EmbeddedDerpHandler(ctx *gin.Context) {
	up := strings.ToLower(ctx.Request.Header.Get("Upgrade"))
	if up != "websocket" && up != "derp" {
		if up != "" {
			log.Warn().Caller().Msgf("Weird websockets connection upgrade: %q", up)
		}
		ctx.String(http.StatusUpgradeRequired, "DERP requires connection upgrade")
		return
	}

	fastStart := ctx.Request.Header.Get(fastStartHeader) == "1"

	hijacker, ok := ctx.Writer.(http.Hijacker)
	if !ok {
		log.Error().Caller().Msg("DERP requires Hijacker interface from Gin")
		ctx.String(http.StatusInternalServerError, "HTTP does not support general TCP support")
		return
	}

	netConn, conn, err := hijacker.Hijack()
	if err != nil {
		log.Error().Caller().Err(err).Msgf("Hijack failed")
		ctx.String(http.StatusInternalServerError, "HTTP does not support general TCP support")
		return
	}

	if !fastStart {
		pubKey := h.privateKey.Public()
		fmt.Fprintf(conn, "HTTP/1.1 101 Switching Protocols\r\n"+
			"Upgrade: DERP\r\n"+
			"Connection: Upgrade\r\n"+
			"Derp-Version: %v\r\n"+
			"Derp-Public-Key: %s\r\n\r\n",
			derp.ProtocolVersion,
			pubKey.UntypedHexString())
	}

	h.EmbeddedDerpServer.tailscaleDerp.Accept(netConn, conn, netConn.RemoteAddr().String())
}

// EmbeddedDerpProbeHandler is the endpoint that js/wasm clients hit to measure
// DERP latency, since they can't do UDP STUN queries.
func (h *Headscale) EmbeddedDerpProbeHandler(ctx *gin.Context) {
	switch ctx.Request.Method {
	case "HEAD", "GET":
		ctx.Writer.Header().Set("Access-Control-Allow-Origin", "*")
	default:
		ctx.String(http.StatusMethodNotAllowed, "bogus probe method")
	}
}

func (h *Headscale) EmbeddedDerpBootstrapDNSHandler(ctx *gin.Context) {
	ctx.Header("Content-Type", "application/json")
	j, _ := dnsCache.Load().([]byte)
	// Bootstrap DNS requests occur cross-regions,
	// and are randomized per request,
	// so keeping a connection open is pointlessly expensive.
	ctx.Header("Connection", "close")
	ctx.Writer.Write(j)
}

// ServeSTUN starts a STUN server on udp/3478
func (h *Headscale) ServeSTUN() {
	pc, err := net.ListenPacket("udp", "0.0.0.0:3478")
	if err != nil {
		log.Fatal().Msgf("failed to open STUN listener: %v", err)
	}
	log.Printf("running STUN server on %v", pc.LocalAddr())
	serverSTUNListener(context.Background(), pc.(*net.UDPConn))
}

func serverSTUNListener(ctx context.Context, pc *net.UDPConn) {
	var buf [64 << 10]byte
	var (
		n   int
		ua  *net.UDPAddr
		err error
	)
	for {
		n, ua, err = pc.ReadFromUDP(buf[:])
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Printf("STUN ReadFrom: %v", err)
			time.Sleep(time.Second)
			continue
		}
		pkt := buf[:n]
		if !stun.Is(pkt) {
			continue
		}
		txid, err := stun.ParseBindingRequest(pkt)
		if err != nil {
			continue
		}

		res := stun.Response(txid, ua.IP, uint16(ua.Port))
		pc.WriteTo(res, ua)
	}
}

// Shamelessly taken from
// https://github.com/tailscale/tailscale/blob/main/cmd/derper/bootstrap_dns.go
func refreshBootstrapDNSLoop() {
	if bootstrapDNS == "" {
		return
	}
	for {
		refreshBootstrapDNS()
		time.Sleep(10 * time.Minute)
	}
}

func refreshBootstrapDNS() {
	if bootstrapDNS == "" {
		return
	}
	dnsEntries := make(map[string][]net.IP)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	names := strings.Split(bootstrapDNS, ",")
	var r net.Resolver
	for _, name := range names {
		addrs, err := r.LookupIP(ctx, "ip", name)
		if err != nil {
			log.Printf("bootstrap DNS lookup %q: %v", name, err)
			continue
		}
		dnsEntries[name] = addrs
	}
	j, err := json.MarshalIndent(dnsEntries, "", "\t")
	if err != nil {
		// leave the old values in place
		return
	}
	dnsCache.Store(j)
}
