package headscale

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
	"tailscale.com/derp"
	"tailscale.com/net/stun"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

// fastStartHeader is the header (with value "1") that signals to the HTTP
// server that the DERP HTTP client does not want the HTTP 101 response
// headers and it will begin writing & reading the DERP protocol immediately
// following its HTTP request.
const fastStartHeader = "Derp-Fast-Start"

type DERPServer struct {
	tailscaleDERP *derp.Server
	region        tailcfg.DERPRegion
}

func (h *Headscale) NewDERPServer() (*DERPServer, error) {
	server := derp.NewServer(key.NodePrivate(*h.privateKey), log.Info().Msgf)
	region, err := h.generateRegionLocalDERP()
	if err != nil {
		return nil, err
	}

	return &DERPServer{server, region}, nil
}

func (h *Headscale) generateRegionLocalDERP() (tailcfg.DERPRegion, error) {
	serverURL, err := url.Parse(h.cfg.ServerURL)
	if err != nil {
		return tailcfg.DERPRegion{}, err
	}
	var host string
	var port int
	host, portStr, err := net.SplitHostPort(serverURL.Host)
	if err != nil {
		if serverURL.Scheme == "https" {
			host = serverURL.Host
			port = 443
		} else {
			host = serverURL.Host
			port = 80
		}
	} else {
		port, err = strconv.Atoi(portStr)
		if err != nil {
			return tailcfg.DERPRegion{}, err
		}
	}

	localDERPregion := tailcfg.DERPRegion{
		RegionID:   h.cfg.DERP.ServerRegionID,
		RegionCode: h.cfg.DERP.ServerRegionCode,
		RegionName: h.cfg.DERP.ServerRegionName,
		Avoid:      false,
		Nodes: []*tailcfg.DERPNode{
			{
				Name:     fmt.Sprintf("%d", h.cfg.DERP.ServerRegionID),
				RegionID: h.cfg.DERP.ServerRegionID,
				HostName: host,
				DERPPort: port,
			},
		},
	}

	if h.cfg.DERP.STUNEnabled {
		_, portStr, err := net.SplitHostPort(h.cfg.DERP.STUNAddr)
		if err != nil {
			return tailcfg.DERPRegion{}, err
		}
		port, err := strconv.Atoi(portStr)
		if err != nil {
			return tailcfg.DERPRegion{}, err
		}
		localDERPregion.Nodes[0].STUNPort = port
	}

	return localDERPregion, nil
}

func (h *Headscale) DERPHandler(ctx *gin.Context) {
	log.Trace().Caller().Msgf("/derp request from %v", ctx.ClientIP())
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
		pubKeyStr := pubKey.UntypedHexString() // nolint
		fmt.Fprintf(conn, "HTTP/1.1 101 Switching Protocols\r\n"+
			"Upgrade: DERP\r\n"+
			"Connection: Upgrade\r\n"+
			"Derp-Version: %v\r\n"+
			"Derp-Public-Key: %s\r\n\r\n",
			derp.ProtocolVersion,
			pubKeyStr)
	}

	h.DERPServer.tailscaleDERP.Accept(netConn, conn, netConn.RemoteAddr().String())
}

// DERPProbeHandler is the endpoint that js/wasm clients hit to measure
// DERP latency, since they can't do UDP STUN queries.
func (h *Headscale) DERPProbeHandler(ctx *gin.Context) {
	switch ctx.Request.Method {
	case "HEAD", "GET":
		ctx.Writer.Header().Set("Access-Control-Allow-Origin", "*")
	default:
		ctx.String(http.StatusMethodNotAllowed, "bogus probe method")
	}
}

// DERPBootstrapDNSHandler implements the /bootsrap-dns endpoint
// Described in https://github.com/tailscale/tailscale/issues/1405,
// this endpoint provides a way to help a client when it fails to start up
// because its DNS are broken.
// The initial implementation is here https://github.com/tailscale/tailscale/pull/1406
// They have a cache, but not clear if that is really necessary at Headscale, uh, scale.
// An example implementation is found here https://derp.tailscale.com/bootstrap-dns
func (h *Headscale) DERPBootstrapDNSHandler(ctx *gin.Context) {
	dnsEntries := make(map[string][]net.IP)

	resolvCtx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	var r net.Resolver
	for _, region := range h.DERPMap.Regions {
		for _, node := range region.Nodes { // we don't care if we override some nodes
			addrs, err := r.LookupIP(resolvCtx, "ip", node.HostName)
			if err != nil {
				log.Trace().Caller().Err(err).Msgf("bootstrap DNS lookup failed %q", node.HostName)

				continue
			}
			dnsEntries[node.HostName] = addrs
		}
	}
	ctx.JSON(http.StatusOK, dnsEntries)
}

// ServeSTUN starts a STUN server on the configured addr.
func (h *Headscale) ServeSTUN() {
	packetConn, err := net.ListenPacket("udp", h.cfg.DERP.STUNAddr)
	if err != nil {
		log.Fatal().Msgf("failed to open STUN listener: %v", err)
	}
	log.Info().Msgf("STUN server started at %s", packetConn.LocalAddr())

	udpConn, ok := packetConn.(*net.UDPConn)
	if !ok {
		log.Fatal().Msg("STUN listener is not a UDP listener")
	}
	serverSTUNListener(context.Background(), udpConn)
}

func serverSTUNListener(ctx context.Context, packetConn *net.UDPConn) {
	var buf [64 << 10]byte
	var (
		bytesRead int
		udpAddr   *net.UDPAddr
		err       error
	)
	for {
		bytesRead, udpAddr, err = packetConn.ReadFromUDP(buf[:])
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Error().Caller().Err(err).Msgf("STUN ReadFrom")
			time.Sleep(time.Second)

			continue
		}
		log.Trace().Caller().Msgf("STUN request from %v", udpAddr)
		pkt := buf[:bytesRead]
		if !stun.Is(pkt) {
			log.Trace().Caller().Msgf("UDP packet is not STUN")

			continue
		}
		txid, err := stun.ParseBindingRequest(pkt)
		if err != nil {
			log.Trace().Caller().Err(err).Msgf("STUN parse error")

			continue
		}

		res := stun.Response(txid, udpAddr.IP, uint16(udpAddr.Port))
		_, err = packetConn.WriteTo(res, udpAddr)
		if err != nil {
			log.Trace().Caller().Err(err).Msgf("Issue writing to UDP")

			continue
		}
	}
}
