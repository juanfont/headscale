package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
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
	serverURL     string
	key           key.NodePrivate
	cfg           *types.DERPConfig
	tailscaleDERP *derp.Server
}

func NewDERPServer(
	serverURL string,
	derpKey key.NodePrivate,
	cfg *types.DERPConfig,
) (*DERPServer, error) {
	log.Trace().Caller().Msg("Creating new embedded DERP server")
	server := derp.NewServer(derpKey, util.TSLogfWrapper()) // nolint // zerolinter complains

	return &DERPServer{
		serverURL:     serverURL,
		key:           derpKey,
		cfg:           cfg,
		tailscaleDERP: server,
	}, nil
}

func (d *DERPServer) GenerateRegion() (tailcfg.DERPRegion, error) {
	serverURL, err := url.Parse(d.serverURL)
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
		RegionID:   d.cfg.ServerRegionID,
		RegionCode: d.cfg.ServerRegionCode,
		RegionName: d.cfg.ServerRegionName,
		Avoid:      false,
		Nodes: []*tailcfg.DERPNode{
			{
				Name:     fmt.Sprintf("%d", d.cfg.ServerRegionID),
				RegionID: d.cfg.ServerRegionID,
				HostName: host,
				DERPPort: port,
				IPv4:     d.cfg.IPv4,
				IPv6:     d.cfg.IPv6,
			},
		},
	}

	_, portSTUNStr, err := net.SplitHostPort(d.cfg.STUNAddr)
	if err != nil {
		return tailcfg.DERPRegion{}, err
	}
	portSTUN, err := strconv.Atoi(portSTUNStr)
	if err != nil {
		return tailcfg.DERPRegion{}, err
	}
	localDERPregion.Nodes[0].STUNPort = portSTUN

	log.Info().Caller().Msgf("DERP region: %+v", localDERPregion)
	log.Info().Caller().Msgf("DERP Nodes[0]: %+v", localDERPregion.Nodes[0])

	return localDERPregion, nil
}

func (d *DERPServer) DERPHandler(
	writer http.ResponseWriter,
	req *http.Request,
) {
	log.Trace().Caller().Msgf("/derp request from %v", req.RemoteAddr)
	upgrade := strings.ToLower(req.Header.Get("Upgrade"))

	if upgrade != "websocket" && upgrade != "derp" {
		if upgrade != "" {
			log.Warn().
				Caller().
				Msg("No Upgrade header in DERP server request. If headscale is behind a reverse proxy, make sure it is configured to pass WebSockets through.")
		}
		writer.Header().Set("Content-Type", "text/plain")
		writer.WriteHeader(http.StatusUpgradeRequired)
		_, err := writer.Write([]byte("DERP requires connection upgrade"))
		if err != nil {
			log.Error().
				Caller().
				Err(err).
				Msg("Failed to write response")
		}

		return
	}

	fastStart := req.Header.Get(fastStartHeader) == "1"

	hijacker, ok := writer.(http.Hijacker)
	if !ok {
		log.Error().Caller().Msg("DERP requires Hijacker interface from Gin")
		writer.Header().Set("Content-Type", "text/plain")
		writer.WriteHeader(http.StatusInternalServerError)
		_, err := writer.Write([]byte("HTTP does not support general TCP support"))
		if err != nil {
			log.Error().
				Caller().
				Err(err).
				Msg("Failed to write response")
		}

		return
	}

	netConn, conn, err := hijacker.Hijack()
	if err != nil {
		log.Error().Caller().Err(err).Msgf("Hijack failed")
		writer.Header().Set("Content-Type", "text/plain")
		writer.WriteHeader(http.StatusInternalServerError)
		_, err = writer.Write([]byte("HTTP does not support general TCP support"))
		if err != nil {
			log.Error().
				Caller().
				Err(err).
				Msg("Failed to write response")
		}

		return
	}
	log.Trace().Caller().Msgf("Hijacked connection from %v", req.RemoteAddr)

	if !fastStart {
		pubKey := d.key.Public()
		pubKeyStr, _ := pubKey.MarshalText() //nolint
		fmt.Fprintf(conn, "HTTP/1.1 101 Switching Protocols\r\n"+
			"Upgrade: DERP\r\n"+
			"Connection: Upgrade\r\n"+
			"Derp-Version: %v\r\n"+
			"Derp-Public-Key: %s\r\n\r\n",
			derp.ProtocolVersion,
			string(pubKeyStr))
	}

	d.tailscaleDERP.Accept(req.Context(), netConn, conn, netConn.RemoteAddr().String())
}

// DERPProbeHandler is the endpoint that js/wasm clients hit to measure
// DERP latency, since they can't do UDP STUN queries.
func DERPProbeHandler(
	writer http.ResponseWriter,
	req *http.Request,
) {
	switch req.Method {
	case http.MethodHead, http.MethodGet:
		writer.Header().Set("Access-Control-Allow-Origin", "*")
		writer.WriteHeader(http.StatusOK)
	default:
		writer.WriteHeader(http.StatusMethodNotAllowed)
		_, err := writer.Write([]byte("bogus probe method"))
		if err != nil {
			log.Error().
				Caller().
				Err(err).
				Msg("Failed to write response")
		}
	}
}

// DERPBootstrapDNSHandler implements the /bootsrap-dns endpoint
// Described in https://github.com/tailscale/tailscale/issues/1405,
// this endpoint provides a way to help a client when it fails to start up
// because its DNS are broken.
// The initial implementation is here https://github.com/tailscale/tailscale/pull/1406
// They have a cache, but not clear if that is really necessary at Headscale, uh, scale.
// An example implementation is found here https://derp.tailscale.com/bootstrap-dns
// Coordination server is included automatically, since local DERP is using the same DNS Name in d.serverURL.
func DERPBootstrapDNSHandler(
	derpMap *tailcfg.DERPMap,
) func(http.ResponseWriter, *http.Request) {
	return func(
		writer http.ResponseWriter,
		req *http.Request,
	) {
		dnsEntries := make(map[string][]net.IP)

		resolvCtx, cancel := context.WithTimeout(req.Context(), time.Minute)
		defer cancel()
		var resolver net.Resolver
		for _, region := range derpMap.Regions {
			for _, node := range region.Nodes { // we don't care if we override some nodes
				addrs, err := resolver.LookupIP(resolvCtx, "ip", node.HostName)
				if err != nil {
					log.Trace().
						Caller().
						Err(err).
						Msgf("bootstrap DNS lookup failed %q", node.HostName)

					continue
				}
				dnsEntries[node.HostName] = addrs
			}
		}
		writer.Header().Set("Content-Type", "application/json")
		writer.WriteHeader(http.StatusOK)
		err := json.NewEncoder(writer).Encode(dnsEntries)
		if err != nil {
			log.Error().
				Caller().
				Err(err).
				Msg("Failed to write response")
		}
	}
}

// ServeSTUN starts a STUN server on the configured addr.
func (d *DERPServer) ServeSTUN() {
	packetConn, err := net.ListenPacket("udp", d.cfg.STUNAddr)
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

		addr, _ := netip.AddrFromSlice(udpAddr.IP)
		res := stun.Response(txid, netip.AddrPortFrom(addr, uint16(udpAddr.Port)))
		_, err = packetConn.WriteTo(res, udpAddr)
		if err != nil {
			log.Trace().Caller().Err(err).Msgf("Issue writing to UDP")

			continue
		}
	}
}
