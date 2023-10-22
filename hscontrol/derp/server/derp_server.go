package server

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/juanfont/headscale/hscontrol/db"
	"github.com/juanfont/headscale/hscontrol/util"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path"
	"strconv"
	"strings"
	"tailscale.com/client/tailscale"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/paths"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
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
	db            *db.HSDatabase
	tailscaleDERP *derp.Server
}

func NewDERPServer(
	serverURL string,
	derpKey key.NodePrivate,
	cfg *types.DERPConfig,
	db *db.HSDatabase,
) (*DERPServer, error) {
	log.Trace().Caller().Msg("Creating new embedded DERP server")
	server := derp.NewServer(derpKey, log.Debug().Msgf) // nolint // zerolinter complains
	server.SetVerifyClient(cfg.ServerVerifyClients)

	return &DERPServer{
		serverURL:     serverURL,
		key:           derpKey,
		cfg:           cfg,
		db:            db,
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

func (d *DERPServer) ServeFakeStatus() error {
	socketPath := paths.DefaultTailscaledSocket()
	socketDir := path.Dir(socketPath)
	st, err := os.Stat(socketDir)
	if err != nil {
		if os.IsNotExist(err) {
			err = os.MkdirAll(socketDir, 0755)
			if err != nil {
				return err
			}
		} else {
			return err
		}
	}
	if !st.IsDir() {
		return fmt.Errorf("the socket dir path(%s) already exists, but is a file", socketDir)
	}

	laCtx, laCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer laCancel()
	if _, err = tailscale.Status(laCtx); err == nil {
		return fmt.Errorf("derp simulate local socket api error: "+
			"another tailscaled process is already listening to this service(%s)", socketPath)
	}

	log.Info().Msgf("Clean up local api socket file: %s", socketPath)
	if err := os.RemoveAll(socketPath); err != nil {
		return err
	}

	log.Trace().Caller().Msg("Listen fake status socket")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		return err
	}

	server := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet {
				http.Error(w, "use GET", http.StatusMethodNotAllowed)
				return
			}

			nodes, err := d.db.ListNodes()
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			peer := make(map[key.NodePublic]*ipnstate.PeerStatus)
			for _, node := range nodes {
				pk := &key.NodePublic{}
				if err = pk.UnmarshalText([]byte(util.NodePublicKeyEnsurePrefix(node.NodeKey))); err != nil {
					log.Error().Err(err).Msg("failed to decode node public key")
					continue
				}
				peer[*pk] = &ipnstate.PeerStatus{}
			}
			status := &ipnstate.Status{
				Self: &ipnstate.PeerStatus{},
				Peer: peer,
			}
			w.Header().Set("Content-Type", "application/json")
			e := json.NewEncoder(w)
			e.SetIndent("", "\t")
			_ = e.Encode(status)
		}),
	}
	go func() {
		err := server.Serve(listener)
		if err != nil {
			log.Error().Err(err).Msg("Fake status server error")
		}
	}()
	return nil
}
