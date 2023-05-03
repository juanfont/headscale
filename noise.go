package headscale

import (
	"encoding/binary"
	"encoding/json"
	"io"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/rs/zerolog/log"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
	"tailscale.com/control/controlbase"
	"tailscale.com/control/controlhttp"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

const (
	// ts2021UpgradePath is the path that the server listens on for the WebSockets upgrade.
	ts2021UpgradePath = "/ts2021"

	// The first 9 bytes from the server to client over Noise are either an HTTP/2
	// settings frame (a normal HTTP/2 setup) or, as Tailscale added later, an "early payload"
	// header that's also 9 bytes long: 5 bytes (earlyPayloadMagic) followed by 4 bytes
	// of length. Then that many bytes of JSON-encoded tailcfg.EarlyNoise.
	// The early payload is optional. Some servers may not send it... But we do!
	earlyPayloadMagic = "\xff\xff\xffTS"

	// EarlyNoise was added in protocol version 49.
	earlyNoiseCapabilityVersion = 49
)

type noiseServer struct {
	headscale *Headscale

	httpBaseConfig *http.Server
	http2Server    *http2.Server
	conn           *controlbase.Conn
	machineKey     key.MachinePublic
	nodeKey        key.NodePublic

	// EarlyNoise-related stuff
	challenge       key.ChallengePrivate
	protocolVersion int
}

// NoiseUpgradeHandler is to upgrade the connection and hijack the net.Conn
// in order to use the Noise-based TS2021 protocol. Listens in /ts2021.
func (h *Headscale) NoiseUpgradeHandler(
	writer http.ResponseWriter,
	req *http.Request,
) {
	log.Trace().Caller().Msgf("Noise upgrade handler for client %s", req.RemoteAddr)

	upgrade := req.Header.Get("Upgrade")
	if upgrade == "" {
		// This probably means that the user is running Headscale behind an
		// improperly configured reverse proxy. TS2021 requires WebSockets to
		// be passed to Headscale. Let's give them a hint.
		log.Warn().
			Caller().
			Msg("No Upgrade header in TS2021 request. If headscale is behind a reverse proxy, make sure it is configured to pass WebSockets through.")
		http.Error(writer, "Internal error", http.StatusInternalServerError)

		return
	}

	noiseServer := noiseServer{
		headscale: h,
		challenge: key.NewChallenge(),
	}

	noiseConn, err := controlhttp.AcceptHTTP(
		req.Context(),
		writer,
		req,
		*h.noisePrivateKey,
		noiseServer.earlyNoise,
	)
	if err != nil {
		log.Error().Err(err).Msg("noise upgrade failed")
		http.Error(writer, err.Error(), http.StatusInternalServerError)

		return
	}

	noiseServer.conn = noiseConn
	noiseServer.machineKey = noiseServer.conn.Peer()
	noiseServer.protocolVersion = noiseServer.conn.ProtocolVersion()

	// This router is served only over the Noise connection, and exposes only the new API.
	//
	// The HTTP2 server that exposes this router is created for
	// a single hijacked connection from /ts2021, using netutil.NewOneConnListener
	router := mux.NewRouter()

	router.HandleFunc("/machine/register", noiseServer.NoiseRegistrationHandler).
		Methods(http.MethodPost)
	router.HandleFunc("/machine/map", noiseServer.NoisePollNetMapHandler)

	server := http.Server{
		ReadTimeout: HTTPReadTimeout,
	}

	noiseServer.httpBaseConfig = &http.Server{
		Handler:           router,
		ReadHeaderTimeout: HTTPReadTimeout,
	}
	noiseServer.http2Server = &http2.Server{}

	server.Handler = h2c.NewHandler(router, noiseServer.http2Server)

	noiseServer.http2Server.ServeConn(
		noiseConn,
		&http2.ServeConnOpts{
			BaseConfig: noiseServer.httpBaseConfig,
		},
	)
}

func (ns *noiseServer) earlyNoise(protocolVersion int, writer io.Writer) error {
	log.Trace().
		Caller().
		Int("protocol_version", protocolVersion).
		Str("challenge", ns.challenge.Public().String()).
		Msg("earlyNoise called")

	if protocolVersion < earlyNoiseCapabilityVersion {
		log.Trace().
			Caller().
			Msgf("protocol version %d does not support early noise", protocolVersion)

		return nil
	}

	earlyJSON, err := json.Marshal(&tailcfg.EarlyNoise{
		NodeKeyChallenge: ns.challenge.Public(),
	})
	if err != nil {
		return err
	}

	// 5 bytes that won't be mistaken for an HTTP/2 frame:
	// https://httpwg.org/specs/rfc7540.html#rfc.section.4.1 (Especially not
	// an HTTP/2 settings frame, which isn't of type 'T')
	var notH2Frame [5]byte
	copy(notH2Frame[:], earlyPayloadMagic)
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(earlyJSON)))
	// These writes are all buffered by caller, so fine to do them
	// separately:
	if _, err := writer.Write(notH2Frame[:]); err != nil {
		return err
	}
	if _, err := writer.Write(lenBuf[:]); err != nil {
		return err
	}
	if _, err := writer.Write(earlyJSON); err != nil {
		return err
	}

	return nil
}
