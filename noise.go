package headscale

import (
	"encoding/base64"
	"net/http"

	"github.com/rs/zerolog/log"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
	"tailscale.com/control/controlbase"
	"tailscale.com/net/netutil"
)

const (
	errWrongConnectionUpgrade = Error("wrong connection upgrade")
	errCannotHijack           = Error("cannot hijack connection")
	errNoiseHandshakeFailed   = Error("noise handshake failed")
)

const (
	// ts2021UpgradePath is the path that the server listens on for the WebSockets upgrade.
	ts2021UpgradePath = "/ts2021"

	// upgradeHeader is the value of the Upgrade HTTP header used to
	// indicate the Tailscale control protocol.
	upgradeHeaderValue = "tailscale-control-protocol"

	// handshakeHeaderName is the HTTP request header that can
	// optionally contain base64-encoded initial handshake
	// payload, to save an RTT.
	handshakeHeaderName = "X-Tailscale-Handshake"
)

// NoiseUpgradeHandler is to upgrade the connection and hijack the net.Conn
// in order to use the Noise-based TS2021 protocol. Listens in /ts2021.
func (h *Headscale) NoiseUpgradeHandler(
	writer http.ResponseWriter,
	req *http.Request,
) {
	log.Trace().Caller().Msgf("Noise upgrade handler for client %s", req.RemoteAddr)

	// Under normal circumstances, we should be able to use the controlhttp.AcceptHTTP()
	// function to do this - kindly left there by the Tailscale authors for us to use.
	// (https://github.com/tailscale/tailscale/blob/main/control/controlhttp/server.go)
	//
	// When we used to use Gin, we had troubles here as Gin seems to do some
	// fun stuff, and not flusing the writer properly.
	// So have getNoiseConnection() that is essentially an AcceptHTTP, but in our side.
	noiseConn, err := h.getNoiseConnection(writer, req)
	if err != nil {
		log.Error().Err(err).Msg("noise upgrade failed")
		http.Error(writer, err.Error(), http.StatusInternalServerError)

		return
	}

	server := http.Server{}
	server.Handler = h2c.NewHandler(h.noiseMux, &http2.Server{})
	err = server.Serve(netutil.NewOneConnListener(noiseConn, nil))
	if err != nil {
		log.Info().Err(err).Msg("The HTTP2 server was closed")
	}
}

// getNoiseConnection is basically AcceptHTTP from tailscale
// TODO(juan): Figure out why we need to do this at all.
func (h *Headscale) getNoiseConnection(
	writer http.ResponseWriter,
	req *http.Request,
) (*controlbase.Conn, error) {
	next := req.Header.Get("Upgrade")
	if next == "" {
		http.Error(writer, errWrongConnectionUpgrade.Error(), http.StatusBadRequest)

		return nil, errWrongConnectionUpgrade
	}
	if next != upgradeHeaderValue {
		http.Error(writer, errWrongConnectionUpgrade.Error(), http.StatusBadRequest)

		return nil, errWrongConnectionUpgrade
	}

	initB64 := req.Header.Get(handshakeHeaderName)
	if initB64 == "" {
		log.Warn().
			Caller().
			Msg("no handshake header")
		http.Error(writer, "missing Tailscale handshake header", http.StatusBadRequest)

		return nil, errWrongConnectionUpgrade
	}

	init, err := base64.StdEncoding.DecodeString(initB64)
	if err != nil {
		log.Warn().Err(err).Msg("invalid handshake header")
		http.Error(writer, "invalid tailscale handshake header", http.StatusBadRequest)

		return nil, errWrongConnectionUpgrade
	}

	hijacker, ok := writer.(http.Hijacker)
	if !ok {
		log.Error().Caller().Err(err).Msgf("Hijack failed")
		http.Error(writer, errCannotHijack.Error(), http.StatusInternalServerError)

		return nil, errCannotHijack
	}

	// This is what changes from the original AcceptHTTP() function.
	writer.Header().Set("Upgrade", upgradeHeaderValue)
	writer.Header().Set("Connection", "upgrade")
	writer.WriteHeader(http.StatusSwitchingProtocols)
	// end

	netConn, conn, err := hijacker.Hijack()
	if err != nil {
		log.Error().Caller().Err(err).Msgf("Hijack failed")
		http.Error(writer, "HTTP does not support general TCP support", http.StatusInternalServerError)

		return nil, errCannotHijack
	}
	if err := conn.Flush(); err != nil {
		netConn.Close()

		return nil, errCannotHijack
	}

	netConn = netutil.NewDrainBufConn(netConn, conn.Reader)

	noiseConn, err := controlbase.Server(req.Context(), netConn, *h.noisePrivateKey, init)
	if err != nil {
		netConn.Close()

		return nil, errNoiseHandshakeFailed
	}

	return noiseConn, nil
}
