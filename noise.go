package headscale

import (
	"net/http"

	"github.com/rs/zerolog/log"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
	"tailscale.com/control/controlhttp"
	"tailscale.com/net/netutil"
)

const (
	// ts2021UpgradePath is the path that the server listens on for the WebSockets upgrade.
	ts2021UpgradePath = "/ts2021"
)

// NoiseUpgradeHandler is to upgrade the connection and hijack the net.Conn
// in order to use the Noise-based TS2021 protocol. Listens in /ts2021.
func (h *Headscale) NoiseUpgradeHandler(
	writer http.ResponseWriter,
	req *http.Request,
) {
	log.Trace().Caller().Msgf("Noise upgrade handler for client %s", req.RemoteAddr)

	noiseConn, err := controlhttp.AcceptHTTP(req.Context(), writer, req, *h.noisePrivateKey)
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
