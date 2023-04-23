package headscale

import (
	"net/http"

	"github.com/gorilla/mux"
	"github.com/rs/zerolog/log"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
	"tailscale.com/control/controlbase"
	"tailscale.com/control/controlhttp"
	"tailscale.com/net/netutil"
)

const (
	// ts2021UpgradePath is the path that the server listens on for the WebSockets upgrade.
	ts2021UpgradePath = "/ts2021"
)

type noiseServer struct {
	headscale *Headscale

	conn *controlbase.Conn
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

	noiseConn, err := controlhttp.AcceptHTTP(req.Context(), writer, req, *h.noisePrivateKey, nil)
	if err != nil {
		log.Error().Err(err).Msg("noise upgrade failed")
		http.Error(writer, err.Error(), http.StatusInternalServerError)

		return
	}

	noiseServer := noiseServer{
		headscale: h,
		conn:      noiseConn,
	}

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
	server.Handler = h2c.NewHandler(router, &http2.Server{})
	err = server.Serve(netutil.NewOneConnListener(noiseConn, nil))
	if err != nil {
		log.Info().Err(err).Msg("The HTTP2 server was closed")
	}
}
