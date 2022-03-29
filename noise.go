package headscale

import (
	"encoding/base64"
	"net/http"

	"github.com/gin-gonic/gin"
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
	// upgradeHeader is the value of the Upgrade HTTP header used to
	// indicate the Tailscale control protocol.
	upgradeHeaderValue = "tailscale-control-protocol"

	// handshakeHeaderName is the HTTP request header that can
	// optionally contain base64-encoded initial handshake
	// payload, to save an RTT.
	handshakeHeaderName = "X-Tailscale-Handshake"
)

// NoiseUpgradeHandler is to upgrade the connection and hijack the net.Conn
// in order to use the Noise-based TS2021 protocol. Listens in /ts2021
func (h *Headscale) NoiseUpgradeHandler(ctx *gin.Context) {
	log.Trace().Caller().Msgf("Noise upgrade handler for client %s", ctx.ClientIP())

	// Under normal circumpstances, we should be able to use the controlhttp.AcceptHTTP()
	// function to do this - kindly left there by the Tailscale authors for us to use.
	// (https://github.com/tailscale/tailscale/blob/main/control/controlhttp/server.go)
	//
	// However, Gin seems to be doing something funny/different with its writer (see AcceptHTTP code).
	// This causes problems when the upgrade headers are sent in AcceptHTTP.
	// So have getNoiseConnection() that is essentially an AcceptHTTP but using the native Gin methods.
	noiseConn, err := h.getNoiseConnection(ctx)

	if err != nil {
		log.Error().Err(err).Msg("noise upgrade failed")
		ctx.AbortWithError(http.StatusInternalServerError, err)

		return
	}

	server := http.Server{}
	server.Handler = h2c.NewHandler(h.noiseRouter, &http2.Server{})
	server.Serve(netutil.NewOneConnListener(noiseConn, nil))
}

// getNoiseConnection is basically AcceptHTTP from tailscale, but more _alla_ Gin
// TODO(juan): Figure out why we need to do this at all.
func (h *Headscale) getNoiseConnection(ctx *gin.Context) (*controlbase.Conn, error) {
	next := ctx.GetHeader("Upgrade")
	if next == "" {
		ctx.String(http.StatusBadRequest, "missing next protocol")
		return nil, errWrongConnectionUpgrade
	}
	if next != upgradeHeaderValue {
		ctx.String(http.StatusBadRequest, "unknown next protocol")
		return nil, errWrongConnectionUpgrade
	}

	initB64 := ctx.GetHeader(handshakeHeaderName)
	if initB64 == "" {
		ctx.String(http.StatusBadRequest, "missing Tailscale handshake header")
		return nil, errWrongConnectionUpgrade
	}
	init, err := base64.StdEncoding.DecodeString(initB64)
	if err != nil {
		ctx.String(http.StatusBadRequest, "invalid tailscale handshake header")
		return nil, errWrongConnectionUpgrade
	}

	hijacker, ok := ctx.Writer.(http.Hijacker)
	if !ok {
		log.Error().Caller().Err(err).Msgf("Hijack failed")
		ctx.String(http.StatusInternalServerError, "HTTP does not support general TCP support")
		return nil, errCannotHijack
	}

	// This is what changes from the original AcceptHTTP() function.
	ctx.Header("Upgrade", upgradeHeaderValue)
	ctx.Header("Connection", "upgrade")
	ctx.Status(http.StatusSwitchingProtocols)
	ctx.Writer.WriteHeaderNow()
	// end

	netConn, conn, err := hijacker.Hijack()
	if err != nil {
		log.Error().Caller().Err(err).Msgf("Hijack failed")
		ctx.String(http.StatusInternalServerError, "HTTP does not support general TCP support")

		return nil, errCannotHijack
	}
	if err := conn.Flush(); err != nil {
		netConn.Close()
		return nil, errCannotHijack
	}
	netConn = netutil.NewDrainBufConn(netConn, conn.Reader)

	nc, err := controlbase.Server(ctx.Request.Context(), netConn, *h.noisePrivateKey, init)
	if err != nil {
		netConn.Close()
		return nil, errNoiseHandshakeFailed
	}

	return nc, nil
}
