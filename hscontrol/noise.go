package hscontrol

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/metrics"
	"github.com/juanfont/headscale/hscontrol/capver"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"golang.org/x/net/http2"
	"tailscale.com/control/controlbase"
	"tailscale.com/control/controlhttp/controlhttpserver"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

// ErrUnsupportedClientVersion is returned when a client connects with an unsupported protocol version.
var ErrUnsupportedClientVersion = errors.New("unsupported client version")

// ErrMissingURLParameter is returned when a required URL parameter is not provided.
var ErrMissingURLParameter = errors.New("missing URL parameter")

// ErrUnsupportedURLParameterType is returned when a URL parameter has an unsupported type.
var ErrUnsupportedURLParameterType = errors.New("unsupported URL parameter type")

// ErrNoAuthSession is returned when an auth_id does not match any active auth session.
var ErrNoAuthSession = errors.New("no auth session found")

const (
	// ts2021UpgradePath is the path that the server listens on for the WebSockets upgrade.
	ts2021UpgradePath = "/ts2021"

	// The first 9 bytes from the server to client over Noise are either an HTTP/2
	// settings frame (a normal HTTP/2 setup) or, as Tailscale added later, an "early payload"
	// header that's also 9 bytes long: 5 bytes (earlyPayloadMagic) followed by 4 bytes
	// of length. Then that many bytes of JSON-encoded tailcfg.EarlyNoise.
	// The early payload is optional. Some servers may not send it... But we do!
	earlyPayloadMagic = "\xff\xff\xffTS"
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
	log.Trace().Caller().Msgf("noise upgrade handler for client %s", req.RemoteAddr)

	upgrade := req.Header.Get("Upgrade")
	if upgrade == "" {
		// This probably means that the user is running Headscale behind an
		// improperly configured reverse proxy. TS2021 requires WebSockets to
		// be passed to Headscale. Let's give them a hint.
		log.Warn().
			Caller().
			Msg("no upgrade header in TS2021 request. If headscale is behind a reverse proxy, make sure it is configured to pass WebSockets through.")
		http.Error(writer, "Internal error", http.StatusInternalServerError)

		return
	}

	ns := noiseServer{
		headscale: h,
		challenge: key.NewChallenge(),
	}

	noiseConn, err := controlhttpserver.AcceptHTTP(
		req.Context(),
		writer,
		req,
		*h.noisePrivateKey,
		ns.earlyNoise,
	)
	if err != nil {
		httpError(writer, fmt.Errorf("upgrading noise connection: %w", err))
		return
	}

	ns.conn = noiseConn
	ns.machineKey = ns.conn.Peer()
	ns.protocolVersion = ns.conn.ProtocolVersion()

	// This router is served only over the Noise connection, and exposes only the new API.
	//
	// The HTTP2 server that exposes this router is created for
	// a single hijacked connection from /ts2021, using netutil.NewOneConnListener

	r := chi.NewRouter()
	r.Use(metrics.Collector(metrics.CollectorOpts{
		Host:  false,
		Proto: true,
		Skip: func(r *http.Request) bool {
			return r.Method != http.MethodOptions
		},
	}))
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.RequestLogger(&zerologRequestLogger{}))
	r.Use(middleware.Recoverer)

	r.Handle("/metrics", metrics.Handler())

	r.Route("/machine", func(r chi.Router) {
		r.Post("/register", ns.RegistrationHandler)
		r.Post("/map", ns.PollNetMapHandler)

		// SSH Check mode endpoint, consulted to validate if a given SSH connection should be accepted or rejected.
		r.Get("/ssh/action/from/{src_node_id}/to/{dst_node_id}", ns.SSHActionHandler)

		// Not implemented yet
		//
		// /whoami is a debug endpoint to validate that the client can communicate over the connection,
		// not clear if there is a specific response, it looks like it is just logged.
		// https://github.com/tailscale/tailscale/blob/dfba01ca9bd8c4df02c3c32f400d9aeb897c5fc7/cmd/tailscale/cli/debug.go#L1138
		r.Get("/whoami", ns.NotImplementedHandler)

		// client sends a [tailcfg.SetDNSRequest] to this endpoints and expect
		// the server to create or update this DNS record "somewhere".
		// It is typically a TXT record for an ACME challenge.
		r.Post("/set-dns", ns.NotImplementedHandler)

		// A patch of [tailcfg.SetDeviceAttributesRequest] to update device attributes.
		// We currently do not support device attributes.
		r.Patch("/set-device-attr", ns.NotImplementedHandler)

		// A [tailcfg.AuditLogRequest] to send audit log entries to the server.
		// The server is expected to store them "somewhere".
		// We currently do not support device attributes.
		r.Post("/audit-log", ns.NotImplementedHandler)

		// handles requests to get an OIDC ID token. Receives a [tailcfg.TokenRequest].
		r.Post("/id-token", ns.NotImplementedHandler)

		// Asks the server if a feature is available and receive information about how to enable it.
		// Gets a [tailcfg.QueryFeatureRequest] and returns a [tailcfg.QueryFeatureResponse].
		r.Post("/feature/query", ns.NotImplementedHandler)

		r.Post("/update-health", ns.NotImplementedHandler)

		r.Route("/webclient", func(r chi.Router) {})

		r.Post("/c2n", ns.NotImplementedHandler)
	})

	ns.httpBaseConfig = &http.Server{
		Handler:           r,
		ReadHeaderTimeout: types.HTTPTimeout,
	}
	ns.http2Server = &http2.Server{}

	ns.http2Server.ServeConn(
		noiseConn,
		&http2.ServeConnOpts{
			BaseConfig: ns.httpBaseConfig,
		},
	)
}

func unsupportedClientError(version tailcfg.CapabilityVersion) error {
	return fmt.Errorf("%w: %s (%d)", ErrUnsupportedClientVersion, capver.TailscaleVersion(version), version)
}

func (ns *noiseServer) earlyNoise(protocolVersion int, writer io.Writer) error {
	if !isSupportedVersion(tailcfg.CapabilityVersion(protocolVersion)) {
		return unsupportedClientError(tailcfg.CapabilityVersion(protocolVersion))
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
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(earlyJSON))) //nolint:gosec // JSON length is bounded
	// These writes are all buffered by caller, so fine to do them
	// separately:
	if _, err := writer.Write(notH2Frame[:]); err != nil { //nolint:noinlineerr
		return err
	}

	if _, err := writer.Write(lenBuf[:]); err != nil { //nolint:noinlineerr
		return err
	}

	if _, err := writer.Write(earlyJSON); err != nil { //nolint:noinlineerr
		return err
	}

	return nil
}

func isSupportedVersion(version tailcfg.CapabilityVersion) bool {
	return version >= capver.MinSupportedCapabilityVersion
}

func rejectUnsupported(
	writer http.ResponseWriter,
	version tailcfg.CapabilityVersion,
	mkey key.MachinePublic,
	nkey key.NodePublic,
) bool {
	// Reject unsupported versions
	if !isSupportedVersion(version) {
		log.Error().
			Caller().
			Int("minimum_cap_ver", int(capver.MinSupportedCapabilityVersion)).
			Int("client_cap_ver", int(version)).
			Str("minimum_version", capver.TailscaleVersion(capver.MinSupportedCapabilityVersion)).
			Str("client_version", capver.TailscaleVersion(version)).
			Str("node.key", nkey.ShortString()).
			Str("machine.key", mkey.ShortString()).
			Msg("unsupported client connected")
		http.Error(writer, unsupportedClientError(version).Error(), http.StatusBadRequest)

		return true
	}

	return false
}

func (ns *noiseServer) NotImplementedHandler(writer http.ResponseWriter, req *http.Request) {
	d, _ := io.ReadAll(req.Body)
	log.Trace().Caller().Str("path", req.URL.String()).Bytes("body", d).Msgf("not implemented handler hit")
	http.Error(writer, "Not implemented yet", http.StatusNotImplemented)
}

func urlParam[T any](req *http.Request, key string) (T, error) {
	var zero T

	param := chi.URLParam(req, key)
	if param == "" {
		return zero, fmt.Errorf("%w: %s", ErrMissingURLParameter, key)
	}

	var value T
	switch any(value).(type) {
	case string:
		v, ok := any(param).(T)
		if !ok {
			return zero, fmt.Errorf("%w: %T", ErrUnsupportedURLParameterType, value)
		}

		value = v
	case types.NodeID:
		id, err := types.ParseNodeID(param)
		if err != nil {
			return zero, fmt.Errorf("parsing %s: %w", key, err)
		}

		v, ok := any(id).(T)
		if !ok {
			return zero, fmt.Errorf("%w: %T", ErrUnsupportedURLParameterType, value)
		}

		value = v
	default:
		return zero, fmt.Errorf("%w: %T", ErrUnsupportedURLParameterType, value)
	}

	return value, nil
}

// SSHActionHandler handles the /ssh-action endpoint, returning a
// [tailcfg.SSHAction] to the client with the verdict of an SSH access
// request.
func (ns *noiseServer) SSHActionHandler(
	writer http.ResponseWriter,
	req *http.Request,
) {
	srcNodeID, err := urlParam[types.NodeID](req, "src_node_id")
	if err != nil {
		httpError(writer, NewHTTPError(
			http.StatusBadRequest,
			"Invalid src_node_id",
			err,
		))

		return
	}

	dstNodeID, err := urlParam[types.NodeID](req, "dst_node_id")
	if err != nil {
		httpError(writer, NewHTTPError(
			http.StatusBadRequest,
			"Invalid dst_node_id",
			err,
		))

		return
	}

	reqLog := log.With().
		Uint64("src_node_id", srcNodeID.Uint64()).
		Uint64("dst_node_id", dstNodeID.Uint64()).
		Str("ssh_user", req.URL.Query().Get("ssh_user")).
		Str("local_user", req.URL.Query().Get("local_user")).
		Logger()

	reqLog.Trace().Caller().Msg("SSH action request")

	action, err := ns.sshAction(
		reqLog,
		req.URL.Query().Get("auth_id"),
	)
	if err != nil {
		httpError(writer, err)

		return
	}

	writer.Header().Set("Content-Type", "application/json; charset=utf-8")
	writer.WriteHeader(http.StatusOK)

	err = json.NewEncoder(writer).Encode(action)
	if err != nil {
		reqLog.Error().Caller().Err(err).
			Msg("failed to encode SSH action response")

		return
	}

	if flusher, ok := writer.(http.Flusher); ok {
		flusher.Flush()
	}
}

// sshAction resolves the SSH action for the given request parameters.
// It returns the action to send to the client, or an HTTPError on
// failure.
//
// Two cases:
//  1. Initial request — build a HoldAndDelegate URL and wait for the
//     user to authenticate.
//  2. Follow-up request — an auth_id is present, wait for the auth
//     verdict and accept or reject.
func (ns *noiseServer) sshAction(
	reqLog zerolog.Logger,
	authIDStr string,
) (*tailcfg.SSHAction, error) {
	action := tailcfg.SSHAction{
		AllowAgentForwarding:      true,
		AllowLocalPortForwarding:  true,
		AllowRemotePortForwarding: true,
	}

	// Follow-up request with auth_id — wait for the auth verdict.
	if authIDStr != "" {
		return ns.sshActionFollowUp(
			reqLog, &action, authIDStr,
		)
	}

	// Initial request — create an auth session and hold.
	return ns.sshActionHoldAndDelegate(reqLog, &action)
}

// sshActionHoldAndDelegate creates a new auth session and returns a
// HoldAndDelegate action that directs the client to authenticate.
func (ns *noiseServer) sshActionHoldAndDelegate(
	reqLog zerolog.Logger,
	action *tailcfg.SSHAction,
) (*tailcfg.SSHAction, error) {
	holdURL, err := url.Parse(
		ns.headscale.cfg.ServerURL +
			"/machine/ssh/action/from/$SRC_NODE_ID/to/$DST_NODE_ID" +
			"?ssh_user=$SSH_USER&local_user=$LOCAL_USER",
	)
	if err != nil {
		return nil, NewHTTPError(
			http.StatusInternalServerError,
			"Internal error",
			fmt.Errorf("parsing SSH action URL: %w", err),
		)
	}

	authID, err := types.NewAuthID()
	if err != nil {
		return nil, NewHTTPError(
			http.StatusInternalServerError,
			"Internal error",
			fmt.Errorf("generating auth ID: %w", err),
		)
	}

	ns.headscale.state.SetAuthCacheEntry(authID, types.NewAuthRequest())

	authURL := ns.headscale.authProvider.AuthURL(authID)

	q := holdURL.Query()
	q.Set("auth_id", authID.String())
	holdURL.RawQuery = q.Encode()

	action.HoldAndDelegate = holdURL.String()

	// TODO(kradalby): here we can also send a very tiny mapresponse
	// "popping" the url and opening it for the user.
	action.Message = fmt.Sprintf(
		"# Headscale SSH requires an additional check.\n"+
			"# To authenticate, visit: %s\n"+
			"# Authentication checked with Headscale SSH.\n",
		authURL,
	)

	reqLog.Info().Caller().
		Str("auth_id", authID.String()).
		Msg("SSH check pending, waiting for auth")

	return action, nil
}

// sshActionFollowUp handles follow-up requests where the client
// provides an auth_id. It blocks until the auth session resolves.
func (ns *noiseServer) sshActionFollowUp(
	reqLog zerolog.Logger,
	action *tailcfg.SSHAction,
	authIDStr string,
) (*tailcfg.SSHAction, error) {
	authID, err := types.AuthIDFromString(authIDStr)
	if err != nil {
		return nil, NewHTTPError(
			http.StatusBadRequest,
			"Invalid auth_id",
			fmt.Errorf("parsing auth_id: %w", err),
		)
	}

	reqLog = reqLog.With().Str("auth_id", authID.String()).Logger()

	auth, ok := ns.headscale.state.GetAuthCacheEntry(authID)
	if !ok {
		return nil, NewHTTPError(
			http.StatusBadRequest,
			"Invalid auth_id",
			fmt.Errorf("%w: %s", ErrNoAuthSession, authID),
		)
	}

	reqLog.Trace().Caller().Msg("SSH action follow-up")

	verdict := <-auth.WaitForAuth()

	if !verdict.Accept() {
		action.Reject = true

		reqLog.Trace().Caller().Err(verdict.Err).
			Msg("authentication rejected")

		return action, nil
	}

	action.Accept = true

	return action, nil
}

// PollNetMapHandler takes care of /machine/:id/map using the Noise protocol
//
// This is the busiest endpoint, as it keeps the HTTP long poll that updates
// the clients when something in the network changes.
//
// The clients POST stuff like HostInfo and their Endpoints here, but
// only after their first request (marked with the ReadOnly field).
//
// At this moment the updates are sent in a quite horrendous way, but they kinda work.
func (ns *noiseServer) PollNetMapHandler(
	writer http.ResponseWriter,
	req *http.Request,
) {
	body, _ := io.ReadAll(req.Body)

	var mapRequest tailcfg.MapRequest
	if err := json.Unmarshal(body, &mapRequest); err != nil { //nolint:noinlineerr
		httpError(writer, err)
		return
	}

	// Reject unsupported versions
	if rejectUnsupported(writer, mapRequest.Version, ns.machineKey, mapRequest.NodeKey) {
		return
	}

	nv, err := ns.getAndValidateNode(mapRequest)
	if err != nil {
		httpError(writer, err)
		return
	}

	ns.nodeKey = nv.NodeKey()

	sess := ns.headscale.newMapSession(req.Context(), mapRequest, writer, nv.AsStruct())
	sess.log.Trace().Caller().Msg("a node sending a MapRequest with Noise protocol")

	if !sess.isStreaming() {
		sess.serve()
	} else {
		sess.serveLongPoll()
	}
}

func regErr(err error) *tailcfg.RegisterResponse {
	return &tailcfg.RegisterResponse{Error: err.Error()}
}

// RegistrationHandler handles the actual registration process of a node.
func (ns *noiseServer) RegistrationHandler(
	writer http.ResponseWriter,
	req *http.Request,
) {
	if req.Method != http.MethodPost {
		httpError(writer, errMethodNotAllowed)

		return
	}

	registerRequest, registerResponse := func() (*tailcfg.RegisterRequest, *tailcfg.RegisterResponse) { //nolint:contextcheck
		var resp *tailcfg.RegisterResponse

		body, err := io.ReadAll(req.Body)
		if err != nil {
			return &tailcfg.RegisterRequest{}, regErr(err)
		}

		var regReq tailcfg.RegisterRequest
		if err := json.Unmarshal(body, &regReq); err != nil { //nolint:noinlineerr
			return &regReq, regErr(err)
		}

		ns.nodeKey = regReq.NodeKey

		resp, err = ns.headscale.handleRegister(req.Context(), regReq, ns.conn.Peer())
		if err != nil {
			if httpErr, ok := errors.AsType[HTTPError](err); ok {
				resp = &tailcfg.RegisterResponse{
					Error: httpErr.Msg,
				}

				return &regReq, resp
			}

			return &regReq, regErr(err)
		}

		return &regReq, resp
	}()

	// Reject unsupported versions
	if rejectUnsupported(writer, registerRequest.Version, ns.machineKey, registerRequest.NodeKey) {
		return
	}

	writer.Header().Set("Content-Type", "application/json; charset=utf-8")
	writer.WriteHeader(http.StatusOK)

	err := json.NewEncoder(writer).Encode(registerResponse)
	if err != nil {
		log.Error().Caller().Err(err).Msg("noise registration handler: failed to encode RegisterResponse")
		return
	}

	// Ensure response is flushed to client
	if flusher, ok := writer.(http.Flusher); ok {
		flusher.Flush()
	}
}

// getAndValidateNode retrieves the node from the database using the NodeKey
// and validates that it matches the MachineKey from the Noise session.
func (ns *noiseServer) getAndValidateNode(mapRequest tailcfg.MapRequest) (types.NodeView, error) {
	nv, ok := ns.headscale.state.GetNodeByNodeKey(mapRequest.NodeKey)
	if !ok {
		return types.NodeView{}, NewHTTPError(http.StatusNotFound, "node not found", nil)
	}

	// Validate that the MachineKey in the Noise session matches the one associated with the NodeKey.
	if ns.machineKey != nv.MachineKey() {
		return types.NodeView{}, NewHTTPError(http.StatusNotFound, "node key in request does not match the one associated with this machine key", nil)
	}

	return nv, nil
}
