package hscontrol

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	_ "net/http/pprof" //nolint
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gorilla/mux"
	grpcMiddleware "github.com/grpc-ecosystem/go-grpc-middleware"
	grpcRuntime "github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/juanfont/headscale"
	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
	"github.com/juanfont/headscale/hscontrol/db"
	"github.com/juanfont/headscale/hscontrol/derp"
	derpServer "github.com/juanfont/headscale/hscontrol/derp/server"
	"github.com/juanfont/headscale/hscontrol/mapper"
	"github.com/juanfont/headscale/hscontrol/notifier"
	"github.com/juanfont/headscale/hscontrol/policy"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/patrickmn/go-cache"
	zerolog "github.com/philip-bui/grpc-zerolog"
	"github.com/pkg/profile"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	zl "github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/oauth2"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/reflection"
	"google.golang.org/grpc/status"
	"gorm.io/gorm"
	"tailscale.com/envknob"
	"tailscale.com/tailcfg"
	"tailscale.com/types/dnstype"
	"tailscale.com/types/key"
	"tailscale.com/util/dnsname"
)

var (
	errSTUNAddressNotSet                   = errors.New("STUN address not set")
	errUnsupportedLetsEncryptChallengeType = errors.New(
		"unknown value for Lets Encrypt challenge type",
	)
	errEmptyInitialDERPMap = errors.New(
		"initial DERPMap is empty, Headscale requires at least one entry",
	)
)

const (
	AuthPrefix         = "Bearer "
	updateInterval     = 5000
	privateKeyFileMode = 0o600
	headscaleDirPerm   = 0o700

	registerCacheExpiration = time.Minute * 15
	registerCacheCleanup    = time.Minute * 20
)

// func init() {
// 	deadlock.Opts.DeadlockTimeout = 15 * time.Second
// 	deadlock.Opts.PrintAllCurrentGoroutines = true
// }

// Headscale represents the base app of the service.
type Headscale struct {
	cfg             *types.Config
	db              *db.HSDatabase
	ipAlloc         *db.IPAllocator
	noisePrivateKey *key.MachinePrivate

	DERPMap    *tailcfg.DERPMap
	DERPServer *derpServer.DERPServer

	ACLPolicy *policy.ACLPolicy

	mapper       *mapper.Mapper
	nodeNotifier *notifier.Notifier

	oidcProvider *oidc.Provider
	oauth2Config *oauth2.Config

	registrationCache *cache.Cache

	pollNetMapStreamWG sync.WaitGroup

	mapSessions  map[types.NodeID]*mapSession
	mapSessionMu sync.Mutex
}

var (
	profilingEnabled = envknob.Bool("HEADSCALE_PROFILING_ENABLED")
	tailsqlEnabled   = envknob.Bool("HEADSCALE_DEBUG_TAILSQL_ENABLED")
	tailsqlStateDir  = envknob.String("HEADSCALE_DEBUG_TAILSQL_STATE_DIR")
	tailsqlTSKey     = envknob.String("TS_AUTHKEY")
)

func NewHeadscale(cfg *types.Config) (*Headscale, error) {
	var err error
	if profilingEnabled {
		runtime.SetBlockProfileRate(1)
	}

	noisePrivateKey, err := readOrCreatePrivateKey(cfg.NoisePrivateKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read or create Noise protocol private key: %w", err)
	}

	registrationCache := cache.New(
		registerCacheExpiration,
		registerCacheCleanup,
	)

	app := Headscale{
		cfg:                cfg,
		noisePrivateKey:    noisePrivateKey,
		registrationCache:  registrationCache,
		pollNetMapStreamWG: sync.WaitGroup{},
		nodeNotifier:       notifier.NewNotifier(cfg),
		mapSessions:        make(map[types.NodeID]*mapSession),
	}

	app.db, err = db.NewHeadscaleDatabase(
		cfg.Database,
		cfg.BaseDomain)
	if err != nil {
		return nil, err
	}

	app.ipAlloc, err = db.NewIPAllocator(app.db, cfg.PrefixV4, cfg.PrefixV6, cfg.IPAllocation)
	if err != nil {
		return nil, err
	}

	if cfg.OIDC.Issuer != "" {
		err = app.initOIDC()
		if err != nil {
			if cfg.OIDC.OnlyStartIfOIDCIsAvailable {
				return nil, err
			} else {
				log.Warn().Err(err).Msg("failed to set up OIDC provider, falling back to CLI based authentication")
			}
		}
	}

	if app.cfg.DNSConfig != nil && app.cfg.DNSConfig.Proxied { // if MagicDNS
		// TODO(kradalby): revisit why this takes a list.

		var magicDNSDomains []dnsname.FQDN
		if cfg.PrefixV4 != nil {
			magicDNSDomains = append(magicDNSDomains, util.GenerateIPv4DNSRootDomain(*cfg.PrefixV4)...)
		}
		if cfg.PrefixV6 != nil {
			magicDNSDomains = append(magicDNSDomains, util.GenerateIPv6DNSRootDomain(*cfg.PrefixV6)...)
		}

		// we might have routes already from Split DNS
		if app.cfg.DNSConfig.Routes == nil {
			app.cfg.DNSConfig.Routes = make(map[string][]*dnstype.Resolver)
		}
		for _, d := range magicDNSDomains {
			app.cfg.DNSConfig.Routes[d.WithoutTrailingDot()] = nil
		}
	}

	if cfg.DERP.ServerEnabled {
		derpServerKey, err := readOrCreatePrivateKey(cfg.DERP.ServerPrivateKeyPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read or create DERP server private key: %w", err)
		}

		if derpServerKey.Equal(*noisePrivateKey) {
			return nil, fmt.Errorf(
				"DERP server private key and noise private key are the same: %w",
				err,
			)
		}

		embeddedDERPServer, err := derpServer.NewDERPServer(
			cfg.ServerURL,
			key.NodePrivate(*derpServerKey),
			&cfg.DERP,
		)
		if err != nil {
			return nil, err
		}
		app.DERPServer = embeddedDERPServer
	}

	return &app, nil
}

// Redirect to our TLS url.
func (h *Headscale) redirect(w http.ResponseWriter, req *http.Request) {
	target := h.cfg.ServerURL + req.URL.RequestURI()
	http.Redirect(w, req, target, http.StatusFound)
}

// deleteExpireEphemeralNodes deletes ephemeral node records that have not been
// seen for longer than h.cfg.EphemeralNodeInactivityTimeout.
func (h *Headscale) deleteExpireEphemeralNodes(milliSeconds int64) {
	ticker := time.NewTicker(time.Duration(milliSeconds) * time.Millisecond)

	for range ticker.C {
		var removed []types.NodeID
		var changed []types.NodeID
		if err := h.db.Write(func(tx *gorm.DB) error {
			removed, changed = db.DeleteExpiredEphemeralNodes(tx, h.cfg.EphemeralNodeInactivityTimeout)

			return nil
		}); err != nil {
			log.Error().Err(err).Msg("database error while expiring ephemeral nodes")
			continue
		}

		if removed != nil {
			ctx := types.NotifyCtx(context.Background(), "expire-ephemeral", "na")
			h.nodeNotifier.NotifyAll(ctx, types.StateUpdate{
				Type:    types.StatePeerRemoved,
				Removed: removed,
			})
		}

		if changed != nil {
			ctx := types.NotifyCtx(context.Background(), "expire-ephemeral", "na")
			h.nodeNotifier.NotifyAll(ctx, types.StateUpdate{
				Type:        types.StatePeerChanged,
				ChangeNodes: changed,
			})
		}
	}
}

// expireExpiredMachines expires nodes that have an explicit expiry set
// after that expiry time has passed.
func (h *Headscale) expireExpiredMachines(intervalMs int64) {
	interval := time.Duration(intervalMs) * time.Millisecond
	ticker := time.NewTicker(interval)

	lastCheck := time.Unix(0, 0)
	var update types.StateUpdate
	var changed bool

	for range ticker.C {
		if err := h.db.Write(func(tx *gorm.DB) error {
			lastCheck, update, changed = db.ExpireExpiredNodes(tx, lastCheck)

			return nil
		}); err != nil {
			log.Error().Err(err).Msg("database error while expiring nodes")
			continue
		}

		if changed {
			log.Trace().Interface("nodes", update.ChangePatches).Msgf("expiring nodes")

			ctx := types.NotifyCtx(context.Background(), "expire-expired", "na")
			h.nodeNotifier.NotifyAll(ctx, update)
		}
	}
}

// scheduledDERPMapUpdateWorker refreshes the DERPMap stored on the global object
// at a set interval.
func (h *Headscale) scheduledDERPMapUpdateWorker(cancelChan <-chan struct{}) {
	log.Info().
		Dur("frequency", h.cfg.DERP.UpdateFrequency).
		Msg("Setting up a DERPMap update worker")
	ticker := time.NewTicker(h.cfg.DERP.UpdateFrequency)

	for {
		select {
		case <-cancelChan:
			return

		case <-ticker.C:
			log.Info().Msg("Fetching DERPMap updates")
			h.DERPMap = derp.GetDERPMap(h.cfg.DERP)
			if h.cfg.DERP.ServerEnabled && h.cfg.DERP.AutomaticallyAddEmbeddedDerpRegion {
				region, _ := h.DERPServer.GenerateRegion()
				h.DERPMap.Regions[region.RegionID] = &region
			}

			ctx := types.NotifyCtx(context.Background(), "derpmap-update", "na")
			h.nodeNotifier.NotifyAll(ctx, types.StateUpdate{
				Type:    types.StateDERPUpdated,
				DERPMap: h.DERPMap,
			})
		}
	}
}

func (h *Headscale) grpcAuthenticationInterceptor(ctx context.Context,
	req interface{},
	info *grpc.UnaryServerInfo,
	handler grpc.UnaryHandler,
) (interface{}, error) {
	// Check if the request is coming from the on-server client.
	// This is not secure, but it is to maintain maintainability
	// with the "legacy" database-based client
	// It is also neede for grpc-gateway to be able to connect to
	// the server
	client, _ := peer.FromContext(ctx)

	log.Trace().
		Caller().
		Str("client_address", client.Addr.String()).
		Msg("Client is trying to authenticate")

	meta, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return ctx, status.Errorf(
			codes.InvalidArgument,
			"Retrieving metadata is failed",
		)
	}

	authHeader, ok := meta["authorization"]
	if !ok {
		return ctx, status.Errorf(
			codes.Unauthenticated,
			"Authorization token is not supplied",
		)
	}

	token := authHeader[0]

	if !strings.HasPrefix(token, AuthPrefix) {
		return ctx, status.Error(
			codes.Unauthenticated,
			`missing "Bearer " prefix in "Authorization" header`,
		)
	}

	valid, err := h.db.ValidateAPIKey(strings.TrimPrefix(token, AuthPrefix))
	if err != nil {
		return ctx, status.Error(codes.Internal, "failed to validate token")
	}

	if !valid {
		log.Info().
			Str("client_address", client.Addr.String()).
			Msg("invalid token")

		return ctx, status.Error(codes.Unauthenticated, "invalid token")
	}

	return handler(ctx, req)
}

func (h *Headscale) httpAuthenticationMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(
		writer http.ResponseWriter,
		req *http.Request,
	) {
		log.Trace().
			Caller().
			Str("client_address", req.RemoteAddr).
			Msg("HTTP authentication invoked")

		authHeader := req.Header.Get("authorization")

		if !strings.HasPrefix(authHeader, AuthPrefix) {
			log.Error().
				Caller().
				Str("client_address", req.RemoteAddr).
				Msg(`missing "Bearer " prefix in "Authorization" header`)
			writer.WriteHeader(http.StatusUnauthorized)
			_, err := writer.Write([]byte("Unauthorized"))
			if err != nil {
				log.Error().
					Caller().
					Err(err).
					Msg("Failed to write response")
			}

			return
		}

		valid, err := h.db.ValidateAPIKey(strings.TrimPrefix(authHeader, AuthPrefix))
		if err != nil {
			log.Error().
				Caller().
				Err(err).
				Str("client_address", req.RemoteAddr).
				Msg("failed to validate token")

			writer.WriteHeader(http.StatusInternalServerError)
			_, err := writer.Write([]byte("Unauthorized"))
			if err != nil {
				log.Error().
					Caller().
					Err(err).
					Msg("Failed to write response")
			}

			return
		}

		if !valid {
			log.Info().
				Str("client_address", req.RemoteAddr).
				Msg("invalid token")

			writer.WriteHeader(http.StatusUnauthorized)
			_, err := writer.Write([]byte("Unauthorized"))
			if err != nil {
				log.Error().
					Caller().
					Err(err).
					Msg("Failed to write response")
			}

			return
		}

		next.ServeHTTP(writer, req)
	})
}

// ensureUnixSocketIsAbsent will check if the given path for headscales unix socket is clear
// and will remove it if it is not.
func (h *Headscale) ensureUnixSocketIsAbsent() error {
	// File does not exist, all fine
	if _, err := os.Stat(h.cfg.UnixSocket); errors.Is(err, os.ErrNotExist) {
		return nil
	}

	return os.Remove(h.cfg.UnixSocket)
}

func (h *Headscale) createRouter(grpcMux *grpcRuntime.ServeMux) *mux.Router {
	router := mux.NewRouter()
	router.Use(prometheusMiddleware)

	router.HandleFunc(ts2021UpgradePath, h.NoiseUpgradeHandler).Methods(http.MethodPost)

	router.HandleFunc("/health", h.HealthHandler).Methods(http.MethodGet)
	router.HandleFunc("/key", h.KeyHandler).Methods(http.MethodGet)
	router.HandleFunc("/register/{mkey}", h.RegisterWebAPI).Methods(http.MethodGet)

	router.HandleFunc("/oidc/register/{mkey}", h.RegisterOIDC).Methods(http.MethodGet)
	router.HandleFunc("/oidc/callback", h.OIDCCallback).Methods(http.MethodGet)
	router.HandleFunc("/apple", h.AppleConfigMessage).Methods(http.MethodGet)
	router.HandleFunc("/apple/{platform}", h.ApplePlatformConfig).
		Methods(http.MethodGet)
	router.HandleFunc("/windows", h.WindowsConfigMessage).Methods(http.MethodGet)
	router.HandleFunc("/windows/tailscale.reg", h.WindowsRegConfig).
		Methods(http.MethodGet)

	// TODO(kristoffer): move swagger into a package
	router.HandleFunc("/swagger", headscale.SwaggerUI).Methods(http.MethodGet)
	router.HandleFunc("/swagger/v1/openapiv2.json", headscale.SwaggerAPIv1).
		Methods(http.MethodGet)

	if h.cfg.DERP.ServerEnabled {
		router.HandleFunc("/derp", h.DERPServer.DERPHandler)
		router.HandleFunc("/derp/probe", derpServer.DERPProbeHandler)
		router.HandleFunc("/bootstrap-dns", derpServer.DERPBootstrapDNSHandler(h.DERPMap))
	}

	apiRouter := router.PathPrefix("/api").Subrouter()
	apiRouter.Use(h.httpAuthenticationMiddleware)
	apiRouter.PathPrefix("/v1/").HandlerFunc(grpcMux.ServeHTTP)

	router.PathPrefix("/").HandlerFunc(notFoundHandler)

	return router
}

// Serve launches the HTTP and gRPC server service Headscale and the API.
func (h *Headscale) Serve() error {
	if _, enableProfile := os.LookupEnv("HEADSCALE_PROFILING_ENABLED"); enableProfile {
		if profilePath, ok := os.LookupEnv("HEADSCALE_PROFILING_PATH"); ok {
			err := os.MkdirAll(profilePath, os.ModePerm)
			if err != nil {
				log.Fatal().Err(err).Msg("failed to create profiling directory")
			}

			defer profile.Start(profile.ProfilePath(profilePath)).Stop()
		} else {
			defer profile.Start().Stop()
		}
	}

	var err error

	// Fetch an initial DERP Map before we start serving
	h.DERPMap = derp.GetDERPMap(h.cfg.DERP)
	h.mapper = mapper.NewMapper(h.db, h.cfg, h.DERPMap, h.nodeNotifier)

	if h.cfg.DERP.ServerEnabled {
		// When embedded DERP is enabled we always need a STUN server
		if h.cfg.DERP.STUNAddr == "" {
			return errSTUNAddressNotSet
		}

		region, err := h.DERPServer.GenerateRegion()
		if err != nil {
			return fmt.Errorf("generating DERP region for embedded server: %w", err)
		}

		if h.cfg.DERP.AutomaticallyAddEmbeddedDerpRegion {
			h.DERPMap.Regions[region.RegionID] = &region
		}

		go h.DERPServer.ServeSTUN()
	}

	if h.cfg.DERP.AutoUpdate {
		derpMapCancelChannel := make(chan struct{})
		defer func() { derpMapCancelChannel <- struct{}{} }()
		go h.scheduledDERPMapUpdateWorker(derpMapCancelChannel)
	}

	if len(h.DERPMap.Regions) == 0 {
		return errEmptyInitialDERPMap
	}

	// TODO(kradalby): These should have cancel channels and be cleaned
	// up on shutdown.
	go h.deleteExpireEphemeralNodes(updateInterval)
	go h.expireExpiredMachines(updateInterval)

	if zl.GlobalLevel() == zl.TraceLevel {
		zerolog.RespLog = true
	} else {
		zerolog.RespLog = false
	}

	// Prepare group for running listeners
	errorGroup := new(errgroup.Group)

	ctx := context.Background()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	//
	//
	// Set up LOCAL listeners
	//

	err = h.ensureUnixSocketIsAbsent()
	if err != nil {
		return fmt.Errorf("unable to remove old socket file: %w", err)
	}

	socketDir := filepath.Dir(h.cfg.UnixSocket)
	err = util.EnsureDir(socketDir)
	if err != nil {
		return fmt.Errorf("setting up unix socket: %w", err)
	}

	socketListener, err := net.Listen("unix", h.cfg.UnixSocket)
	if err != nil {
		return fmt.Errorf("failed to set up gRPC socket: %w", err)
	}

	// Change socket permissions
	if err := os.Chmod(h.cfg.UnixSocket, h.cfg.UnixSocketPermission); err != nil {
		return fmt.Errorf("failed change permission of gRPC socket: %w", err)
	}

	grpcGatewayMux := grpcRuntime.NewServeMux()

	// Make the grpc-gateway connect to grpc over socket
	grpcGatewayConn, err := grpc.Dial(
		h.cfg.UnixSocket,
		[]grpc.DialOption{
			grpc.WithTransportCredentials(insecure.NewCredentials()),
			grpc.WithContextDialer(util.GrpcSocketDialer),
		}...,
	)
	if err != nil {
		return fmt.Errorf("setting up gRPC gateway via socket: %w", err)
	}

	// Connect to the gRPC server over localhost to skip
	// the authentication.
	err = v1.RegisterHeadscaleServiceHandler(ctx, grpcGatewayMux, grpcGatewayConn)
	if err != nil {
		return fmt.Errorf("registering Headscale API service to gRPC: %w", err)
	}

	// Start the local gRPC server without TLS and without authentication
	grpcSocket := grpc.NewServer(
	// Uncomment to debug grpc communication.
	// zerolog.UnaryInterceptor(),
	)

	v1.RegisterHeadscaleServiceServer(grpcSocket, newHeadscaleV1APIServer(h))
	reflection.Register(grpcSocket)

	errorGroup.Go(func() error { return grpcSocket.Serve(socketListener) })

	//
	//
	// Set up REMOTE listeners
	//

	tlsConfig, err := h.getTLSSettings()
	if err != nil {
		return fmt.Errorf("configuring TLS settings: %w", err)
	}

	//
	//
	// gRPC setup
	//

	// We are sadly not able to run gRPC and HTTPS (2.0) on the same
	// port because the connection mux does not support matching them
	// since they are so similar. There is multiple issues open and we
	// can revisit this if changes:
	// https://github.com/soheilhy/cmux/issues/68
	// https://github.com/soheilhy/cmux/issues/91

	var grpcServer *grpc.Server
	var grpcListener net.Listener
	if tlsConfig != nil || h.cfg.GRPCAllowInsecure {
		log.Info().Msgf("Enabling remote gRPC at %s", h.cfg.GRPCAddr)

		grpcOptions := []grpc.ServerOption{
			grpc.UnaryInterceptor(
				grpcMiddleware.ChainUnaryServer(
					h.grpcAuthenticationInterceptor,
					// Uncomment to debug grpc communication.
					// zerolog.NewUnaryServerInterceptor(),
				),
			),
		}

		if tlsConfig != nil {
			grpcOptions = append(grpcOptions,
				grpc.Creds(credentials.NewTLS(tlsConfig)),
			)
		} else {
			log.Warn().Msg("gRPC is running without security")
		}

		grpcServer = grpc.NewServer(grpcOptions...)

		v1.RegisterHeadscaleServiceServer(grpcServer, newHeadscaleV1APIServer(h))
		reflection.Register(grpcServer)

		grpcListener, err = net.Listen("tcp", h.cfg.GRPCAddr)
		if err != nil {
			return fmt.Errorf("failed to bind to TCP address: %w", err)
		}

		errorGroup.Go(func() error { return grpcServer.Serve(grpcListener) })

		log.Info().
			Msgf("listening and serving gRPC on: %s", h.cfg.GRPCAddr)
	}

	//
	//
	// HTTP setup
	//
	// This is the regular router that we expose
	// over our main Addr
	router := h.createRouter(grpcGatewayMux)

	httpServer := &http.Server{
		Addr:        h.cfg.Addr,
		Handler:     router,
		ReadTimeout: types.HTTPTimeout,

		// Long polling should not have any timeout, this is overriden
		// further down the chain
		WriteTimeout: types.HTTPTimeout,
	}

	var httpListener net.Listener
	if tlsConfig != nil {
		httpServer.TLSConfig = tlsConfig
		httpListener, err = tls.Listen("tcp", h.cfg.Addr, tlsConfig)
	} else {
		httpListener, err = net.Listen("tcp", h.cfg.Addr)
	}
	if err != nil {
		return fmt.Errorf("failed to bind to TCP address: %w", err)
	}

	errorGroup.Go(func() error { return httpServer.Serve(httpListener) })

	log.Info().
		Msgf("listening and serving HTTP on: %s", h.cfg.Addr)

	debugMux := http.NewServeMux()
	debugMux.Handle("/debug/pprof/", http.DefaultServeMux)
	debugMux.HandleFunc("/debug/notifier", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(h.nodeNotifier.String()))
	})
	debugMux.HandleFunc("/debug/mapresp", func(w http.ResponseWriter, r *http.Request) {
		h.mapSessionMu.Lock()
		defer h.mapSessionMu.Unlock()

		var b strings.Builder
		b.WriteString("mapresponders:\n")
		for k, v := range h.mapSessions {
			fmt.Fprintf(&b, "\t%d: %p\n", k, v)
		}

		w.WriteHeader(http.StatusOK)
		w.Write([]byte(b.String()))
	})
	debugMux.Handle("/metrics", promhttp.Handler())

	debugHTTPServer := &http.Server{
		Addr:         h.cfg.MetricsAddr,
		Handler:      debugMux,
		ReadTimeout:  types.HTTPTimeout,
		WriteTimeout: 0,
	}

	debugHTTPListener, err := net.Listen("tcp", h.cfg.MetricsAddr)
	if err != nil {
		return fmt.Errorf("failed to bind to TCP address: %w", err)
	}

	errorGroup.Go(func() error { return debugHTTPServer.Serve(debugHTTPListener) })

	log.Info().
		Msgf("listening and serving debug and metrics on: %s", h.cfg.MetricsAddr)

	var tailsqlContext context.Context
	if tailsqlEnabled {
		if h.cfg.Database.Type != types.DatabaseSqlite {
			log.Fatal().
				Str("type", h.cfg.Database.Type).
				Msgf("tailsql only support %q", types.DatabaseSqlite)
		}
		if tailsqlTSKey == "" {
			log.Fatal().Msg("tailsql requires TS_AUTHKEY to be set")
		}
		tailsqlContext = context.Background()
		go runTailSQLService(ctx, util.TSLogfWrapper(), tailsqlStateDir, h.cfg.Database.Sqlite.Path)
	}

	// Handle common process-killing signals so we can gracefully shut down:
	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc,
		syscall.SIGHUP,
		syscall.SIGINT,
		syscall.SIGTERM,
		syscall.SIGQUIT,
		syscall.SIGHUP)
	sigFunc := func(c chan os.Signal) {
		// Wait for a SIGINT or SIGKILL:
		for {
			sig := <-c
			switch sig {
			case syscall.SIGHUP:
				log.Info().
					Str("signal", sig.String()).
					Msg("Received SIGHUP, reloading ACL and Config")

				// TODO(kradalby): Reload config on SIGHUP

				if h.cfg.ACL.PolicyPath != "" {
					aclPath := util.AbsolutePathFromConfigPath(h.cfg.ACL.PolicyPath)
					pol, err := policy.LoadACLPolicyFromPath(aclPath)
					if err != nil {
						log.Error().Err(err).Msg("Failed to reload ACL policy")
					}

					h.ACLPolicy = pol
					log.Info().
						Str("path", aclPath).
						Msg("ACL policy successfully reloaded, notifying nodes of change")

					ctx := types.NotifyCtx(context.Background(), "acl-sighup", "na")
					h.nodeNotifier.NotifyAll(ctx, types.StateUpdate{
						Type: types.StateFullUpdate,
					})
				}

			default:
				trace := log.Trace().Msgf
				log.Info().
					Str("signal", sig.String()).
					Msg("Received signal to stop, shutting down gracefully")

				trace("closing map sessions")
				wg := sync.WaitGroup{}
				for _, mapSess := range h.mapSessions {
					wg.Add(1)
					go func() {
						mapSess.close()
						wg.Done()
					}()
				}
				wg.Wait()

				trace("waiting for netmap stream to close")
				h.pollNetMapStreamWG.Wait()

				// Gracefully shut down servers
				ctx, cancel := context.WithTimeout(
					context.Background(),
					types.HTTPShutdownTimeout,
				)
				trace("shutting down debug http server")
				if err := debugHTTPServer.Shutdown(ctx); err != nil {
					log.Error().Err(err).Msg("Failed to shutdown prometheus http")
				}
				trace("shutting down main http server")
				if err := httpServer.Shutdown(ctx); err != nil {
					log.Error().Err(err).Msg("Failed to shutdown http")
				}

				trace("shutting down grpc server (socket)")
				grpcSocket.GracefulStop()

				if grpcServer != nil {
					trace("shutting down grpc server (external)")
					grpcServer.GracefulStop()
					grpcListener.Close()
				}

				if tailsqlContext != nil {
					trace("shutting down tailsql")
					tailsqlContext.Done()
				}

				trace("closing node notifier")
				h.nodeNotifier.Close()

				// Close network listeners
				trace("closing network listeners")
				debugHTTPListener.Close()
				httpListener.Close()
				grpcGatewayConn.Close()

				// Stop listening (and unlink the socket if unix type):
				trace("closing socket listener")
				socketListener.Close()

				// Close db connections
				trace("closing database connection")
				err = h.db.Close()
				if err != nil {
					log.Error().Err(err).Msg("Failed to close db")
				}

				log.Info().
					Msg("Headscale stopped")

				// And we're done:
				cancel()

				return
			}
		}
	}
	errorGroup.Go(func() error {
		sigFunc(sigc)

		return nil
	})

	return errorGroup.Wait()
}

func (h *Headscale) getTLSSettings() (*tls.Config, error) {
	var err error
	if h.cfg.TLS.LetsEncrypt.Hostname != "" {
		if !strings.HasPrefix(h.cfg.ServerURL, "https://") {
			log.Warn().
				Msg("Listening with TLS but ServerURL does not start with https://")
		}

		certManager := autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(h.cfg.TLS.LetsEncrypt.Hostname),
			Cache:      autocert.DirCache(h.cfg.TLS.LetsEncrypt.CacheDir),
			Client: &acme.Client{
				DirectoryURL: h.cfg.ACMEURL,
			},
			Email: h.cfg.ACMEEmail,
		}

		switch h.cfg.TLS.LetsEncrypt.ChallengeType {
		case types.TLSALPN01ChallengeType:
			// Configuration via autocert with TLS-ALPN-01 (https://tools.ietf.org/html/rfc8737)
			// The RFC requires that the validation is done on port 443; in other words, headscale
			// must be reachable on port 443.
			return certManager.TLSConfig(), nil

		case types.HTTP01ChallengeType:
			// Configuration via autocert with HTTP-01. This requires listening on
			// port 80 for the certificate validation in addition to the headscale
			// service, which can be configured to run on any other port.

			server := &http.Server{
				Addr:        h.cfg.TLS.LetsEncrypt.Listen,
				Handler:     certManager.HTTPHandler(http.HandlerFunc(h.redirect)),
				ReadTimeout: types.HTTPTimeout,
			}

			go func() {
				err := server.ListenAndServe()
				log.Fatal().
					Caller().
					Err(err).
					Msg("failed to set up a HTTP server")
			}()

			return certManager.TLSConfig(), nil

		default:
			return nil, errUnsupportedLetsEncryptChallengeType
		}
	} else if h.cfg.TLS.CertPath == "" {
		if !strings.HasPrefix(h.cfg.ServerURL, "http://") {
			log.Warn().Msg("Listening without TLS but ServerURL does not start with http://")
		}

		return nil, err
	} else {
		if !strings.HasPrefix(h.cfg.ServerURL, "https://") {
			log.Warn().Msg("Listening with TLS but ServerURL does not start with https://")
		}

		tlsConfig := &tls.Config{
			NextProtos:   []string{"http/1.1"},
			Certificates: make([]tls.Certificate, 1),
			MinVersion:   tls.VersionTLS12,
		}

		tlsConfig.Certificates[0], err = tls.LoadX509KeyPair(h.cfg.TLS.CertPath, h.cfg.TLS.KeyPath)

		return tlsConfig, err
	}
}

func notFoundHandler(
	writer http.ResponseWriter,
	req *http.Request,
) {
	body, _ := io.ReadAll(req.Body)

	log.Trace().
		Interface("header", req.Header).
		Interface("proto", req.Proto).
		Interface("url", req.URL).
		Bytes("body", body).
		Msg("Request did not match")
	writer.WriteHeader(http.StatusNotFound)
}

func readOrCreatePrivateKey(path string) (*key.MachinePrivate, error) {
	dir := filepath.Dir(path)
	err := util.EnsureDir(dir)
	if err != nil {
		return nil, fmt.Errorf("ensuring private key directory: %w", err)
	}

	privateKey, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		log.Info().Str("path", path).Msg("No private key file at path, creating...")

		machineKey := key.NewMachine()

		machineKeyStr, err := machineKey.MarshalText()
		if err != nil {
			return nil, fmt.Errorf(
				"failed to convert private key to string for saving: %w",
				err,
			)
		}
		err = os.WriteFile(path, machineKeyStr, privateKeyFileMode)
		if err != nil {
			return nil, fmt.Errorf(
				"failed to save private key to disk at path %q: %w",
				path,
				err,
			)
		}

		return &machineKey, nil
	} else if err != nil {
		return nil, fmt.Errorf("failed to read private key file: %w", err)
	}

	trimmedPrivateKey := strings.TrimSpace(string(privateKey))

	var machineKey key.MachinePrivate
	if err = machineKey.UnmarshalText([]byte(trimmedPrivateKey)); err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	return &machineKey, nil
}
