package headscale

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gin-gonic/gin"
	"github.com/gorilla/mux"
	grpc_middleware "github.com/grpc-ecosystem/go-grpc-middleware"
	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
	"github.com/patrickmn/go-cache"
	zerolog "github.com/philip-bui/grpc-zerolog"
	"github.com/puzpuzpuz/xsync"
	zl "github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	ginprometheus "github.com/zsais/go-gin-prometheus"
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
	"tailscale.com/tailcfg"
	"tailscale.com/types/dnstype"
	"tailscale.com/types/key"
)

const (
	errSTUNAddressNotSet                   = Error("STUN address not set")
	errUnsupportedDatabase                 = Error("unsupported DB")
	errUnsupportedLetsEncryptChallengeType = Error(
		"unknown value for Lets Encrypt challenge type",
	)
)

const (
	AuthPrefix          = "Bearer "
	Postgres            = "postgres"
	Sqlite              = "sqlite3"
	updateInterval      = 5000
	HTTPReadTimeout     = 30 * time.Second
	HTTPShutdownTimeout = 3 * time.Second
	privateKeyFileMode  = 0o600

	registerCacheExpiration = time.Minute * 15
	registerCacheCleanup    = time.Minute * 20

	DisabledClientAuth = "disabled"
	RelaxedClientAuth  = "relaxed"
	EnforcedClientAuth = "enforced"
)

// Headscale represents the base app of the service.
type Headscale struct {
	cfg        *Config
	db         *gorm.DB
	dbString   string
	dbType     string
	dbDebug    bool
	privateKey *key.MachinePrivate

	DERPMap    *tailcfg.DERPMap
	DERPServer *DERPServer

	aclPolicy *ACLPolicy
	aclRules  []tailcfg.FilterRule

	lastStateChange *xsync.MapOf[time.Time]

	oidcProvider *oidc.Provider
	oauth2Config *oauth2.Config

	registrationCache *cache.Cache

	ipAllocationMutex sync.Mutex

	shutdownChan chan struct{}
}

// Look up the TLS constant relative to user-supplied TLS client
// authentication mode. If an unknown mode is supplied, the default
// value, tls.RequireAnyClientCert, is returned. The returned boolean
// indicates if the supplied mode was valid.
func LookupTLSClientAuthMode(mode string) (tls.ClientAuthType, bool) {
	switch mode {
	case DisabledClientAuth:
		// Client cert is _not_ required.
		return tls.NoClientCert, true
	case RelaxedClientAuth:
		// Client cert required, but _not verified_.
		return tls.RequireAnyClientCert, true
	case EnforcedClientAuth:
		// Client cert is _required and verified_.
		return tls.RequireAndVerifyClientCert, true
	default:
		// Return the default when an unknown value is supplied.
		return tls.RequireAnyClientCert, false
	}
}

func NewHeadscale(cfg *Config) (*Headscale, error) {
	privKey, err := readOrCreatePrivateKey(cfg.PrivateKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read or create private key: %w", err)
	}

	var dbString string
	switch cfg.DBtype {
	case Postgres:
		dbString = fmt.Sprintf(
			"host=%s port=%d dbname=%s user=%s password=%s sslmode=disable",
			cfg.DBhost,
			cfg.DBport,
			cfg.DBname,
			cfg.DBuser,
			cfg.DBpass,
		)
	case Sqlite:
		dbString = cfg.DBpath
	default:
		return nil, errUnsupportedDatabase
	}

	registrationCache := cache.New(
		registerCacheExpiration,
		registerCacheCleanup,
	)

	app := Headscale{
		cfg:               cfg,
		dbType:            cfg.DBtype,
		dbString:          dbString,
		privateKey:        privKey,
		aclRules:          tailcfg.FilterAllowAll, // default allowall
		registrationCache: registrationCache,
	}

	err = app.initDB()
	if err != nil {
		return nil, err
	}

	if cfg.OIDC.Issuer != "" {
		err = app.initOIDC()
		if err != nil {
			return nil, err
		}
	}

	if app.cfg.DNSConfig != nil && app.cfg.DNSConfig.Proxied { // if MagicDNS
		magicDNSDomains := generateMagicDNSRootDomains(app.cfg.IPPrefixes)
		// we might have routes already from Split DNS
		if app.cfg.DNSConfig.Routes == nil {
			app.cfg.DNSConfig.Routes = make(map[string][]*dnstype.Resolver)
		}
		for _, d := range magicDNSDomains {
			app.cfg.DNSConfig.Routes[d.WithoutTrailingDot()] = nil
		}
	}

	if cfg.DERP.ServerEnabled {
		embeddedDERPServer, err := app.NewDERPServer()
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

// expireEphemeralNodes deletes ephemeral machine records that have not been
// seen for longer than h.cfg.EphemeralNodeInactivityTimeout.
func (h *Headscale) expireEphemeralNodes(milliSeconds int64) {
	ticker := time.NewTicker(time.Duration(milliSeconds) * time.Millisecond)
	for range ticker.C {
		h.expireEphemeralNodesWorker()
	}
}

func (h *Headscale) expireEphemeralNodesWorker() {
	namespaces, err := h.ListNamespaces()
	if err != nil {
		log.Error().Err(err).Msg("Error listing namespaces")

		return
	}

	for _, namespace := range namespaces {
		machines, err := h.ListMachinesInNamespace(namespace.Name)
		if err != nil {
			log.Error().
				Err(err).
				Str("namespace", namespace.Name).
				Msg("Error listing machines in namespace")

			return
		}

		expiredFound := false
		for _, machine := range machines {
			if machine.AuthKey != nil && machine.LastSeen != nil &&
				machine.AuthKey.Ephemeral &&
				time.Now().
					After(machine.LastSeen.Add(h.cfg.EphemeralNodeInactivityTimeout)) {
				expiredFound = true
				log.Info().
					Str("machine", machine.Hostname).
					Msg("Ephemeral client removed from database")

				err = h.db.Unscoped().Delete(machine).Error
				if err != nil {
					log.Error().
						Err(err).
						Str("machine", machine.Hostname).
						Msg("🤮 Cannot delete ephemeral machine from the database")
				}
			}
		}

		if expiredFound {
			h.setLastStateChangeToNow(namespace.Name)
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
		log.Error().
			Caller().
			Str("client_address", client.Addr.String()).
			Msg("Retrieving metadata is failed")

		return ctx, status.Errorf(
			codes.InvalidArgument,
			"Retrieving metadata is failed",
		)
	}

	authHeader, ok := meta["authorization"]
	if !ok {
		log.Error().
			Caller().
			Str("client_address", client.Addr.String()).
			Msg("Authorization token is not supplied")

		return ctx, status.Errorf(
			codes.Unauthenticated,
			"Authorization token is not supplied",
		)
	}

	token := authHeader[0]

	if !strings.HasPrefix(token, AuthPrefix) {
		log.Error().
			Caller().
			Str("client_address", client.Addr.String()).
			Msg(`missing "Bearer " prefix in "Authorization" header`)

		return ctx, status.Error(
			codes.Unauthenticated,
			`missing "Bearer " prefix in "Authorization" header`,
		)
	}

	valid, err := h.ValidateAPIKey(strings.TrimPrefix(token, AuthPrefix))
	if err != nil {
		log.Error().
			Caller().
			Err(err).
			Str("client_address", client.Addr.String()).
			Msg("failed to validate token")

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

		valid, err := h.ValidateAPIKey(strings.TrimPrefix(authHeader, AuthPrefix))
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

func (h *Headscale) createPrometheusRouter() *gin.Engine {
	promRouter := gin.Default()

	prometheus := ginprometheus.NewPrometheus("gin")
	prometheus.Use(promRouter)

	return promRouter
}

func (h *Headscale) createRouter(grpcMux *runtime.ServeMux) *mux.Router {
	router := mux.NewRouter()

	router.HandleFunc(
		"/health",
		func(writer http.ResponseWriter, req *http.Request) {
			writer.WriteHeader(http.StatusOK)
			_, err := writer.Write([]byte("{\"healthy\": \"ok\"}"))
			if err != nil {
				log.Error().
					Caller().
					Err(err).
					Msg("Failed to write response")
			}
		}).Methods(http.MethodGet)

	router.HandleFunc("/key", h.KeyHandler).Methods(http.MethodGet)
	router.HandleFunc("/register", h.RegisterWebAPI).Methods(http.MethodGet)
	router.HandleFunc("/machine/{mkey}/map", h.PollNetMapHandler).Methods(http.MethodPost)
	router.HandleFunc("/machine/{mkey}", h.RegistrationHandler).Methods(http.MethodPost)
	router.HandleFunc("/oidc/register/{mkey}", h.RegisterOIDC).Methods(http.MethodGet)
	router.HandleFunc("/oidc/callback", h.OIDCCallback).Methods(http.MethodGet)
	router.HandleFunc("/apple", h.AppleConfigMessage).Methods(http.MethodGet)
	router.HandleFunc("/apple/{platform}", h.ApplePlatformConfig).Methods(http.MethodGet)
	router.HandleFunc("/windows", h.WindowsConfigMessage).Methods(http.MethodGet)
	router.HandleFunc("/windows/tailscale.reg", h.WindowsRegConfig).Methods(http.MethodGet)
	router.HandleFunc("/swagger", SwaggerUI).Methods(http.MethodGet)
	router.HandleFunc("/swagger/v1/openapiv2.json", SwaggerAPIv1).Methods(http.MethodGet)

	if h.cfg.DERP.ServerEnabled {
		router.HandleFunc("/derp", h.DERPHandler)
		router.HandleFunc("/derp/probe", h.DERPProbeHandler)
		router.HandleFunc("/bootstrap-dns", h.DERPBootstrapDNSHandler)
	}

	api := router.PathPrefix("/api").Subrouter()
	api.Use(h.httpAuthenticationMiddleware)
	{
		api.HandleFunc("/v1/*any", grpcMux.ServeHTTP)
	}

	router.PathPrefix("/").HandlerFunc(stdoutHandler)

	return router
}

// Serve launches a GIN server with the Headscale API.
func (h *Headscale) Serve() error {
	var err error

	// Fetch an initial DERP Map before we start serving
	h.DERPMap = GetDERPMap(h.cfg.DERP)

	if h.cfg.DERP.ServerEnabled {
		// When embedded DERP is enabled we always need a STUN server
		if h.cfg.DERP.STUNAddr == "" {
			return errSTUNAddressNotSet
		}

		h.DERPMap.Regions[h.DERPServer.region.RegionID] = &h.DERPServer.region
		go h.ServeSTUN()
	}

	if h.cfg.DERP.AutoUpdate {
		derpMapCancelChannel := make(chan struct{})
		defer func() { derpMapCancelChannel <- struct{}{} }()
		go h.scheduledDERPMapUpdateWorker(derpMapCancelChannel)
	}

	go h.expireEphemeralNodes(updateInterval)

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

	socketListener, err := net.Listen("unix", h.cfg.UnixSocket)
	if err != nil {
		return fmt.Errorf("failed to set up gRPC socket: %w", err)
	}

	// Change socket permissions
	if err := os.Chmod(h.cfg.UnixSocket, h.cfg.UnixSocketPermission); err != nil {
		return fmt.Errorf("failed change permission of gRPC socket: %w", err)
	}

	grpcGatewayMux := runtime.NewServeMux()

	// Make the grpc-gateway connect to grpc over socket
	grpcGatewayConn, err := grpc.Dial(
		h.cfg.UnixSocket,
		[]grpc.DialOption{
			grpc.WithTransportCredentials(insecure.NewCredentials()),
			grpc.WithContextDialer(GrpcSocketDialer),
		}...,
	)
	if err != nil {
		return err
	}

	// Connect to the gRPC server over localhost to skip
	// the authentication.
	err = v1.RegisterHeadscaleServiceHandler(ctx, grpcGatewayMux, grpcGatewayConn)
	if err != nil {
		return err
	}

	// Start the local gRPC server without TLS and without authentication
	grpcSocket := grpc.NewServer(zerolog.UnaryInterceptor())

	v1.RegisterHeadscaleServiceServer(grpcSocket, newHeadscaleV1APIServer(h))
	reflection.Register(grpcSocket)

	errorGroup.Go(func() error { return grpcSocket.Serve(socketListener) })

	//
	//
	// Set up REMOTE listeners
	//

	tlsConfig, err := h.getTLSSettings()
	if err != nil {
		log.Error().Err(err).Msg("Failed to set up TLS configuration")

		return err
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

	if tlsConfig != nil || h.cfg.GRPCAllowInsecure {
		log.Info().Msgf("Enabling remote gRPC at %s", h.cfg.GRPCAddr)

		grpcOptions := []grpc.ServerOption{
			grpc.UnaryInterceptor(
				grpc_middleware.ChainUnaryServer(
					h.grpcAuthenticationInterceptor,
					zerolog.NewUnaryServerInterceptor(),
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

		grpcServer := grpc.NewServer(grpcOptions...)

		v1.RegisterHeadscaleServiceServer(grpcServer, newHeadscaleV1APIServer(h))
		reflection.Register(grpcServer)

		grpcListener, err := net.Listen("tcp", h.cfg.GRPCAddr)
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

	router := h.createRouter(grpcGatewayMux)

	httpServer := &http.Server{
		Addr:        h.cfg.Addr,
		Handler:     router,
		ReadTimeout: HTTPReadTimeout,
		// Go does not handle timeouts in HTTP very well, and there is
		// no good way to handle streaming timeouts, therefore we need to
		// keep this at unlimited and be careful to clean up connections
		// https://blog.cloudflare.com/the-complete-guide-to-golang-net-http-timeouts/#aboutstreaming
		WriteTimeout: 0,
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

	promRouter := h.createPrometheusRouter()

	promHTTPServer := &http.Server{
		Addr:         h.cfg.MetricsAddr,
		Handler:      promRouter,
		ReadTimeout:  HTTPReadTimeout,
		WriteTimeout: 0,
	}

	var promHTTPListener net.Listener
	promHTTPListener, err = net.Listen("tcp", h.cfg.MetricsAddr)

	if err != nil {
		return fmt.Errorf("failed to bind to TCP address: %w", err)
	}

	errorGroup.Go(func() error { return promHTTPServer.Serve(promHTTPListener) })

	log.Info().
		Msgf("listening and serving metrics on: %s", h.cfg.MetricsAddr)

	// Handle common process-killing signals so we can gracefully shut down:
	h.shutdownChan = make(chan struct{})
	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc,
		syscall.SIGHUP,
		syscall.SIGINT,
		syscall.SIGTERM,
		syscall.SIGQUIT,
		syscall.SIGHUP)
	go func(c chan os.Signal) {
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
					aclPath := AbsolutePathFromConfigPath(h.cfg.ACL.PolicyPath)
					err := h.LoadACLPolicy(aclPath)
					if err != nil {
						log.Error().Err(err).Msg("Failed to reload ACL policy")
					}
					log.Info().
						Str("path", aclPath).
						Msg("ACL policy successfully reloaded, notifying nodes of change")

					h.setLastStateChangeToNow()
				}

			default:
				log.Info().
					Str("signal", sig.String()).
					Msg("Received signal to stop, shutting down gracefully")

				h.shutdownChan <- struct{}{}

				// Gracefully shut down servers
				ctx, cancel := context.WithTimeout(context.Background(), HTTPShutdownTimeout)
				if err := promHTTPServer.Shutdown(ctx); err != nil {
					log.Error().Err(err).Msg("Failed to shutdown prometheus http")
				}
				if err := httpServer.Shutdown(ctx); err != nil {
					log.Error().Err(err).Msg("Failed to shutdown http")
				}
				grpcSocket.GracefulStop()

				// Close network listeners
				promHTTPListener.Close()
				httpListener.Close()
				grpcGatewayConn.Close()

				// Stop listening (and unlink the socket if unix type):
				socketListener.Close()

				// Close db connections
				db, err := h.db.DB()
				if err != nil {
					log.Error().Err(err).Msg("Failed to get db handle")
				}
				err = db.Close()
				if err != nil {
					log.Error().Err(err).Msg("Failed to close db")
				}

				log.Info().
					Msg("Headscale stopped")

				// And we're done:
				cancel()
				os.Exit(0)
			}
		}
	}(sigc)

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
		case "TLS-ALPN-01":
			// Configuration via autocert with TLS-ALPN-01 (https://tools.ietf.org/html/rfc8737)
			// The RFC requires that the validation is done on port 443; in other words, headscale
			// must be reachable on port 443.
			return certManager.TLSConfig(), nil

		case "HTTP-01":
			// Configuration via autocert with HTTP-01. This requires listening on
			// port 80 for the certificate validation in addition to the headscale
			// service, which can be configured to run on any other port.
			go func() {
				log.Fatal().
					Caller().
					Err(http.ListenAndServe(h.cfg.TLS.LetsEncrypt.Listen, certManager.HTTPHandler(http.HandlerFunc(h.redirect)))).
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

		log.Info().Msg(fmt.Sprintf(
			"Client authentication (mTLS) is \"%s\". See the docs to learn about configuring this setting.",
			h.cfg.TLS.ClientAuthMode))

		tlsConfig := &tls.Config{
			ClientAuth:   h.cfg.TLS.ClientAuthMode,
			NextProtos:   []string{"http/1.1"},
			Certificates: make([]tls.Certificate, 1),
			MinVersion:   tls.VersionTLS12,
		}

		tlsConfig.Certificates[0], err = tls.LoadX509KeyPair(h.cfg.TLS.CertPath, h.cfg.TLS.KeyPath)

		return tlsConfig, err
	}
}

func (h *Headscale) setLastStateChangeToNow(namespaces ...string) {
	var err error

	now := time.Now().UTC()

	if len(namespaces) == 0 {
		namespaces, err = h.ListNamespacesStr()
		if err != nil {
			log.Error().Caller().Err(err).Msg("failed to fetch all namespaces, failing to update last changed state.")
		}
	}

	for _, namespace := range namespaces {
		lastStateUpdate.WithLabelValues(namespace, "headscale").Set(float64(now.Unix()))
		if h.lastStateChange == nil {
			h.lastStateChange = xsync.NewMapOf[time.Time]()
		}
		h.lastStateChange.Store(namespace, now)
	}
}

func (h *Headscale) getLastStateChange(namespaces ...string) time.Time {
	times := []time.Time{}

	// getLastStateChange takes a list of namespaces as a "filter", if no namespaces
	// are past, then use the entier list of namespaces and look for the last update
	if len(namespaces) > 0 {
		for _, namespace := range namespaces {
			if lastChange, ok := h.lastStateChange.Load(namespace); ok {
				times = append(times, lastChange)
			}
		}
	} else {
		h.lastStateChange.Range(func(key string, value time.Time) bool {
			times = append(times, value)

			return true
		})
	}

	sort.Slice(times, func(i, j int) bool {
		return times[i].After(times[j])
	})

	log.Trace().Msgf("Latest times %#v", times)

	if len(times) == 0 {
		return time.Now().UTC()
	} else {
		return times[0]
	}
}

func stdoutHandler(
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
}

func readOrCreatePrivateKey(path string) (*key.MachinePrivate, error) {
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
				"failed to save private key to disk: %w",
				err,
			)
		}

		return &machineKey, nil
	} else if err != nil {
		return nil, fmt.Errorf("failed to read private key file: %w", err)
	}

	trimmedPrivateKey := strings.TrimSpace(string(privateKey))
	privateKeyEnsurePrefix := PrivateKeyEnsurePrefix(trimmedPrivateKey)

	var machineKey key.MachinePrivate
	if err = machineKey.UnmarshalText([]byte(privateKeyEnsurePrefix)); err != nil {
		log.Info().
			Str("path", path).
			Msg("This might be due to a legacy (headscale pre-0.12) private key. " +
				"If the key is in WireGuard format, delete the key and restart headscale. " +
				"A new key will automatically be generated. All Tailscale clients will have to be restarted")

		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	return &machineKey, nil
}
