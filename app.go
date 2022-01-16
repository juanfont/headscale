package headscale

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gin-gonic/gin"
	grpc_middleware "github.com/grpc-ecosystem/go-grpc-middleware"
	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
	"github.com/patrickmn/go-cache"
	zerolog "github.com/philip-bui/grpc-zerolog"
	zl "github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/soheilhy/cmux"
	ginprometheus "github.com/zsais/go-gin-prometheus"
	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/oauth2"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/reflection"
	"google.golang.org/grpc/status"
	"gorm.io/gorm"
	"inet.af/netaddr"
	"tailscale.com/tailcfg"
	"tailscale.com/types/dnstype"
	"tailscale.com/types/key"
)

const (
	AuthPrefix         = "Bearer "
	Postgres           = "postgres"
	Sqlite             = "sqlite3"
	updateInterval     = 5000
	HTTPReadTimeout    = 30 * time.Second
	privateKeyFileMode = 0o600

	requestedExpiryCacheExpiration      = time.Minute * 5
	requestedExpiryCacheCleanupInterval = time.Minute * 10

	errUnsupportedDatabase                 = Error("unsupported DB")
	errUnsupportedLetsEncryptChallengeType = Error(
		"unknown value for Lets Encrypt challenge type",
	)
)

// Config contains the initial Headscale configuration.
type Config struct {
	ServerURL                      string
	Addr                           string
	EphemeralNodeInactivityTimeout time.Duration
	IPPrefixes                     []netaddr.IPPrefix
	PrivateKeyPath                 string
	BaseDomain                     string

	DERP DERPConfig

	DBtype string
	DBpath string
	DBhost string
	DBport int
	DBname string
	DBuser string
	DBpass string

	TLSLetsEncryptListen        string
	TLSLetsEncryptHostname      string
	TLSLetsEncryptCacheDir      string
	TLSLetsEncryptChallengeType string

	TLSCertPath string
	TLSKeyPath  string

	ACMEURL   string
	ACMEEmail string

	DNSConfig *tailcfg.DNSConfig

	UnixSocket string

	OIDC OIDCConfig

	CLI CLIConfig
}

type OIDCConfig struct {
	Issuer       string
	ClientID     string
	ClientSecret string
	MatchMap     map[string]string
}

type DERPConfig struct {
	URLs            []url.URL
	Paths           []string
	AutoUpdate      bool
	UpdateFrequency time.Duration
}

type CLIConfig struct {
	Address  string
	APIKey   string
	Insecure bool
	Timeout  time.Duration
}

// Headscale represents the base app of the service.
type Headscale struct {
	cfg        Config
	db         *gorm.DB
	dbString   string
	dbType     string
	dbDebug    bool
	privateKey *key.MachinePrivate

	DERPMap *tailcfg.DERPMap

	aclPolicy *ACLPolicy
	aclRules  []tailcfg.FilterRule

	lastStateChange sync.Map

	oidcProvider   *oidc.Provider
	oauth2Config   *oauth2.Config
	oidcStateCache *cache.Cache

	requestedExpiryCache *cache.Cache
}

// NewHeadscale returns the Headscale app.
func NewHeadscale(cfg Config) (*Headscale, error) {
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

	requestedExpiryCache := cache.New(
		requestedExpiryCacheExpiration,
		requestedExpiryCacheCleanupInterval,
	)

	app := Headscale{
		cfg:                  cfg,
		dbType:               cfg.DBtype,
		dbString:             dbString,
		privateKey:           privKey,
		aclRules:             tailcfg.FilterAllowAll, // default allowall
		requestedExpiryCache: requestedExpiryCache,
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
			app.cfg.DNSConfig.Routes = make(map[string][]dnstype.Resolver)
		}
		for _, d := range magicDNSDomains {
			app.cfg.DNSConfig.Routes[d.WithoutTrailingDot()] = nil
		}
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

		for _, machine := range machines {
			if machine.AuthKey != nil && machine.LastSeen != nil &&
				machine.AuthKey.Ephemeral &&
				time.Now().
					After(machine.LastSeen.Add(h.cfg.EphemeralNodeInactivityTimeout)) {
				log.Info().
					Str("machine", machine.Name).
					Msg("Ephemeral client removed from database")

				err = h.db.Unscoped().Delete(machine).Error
				if err != nil {
					log.Error().
						Err(err).
						Str("machine", machine.Name).
						Msg("🤮 Cannot delete ephemeral machine from the database")
				}
			}
		}

		h.setLastStateChangeToNow(namespace.Name)
	}
}

// WatchForKVUpdates checks the KV DB table for requests to perform tailnet upgrades
// This is a way to communitate the CLI with the headscale server.
func (h *Headscale) watchForKVUpdates(milliSeconds int64) {
	ticker := time.NewTicker(time.Duration(milliSeconds) * time.Millisecond)
	for range ticker.C {
		h.watchForKVUpdatesWorker()
	}
}

func (h *Headscale) watchForKVUpdatesWorker() {
	h.checkForNamespacesPendingUpdates()
	// more functions will come here in the future
}

func (h *Headscale) grpcAuthenticationInterceptor(ctx context.Context,
	req interface{},
	info *grpc.UnaryServerInfo,
	handler grpc.UnaryHandler) (interface{}, error) {
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

	// TODO(kradalby): Implement API key backend:
	// - Table in the DB
	// - Key name
	// - Encrypted
	// - Expiry
	//
	// Currently all other than localhost traffic is unauthorized, this is intentional to allow
	// us to make use of gRPC for our CLI, but not having to implement any of the remote capabilities
	// and API key auth
	return ctx, status.Error(
		codes.Unauthenticated,
		"Authentication is not implemented yet",
	)

	// if strings.TrimPrefix(token, AUTH_PREFIX) != a.Token {
	// 	log.Error().Caller().Str("client_address", p.Addr.String()).Msg("invalid token")
	// 	return ctx, status.Error(codes.Unauthenticated, "invalid token")
	// }

	// return handler(ctx, req)
}

func (h *Headscale) httpAuthenticationMiddleware(ctx *gin.Context) {
	log.Trace().
		Caller().
		Str("client_address", ctx.ClientIP()).
		Msg("HTTP authentication invoked")

	authHeader := ctx.GetHeader("authorization")

	if !strings.HasPrefix(authHeader, AuthPrefix) {
		log.Error().
			Caller().
			Str("client_address", ctx.ClientIP()).
			Msg(`missing "Bearer " prefix in "Authorization" header`)
		ctx.AbortWithStatus(http.StatusUnauthorized)

		return
	}

	ctx.AbortWithStatus(http.StatusUnauthorized)

	// TODO(kradalby): Implement API key backend
	// Currently all traffic is unauthorized, this is intentional to allow
	// us to make use of gRPC for our CLI, but not having to implement any of the remote capabilities
	// and API key auth
	//
	// if strings.TrimPrefix(authHeader, AUTH_PREFIX) != a.Token {
	// 	log.Error().Caller().Str("client_address", c.ClientIP()).Msg("invalid token")
	// 	c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error", "unauthorized"})

	// 	return
	// }

	// c.Next()
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

// Serve launches a GIN server with the Headscale API.
func (h *Headscale) Serve() error {
	var err error

	ctx := context.Background()
	ctx, cancel := context.WithCancel(ctx)

	defer cancel()

	err = h.ensureUnixSocketIsAbsent()
	if err != nil {
		return fmt.Errorf("unable to remove old socket file: %w", err)
	}

	socketListener, err := net.Listen("unix", h.cfg.UnixSocket)
	if err != nil {
		return fmt.Errorf("failed to set up gRPC socket: %w", err)
	}

	// Handle common process-killing signals so we can gracefully shut down:
	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, os.Interrupt, syscall.SIGTERM)
	go func(c chan os.Signal) {
		// Wait for a SIGINT or SIGKILL:
		sig := <-c
		log.Printf("Caught signal %s: shutting down.", sig)
		// Stop listening (and unlink the socket if unix type):
		socketListener.Close()
		// And we're done:
		os.Exit(0)
	}(sigc)

	networkListener, err := net.Listen("tcp", h.cfg.Addr)
	if err != nil {
		return fmt.Errorf("failed to bind to TCP address: %w", err)
	}

	// Create the cmux object that will multiplex 2 protocols on the same port.
	// The two following listeners will be served on the same port below gracefully.
	networkMutex := cmux.New(networkListener)
	// Match gRPC requests here
	grpcListener := networkMutex.MatchWithWriters(
		cmux.HTTP2MatchHeaderFieldSendSettings("content-type", "application/grpc"),
		cmux.HTTP2MatchHeaderFieldSendSettings(
			"content-type",
			"application/grpc+proto",
		),
	)
	// Otherwise match regular http requests.
	httpListener := networkMutex.Match(cmux.Any())

	grpcGatewayMux := runtime.NewServeMux()

	// Make the grpc-gateway connect to grpc over socket
	grpcGatewayConn, err := grpc.Dial(
		h.cfg.UnixSocket,
		[]grpc.DialOption{
			grpc.WithInsecure(),
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

	router := gin.Default()

	prometheus := ginprometheus.NewPrometheus("gin")
	prometheus.Use(router)

	router.GET(
		"/health",
		func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"healthy": "ok"}) },
	)
	router.GET("/key", h.KeyHandler)
	router.GET("/register", h.RegisterWebAPI)
	router.POST("/machine/:id/map", h.PollNetMapHandler)
	router.POST("/machine/:id", h.RegistrationHandler)
	router.GET("/oidc/register/:mkey", h.RegisterOIDC)
	router.GET("/oidc/callback", h.OIDCCallback)
	router.GET("/apple", h.AppleMobileConfig)
	router.GET("/apple/:platform", h.ApplePlatformConfig)
	router.GET("/swagger", SwaggerUI)
	router.GET("/swagger/v1/openapiv2.json", SwaggerAPIv1)

	api := router.Group("/api")
	api.Use(h.httpAuthenticationMiddleware)
	{
		api.Any("/v1/*any", gin.WrapF(grpcGatewayMux.ServeHTTP))
	}

	router.NoRoute(stdoutHandler)

	// Fetch an initial DERP Map before we start serving
	h.DERPMap = GetDERPMap(h.cfg.DERP)

	if h.cfg.DERP.AutoUpdate {
		derpMapCancelChannel := make(chan struct{})
		defer func() { derpMapCancelChannel <- struct{}{} }()
		go h.scheduledDERPMapUpdateWorker(derpMapCancelChannel)
	}

	// I HATE THIS
	go h.watchForKVUpdates(updateInterval)
	go h.expireEphemeralNodes(updateInterval)

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

	if zl.GlobalLevel() == zl.TraceLevel {
		zerolog.RespLog = true
	} else {
		zerolog.RespLog = false
	}

	grpcOptions := []grpc.ServerOption{
		grpc.UnaryInterceptor(
			grpc_middleware.ChainUnaryServer(
				h.grpcAuthenticationInterceptor,
				zerolog.NewUnaryServerInterceptor(),
			),
		),
	}

	tlsConfig, err := h.getTLSSettings()
	if err != nil {
		log.Error().Err(err).Msg("Failed to set up TLS configuration")

		return err
	}

	if tlsConfig != nil {
		httpServer.TLSConfig = tlsConfig

		grpcOptions = append(grpcOptions, grpc.Creds(credentials.NewTLS(tlsConfig)))
	}

	grpcServer := grpc.NewServer(grpcOptions...)

	// Start the local gRPC server without TLS and without authentication
	grpcSocket := grpc.NewServer(zerolog.UnaryInterceptor())

	v1.RegisterHeadscaleServiceServer(grpcServer, newHeadscaleV1APIServer(h))
	v1.RegisterHeadscaleServiceServer(grpcSocket, newHeadscaleV1APIServer(h))
	reflection.Register(grpcServer)
	reflection.Register(grpcSocket)

	errorGroup := new(errgroup.Group)

	errorGroup.Go(func() error { return grpcSocket.Serve(socketListener) })

	// TODO(kradalby): Verify if we need the same TLS setup for gRPC as HTTP
	errorGroup.Go(func() error { return grpcServer.Serve(grpcListener) })

	if tlsConfig != nil {
		errorGroup.Go(func() error {
			tlsl := tls.NewListener(httpListener, tlsConfig)

			return httpServer.Serve(tlsl)
		})
	} else {
		errorGroup.Go(func() error { return httpServer.Serve(httpListener) })
	}

	errorGroup.Go(func() error { return networkMutex.Serve() })

	log.Info().
		Msgf("listening and serving (multiplexed HTTP and gRPC) on: %s", h.cfg.Addr)

	return errorGroup.Wait()
}

func (h *Headscale) getTLSSettings() (*tls.Config, error) {
	var err error
	if h.cfg.TLSLetsEncryptHostname != "" {
		if !strings.HasPrefix(h.cfg.ServerURL, "https://") {
			log.Warn().
				Msg("Listening with TLS but ServerURL does not start with https://")
		}

		certManager := autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(h.cfg.TLSLetsEncryptHostname),
			Cache:      autocert.DirCache(h.cfg.TLSLetsEncryptCacheDir),
			Client: &acme.Client{
				DirectoryURL: h.cfg.ACMEURL,
			},
			Email: h.cfg.ACMEEmail,
		}

		switch h.cfg.TLSLetsEncryptChallengeType {
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
					Err(http.ListenAndServe(h.cfg.TLSLetsEncryptListen, certManager.HTTPHandler(http.HandlerFunc(h.redirect)))).
					Msg("failed to set up a HTTP server")
			}()

			return certManager.TLSConfig(), nil

		default:
			return nil, errUnsupportedLetsEncryptChallengeType
		}
	} else if h.cfg.TLSCertPath == "" {
		if !strings.HasPrefix(h.cfg.ServerURL, "http://") {
			log.Warn().Msg("Listening without TLS but ServerURL does not start with http://")
		}

		return nil, err
	} else {
		if !strings.HasPrefix(h.cfg.ServerURL, "https://") {
			log.Warn().Msg("Listening with TLS but ServerURL does not start with https://")
		}
		tlsConfig := &tls.Config{
			ClientAuth:   tls.RequireAnyClientCert,
			NextProtos:   []string{"http/1.1"},
			Certificates: make([]tls.Certificate, 1),
			MinVersion:   tls.VersionTLS12,
		}
		tlsConfig.Certificates[0], err = tls.LoadX509KeyPair(h.cfg.TLSCertPath, h.cfg.TLSKeyPath)

		return tlsConfig, err
	}
}

func (h *Headscale) setLastStateChangeToNow(namespace string) {
	now := time.Now().UTC()
	lastStateUpdate.WithLabelValues("", "headscale").Set(float64(now.Unix()))
	h.lastStateChange.Store(namespace, now)
}

func (h *Headscale) getLastStateChange(namespaces ...string) time.Time {
	times := []time.Time{}

	for _, namespace := range namespaces {
		if wrapped, ok := h.lastStateChange.Load(namespace); ok {
			lastChange, _ := wrapped.(time.Time)

			times = append(times, lastChange)
		}
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

func stdoutHandler(ctx *gin.Context) {
	body, _ := io.ReadAll(ctx.Request.Body)

	log.Trace().
		Interface("header", ctx.Request.Header).
		Interface("proto", ctx.Request.Proto).
		Interface("url", ctx.Request.URL).
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

	privateKeyEnsurePrefix := PrivateKeyEnsurePrefix(string(privateKey))

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
