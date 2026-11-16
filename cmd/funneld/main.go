// Command funneld is a Tailscale Funnel relay for headscale.
//
// It listens on the funnel ports, reads the server name of each TLS
// connection and hands the stream, still encrypted, to the tailnet node
// of that name, which terminates TLS itself. See package
// [github.com/juanfont/headscale/hscontrol/funnel].
//
// The relay node must carry one of the tags in headscale's
// funnel.relay_tags. It joins the tailnet either as its own embedded node
// (tsnet, the default) or through the tailscaled already running on the
// machine (-local).
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"github.com/juanfont/headscale/hscontrol/funnel"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"golang.org/x/sync/errgroup"
	"tailscale.com/client/local"
	"tailscale.com/tsnet"
)

var (
	errNoLoginServer = errors.New("-login-server is required for the embedded node")
	errInvalidPort   = errors.New("invalid port")
)

func main() {
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})

	err := run()
	if err != nil {
		log.Fatal().Err(err).Msg("funneld")
	}
}

func run() error {
	var (
		ports      = flag.String("ports", "443", "comma-separated public ports to relay, among headscale's funnel.ports; PORT=ADDR listens on ADDR for public port PORT, behind an SNI proxy")
		listen     = flag.String("listen", "", "address to listen on (empty: all)")
		useLocal   = flag.Bool("local", false, "use the tailscaled running on this machine instead of an embedded node")
		socket     = flag.String("socket", "", "tailscaled socket with -local (empty: platform default)")
		controlURL = flag.String("login-server", "", "headscale URL, for the embedded node")
		hostname   = flag.String("hostname", "funnel-relay", "hostname of the embedded node")
		stateDir   = flag.String("state-dir", "", "state directory of the embedded node (empty: tsnet default)")
		verbose    = flag.Bool("verbose", false, "log every dropped connection")
		listeners  []listener
	)

	flag.Parse()

	zerolog.SetGlobalLevel(zerolog.InfoLevel)

	if *verbose {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	}

	for p := range strings.SplitSeq(*ports, ",") {
		l, err := parseListener(strings.TrimSpace(p), *listen)
		if err != nil {
			return err
		}

		listeners = append(listeners, l)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var backend funnel.Backend

	if *useLocal {
		backend = &local.Client{Socket: *socket}
	} else {
		if *controlURL == "" {
			return errNoLoginServer
		}

		// The embedded node must not send its logs to Tailscale.
		os.Setenv("TS_NO_LOGS_NO_SUPPORT", "true")

		srv := &tsnet.Server{
			Hostname:   *hostname,
			Dir:        *stateDir,
			ControlURL: *controlURL,
			AuthKey:    os.Getenv("TS_AUTHKEY"),
			UserLogf:   func(format string, args ...any) { log.Info().Msgf(format, args...) },
		}
		defer srv.Close()

		_, err := srv.Up(ctx)
		if err != nil {
			return fmt.Errorf("joining the tailnet: %w", err)
		}

		backend, err = funnel.NewTSNetBackend(srv)
		if err != nil {
			return err
		}
	}

	relay := &funnel.Relay{Backend: backend}

	g, gctx := errgroup.WithContext(ctx)

	for _, l := range listeners {
		ln, err := (&net.ListenConfig{}).Listen(ctx, "tcp", l.addr)
		if err != nil {
			return fmt.Errorf("listening for port %d: %w", l.port, err)
		}

		log.Info().Str("addr", ln.Addr().String()).Uint16("port", l.port).Msg("relaying funnel connections")

		g.Go(func() error { return relay.Serve(gctx, ln, l.port) })
	}

	return g.Wait()
}

// listener is a public funnel port and the address funneld listens on for
// it: the same port by default, another one behind an SNI proxy.
type listener struct {
	port uint16
	addr string
}

// parseListener parses PORT or PORT=ADDR.
func parseListener(s, host string) (listener, error) {
	portStr, addr, mapped := strings.Cut(s, "=")

	n, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil || n == 0 {
		return listener{}, fmt.Errorf("%w %q", errInvalidPort, s)
	}

	if !mapped {
		addr = net.JoinHostPort(host, portStr)
	}

	return listener{port: uint16(n), addr: addr}, nil
}
