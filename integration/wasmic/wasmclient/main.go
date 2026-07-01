//go:build js

// Command wasmclient is a minimal Tailscale control client compiled to
// GOOS=js/GOARCH=wasm and run under Node. It exercises the real
// tailscale.com/control/controlhttp js/wasm dial path
// (control/controlhttp/client_js.go), which opens /ts2021 as a browser-style
// WebSocket GET — the exact transport a Tailscale JS/WASM client uses.
//
// It is the container-side half of the integration test guarding issue #3357:
// headscale must register /ts2021 for GET, not POST only, or the WebSocket
// upgrade is rejected with 405 before the Noise handshake can start.
//
// It is intentionally not the full tsconnect IPN — the regression is entirely
// in the control-connection upgrade, and this drives the real upgrade code with
// the smallest possible harness. On success it prints wasmSuccessMarker and
// exits 0; on any failure it prints wasmFailureMarker and exits non-zero.
package main

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"time"

	"tailscale.com/control/controlhttp"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

// These markers are matched by the integration test on the client's stdout.
const (
	wasmSuccessMarker = "WASM_TS2021_OK"
	wasmFailureMarker = "WASM_TS2021_FAIL"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Printf("%s: usage: wasmclient <control-url> <noise-key>\n", wasmFailureMarker)
		os.Exit(2)
	}

	if err := run(os.Args[1], os.Args[2]); err != nil {
		fmt.Printf("%s: %v\n", wasmFailureMarker, err)
		os.Exit(1)
	}
}

// run dials /ts2021 exactly as tailscale.com/control/controlhttp/client_js.go
// does in a browser: a WebSocket GET via the JS/undici WebSocket. The server's
// Noise key is passed in (the test fetches /key) rather than fetched here,
// because Go's net/http DNS resolver is unavailable under GOOS=js — only the
// WebSocket transport, which runs through the JS host, works.
func run(controlURL, noiseKeyText string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	u, err := url.Parse(controlURL)
	if err != nil {
		return fmt.Errorf("parse control url %q: %w", controlURL, err)
	}

	var controlKey key.MachinePublic
	if err := controlKey.UnmarshalText([]byte(noiseKeyText)); err != nil {
		return fmt.Errorf("parse noise key %q: %w", noiseKeyText, err)
	}

	port := u.Port()
	if port == "" {
		if u.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}

	// client_js.go selects ws:// (and appends the port) only when HTTPPort is a
	// custom non-80 port and HTTPS is 443 or disabled; otherwise it dials wss://
	// on the default port. Set the fields to match the server's actual scheme.
	d := &controlhttp.Dialer{
		Hostname:        u.Hostname(),
		MachineKey:      key.NewMachine(),
		ControlKey:      controlKey,
		ProtocolVersion: uint16(tailcfg.CurrentCapabilityVersion),
	}
	if u.Scheme == "https" {
		d.HTTPSPort = port
	} else {
		d.HTTPPort = port
		d.HTTPSPort = controlhttp.NoPort
	}

	conn, err := d.Dial(ctx)
	if err != nil {
		return fmt.Errorf("ts2021 websocket dial: %w", err)
	}
	defer conn.Close()

	fmt.Printf("%s: noise established over websocket, protocol version %d\n",
		wasmSuccessMarker, conn.ProtocolVersion())

	return nil
}
