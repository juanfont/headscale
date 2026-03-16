package servertest

import (
	"fmt"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
)

// TestHarness orchestrates a TestServer with multiple TestClients,
// providing a convenient setup for multi-node control plane tests.
type TestHarness struct {
	Server  *TestServer
	clients []*TestClient

	// Default user shared by all clients unless overridden.
	defaultUser *types.User
}

// HarnessOption configures a TestHarness.
type HarnessOption func(*harnessConfig)

type harnessConfig struct {
	serverOpts     []ServerOption
	clientOpts     []ClientOption
	convergenceMax time.Duration
}

func defaultHarnessConfig() *harnessConfig {
	return &harnessConfig{
		convergenceMax: 30 * time.Second,
	}
}

// WithServerOptions passes ServerOptions through to the underlying
// TestServer.
func WithServerOptions(opts ...ServerOption) HarnessOption {
	return func(c *harnessConfig) { c.serverOpts = append(c.serverOpts, opts...) }
}

// WithDefaultClientOptions applies ClientOptions to every client
// created by NewHarness.
func WithDefaultClientOptions(opts ...ClientOption) HarnessOption {
	return func(c *harnessConfig) { c.clientOpts = append(c.clientOpts, opts...) }
}

// WithConvergenceTimeout sets how long WaitForMeshComplete waits.
func WithConvergenceTimeout(d time.Duration) HarnessOption {
	return func(c *harnessConfig) { c.convergenceMax = d }
}

// NewHarness creates a TestServer and numClients connected clients.
// All clients share a default user and are registered with reusable
// pre-auth keys. The harness waits for all clients to form a
// complete mesh before returning.
func NewHarness(tb testing.TB, numClients int, opts ...HarnessOption) *TestHarness {
	tb.Helper()

	hc := defaultHarnessConfig()
	for _, o := range opts {
		o(hc)
	}

	server := NewServer(tb, hc.serverOpts...)

	// Create a shared default user.
	user := server.CreateUser(tb, "harness-default")

	h := &TestHarness{
		Server:      server,
		defaultUser: user,
	}

	// Create and connect clients.
	for i := range numClients {
		name := clientName(i)

		copts := append([]ClientOption{WithUser(user)}, hc.clientOpts...)
		c := NewClient(tb, server, name, copts...)
		h.clients = append(h.clients, c)
	}

	// Wait for the mesh to converge.
	if numClients > 1 {
		h.WaitForMeshComplete(tb, hc.convergenceMax)
	} else if numClients == 1 {
		// Single node: just wait for the first netmap.
		h.clients[0].WaitForUpdate(tb, hc.convergenceMax)
	}

	return h
}

// Client returns the i-th client (0-indexed).
func (h *TestHarness) Client(i int) *TestClient {
	return h.clients[i]
}

// Clients returns all clients.
func (h *TestHarness) Clients() []*TestClient {
	return h.clients
}

// ConnectedClients returns clients that currently have an active
// long-poll session (pollDone channel is still open).
func (h *TestHarness) ConnectedClients() []*TestClient {
	var out []*TestClient

	for _, c := range h.clients {
		select {
		case <-c.pollDone:
			// Poll has ended, client is disconnected.
		default:
			out = append(out, c)
		}
	}

	return out
}

// AddClient creates and connects a new client to the existing mesh.
func (h *TestHarness) AddClient(tb testing.TB, opts ...ClientOption) *TestClient {
	tb.Helper()

	name := clientName(len(h.clients))
	copts := append([]ClientOption{WithUser(h.defaultUser)}, opts...)
	c := NewClient(tb, h.Server, name, copts...)
	h.clients = append(h.clients, c)

	return c
}

// WaitForMeshComplete blocks until every connected client sees
// (connectedCount - 1) peers.
func (h *TestHarness) WaitForMeshComplete(tb testing.TB, timeout time.Duration) {
	tb.Helper()

	connected := h.ConnectedClients()

	expectedPeers := max(len(connected)-1, 0)

	for _, c := range connected {
		c.WaitForPeers(tb, expectedPeers, timeout)
	}
}

// WaitForConvergence waits until all connected clients have a
// non-nil NetworkMap and their peer counts have stabilised.
func (h *TestHarness) WaitForConvergence(tb testing.TB, timeout time.Duration) {
	tb.Helper()
	h.WaitForMeshComplete(tb, timeout)
}

func clientName(index int) string {
	return fmt.Sprintf("node-%d", index)
}
