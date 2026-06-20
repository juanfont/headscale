package servertest

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"tailscale.com/control/controlclient"
	"tailscale.com/health"
	"tailscale.com/net/netmon"
	"tailscale.com/net/tsdial"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/types/netmap"
	"tailscale.com/types/persist"
	"tailscale.com/util/eventbus"
)

// TestClient wraps a Tailscale [controlclient.Direct] connected to a
// [TestServer]. It tracks all received [netmap.NetworkMap] updates, providing
// helpers to wait for convergence and inspect the client's view of
// the network.
type TestClient struct {
	// Name is a human-readable identifier for this client.
	Name string

	server  *TestServer
	direct  *controlclient.Direct
	authKey string
	user    *types.User

	// Connection lifecycle.
	pollCtx    context.Context //nolint:containedctx // test-only; context stored for cancel control
	pollCancel context.CancelFunc
	pollDone   chan struct{}

	// Accumulated state from [tailcfg.MapResponse] callbacks.
	mu      sync.RWMutex
	netmap  *netmap.NetworkMap
	history []*netmap.NetworkMap

	// updates is a buffered channel that receives a signal
	// each time a new [netmap.NetworkMap] arrives.
	updates chan *netmap.NetworkMap

	bus     *eventbus.Bus
	dialer  *tsdial.Dialer
	tracker *health.Tracker
}

// ClientOption configures a [TestClient].
type ClientOption func(*clientConfig)

type clientConfig struct {
	ephemeral bool
	hostname  string
	tags      []string
	user      *types.User
}

// WithEphemeral makes the client register as an ephemeral node.
func WithEphemeral() ClientOption {
	return func(c *clientConfig) { c.ephemeral = true }
}

// WithHostname sets the client's hostname in [tailcfg.Hostinfo].
func WithHostname(name string) ClientOption {
	return func(c *clientConfig) { c.hostname = name }
}

// WithTags sets ACL tags on the pre-auth key.
func WithTags(tags ...string) ClientOption {
	return func(c *clientConfig) { c.tags = tags }
}

// WithUser sets the user for the client. If not set, the harness
// creates a default user.
func WithUser(user *types.User) ClientOption {
	return func(c *clientConfig) { c.user = user }
}

// NewClient creates a [TestClient], registers it with the [TestServer]
// using a pre-auth key, and starts long-polling for map updates.
func NewClient(tb testing.TB, server *TestServer, name string, opts ...ClientOption) *TestClient {
	tb.Helper()

	cc := &clientConfig{
		hostname: name,
	}
	for _, o := range opts {
		o(cc)
	}

	// Resolve user.
	user := cc.user
	if user == nil {
		// Create a per-client user if none specified.
		user = server.CreateUser(tb, "user-"+name)
	}

	// Create pre-auth key.
	uid := types.UserID(user.ID)

	var authKey string

	switch {
	case cc.ephemeral:
		authKey = server.CreateEphemeralPreAuthKey(tb, uid)
	case len(cc.tags) > 0:
		authKey = server.CreateTaggedPreAuthKey(tb, uid, cc.tags)
	default:
		authKey = server.CreatePreAuthKey(tb, uid)
	}

	// Set up Tailscale client infrastructure.
	bus := eventbus.New()
	tracker := health.NewTracker(bus)
	dialer := tsdial.NewDialer(netmon.NewStatic())
	dialer.SetBus(bus)

	// Route all connections through the server's in-memory network
	// so that no real TCP sockets are used.
	dialer.SetSystemDialerForTest(server.MemNet().Dial)

	machineKey := key.NewMachine()

	direct, err := controlclient.NewDirect(controlclient.Options{
		Persist:              persist.Persist{},
		GetMachinePrivateKey: func() (key.MachinePrivate, error) { return machineKey, nil },
		ServerURL:            server.URL,
		AuthKey:              authKey,
		Hostinfo: &tailcfg.Hostinfo{
			BackendLogID: "servertest-" + name,
			Hostname:     cc.hostname,
		},
		DiscoPublicKey: key.NewDisco().Public(),
		Logf:           tb.Logf,
		HealthTracker:  tracker,
		Dialer:         dialer,
		Bus:            bus,
	})
	if err != nil {
		tb.Fatalf("servertest: NewDirect(%s): %v", name, err)
	}

	tc := &TestClient{
		Name:    name,
		server:  server,
		direct:  direct,
		authKey: authKey,
		user:    user,
		updates: make(chan *netmap.NetworkMap, 64),
		bus:     bus,
		dialer:  dialer,
		tracker: tracker,
	}

	tb.Cleanup(func() {
		tc.cleanup()
	})

	// Register with the server.
	tc.register(tb)

	// Start long-polling in the background.
	tc.startPoll(tb)

	return tc
}

// register performs the initial [controlclient.Direct.TryLogin] to register the client.
func (c *TestClient) register(tb testing.TB) {
	tb.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	url, err := c.direct.TryLogin(ctx, controlclient.LoginDefault)
	if err != nil {
		tb.Fatalf("servertest: TryLogin(%s): %v", c.Name, err)
	}

	if url != "" {
		tb.Fatalf("servertest: TryLogin(%s): unexpected auth URL: %s (expected auto-auth with preauth key)", c.Name, url)
	}
}

// startPoll begins the long-poll [tailcfg.MapRequest] loop.
func (c *TestClient) startPoll(tb testing.TB) {
	tb.Helper()

	c.startPollLoop()
}

// startPollLoop creates a fresh poll context and launches the background
// [controlclient.Direct.PollNetMap] goroutine, which blocks until the
// context is cancelled or the server closes the connection.
func (c *TestClient) startPollLoop() {
	c.pollCtx, c.pollCancel = context.WithCancel(context.Background())
	c.pollDone = make(chan struct{})

	go func() {
		defer close(c.pollDone)

		_ = c.direct.PollNetMap(c.pollCtx, c)
	}()
}

// resetNetmapState clears the cached netmap and drains any pending
// updates from a previous session so that convergence waits observe
// only the new session's maps.
func (c *TestClient) resetNetmapState() {
	c.mu.Lock()
	c.netmap = nil
	c.mu.Unlock()

	for {
		select {
		case <-c.updates:
		default:
			return
		}
	}
}

// UpdateFullNetmap implements [controlclient.NetmapUpdater].
// Called by [controlclient.Direct] when a new [netmap.NetworkMap] is received.
func (c *TestClient) UpdateFullNetmap(nm *netmap.NetworkMap) {
	c.mu.Lock()
	c.netmap = nm
	c.history = append(c.history, nm)
	c.mu.Unlock()

	// Non-blocking send to the updates channel.
	select {
	case c.updates <- nm:
	default:
	}
}

// cleanup releases all resources.
func (c *TestClient) cleanup() {
	if c.pollCancel != nil {
		c.pollCancel()
	}

	if c.pollDone != nil {
		// Wait for PollNetMap to exit, but don't hang.
		select {
		case <-c.pollDone:
		case <-time.After(5 * time.Second):
		}
	}

	if c.direct != nil {
		c.direct.Close()
	}

	if c.dialer != nil {
		c.dialer.Close()
	}

	if c.bus != nil {
		c.bus.Close()
	}
}

// --- Lifecycle methods ---

// Disconnect cancels the long-poll context, simulating a clean
// client disconnect.
func (c *TestClient) Disconnect(tb testing.TB) {
	tb.Helper()

	if c.pollCancel != nil {
		c.pollCancel()
		<-c.pollDone
	}
}

// Reconnect registers and starts a new long-poll session.
// Call [TestClient.Disconnect] first, or this will disconnect automatically.
func (c *TestClient) Reconnect(tb testing.TB) {
	tb.Helper()

	// Cancel any existing poll.
	if c.pollCancel != nil {
		c.pollCancel()

		select {
		case <-c.pollDone:
		case <-time.After(5 * time.Second):
			tb.Fatalf("servertest: Reconnect(%s): old poll did not exit", c.Name)
		}
	}

	// Clear stale netmap data and drain pending updates so that callers
	// like [TestClient.WaitForPeers] actually wait for the new session's
	// map instead of returning immediately based on the old session's
	// cached state.
	c.resetNetmapState()

	// Re-register and start polling again.
	c.register(tb)

	c.startPoll(tb)
}

// LogoutAndDisconnect sends a logout [tailcfg.RegisterRequest] (expiry in
// the past) and tears down the long-poll session, mirroring what
// tailscaled does on `tailscale logout`. The server marks the node
// expired; the poll teardown then triggers the server's disconnect
// grace period, after which the node goes offline.
//
// Safe to call from non-test goroutines: errors are returned, not
// fataled, so many clients can log out concurrently.
func (c *TestClient) LogoutAndDisconnect(ctx context.Context) error {
	err := c.direct.TryLogout(ctx)
	if err != nil {
		return fmt.Errorf("servertest: TryLogout(%s): %w", c.Name, err)
	}

	if c.pollCancel != nil {
		c.pollCancel()

		select {
		case <-c.pollDone:
		case <-ctx.Done():
			return fmt.Errorf("servertest: LogoutAndDisconnect(%s): poll did not exit: %w", c.Name, ctx.Err())
		}
	}

	return nil
}

// ReloginAndPoll logs the client back in after [TestClient.LogoutAndDisconnect]
// and starts a fresh long-poll session. [controlclient.Direct.TryLogout] cleared
// the persisted node key, so this generates a new NodeKey and re-registers with
// the same pre-auth key and machine key — the same shape as a real client
// running `tailscale up --authkey=...` after a logout.
//
// Safe to call from non-test goroutines.
func (c *TestClient) ReloginAndPoll(ctx context.Context) error {
	url, err := c.direct.TryLogin(ctx, controlclient.LoginDefault)
	if err != nil {
		return fmt.Errorf("servertest: TryLogin(%s): %w", c.Name, err)
	}

	if url != "" {
		return fmt.Errorf("servertest: TryLogin(%s): unexpected auth URL %q (expected auto-auth with preauth key)", c.Name, url) //nolint:err113
	}

	c.resetNetmapState()
	c.startPollLoop()

	return nil
}

// RestartPoll tears down the current long-poll session and immediately
// starts a new one without re-registering, the way tailscaled restarts
// its map poll on state-machine transitions (pause/unpause around
// login). The node key is unchanged; the server sees a rapid
// disconnect/reconnect.
//
// Safe to call from non-test goroutines.
func (c *TestClient) RestartPoll(ctx context.Context) error {
	if c.pollCancel != nil {
		c.pollCancel()

		select {
		case <-c.pollDone:
		case <-ctx.Done():
			return fmt.Errorf("servertest: RestartPoll(%s): old poll did not exit: %w", c.Name, ctx.Err())
		}
	}

	c.startPollLoop()

	return nil
}

// ReconnectAfter disconnects, waits for d, then reconnects.
// The timer works correctly with testing/synctest for
// time-controlled tests.
func (c *TestClient) ReconnectAfter(tb testing.TB, d time.Duration) {
	tb.Helper()
	c.Disconnect(tb)

	timer := time.NewTimer(d)
	defer timer.Stop()

	<-timer.C
	c.Reconnect(tb)
}

// --- State accessors ---

// Netmap returns the latest [netmap.NetworkMap], or nil if none received yet.
func (c *TestClient) Netmap() *netmap.NetworkMap {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return c.netmap
}

// WaitForPeers blocks until the client sees at least n peers,
// or until timeout expires.
func (c *TestClient) WaitForPeers(tb testing.TB, n int, timeout time.Duration) {
	tb.Helper()

	c.waitForPeers(tb, n, timeout, "WaitForPeers", func(got int) bool { return got >= n })
}

// waitForPeers blocks until match reports the current peer count
// satisfies the caller's predicate, or until timeout expires. op
// names the caller for the timeout failure message.
func (c *TestClient) waitForPeers(
	tb testing.TB,
	n int,
	timeout time.Duration,
	op string,
	match func(got int) bool,
) {
	tb.Helper()

	deadline := time.After(timeout)

	for {
		if nm := c.Netmap(); nm != nil && match(len(nm.Peers)) {
			return
		}

		select {
		case <-c.updates:
			// Check again.
		case <-deadline:
			nm := c.Netmap()

			got := 0
			if nm != nil {
				got = len(nm.Peers)
			}

			tb.Fatalf("servertest: %s(%s, %d): timeout after %v (got %d peers)", op, c.Name, n, timeout, got)
		}
	}
}

// WaitForUpdate blocks until the next netmap update arrives or timeout.
func (c *TestClient) WaitForUpdate(tb testing.TB, timeout time.Duration) *netmap.NetworkMap {
	tb.Helper()

	select {
	case nm := <-c.updates:
		return nm
	case <-time.After(timeout):
		tb.Fatalf("servertest: WaitForUpdate(%s): timeout after %v", c.Name, timeout)

		return nil
	}
}

// Peers returns the current peer list, or nil.
func (c *TestClient) Peers() []tailcfg.NodeView {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.netmap == nil {
		return nil
	}

	return c.netmap.Peers
}

// PeerByName finds a peer by hostname. Returns the peer and true
// if found, zero value and false otherwise.
func (c *TestClient) PeerByName(hostname string) (tailcfg.NodeView, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.netmap == nil {
		return tailcfg.NodeView{}, false
	}

	for _, p := range c.netmap.Peers {
		hi := p.Hostinfo()
		if hi.Valid() && hi.Hostname() == hostname {
			return p, true
		}
	}

	return tailcfg.NodeView{}, false
}

// PeerNames returns the hostnames of all current peers.
func (c *TestClient) PeerNames() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.netmap == nil {
		return nil
	}

	names := make([]string, 0, len(c.netmap.Peers))
	for _, p := range c.netmap.Peers {
		hi := p.Hostinfo()
		if hi.Valid() {
			names = append(names, hi.Hostname())
		}
	}

	return names
}

// UpdateCount returns the total number of full netmap updates received.
func (c *TestClient) UpdateCount() int {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return len(c.history)
}

// History returns a copy of all [netmap.NetworkMap] snapshots in order.
func (c *TestClient) History() []*netmap.NetworkMap {
	c.mu.RLock()
	defer c.mu.RUnlock()

	out := make([]*netmap.NetworkMap, len(c.history))
	copy(out, c.history)

	return out
}

// SelfName returns the self node's hostname from the latest netmap.
func (c *TestClient) SelfName() string {
	nm := c.Netmap()
	if nm == nil || !nm.SelfNode.Valid() {
		return ""
	}

	return nm.SelfNode.Hostinfo().Hostname()
}

// WaitForPeerCount blocks until the client sees exactly n peers.
func (c *TestClient) WaitForPeerCount(tb testing.TB, n int, timeout time.Duration) {
	tb.Helper()

	c.waitForPeers(tb, n, timeout, "WaitForPeerCount", func(got int) bool { return got == n })
}

// WaitForCondition blocks until condFn returns true on the latest
// netmap, or until timeout expires. This is useful for waiting for
// specific state changes (e.g., peer going offline).
func (c *TestClient) WaitForCondition(tb testing.TB, desc string, timeout time.Duration, condFn func(*netmap.NetworkMap) bool) {
	tb.Helper()

	deadline := time.After(timeout)

	for {
		if nm := c.Netmap(); nm != nil && condFn(nm) {
			return
		}

		select {
		case <-c.updates:
			// Check again.
		case <-deadline:
			tb.Fatalf("servertest: WaitForCondition(%s, %q): timeout after %v", c.Name, desc, timeout)
		}
	}
}

// Direct returns the underlying [controlclient.Direct] for
// advanced operations like [controlclient.Direct.SetHostinfo] or SendUpdate.
func (c *TestClient) Direct() *controlclient.Direct {
	return c.direct
}

// String implements [fmt.Stringer] for debug output.
func (c *TestClient) String() string {
	nm := c.Netmap()
	if nm == nil {
		return fmt.Sprintf("TestClient(%s, no netmap)", c.Name)
	}

	return fmt.Sprintf("TestClient(%s, %d peers)", c.Name, len(nm.Peers))
}
