package servertest

import (
	"context"
	"fmt"
	"path"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/types/testcapture"
	"tailscale.com/control/controlclient"
	"tailscale.com/health"
	"tailscale.com/net/netmon"
	"tailscale.com/net/tsdial"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
	"tailscale.com/types/netmap"
	"tailscale.com/types/persist"
	"tailscale.com/types/views"
	"tailscale.com/util/eventbus"
	"tailscale.com/wgengine/filter"
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

	// machineKey survives every login and discoKey every login but
	// [TestClient.Restart], as with tailscaled.
	machineKey key.MachinePrivate
	discoKey   key.DiscoPublic
	logf       logger.Logf

	// approve completes an interactive login; see [WithInteractiveLogin].
	approve func(authID string) error

	// loginFlags and endpoints: see [WithLoginFlags] and [WithEndpoints].
	loginFlags controlclient.LoginFlags
	endpoints  []tailcfg.Endpoint

	// stopFollowup ends the follow-up [TestClient.RotateDisco] left waiting.
	stopFollowup context.CancelFunc

	// Connection lifecycle.
	pollCtx    context.Context //nolint:containedctx // test-only; context stored for cancel control
	pollCancel context.CancelFunc
	pollDone   chan struct{}

	// Accumulated state from [tailcfg.MapResponse] callbacks.
	mu              sync.RWMutex
	netmap          *netmap.NetworkMap
	history         []*netmap.NetworkMap
	updatesReceived int
	noHistory       bool

	// streams and streamMaps: see [TestClient.Stream].
	streams, streamMaps int

	// deltaUpdates, deltaRemoved and deltaSeen: see [WithDeltaUpdates].
	deltaUpdates bool
	deltaRemoved []tailcfg.NodeID
	deltaSeen    []time.Time

	// registers: see [TestClient.RegisterAttempts].
	registers []testcapture.RegisterAttempt

	// frames: see [TestClient.Frames]. stamped is set while the response
	// in hand carried a ControlTime, so its rebuild is already counted.
	frames  int
	stamped bool

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
	ephemeral    bool
	hostname     string
	tags         []string
	user         *types.User
	authKey      string
	deltaUpdates bool
	noHistory    bool
	hostinfo     *tailcfg.Hostinfo
	approve      func(authID string) error
	loginFlags   controlclient.LoginFlags
	endpoints    []tailcfg.Endpoint
}

// WithoutNetmapHistory retains only the latest netmap and one queued update.
// Scale tests use this to avoid retaining every client's old peer lists.
// [TestClient.UpdateCount] still counts every received full netmap.
func WithoutNetmapHistory() ClientOption {
	return func(c *clientConfig) { c.noHistory = true }
}

// WithDeltaUpdates makes the client accept incremental map updates the way
// a real tailscaled does, and record the peer removals it could apply that
// way ([TestClient.DeltaRemovedPeers]). Only those removals reach IPN bus
// watchers opted out of full netmaps, such as the Android app.
func WithDeltaUpdates() ClientOption {
	return func(c *clientConfig) { c.deltaUpdates = true }
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

// WithAuthKey registers with key instead of a key minted for the client.
func WithAuthKey(key string) ClientOption {
	return func(c *clientConfig) { c.authKey = key }
}

// WithHostinfo registers with hi instead of a Hostinfo holding only the
// client's name, so a client can request tags or announce routes at
// registration.
func WithHostinfo(hi *tailcfg.Hostinfo) ClientOption {
	return func(c *clientConfig) { c.hostinfo = hi }
}

// WithInteractiveLogin registers without an auth key, as `tailscale up`
// does: the server answers with an auth URL and approve, given its auth ID,
// completes the login, as `headscale auth register` would.
func WithInteractiveLogin(approve func(authID string) error) ClientOption {
	return func(c *clientConfig) { c.approve = approve }
}

// WithLoginFlags adds flags to every login, as tailscaled adds
// [controlclient.LoginEphemeral] when it runs with --state=mem:.
func WithLoginFlags(flags controlclient.LoginFlags) ClientOption {
	return func(c *clientConfig) { c.loginFlags = flags }
}

// WithEndpoints makes the client report eps in its map requests, as
// tailscaled does once it has found its paths.
func WithEndpoints(eps ...tailcfg.Endpoint) ClientOption {
	return func(c *clientConfig) { c.endpoints = eps }
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

	tc, err := TryNewClient(tb, server, name, opts...)
	if err != nil {
		tb.Fatalf("servertest: NewClient(%s): %v", name, err)
	}

	return tc
}

// TryNewClient is [NewClient] for a registration that may be refused: it
// returns the login error, and a client that holds no node and does not
// poll.
func TryNewClient(tb testing.TB, server *TestServer, name string, opts ...ClientOption) (*TestClient, error) {
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
	case cc.approve != nil:
		// Interactive: no key.
	case cc.authKey != "":
		authKey = cc.authKey
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

	updateBuffer := 64
	if cc.noHistory {
		updateBuffer = 1
	}

	tc := &TestClient{
		Name:       name,
		server:     server,
		authKey:    authKey,
		user:       user,
		machineKey: key.NewMachine(),
		discoKey:   key.NewDisco().Public(),
		approve:    cc.approve,
		loginFlags: cc.loginFlags,
		endpoints:  cc.endpoints,
		updates:    make(chan *netmap.NetworkMap, updateBuffer),
		bus:        bus,
		dialer:     dialer,
		tracker:    tracker,

		deltaUpdates: cc.deltaUpdates,
		noHistory:    cc.noHistory,
	}

	tc.logf = func(format string, args ...any) {
		line := fmt.Sprintf(format, args...)
		tb.Logf("%s", line)

		tc.mu.Lock()
		tc.registers, _ = testcapture.AppendRegisterLine(tc.registers, line)

		// The poll logs a response's ControlTime before it applies it.
		if strings.Contains(line, `{"controltime":`) {
			tc.frames++
			tc.stamped = true
		}
		tc.mu.Unlock()
	}

	hi := cc.hostinfo
	if hi == nil {
		hi = &tailcfg.Hostinfo{
			BackendLogID: "servertest-" + name,
			Hostname:     cc.hostname,
		}
	}

	direct, err := tc.newDirect(persist.Persist{}, authKey, hi)
	if err != nil {
		tb.Fatalf("servertest: NewDirect(%s): %v", name, err)
	}

	tc.direct = direct

	tb.Cleanup(func() {
		tc.cleanup()
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err = tc.tryLogin(ctx, controlclient.LoginDefault, tc.approve)
	if err != nil {
		return tc, err
	}

	// Start long-polling in the background.
	tc.startPoll(tb)

	return tc, nil
}

// newDirect builds a [controlclient.Direct] for the client's machine.
func (c *TestClient) newDirect(
	p persist.Persist,
	authKey string,
	hi *tailcfg.Hostinfo,
) (*controlclient.Direct, error) {
	direct, err := controlclient.NewDirect(controlclient.Options{
		Persist:              p,
		GetMachinePrivateKey: func() (key.MachinePrivate, error) { return c.machineKey, nil },
		ServerURL:            c.server.URL,
		AuthKey:              authKey,
		Hostinfo:             hi,
		DiscoPublicKey:       c.discoKey,
		Logf:                 c.logf,
		HealthTracker:        c.tracker,
		Dialer:               c.dialer,
		Bus:                  c.bus,
	})
	if err == nil && len(c.endpoints) > 0 {
		direct.SetEndpoints(c.endpoints)
	}

	return direct, err
}

// register performs the initial [controlclient.Direct.TryLogin] to register the client.
func (c *TestClient) register(tb testing.TB) {
	tb.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err := c.tryLogin(ctx, controlclient.LoginDefault, c.approve)
	if err != nil {
		tb.Fatalf("servertest: TryLogin(%s): %v", c.Name, err)
	}
}

// tryLogin logs the current Direct in. An auth URL is completed through
// approve, and is an error without it. A failed login is recorded in
// [TestClient.RegisterAttempts], as tailscaled logs it.
func (c *TestClient) tryLogin(ctx context.Context, flags controlclient.LoginFlags, approve func(string) error) error {
	url, err := c.direct.TryLogin(ctx, flags|c.loginFlags)

	switch {
	case err != nil:
	case url != "" && approve != nil:
		err = c.waitLogin(ctx, url, approve)
	case url != "":
		err = fmt.Errorf("unexpected auth URL %q (expected auto-auth with preauth key)", url) //nolint:err113
	}

	if err != nil {
		c.mu.Lock()
		c.registers = append(c.registers, testcapture.RegisterAttempt{Err: err.Error()})
		c.mu.Unlock()
	}

	return err
}

// waitLogin waits on the auth URL while approve completes the login it names.
func (c *TestClient) waitLogin(ctx context.Context, url string, approve func(string) error) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	done := make(chan error, 1)

	go func() {
		_, err := c.direct.WaitLoginURL(ctx, url)
		done <- err
	}()

	// The URL ends in the auth ID: /register/<id>.
	err := approve(path.Base(url))
	if err != nil {
		return err
	}

	return <-done
}

// RegisterAttempts returns the client's /machine/register exchanges as
// tailscaled logs them, with each failed login as its own entry; see
// [testcapture.AppendRegisterLine]. Node keys are short forms, not labels.
func (c *TestClient) RegisterAttempts() []testcapture.RegisterAttempt {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return slices.Clone(c.registers)
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

	c.mu.Lock()
	c.streams++
	c.streamMaps = 0
	c.stamped = false
	c.mu.Unlock()

	go func() {
		defer close(c.pollDone)

		var updater controlclient.NetmapUpdater = c
		if c.deltaUpdates {
			updater = deltaRecorder{c}
		}

		_ = c.direct.PollNetMap(c.pollCtx, updater)
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
	c.updatesReceived++
	c.streamMaps++

	if !c.noHistory {
		c.history = append(c.history, nm)
	}

	// Removals sent ahead of their batch and a deleted node's expiry carry
	// no ControlTime, so a rebuild with none before it is a response too.
	// shortcut: one right after a response a delta client applied in place
	// goes uncounted; count at the decoder if headscale sends one alone.
	if !c.stamped {
		c.frames++
	}

	c.stamped = false
	c.mu.Unlock()

	// Non-blocking send to the updates channel.
	select {
	case c.updates <- nm:
	default:
	}
}

// deltaRecorder is the [controlclient.NetmapUpdater] of a [WithDeltaUpdates]
// client. Like tailscaled it takes packet filter and user profile updates
// narrowly, which lets [controlclient.Direct] try the delta path. It
// records removals and last seen times and declines the mutations, so the
// full netmap is still delivered and the client's peer state stays exact.
type deltaRecorder struct{ *TestClient }

func (d deltaRecorder) UpdatePacketFilter(views.Slice[tailcfg.FilterRule], []filter.Match) bool {
	return true
}

func (d deltaRecorder) UpdateUserProfiles(map[tailcfg.UserID]tailcfg.UserProfileView) bool {
	return true
}

func (d deltaRecorder) UpdateNetmapDelta(muts []netmap.NodeMutation) bool {
	d.mu.Lock()
	defer d.mu.Unlock()

	for _, m := range muts {
		switch m := m.(type) {
		case netmap.NodeMutationRemove:
			d.deltaRemoved = append(d.deltaRemoved, m.NodeIDBeingMutated())
		case netmap.NodeMutationLastSeen:
			d.deltaSeen = append(d.deltaSeen, m.LastSeen)
		}
	}

	return false
}

// DeltaLastSeen returns the last seen times that arrived in a response the
// client could apply incrementally; see [WithDeltaUpdates].
func (c *TestClient) DeltaLastSeen() []time.Time {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return slices.Clone(c.deltaSeen)
}

// DeltaRemovedPeers returns the peers whose removal arrived in a response
// the client could apply incrementally; see [WithDeltaUpdates].
func (c *TestClient) DeltaRemovedPeers() []tailcfg.NodeID {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return slices.Clone(c.deltaRemoved)
}

// cleanup releases all resources.
func (c *TestClient) cleanup() {
	if c.stopFollowup != nil {
		c.stopFollowup()
	}

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

// Relogin logs the client in again with authKey, as tailscaled does for
// `tailscale up --auth-key` (force: `--force-reauth`): see [TestClient.Login],
// with the current login. The first request presents the current node key
// unless force rotates it. hi replaces the Hostinfo, so routes can be
// restated.
//
// Safe to call from non-test goroutines.
func (c *TestClient) Relogin(ctx context.Context, authKey string, force bool, hi *tailcfg.Hostinfo) error {
	flags := controlclient.LoginDefault
	if force {
		flags = controlclient.LoginInteractive
	}

	return c.Login(ctx, c.Persist(), authKey, flags, hi, nil)
}

// Login logs the machine in from p, as LocalBackend.Start does: a new
// [controlclient.Direct] keeps the machine key and presents p's node key,
// unless flags ask for a new one. p is the current login ([TestClient.Persist])
// for a relogin or restart, another profile's for a profile switch, and
// empty for a new profile. With approve set and no authKey the login is
// interactive, see [WithInteractiveLogin]. The poll restarts once the login
// succeeds; after a failed one the client does not poll.
//
// Safe to call from non-test goroutines.
func (c *TestClient) Login(
	ctx context.Context,
	p persist.Persist,
	authKey string,
	flags controlclient.LoginFlags,
	hi *tailcfg.Hostinfo,
	approve func(authID string) error,
) error {
	if c.stopFollowup != nil {
		c.stopFollowup()
	}

	if c.pollCancel != nil {
		c.pollCancel()

		select {
		case <-c.pollDone:
		case <-ctx.Done():
			return fmt.Errorf("servertest: Login(%s): poll did not exit: %w", c.Name, ctx.Err())
		}
	}

	direct, err := c.newDirect(p, authKey, hi)
	if err != nil {
		return fmt.Errorf("servertest: Login(%s): NewDirect: %w", c.Name, err)
	}

	c.direct.Close()
	c.direct = direct
	c.authKey = authKey

	err = c.tryLogin(ctx, flags, approve)
	if err != nil {
		return fmt.Errorf("servertest: Login(%s): %w", c.Name, err)
	}

	c.resetNetmapState()
	c.startPollLoop()

	return nil
}

// Restart logs the machine in again with a new disco key and no auth key,
// as a restarted tailscaled does: its login is kept, its disco key is not.
//
// Safe to call from non-test goroutines.
func (c *TestClient) Restart(ctx context.Context, hi *tailcfg.Hostinfo) error {
	c.discoKey = key.NewDisco().Public()

	return c.Login(ctx, c.Persist(), "", controlclient.LoginDefault, hi, nil)
}

// RotateDisco gives the client a new disco key and reports it, then logs in
// again and restarts the map poll on the same [controlclient.Direct], as
// `tailscale debug rotate-disco-key` does by restarting the backend. An auth
// URL is not approved: its follow-up waits, as tailscaled's does, while the
// poll goes on under the current node key.
//
// Safe to call from non-test goroutines.
func (c *TestClient) RotateDisco(ctx context.Context) error {
	c.discoKey = key.NewDisco().Public()
	c.direct.SetDiscoPublicKey(c.discoKey)

	err := c.direct.SendUpdate(ctx)
	if err != nil {
		return fmt.Errorf("servertest: RotateDisco(%s): %w", c.Name, err)
	}

	url, err := c.direct.TryLogin(ctx, controlclient.LoginDefault|c.loginFlags)
	if err != nil {
		return fmt.Errorf("servertest: RotateDisco(%s): %w", c.Name, err)
	}

	if url != "" {
		if c.stopFollowup != nil {
			c.stopFollowup()
		}

		// The follow-up outlives this call, as tailscaled's outlives the CLI.
		var fctx context.Context

		fctx, c.stopFollowup = context.WithCancel(context.WithoutCancel(ctx))
		direct := c.direct

		go func() { _, _ = direct.WaitLoginURL(fctx, url) }()
	}

	return c.RestartPoll(ctx)
}

// SetExpirySooner asks the server to expire the node's key at expiry, as
// `tailscale debug set-expire` does. A refusal is recorded in
// [TestClient.RegisterAttempts], as a failed login is.
//
// Safe to call from non-test goroutines.
func (c *TestClient) SetExpirySooner(ctx context.Context, expiry time.Time) error {
	err := c.direct.SetExpirySooner(ctx, expiry)
	if err != nil {
		c.mu.Lock()
		c.registers = append(c.registers, testcapture.RegisterAttempt{Err: err.Error()})
		c.mu.Unlock()
	}

	return err
}

// Persist returns the client's current login: its node keys and user.
func (c *TestClient) Persist() persist.Persist {
	if v := c.direct.GetPersist(); v.Valid() {
		return *v.AsStruct()
	}

	return persist.Persist{}
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

	return c.updatesReceived
}

// Frames returns how many map responses other than keep-alives the client
// has been sent: each one with a ControlTime, and each netmap rebuild from
// one without. Unlike [TestClient.UpdateCount] it also counts responses that
// a [WithDeltaUpdates] client applies without rebuilding its netmap.
func (c *TestClient) Frames() int {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return c.frames
}

// Stream returns how many map streams the client has opened, then how many
// netmaps the current one delivered. [TestClient.Netmap] outlives a stream,
// so only this tells a new stream that was answered from one that was not.
func (c *TestClient) Stream() (int, int) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return c.streams, c.streamMaps
}

// History returns the retained [netmap.NetworkMap] snapshots in order.
// It is empty when [WithoutNetmapHistory] is set.
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

// MachineKey is the client's machine key, which identifies its nodes across
// logins.
func (c *TestClient) MachineKey() key.MachinePublic {
	return c.machineKey.Public()
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
