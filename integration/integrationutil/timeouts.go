package integrationutil

import "time"

// Convergence timeouts. Every EventuallyWithT block in the integration
// suite waiting for the data plane to reflect a control-plane change
// should pick from this set rather than re-deriving its own
// ScaledTimeout(N*time.Second). The values are wrapped in
// ScaledTimeout so they automatically double on CI.
//
// Picking the right constant matters because the floor of a category
// determines how flaky tests in that category are: too short and the
// suite flakes on slow CI; too long and a real regression hides
// behind the timeout.
//
// These are variables, not constants, because ScaledTimeout reads
// util.IsCI(). The values are stable for the lifetime of the process.
var (
	// HAConvergeTimeout is the default budget for routes / ACL /
	// policy propagation reaching every node and being reflected in
	// `tailscale status`, traceroute paths, or curl reachability.
	HAConvergeTimeout = ScaledTimeout(60 * time.Second)

	// HASlowConvergeTimeout covers multi-step failover sequences
	// (e.g. dual primary loss, docker network disconnect) where the
	// HA prober needs at least one full detection cycle plus the
	// usual data-plane settle. Use this only when HAConvergeTimeout
	// is empirically too short.
	HASlowConvergeTimeout = ScaledTimeout(120 * time.Second)

	// PolicyPropagationTimeout is the budget for the suite to see a
	// freshly-applied policy take effect at the node, both
	// server-side (DebugFilter rules) and client-side (peer
	// reachability after policy refresh).
	PolicyPropagationTimeout = ScaledTimeout(90 * time.Second)

	// AuthFlowTimeout is the budget for OIDC / web-auth / preauth-key
	// flows to complete and the node to reach the Running backend
	// state. Auth flows are state-machine driven, not propagation
	// driven, so this is shorter than the convergence budgets.
	AuthFlowTimeout = ScaledTimeout(30 * time.Second)

	// StatusReadyTimeout is the budget for a post-event read to
	// reflect the event: e.g. after creating a node, listing nodes
	// returns it; after setting tags, fetching the node shows them.
	// These reads should be near-instant but the database write
	// barrier can take a tick on a busy runner.
	StatusReadyTimeout = ScaledTimeout(30 * time.Second)
)

// Polling intervals for EventuallyWithT. Trade off responsiveness
// against load on the docker daemon and the headscale process under
// test. Per-test custom intervals are fine when an event has a known
// signal, but the defaults below cover most cases.
const (
	// FastPoll is appropriate for in-process state reads where a tight
	// loop is cheap: HA prober state, NodeStore snapshot reads, route
	// table inspection.
	FastPoll = 200 * time.Millisecond

	// SlowPoll is for cross-container reads where each tick pays for
	// a docker exec round-trip or a MapResponse: tailscale status,
	// curl reachability, headscale API calls.
	SlowPoll = 500 * time.Millisecond

	// PingPoll is the gap between consecutive ping-matrix sweeps,
	// chosen so a full sweep can complete before the next starts on
	// a slow CI runner.
	PingPoll = 2 * time.Second
)
