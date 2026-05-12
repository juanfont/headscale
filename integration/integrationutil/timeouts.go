package integrationutil

import "time"

// CI-scaled convergence budgets. ScaledTimeout doubles each on CI.
var (
	// HAConvergeTimeout: routes / ACL / policy propagation to reach
	// every node and show up in status, traceroute, or curl.
	HAConvergeTimeout = ScaledTimeout(60 * time.Second)

	// HASlowConvergeTimeout: multi-step failover sequences that need
	// at least one HA prober cycle plus a data-plane settle.
	HASlowConvergeTimeout = ScaledTimeout(120 * time.Second)

	// PolicyPropagationTimeout: post-SetPolicy filter rules and peer
	// reachability to reflect the change.
	PolicyPropagationTimeout = ScaledTimeout(90 * time.Second)

	// AuthFlowTimeout: OIDC / web-auth / preauth-key flows to reach
	// Running.
	AuthFlowTimeout = ScaledTimeout(30 * time.Second)

	// StatusReadyTimeout: post-event read to reflect the event
	// (created node visible in list, set tags visible on node).
	StatusReadyTimeout = ScaledTimeout(30 * time.Second)
)

// Polling intervals for EventuallyWithT.
const (
	// FastPoll: in-process reads (HA state, route table snapshots).
	FastPoll = 200 * time.Millisecond

	// SlowPoll: cross-container reads (tailscale status, curl,
	// headscale API) where each tick pays a docker exec round-trip.
	SlowPoll = 500 * time.Millisecond

	// PingPoll: gap between full ping-matrix sweeps.
	PingPoll = 2 * time.Second
)
