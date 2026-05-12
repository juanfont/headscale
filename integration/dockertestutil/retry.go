package dockertestutil

import "time"

// Docker control-plane retry policy. Every backoff loop in the
// integration suite that talks to the daemon (network attach/detach,
// container inspect, image pull) should reach for these constants
// rather than re-deriving its own intervals. libnetwork bridge
// reprogramming during a back-to-back disconnect/reconnect cycle has
// been observed to take up to ~60 s on a contended GitHub Actions
// runner, which is why MaxElapsedTime sits above the historical 30 s
// budget.
const (
	// DockerOpInitialInterval is the wait before the first retry of
	// a failed docker control-plane call. Long enough to let
	// libnetwork finish its first reprogramming pass before the
	// caller asks again.
	DockerOpInitialInterval = 1 * time.Second

	// DockerOpMaxInterval caps the per-retry wait. Without a cap the
	// default exponential backoff multiplier blows past one minute
	// after a handful of failures, which loses signal — at that
	// point a real outage is more likely than a transient race.
	DockerOpMaxInterval = 10 * time.Second

	// DockerOpMaxElapsedTime is the total budget for the retry loop.
	// Empirically chosen above the worst observed bridge
	// reprogramming time (~60 s) with margin, and well below the
	// HASlowConvergeTimeout used by tests that drive these calls
	// so the test budget isn't dominated by the helper.
	DockerOpMaxElapsedTime = 90 * time.Second
)
