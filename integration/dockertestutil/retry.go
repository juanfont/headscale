package dockertestutil

import "time"

// Docker control-plane retry policy. MaxElapsedTime sits above the
// worst observed libnetwork bridge reprogramming time (~60 s on
// contended GHA runners).
const (
	DockerOpInitialInterval = 1 * time.Second
	DockerOpMaxInterval     = 10 * time.Second
	DockerOpMaxElapsedTime  = 90 * time.Second
)
