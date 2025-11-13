package state

import (
	"time"
)

// Test configuration for NodeStore batching.
// These values are optimized for test speed rather than production use.
const (
	TestBatchSize    = 5
	TestBatchTimeout = 5 * time.Millisecond
)
