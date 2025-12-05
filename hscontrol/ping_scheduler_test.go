package hscontrol

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestNewPingScheduler(t *testing.T) {
	t.Parallel()

	cfg := PingSchedulerConfig{
		Enabled:  true,
		Interval: 2 * time.Minute,
		Jitter:   30 * time.Second,
		Timeout:  10 * time.Second,
	}

	// Create a minimal headscale instance for testing
	// Note: This will be nil for the app reference in tests
	ps := NewPingScheduler(nil, cfg)

	assert.NotNil(t, ps)
	assert.True(t, ps.IsEnabled())
	assert.Equal(t, 2*time.Minute, ps.interval)
	assert.Equal(t, 30*time.Second, ps.jitter)
	assert.Equal(t, 10*time.Second, ps.timeout)
	assert.Equal(t, 0, ps.GetScheduledChecksCount())
}

func TestPingSchedulerDisabled(t *testing.T) {
	t.Parallel()

	cfg := PingSchedulerConfig{
		Enabled:  false,
		Interval: 2 * time.Minute,
		Jitter:   30 * time.Second,
		Timeout:  10 * time.Second,
	}

	ps := NewPingScheduler(nil, cfg)

	assert.NotNil(t, ps)
	assert.False(t, ps.IsEnabled())
}

func TestCalculateJitter(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		jitterDuration time.Duration
	}{
		{
			name:           "30 second jitter",
			jitterDuration: 30 * time.Second,
		},
		{
			name:           "1 minute jitter",
			jitterDuration: 1 * time.Minute,
		},
		{
			name:           "zero jitter",
			jitterDuration: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := PingSchedulerConfig{
				Enabled:  true,
				Interval: 2 * time.Minute,
				Jitter:   tt.jitterDuration,
				Timeout:  10 * time.Second,
			}

			ps := NewPingScheduler(nil, cfg)

			// Test multiple times to ensure randomness
			for i := 0; i < 10; i++ {
				jitter := ps.calculateJitter()

				if tt.jitterDuration == 0 {
					assert.Equal(t, time.Duration(0), jitter, "zero jitter should always return 0")
				} else {
					assert.GreaterOrEqual(t, jitter, time.Duration(0), "jitter should be non-negative")
					assert.LessOrEqual(t, jitter, tt.jitterDuration, "jitter should not exceed max")
				}
			}
		})
	}
}

func TestPingSchedulerStopBeforeStart(t *testing.T) {
	t.Parallel()

	cfg := PingSchedulerConfig{
		Enabled:  true,
		Interval: 2 * time.Minute,
		Jitter:   30 * time.Second,
		Timeout:  10 * time.Second,
	}

	ps := NewPingScheduler(nil, cfg)

	// Stop should be safe to call even if Start was never called
	assert.NotPanics(t, func() {
		ps.Stop()
	})
}
