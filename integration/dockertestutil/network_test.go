package dockertestutil

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

var (
	errTransientEndpointExists = errors.New("endpoint with name foo already exists in network bar")
	errPermanent               = errors.New("permanent error")
)

func TestRetryDockerOp_RecoversFromTransient(t *testing.T) {
	var attempts atomic.Int32

	op := func() error {
		if attempts.Add(1) < 3 {
			return errTransientEndpointExists
		}

		return nil
	}

	err := retryDockerOp(context.Background(), op)
	if err != nil {
		t.Fatalf("retryDockerOp should recover from 2 transient errors, got: %v", err)
	}

	if got := attempts.Load(); got != 3 {
		t.Fatalf("expected 3 attempts, got %d", got)
	}
}

func TestRetryDockerOp_RespectsContextCancellation(t *testing.T) {
	op := func() error {
		return errPermanent
	}

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	start := time.Now()
	err := retryDockerOp(ctx, op)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("retryDockerOp should fail when op always errors")
	}

	if elapsed > 5*time.Second {
		t.Fatalf("retryDockerOp should honour ctx deadline (~200ms), took %s", elapsed)
	}
}
