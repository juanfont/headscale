package client

import (
	"context"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestDialEnds: the dial of a socket that is not there tries again until
// the timeout, then says why the last try failed, whatever the context
// of the transport, which never ends.
func TestDialEnds(t *testing.T) {
	t.Parallel()

	s := &socket{
		path:    filepath.Join(t.TempDir(), "none.sock"),
		timeout: 60 * time.Millisecond,
	}
	done := make(chan error, 1)

	go func() {
		//nolint:usetesting // the transport's dial context never ends
		_, err := s.dial(context.Background())
		done <- err
	}()

	select {
	case err := <-done:
		require.ErrorIs(t, err, syscall.ENOENT)
	case <-time.After(10 * time.Second):
		t.Fatal("the dial still retries after the timeout")
	}
}
