package cli

import (
	"context"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDialHeadscaleSocketRetriesUntilPresent proves the CLI socket dialer
// tolerates a not-yet-created socket (the server-still-starting race) by
// retrying until it appears, rather than failing immediately like a bare dial.
func TestDialHeadscaleSocketRetriesUntilPresent(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "headscale.sock")

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	type result struct {
		conn net.Conn
		err  error
	}

	done := make(chan result, 1)

	go func() {
		conn, err := dialHeadscaleSocket(ctx, sock)
		done <- result{conn, err}
	}()

	// Listen only after the dialer has begun, so its backoff must retry the
	// absent socket and connect once it exists.
	var lc net.ListenConfig

	ln, err := lc.Listen(ctx, "unix", sock)
	require.NoError(t, err)

	defer ln.Close()

	go func() {
		if conn, _ := ln.Accept(); conn != nil {
			conn.Close()
		}
	}()

	res := <-done
	require.NoError(t, res.err)
	require.NotNil(t, res.conn)

	res.conn.Close()
}

// TestDialHeadscaleSocketRespectsDeadline proves the retry is bounded by the
// context: when the socket never appears, the dialer returns an error around the
// deadline instead of hanging.
func TestDialHeadscaleSocketRespectsDeadline(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "absent.sock")

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	start := time.Now()

	conn, err := dialHeadscaleSocket(ctx, sock)
	require.Error(t, err)
	assert.Nil(t, conn)
	assert.Less(t, time.Since(start), 5*time.Second, "should stop near the deadline, not hang")
}
