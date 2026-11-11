package hscontrol_test

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol"
	"github.com/juanfont/headscale/hscontrol/servertest"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/tsnet"
)

var errUnexpectedDial = errors.New("unexpected system dial")

const (
	embeddedHostname = "tailsql"
	embeddedTag      = "tag:tailsql"
)

// TestEmbeddedNode proves an embedded node joins headscale's own tailnet over
// memnet, keeps its identity across restarts without minting a new key, and
// re-joins under its name after an admin deletes it.
func TestEmbeddedNode(t *testing.T) {
	srv := servertest.NewServer(t)
	dir := t.TempDir()
	controlAddr := strings.TrimPrefix(srv.URL, "http://")

	// Control is the only thing reached through SystemDial in this test.
	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		if addr == controlAddr {
			return srv.MemNet().Dial(ctx, network, addr)
		}

		return nil, fmt.Errorf("%w to %s", errUnexpectedDial, addr)
	}

	start := func(t *testing.T) (*tsnet.Server, context.CancelFunc) {
		t.Helper()

		// The context bounds the node's whole life, rejoin watcher included.
		ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)

		ts, err := hscontrol.NewEmbeddedNode(ctx, srv.State(), dial, srv.URL, dir, embeddedHostname, embeddedTag)
		require.NoError(t, err)

		return ts, func() {
			cancel()
			ts.Close()
		}
	}

	embeddedNodes := func() []types.NodeView {
		var out []types.NodeView

		for _, nv := range srv.State().ListNodes().All() {
			if nv.HasTag(embeddedTag) {
				out = append(out, nv)
			}
		}

		return out
	}

	keyCount := func(t *testing.T) int {
		t.Helper()

		keys, err := srv.State().ListPreAuthKeys()
		require.NoError(t, err)

		return len(keys)
	}

	var firstID types.NodeID

	t.Run("join", func(t *testing.T) {
		_, stop := start(t)
		defer stop()

		nodes := embeddedNodes()
		require.Len(t, nodes, 1)
		assert.Equal(t, embeddedHostname, nodes[0].GivenName())
		assert.True(t, nodes[0].IsTagged())
		assert.False(t, nodes[0].UserID().Valid(), "an embedded node belongs to no user")

		firstID = nodes[0].ID()
	})

	t.Run("restart_keeps_identity", func(t *testing.T) {
		keysBefore := keyCount(t)

		_, stop := start(t)
		defer stop()

		nodes := embeddedNodes()
		require.Len(t, nodes, 1)
		assert.Equal(t, firstID, nodes[0].ID())
		assert.Equal(t, keysBefore, keyCount(t), "a known identity must not mint a key")
	})

	t.Run("rejoins_after_delete", func(t *testing.T) {
		_, stop := start(t)
		defer stop()

		nv, ok := srv.State().GetNodeByID(firstID)
		require.True(t, ok)

		changes, err := srv.State().DeleteNode(nv)
		require.NoError(t, err)
		srv.App.Change(changes...)

		assert.EventuallyWithT(t, func(c *assert.CollectT) {
			nodes := embeddedNodes()
			if !assert.Len(c, nodes, 1) {
				return
			}

			assert.NotEqual(c, firstID, nodes[0].ID())
			assert.Equal(c, embeddedHostname, nodes[0].GivenName())
		}, 60*time.Second, 200*time.Millisecond, "deleted embedded node must re-join under its name")
	})
}
