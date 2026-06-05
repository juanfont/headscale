package state

import (
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"tailscale.com/tailcfg"
)

// TestNoOpMapRequestSkipsPersist ensures an identical, no-op MapRequest does
// not issue a database UPDATE (nor the O(n) policy SetNodes scan that follows
// persistNodeToDB). The node state is unchanged, so persisting is pure waste on
// the hot map-request path.
func TestNoOpMapRequestSkipsPersist(t *testing.T) {
	_, s, nodeID := persistTestSetup(t)
	t.Cleanup(func() { _ = s.Close() })

	var nodeUpdateCount atomic.Int64

	gdb := s.DB().DB
	cbName := "noop_count_node_updates"
	err := gdb.Callback().Update().After("gorm:update").Register(cbName, func(tx *gorm.DB) {
		if tx.Statement == nil {
			return
		}

		if tx.Statement.Table == "nodes" ||
			strings.Contains(strings.ToLower(tx.Statement.SQL.String()), "update \"nodes\"") {
			nodeUpdateCount.Add(1)
		}
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = gdb.Callback().Update().Remove(cbName) })

	nv, ok := s.GetNodeByID(nodeID)
	require.True(t, ok, "node should exist in NodeStore")

	stored := nv.AsStruct()

	req := tailcfg.MapRequest{
		NodeKey:  stored.NodeKey,
		DiscoKey: stored.DiscoKey,
		Hostinfo: &tailcfg.Hostinfo{
			Hostname: stored.Hostname,
			NetInfo:  &tailcfg.NetInfo{PreferredDERP: 1},
		},
	}

	// First request establishes the Hostinfo/DERP state (expected to persist).
	_, err = s.UpdateNodeFromMapRequest(nodeID, req)
	require.NoError(t, err)

	nodeUpdateCount.Store(0)

	// Second request is value-identical: a no-op.
	req2 := tailcfg.MapRequest{
		NodeKey:  stored.NodeKey,
		DiscoKey: stored.DiscoKey,
		Hostinfo: &tailcfg.Hostinfo{
			Hostname: stored.Hostname,
			NetInfo:  &tailcfg.NetInfo{PreferredDERP: 1},
		},
	}

	_, err = s.UpdateNodeFromMapRequest(nodeID, req2)
	require.NoError(t, err)

	require.Equalf(t, int64(0), nodeUpdateCount.Load(),
		"no-op MapRequest should not issue any nodes-table UPDATE, got %d",
		nodeUpdateCount.Load())
}
