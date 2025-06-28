package mapper

import (
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/types/change"
	"github.com/puzpuzpuz/xsync/v4"
	"tailscale.com/tailcfg"
)

// Batcher defines the common interface for all batcher implementations
type Batcher interface {
	Start()
	Close()
	AddNode(id types.NodeID, c chan<- []byte, compress string, version tailcfg.CapabilityVersion)
	RemoveNode(id types.NodeID, c chan<- []byte)
	IsConnected(id types.NodeID) bool
	IsLikelyConnected(id types.NodeID) bool
	LikelyConnectedMap() *xsync.Map[types.NodeID, bool]
	AddWork(c change.Change)
}