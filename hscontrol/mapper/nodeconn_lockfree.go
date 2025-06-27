package mapper

import (
	"fmt"
	"sync/atomic"
	"unsafe"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/types/change"
	"tailscale.com/tailcfg"
)

// Connection data structure for atomic updates
type connectionData struct {
	c        chan<- []byte
	compress string
	version  tailcfg.CapabilityVersion
}

// Lock-free nodeConn using atomic pointers
type nodeConnLockFree struct {
	id     types.NodeID
	mapper *mapper

	// Atomic pointer to connection data - allows lock-free updates
	connData atomic.Pointer[connectionData]

	// Optional: statistics
	updateCount atomic.Int64
	errorCount  atomic.Int64
}

func newNodeConnLockFree(id types.NodeID, c chan<- []byte, compress string, version tailcfg.CapabilityVersion, mapper *mapper) *nodeConnLockFree {
	nc := &nodeConnLockFree{
		id:     id,
		mapper: mapper,
	}
	
	// Initialize connection data
	data := &connectionData{
		c:        c,
		compress: compress,
		version:  version,
	}
	nc.connData.Store(data)
	
	return nc
}

// updateConnection atomically updates connection parameters
func (nc *nodeConnLockFree) updateConnection(c chan<- []byte, compress string, version tailcfg.CapabilityVersion) {
	newData := &connectionData{
		c:        c,
		compress: compress,
		version:  version,
	}
	nc.connData.Store(newData)
}

// matchesChannel checks if the given channel matches current connection
func (nc *nodeConnLockFree) matchesChannel(c chan<- []byte) bool {
	data := nc.connData.Load()
	if data == nil {
		return false
	}
	// Compare channel pointers
	return uintptr(unsafe.Pointer(&data.c)) == uintptr(unsafe.Pointer(&c))
}

// compressAndVersion atomically reads connection settings
func (nc *nodeConnLockFree) compressAndVersion() (string, tailcfg.CapabilityVersion) {
	data := nc.connData.Load()
	if data == nil {
		return "", 0
	}
	return data.compress, data.version
}

// change handles updates without locking
func (nc *nodeConnLockFree) change(c change.Change) error {
	switch determineChange(c) {
	case partialUpdate:
		return nc.partialUpdate(c)
	case fullUpdate:
		return nc.fullUpdate()
	default:
		return nil
	}
}

func (nc *nodeConnLockFree) partialUpdate(c change.Change) error {
	var data []byte
	var err error
	
	if c.DERPChanged {
		compress, _ := nc.compressAndVersion()
		data, err = nc.mapper.derpMapResponse(nc.id, compress)
	}

	if err != nil {
		nc.errorCount.Add(1)
		return err
	}

	return nc.send(data)
}

func (nc *nodeConnLockFree) fullUpdate() error {
	compress, version := nc.compressAndVersion()
	data, err := nc.mapper.fullMapResponse(nc.id, version, compress)
	if err != nil {
		nc.errorCount.Add(1)
		return err
	}

	return nc.send(data)
}

// send attempts non-blocking send
func (nc *nodeConnLockFree) send(data []byte) error {
	connData := nc.connData.Load()
	if connData == nil {
		return fmt.Errorf("node %d: no connection data", nc.id)
	}

	select {
	case connData.c <- data:
		nc.updateCount.Add(1)
		return nil
	default:
		nc.errorCount.Add(1)
		return fmt.Errorf("node %d: channel full", nc.id)
	}
}

// GetStats returns lock-free statistics
func (nc *nodeConnLockFree) GetStats() (updates, errors int64) {
	return nc.updateCount.Load(), nc.errorCount.Load()
}

// Add missing methods for compatibility
func (nc *nodeConnLockFree) updateConnectionUnsafe(c chan<- []byte, compress string, version tailcfg.CapabilityVersion) {
	nc.updateConnection(c, compress, version)
}

func (nc *nodeConnLockFree) matchesChannelUnsafe(c chan<- []byte) bool {
	return nc.matchesChannel(c)
}