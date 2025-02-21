package routes

import (
	"net/netip"
	"sort"
	"sync"

	"github.com/juanfont/headscale/hscontrol/types"
	xmaps "golang.org/x/exp/maps"
	"tailscale.com/util/deephash"
	"tailscale.com/util/set"
)

type PrimaryRoutes struct {
	mu sync.Mutex

	// routes is a map of prefixes that are adverties and approved and available
	// in the global headscale state.
	routes map[types.NodeID]set.Set[netip.Prefix]

	// primaries is a map of prefixes to the node that is the primary for that prefix.
	primaries map[netip.Prefix]types.NodeID
	isPrimary map[types.NodeID]bool

	primariesHash deephash.Sum
}

func New() *PrimaryRoutes {
	return &PrimaryRoutes{
		routes:    make(map[types.NodeID]set.Set[netip.Prefix]),
		primaries: make(map[netip.Prefix]types.NodeID),
		isPrimary: make(map[types.NodeID]bool),
	}
}

// updatePrimaryLocked recalculates the primary routes and updates the internal state.
// It returns true if the primary routes have changed.
// It is assumed that the caller holds the lock.
// The algorthm is as follows:
// 1. Reset the primaries map.
// 2. Iterate over the routes and count the number of times a prefix is advertised.
// 3. If a prefix is advertised by at least two nodes, it is a primary route.
// 4. If the primary routes have changed, update the internal state and return true.
// 5. Otherwise, return false.
func (pr *PrimaryRoutes) updatePrimaryLocked() bool {
	// reset the primaries map, as we are going to recalculate it.
	newPrimaries := make(map[netip.Prefix]types.NodeID)
	pr.isPrimary = make(map[types.NodeID]bool)
	count := make(map[netip.Prefix]int)

	// sort the node ids so we can iterate over them in a deterministic order.
	// this is important so the same node is chosen two times in a row
	// as the primary route.
	ids := types.NodeIDs(xmaps.Keys(pr.routes))
	sort.Sort(ids)
	for _, id := range ids {
		prefixes := pr.routes[id]
		for prefix := range prefixes {
			if _, ok := count[prefix]; !ok {
				count[prefix] = 1
			} else {
				count[prefix]++
			}
			if _, ok := newPrimaries[prefix]; !ok {
				newPrimaries[prefix] = id
				pr.isPrimary[id] = true
			}
		}
	}

	// A primary is a route that is advertised by at least two nodes.
	for prefix, c := range count {
		if c < 2 {
			delete(newPrimaries, prefix)
		}
	}

	primariesHash := deephash.Hash(&newPrimaries)
	if primariesHash == pr.primariesHash {
		return false
	}

	if len(newPrimaries) == 0 || len(newPrimaries) == len(pr.primaries) {
		return false
	}

	pr.primaries = newPrimaries
	pr.primariesHash = primariesHash

	return true
}

func (pr *PrimaryRoutes) RegisterRoutes(node types.NodeID, prefix ...netip.Prefix) bool {
	pr.mu.Lock()
	defer pr.mu.Unlock()

	if _, ok := pr.routes[node]; !ok {
		pr.routes[node] = make(set.Set[netip.Prefix], len(prefix))
	}

	for _, p := range prefix {
		pr.routes[node].Add(p)
	}

	return pr.updatePrimaryLocked()
}

func (pr *PrimaryRoutes) DeregisterRoutes(node types.NodeID, prefix ...netip.Prefix) bool {
	pr.mu.Lock()
	defer pr.mu.Unlock()

	if _, ok := pr.routes[node]; !ok {
		return false
	}

	for _, p := range prefix {
		pr.routes[node].Delete(p)
	}

	return pr.updatePrimaryLocked()
}

func (pr *PrimaryRoutes) PrimaryRoutes(id types.NodeID) []netip.Prefix {
	if pr == nil {
		return nil
	}

	pr.mu.Lock()
	defer pr.mu.Unlock()

	// Short circuit if the node is not a primary for any route.
	if _, ok := pr.isPrimary[id]; !ok {
		return nil
	}

	var routes []netip.Prefix

	for prefix, node := range pr.primaries {
		if node == id {
			routes = append(routes, prefix)
		}
	}

	return routes
}
