package routes

import (
	"fmt"
	"net/netip"
	"slices"
	"sort"
	"strings"
	"sync"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/rs/zerolog/log"
	xmaps "golang.org/x/exp/maps"
	"tailscale.com/net/tsaddr"
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
// The algorithm is as follows:
// 1. Reset the primaries map.
// 2. Iterate over the routes and count the number of times a prefix is advertised.
// 3. If a prefix is advertised by at least two nodes, it is a primary route.
// 4. If the primary routes have changed, update the internal state and return true.
// 5. Otherwise, return false.
func (pr *PrimaryRoutes) updatePrimaryLocked() bool {
	log.Debug().Caller().Msg("updatePrimaryLocked starting")

	// reset the primaries map, as we are going to recalculate it.
	allPrimaries := make(map[netip.Prefix][]types.NodeID)
	pr.isPrimary = make(map[types.NodeID]bool)
	changed := false

	// sort the node ids so we can iterate over them in a deterministic order.
	// this is important so the same node is chosen two times in a row
	// as the primary route.
	ids := types.NodeIDs(xmaps.Keys(pr.routes))
	sort.Sort(ids)

	// Create a map of prefixes to nodes that serve them so we
	// can determine the primary route for each prefix.
	for _, id := range ids {
		routes := pr.routes[id]
		for route := range routes {
			if _, ok := allPrimaries[route]; !ok {
				allPrimaries[route] = []types.NodeID{id}
			} else {
				allPrimaries[route] = append(allPrimaries[route], id)
			}
		}
	}

	// Go through all prefixes and determine the primary route for each.
	// If the number of routes is below the minimum, remove the primary.
	// If the current primary is still available, continue.
	// If the current primary is not available, select a new one.
	for prefix, nodes := range allPrimaries {
		log.Debug().
			Caller().
			Str("prefix", prefix.String()).
			Uints64("availableNodes", func() []uint64 {
				ids := make([]uint64, len(nodes))
				for i, id := range nodes {
					ids[i] = id.Uint64()
				}

				return ids
			}()).
			Msg("Processing prefix for primary route selection")

		if node, ok := pr.primaries[prefix]; ok {
			// If the current primary is still available, continue.
			if slices.Contains(nodes, node) {
				log.Debug().
					Caller().
					Str("prefix", prefix.String()).
					Uint64("currentPrimary", node.Uint64()).
					Msg("Current primary still available, keeping it")

				continue
			} else {
				log.Debug().
					Caller().
					Str("prefix", prefix.String()).
					Uint64("oldPrimary", node.Uint64()).
					Msg("Current primary no longer available")
			}
		}
		if len(nodes) >= 1 {
			pr.primaries[prefix] = nodes[0]
			changed = true
			log.Debug().
				Caller().
				Str("prefix", prefix.String()).
				Uint64("newPrimary", nodes[0].Uint64()).
				Msg("Selected new primary for prefix")
		}
	}

	// Clean up any remaining primaries that are no longer valid.
	for prefix := range pr.primaries {
		if _, ok := allPrimaries[prefix]; !ok {
			log.Debug().
				Caller().
				Str("prefix", prefix.String()).
				Msg("Cleaning up primary route that no longer has available nodes")
			delete(pr.primaries, prefix)
			changed = true
		}
	}

	// Populate the quick lookup index for primary routes
	for _, nodeID := range pr.primaries {
		pr.isPrimary[nodeID] = true
	}

	log.Debug().
		Caller().
		Bool("changed", changed).
		Str("finalState", pr.stringLocked()).
		Msg("updatePrimaryLocked completed")

	return changed
}

// SetRoutes sets the routes for a given Node ID and recalculates the primary routes
// of the headscale.
// It returns true if there was a change in primary routes.
// All exit routes are ignored as they are not used in primary route context.
func (pr *PrimaryRoutes) SetRoutes(node types.NodeID, prefixes ...netip.Prefix) bool {
	pr.mu.Lock()
	defer pr.mu.Unlock()

	log.Debug().
		Caller().
		Uint64("node.id", node.Uint64()).
		Strs("prefixes", util.PrefixesToString(prefixes)).
		Msg("PrimaryRoutes.SetRoutes called")

	// If no routes are being set, remove the node from the routes map.
	if len(prefixes) == 0 {
		wasPresent := false
		if _, ok := pr.routes[node]; ok {
			delete(pr.routes, node)
			wasPresent = true
			log.Debug().
				Caller().
				Uint64("node.id", node.Uint64()).
				Msg("Removed node from primary routes (no prefixes)")
		}
		changed := pr.updatePrimaryLocked()
		log.Debug().
			Caller().
			Uint64("node.id", node.Uint64()).
			Bool("wasPresent", wasPresent).
			Bool("changed", changed).
			Str("newState", pr.stringLocked()).
			Msg("SetRoutes completed (remove)")

		return changed
	}

	rs := make(set.Set[netip.Prefix], len(prefixes))
	for _, prefix := range prefixes {
		if !tsaddr.IsExitRoute(prefix) {
			rs.Add(prefix)
		}
	}

	if rs.Len() != 0 {
		pr.routes[node] = rs
		log.Debug().
			Caller().
			Uint64("node.id", node.Uint64()).
			Strs("routes", util.PrefixesToString(rs.Slice())).
			Msg("Updated node routes in primary route manager")
	} else {
		delete(pr.routes, node)
		log.Debug().
			Caller().
			Uint64("node.id", node.Uint64()).
			Msg("Removed node from primary routes (only exit routes)")
	}

	changed := pr.updatePrimaryLocked()
	log.Debug().
		Caller().
		Uint64("node.id", node.Uint64()).
		Bool("changed", changed).
		Str("newState", pr.stringLocked()).
		Msg("SetRoutes completed (update)")

	return changed
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

	tsaddr.SortPrefixes(routes)

	return routes
}

func (pr *PrimaryRoutes) String() string {
	pr.mu.Lock()
	defer pr.mu.Unlock()

	return pr.stringLocked()
}

func (pr *PrimaryRoutes) stringLocked() string {
	var sb strings.Builder

	fmt.Fprintln(&sb, "Available routes:")

	ids := types.NodeIDs(xmaps.Keys(pr.routes))
	sort.Sort(ids)
	for _, id := range ids {
		prefixes := pr.routes[id]
		fmt.Fprintf(&sb, "\nNode %d: %s", id, strings.Join(util.PrefixesToString(prefixes.Slice()), ", "))
	}

	fmt.Fprintln(&sb, "\n\nCurrent primary routes:")
	for route, nodeID := range pr.primaries {
		fmt.Fprintf(&sb, "\nRoute %s: %d", route, nodeID)
	}

	return sb.String()
}

// DebugRoutes represents the primary routes state in a structured format for JSON serialization.
type DebugRoutes struct {
	// AvailableRoutes maps node IDs to their advertised routes
	// In the context of primary routes, this represents the routes that are available
	// for each node. A route will only be available if it is advertised by the node
	// AND approved.
	// Only routes by nodes currently connected to the headscale server are included.
	AvailableRoutes map[types.NodeID][]netip.Prefix `json:"available_routes"`

	// PrimaryRoutes maps route prefixes to the primary node serving them
	PrimaryRoutes map[string]types.NodeID `json:"primary_routes"`
}

// DebugJSON returns a structured representation of the primary routes state suitable for JSON serialization.
func (pr *PrimaryRoutes) DebugJSON() DebugRoutes {
	pr.mu.Lock()
	defer pr.mu.Unlock()

	debug := DebugRoutes{
		AvailableRoutes: make(map[types.NodeID][]netip.Prefix),
		PrimaryRoutes:   make(map[string]types.NodeID),
	}

	// Populate available routes
	for nodeID, routes := range pr.routes {
		prefixes := routes.Slice()
		tsaddr.SortPrefixes(prefixes)
		debug.AvailableRoutes[nodeID] = prefixes
	}

	// Populate primary routes
	for prefix, nodeID := range pr.primaries {
		debug.PrimaryRoutes[prefix.String()] = nodeID
	}

	return debug
}
