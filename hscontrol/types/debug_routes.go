package types

import "net/netip"

// DebugRoutes is the JSON-shaped snapshot of the headscale primary
// route ledger exposed by the /debug/routes endpoint and consumed by
// the integration test harness. It used to live in hscontrol/routes,
// but the algorithm now runs inside hscontrol/state and that package
// must not be imported from integration code.
type DebugRoutes struct {
	// AvailableRoutes maps node IDs to their advertised routes
	// (intersection of announced and approved). Only nodes currently
	// connected to headscale are listed.
	AvailableRoutes map[NodeID][]netip.Prefix `json:"available_routes"`

	// PrimaryRoutes maps route prefixes to the node currently elected
	// primary for that prefix.
	PrimaryRoutes map[string]NodeID `json:"primary_routes"`

	// UnhealthyNodes lists nodes that have failed health probes.
	UnhealthyNodes []NodeID `json:"unhealthy_nodes,omitempty"`
}
