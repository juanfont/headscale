package state

import (
	"fmt"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util/zlog/zf"
	"github.com/rs/zerolog/log"
)

// nodeHealthCheck names a class of stored-node-data defect that breaks normal
// operation and explains how to fix it. ok == true means the node passes the
// check. This is the extension point for node-data validation: add a check
// here as new corrupt-data classes surface (nil hostinfo, invalid IPs,
// tags-XOR-user violations, ...) and both the boot scan and any future caller
// run the whole set.
type nodeHealthCheck struct {
	name  string
	check func(nv types.NodeView, cfg *types.Config) (problem, fixHint string, ok bool)
}

// nodeHealthChecks is the registry of node-data health checks. Today it carries
// the one issue #3346 needs; append to it rather than reshaping callers.
var nodeHealthChecks = []nodeHealthCheck{givenNameMapsToValidFQDN}

// givenNameMapsToValidFQDN flags a node whose stored GivenName cannot produce a
// valid FQDN (empty, or longer than MaxHostnameLength once base_domain is
// applied). Such a node cannot be rendered into a netmap — neither its own nor
// any peer's — so it must be renamed to recover.
var givenNameMapsToValidFQDN = nodeHealthCheck{
	name: "given-name-maps-to-valid-fqdn",
	check: func(nv types.NodeView, cfg *types.Config) (string, string, bool) {
		err := types.ValidateGivenName(nv.GivenName(), cfg.BaseDomain)
		if err != nil {
			return err.Error(), fmt.Sprintf("headscale nodes rename %d <name>", nv.ID()), false
		}

		return "", "", true
	},
}

// nodeHealthFinding is a single failed check for a single node.
type nodeHealthFinding struct {
	nodeID   types.NodeID
	hostname string
	check    string
	problem  string
	fixHint  string
}

// scanNodeHealth runs every registered check against every node in the store
// and returns one finding per failure. It only reports — it never mutates a
// node — so an operator can repair the underlying data without the server
// silently rewriting a user-visible name.
func (s *State) scanNodeHealth() []nodeHealthFinding {
	var findings []nodeHealthFinding

	for _, nv := range s.nodeStore.ListNodes().All() {
		for _, c := range nodeHealthChecks {
			problem, fixHint, ok := c.check(nv, s.cfg)
			if ok {
				continue
			}

			findings = append(findings, nodeHealthFinding{
				nodeID:   nv.ID(),
				hostname: nv.Hostname(),
				check:    c.name,
				problem:  problem,
				fixHint:  fixHint,
			})
		}
	}

	return findings
}

// logNodeHealth scans the store once and logs an actionable warning per
// finding. Called at startup so an operator learns — by node id and fix
// command — about stored data that will break map generation, without the
// server changing anything itself.
func (s *State) logNodeHealth() {
	for _, f := range s.scanNodeHealth() {
		log.Warn().
			Uint64(zf.NodeID, f.nodeID.Uint64()).
			Str(zf.NodeHostname, f.hostname).
			Str("check", f.check).
			Str("problem", f.problem).
			Str("fix", f.fixHint).
			Msg("node has invalid data that breaks map generation; rename it to restore connectivity")
	}
}
