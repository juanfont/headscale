package v2

import (
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gaissmai/bart"
	"github.com/juanfont/headscale/hscontrol/ipset"
	"github.com/juanfont/headscale/hscontrol/policy/packetfilter"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/rs/zerolog/log"
	"tailscale.com/net/tsaddr"
	"tailscale.com/tailcfg"
	"tailscale.com/types/views"
	"tailscale.com/util/deephash"
	"tailscale.com/util/multierr"
)

// ErrInvalidTagOwner is returned when a tag owner is not an [Alias] type.
var ErrInvalidTagOwner = errors.New("tag owner is not an Alias")

type PolicyManager struct {
	// RWMutex, not Mutex, so concurrent map generation does not serialise on
	// reads. The per-node caches are xsync.Maps so a read can fill them without
	// taking the write lock.
	mu    sync.RWMutex
	pol   *Policy
	users []types.User
	nodes views.Slice[types.NodeView]

	filterHash deephash.Sum
	view       ReadView

	tagOwnerMapHash deephash.Sum
	tagOwnerMap     map[Tag]ipset.Set

	exitApproversHash deephash.Sum
	exitApprovers     ipset.Set
	autoApproversHash deephash.Sum
	autoApprovers     *bart.Table[ipset.Set]

	// relayTargetIPs holds the IPs of nodes that are destinations of a
	// tailscale.com/cap/relay grant; viaTargetTags holds the tags used as
	// via targets. A node matching either, or that is a subnet router,
	// forces peers to recompute their netmap when its online state changes
	// (see [PolicyManager.NodeNeedsPeerRecompute]). Recomputed from the
	// compiled grants on every policy/user/node change.
	relayTargetIPs ipset.Set
	viaTargetTags  map[Tag]struct{}

	// needsPerNodeFilter is true when any compiled grant requires
	// per-node work (autogroup:self or via grants).
	needsPerNodeFilter bool

	// nodeAttrsMap is the per-node CapMap compiled from policy.NodeAttrs.
	// nodeAttrsHashes shadow it for change detection between updateLocked
	// runs. nodeAttrsChanged accumulates the union of all per-call diffs
	// since the last drain — refresh APPENDS, never overwrites, so a
	// concurrent SetUsers/SetNodes between SetPolicy and the drain
	// cannot silently lose the policy-reload diff.
	nodeAttrsMap     map[types.NodeID]tailcfg.NodeCapMap
	nodeAttrsHashes  map[types.NodeID]deephash.Sum
	nodeAttrsChanged []types.NodeID

	// nodesGen counts SetNodes calls that reported a change, so a caller
	// can tell the policy moved even when another goroutine (the
	// NodeStore writer) applied the SetNodes.
	nodesGen atomic.Uint64

	// nodeAttrsPending mirrors len(nodeAttrsChanged) > 0 so the drain,
	// called on every dispatched change, skips pm.mu when idle.
	nodeAttrsPending atomic.Bool
}

// filterAndPolicy combines the compiled filter rules with policy content for hashing.
// This ensures filterHash changes when policy changes, even for autogroup:self where
// the compiled filter is always empty.
type filterAndPolicy struct {
	Filter []deephash.Sum
	Policy *Policy
}

// validateUserReferences surfaces ambiguous user@ tokens at policy load so
// duplicate DB rows fail loudly instead of silently dropping rules.
// Missing-user tokens stay tolerant. Empty users → no-op for
// syntax-only checks.
func validateUserReferences(pol *Policy, users types.Users) error {
	if pol == nil || len(users) == 0 {
		return nil
	}

	var errs []error

	check := func(u *Username) {
		if u == nil {
			return
		}

		_, err := u.resolveUser(users)
		if err != nil && errors.Is(err, ErrMultipleUsersFound) {
			errs = append(errs, err)
		}
	}

	checkAlias := func(a Alias) {
		if u, ok := a.(*Username); ok {
			check(u)
		}
	}

	checkOwner := func(o Owner) {
		if u, ok := o.(*Username); ok {
			check(u)
		}
	}

	checkAutoApprover := func(aa AutoApprover) {
		if u, ok := aa.(*Username); ok {
			check(u)
		}
	}

	for _, usernames := range pol.Groups {
		for i := range usernames {
			check(&usernames[i])
		}
	}

	for _, owners := range pol.TagOwners {
		for _, o := range owners {
			checkOwner(o)
		}
	}

	for _, approvers := range pol.AutoApprovers.Routes {
		for _, aa := range approvers {
			checkAutoApprover(aa)
		}
	}

	for _, aa := range pol.AutoApprovers.ExitNode {
		checkAutoApprover(aa)
	}

	for _, acl := range pol.ACLs {
		for _, src := range acl.Sources {
			checkAlias(src)
		}

		for _, dst := range acl.Destinations {
			checkAlias(dst.Alias)
		}
	}

	for _, ssh := range pol.SSHs {
		for _, src := range ssh.Sources {
			checkAlias(src)
		}

		for _, dst := range ssh.Destinations {
			checkAlias(dst)
		}
	}

	return multierr.New(errs...)
}

// NewPolicyManager creates a new [PolicyManager] from a policy file and a list of users and nodes.
// It returns an error if the policy file is invalid.
// The policy manager will update the filter rules based on the users and nodes.
func NewPolicyManager(b []byte, users []types.User, nodes views.Slice[types.NodeView],
) (*PolicyManager, error) {
	policy, err := unmarshalPolicy(b)
	if err != nil {
		return nil, fmt.Errorf("parsing policy: %w", err)
	}

	err = validateUserReferences(policy, users)
	if err != nil {
		return nil, fmt.Errorf("validating policy user references: %w", err)
	}

	pm := PolicyManager{
		pol:   policy,
		users: users,
		nodes: nodes,
	}

	_, err = pm.updateLocked()
	if err != nil {
		return nil, err
	}

	// Boot path: log a warning if the stored policy's tests would
	// fail against the current users and nodes, but keep the server
	// running. A stale stored policy (e.g. referencing a user that
	// was deleted while the server was offline) should not block
	// boot; the operator finds out via logs and re-runs the write
	// boundary when they are ready.
	if testErr := pm.RunTests(); testErr != nil { //nolint:noinlineerr // boot path: warn-and-continue, not return
		log.Warn().Err(testErr).Msg("policy tests failed at boot; server starting anyway, fix the policy and reload")
	}

	if testErr := pm.RunSSHTests(); testErr != nil { //nolint:noinlineerr // boot path: warn-and-continue, not return
		log.Warn().Err(testErr).Msg("policy sshTests failed at boot; server starting anyway, fix the policy and reload")
	}

	return &pm, nil
}

// updateLocked updates the filter rules based on the current policy and nodes.
// It must be called with the lock held. Every step that can fail runs before
// pm is written, so a caller that restores its own input on error leaves pm
// as it was, and a retry with the same input recompiles.
func (pm *PolicyManager) updateLocked() (bool, error) {
	// Compile all grants once. Both global and per-node filter
	// rules are derived from these compiled grants.
	grants := pm.pol.compileGrants(pm.users, pm.nodes)

	relayTargetIPs, err := collectRelayTargetIPs(grants)
	if err != nil {
		return false, fmt.Errorf("collecting relay target IPs: %w", err)
	}

	// Order matters, tags might be used in autoapprovers, so we need to ensure
	// that the map for tag owners is resolved before resolving autoapprovers.
	// TODO(kradalby): Order might not matter after #2417
	tagMap, err := resolveTagOwners(pm.pol, pm.users, pm.nodes)
	if err != nil {
		return false, fmt.Errorf("resolving tag owners map: %w", err)
	}

	autoApprovers, exitApprovers, err := resolveAutoApprovers(pm.pol, pm.users, pm.nodes)
	if err != nil {
		return false, fmt.Errorf("resolving auto approvers map: %w", err)
	}

	// Fast path for the common steady-state shape: tailnet has no
	// nodeAttrs entries and never had any. Skip the compile + per-node
	// hash walk entirely. As soon as the operator adds a nodeAttrs
	// entry pm.nodeAttrsHashes becomes non-empty and the gate opens.
	refreshNodeAttrs := pm.pol == nil ||
		len(pm.pol.NodeAttrs) > 0 ||
		pm.pol.RandomizeClientPort ||
		len(pm.nodeAttrsHashes) > 0

	var nodeAttrs map[types.NodeID]tailcfg.NodeCapMap
	if refreshNodeAttrs {
		nodeAttrs, err = pm.pol.compileNodeAttrs(pm.users, pm.nodes)
		if err != nil {
			return false, fmt.Errorf("compiling nodeAttrs: %w", err)
		}
	}

	caps := nodeAttrs
	if !refreshNodeAttrs {
		caps = pm.nodeAttrsMap
	}

	view := newReadView(pm.pol, pm.users, pm.nodes, grants, caps)
	filter := view.PacketRules()

	ruleHashes := make([]deephash.Sum, len(filter))
	for i, rule := range filter {
		ruleHashes[i] = rule.Hash()
	}

	pm.needsPerNodeFilter = hasPerNodeGrants(grants)
	pm.viaTargetTags = collectViaTargetTags(grants)
	pm.relayTargetIPs = relayTargetIPs
	// Hash both the compiled filter AND the policy content together.
	// This ensures filterHash changes when policy changes, even for autogroup:self
	// where the compiled filter is always empty. This eliminates the need for
	// a separate policyHash field.
	filterHash := deephash.Hash(&filterAndPolicy{
		Filter: ruleHashes,
		Policy: pm.pol,
	})

	filterChanged := filterHash != pm.filterHash
	if filterChanged {
		log.Debug().
			Str("filter.hash.old", pm.filterHash.String()[:8]).
			Str("filter.hash.new", filterHash.String()[:8]).
			Int("filter.rules", len(pm.view.PacketRules())).
			Int("filter.rules.new", len(filter)).
			Msg("Policy filter hash changed")
	}

	pm.view = view
	pm.users = view.generation.users
	pm.nodes = view.generation.nodes
	pm.filterHash = filterHash

	tagPrefixes := make(map[Tag][]netip.Prefix, len(tagMap))
	for tag, addresses := range tagMap {
		tagPrefixes[tag] = slices.Collect(addresses.Prefixes())
	}

	tagOwnerMapHash := deephash.Hash(&tagPrefixes)

	tagOwnerChanged := tagOwnerMapHash != pm.tagOwnerMapHash
	if tagOwnerChanged {
		log.Debug().
			Str("tagOwner.hash.old", pm.tagOwnerMapHash.String()[:8]).
			Str("tagOwner.hash.new", tagOwnerMapHash.String()[:8]).
			Int("tagOwners.old", len(pm.tagOwnerMap)).
			Int("tagOwners.new", len(tagMap)).
			Msg("Tag owner hash changed")
	}

	pm.tagOwnerMap = tagMap
	pm.tagOwnerMapHash = tagOwnerMapHash

	type autoApproverEntry struct {
		Route     netip.Prefix
		Approvers []netip.Prefix
	}

	autoPrefixes := make([]autoApproverEntry, 0, autoApprovers.Size())
	for route, addresses := range autoApprovers.AllSorted() {
		autoPrefixes = append(autoPrefixes, autoApproverEntry{
			Route:     route,
			Approvers: slices.Collect(addresses.Prefixes()),
		})
	}

	autoApproversHash := deephash.Hash(&autoPrefixes)

	autoApproveChanged := autoApproversHash != pm.autoApproversHash
	if autoApproveChanged {
		var oldCount int
		if pm.autoApprovers != nil {
			oldCount = pm.autoApprovers.Size()
		}

		log.Debug().
			Str("autoApprove.hash.old", pm.autoApproversHash.String()[:8]).
			Str("autoApprove.hash.new", autoApproversHash.String()[:8]).
			Int("autoApprovers.old", oldCount).
			Int("autoApprovers.new", autoApprovers.Size()).
			Msg("Auto-approvers hash changed")
	}

	pm.autoApprovers = autoApprovers
	pm.autoApproversHash = autoApproversHash

	exitPrefixes := slices.Collect(exitApprovers.Prefixes())
	exitApproversHash := deephash.Hash(&exitPrefixes)

	exitSetChanged := exitApproversHash != pm.exitApproversHash
	if exitSetChanged {
		log.Debug().
			Str("exitSet.hash.old", pm.exitApproversHash.String()[:8]).
			Str("exitSet.hash.new", exitApproversHash.String()[:8]).
			Msg("Exit node set hash changed")
	}

	pm.exitApprovers = exitApprovers
	pm.exitApproversHash = exitApproversHash

	// Install the per-node nodeAttrs CapMap and append the diff to
	// pm.nodeAttrsChanged. The drain (NodesWithChangedCapMap) returns
	// the accumulated union of every change since the last drain;
	// SetUsers/SetNodes appending between SetPolicy and the drain
	// cannot lose the policy-reload diff.
	if refreshNodeAttrs {
		pm.refreshNodeAttrsLocked(nodeAttrs)
	}

	// Determine if we need to send updates to nodes
	// filterChanged now includes policy content changes (via combined hash),
	// so it will detect changes even for autogroup:self where compiled filter is empty
	needsUpdate := filterChanged || tagOwnerChanged || autoApproveChanged || exitSetChanged

	// If nothing changed, no need to update nodes
	if !needsUpdate {
		log.Trace().
			Msg("Policy evaluation detected no changes - all hashes match")

		return false, nil
	}

	log.Debug().
		Bool("filter.changed", filterChanged).
		Bool("tagOwners.changed", tagOwnerChanged).
		Bool("autoApprovers.changed", autoApproveChanged).
		Bool("exitNodes.changed", exitSetChanged).
		Msg("Policy changes require node updates")

	return true, nil
}

// NodeNeedsPeerRecompute reports whether peers must recompute their netmap
// when node's online state changes. A plain node only needs the lightweight
// online/offline peer patch; these roles change what peers compute when the
// node goes up or down, so they require a full recompute:
//   - subnet router: primary-route failover changes peers' AllowedIPs
//   - relay target (tailscale.com/cap/relay): peers must drop a stale
//     PeerRelay allocation
//   - via target: peers steer traffic through this node
//
// The check is keyed on the node itself, so an ordinary node in a tailnet
// that uses relay or via for other nodes is correctly classified as not
// needing a recompute.
func (pm *PolicyManager) NodeNeedsPeerRecompute(node types.NodeView) bool {
	if !node.Valid() {
		return false
	}

	// Subnet-router status is intrinsic to the node, so it needs no policy
	// state and is checked without the lock.
	if node.IsSubnetRouter() {
		return true
	}

	pm.mu.RLock()
	defer pm.mu.RUnlock()

	if node.InIPSet(pm.relayTargetIPs) {
		return true
	}

	for tag := range pm.viaTargetTags {
		if node.HasTag(string(tag)) {
			return true
		}
	}

	return false
}

// SSHPolicy returns the [tailcfg.SSHPolicy] for node, compiling and
// caching on first access. Rules use SessionDuration = 0 (no
// auto-approval) and emit check URLs of the form
// /machine/ssh/action/{src}/to/{dst}?local_user={local_user} per the
// SaaS wire format. Each captured generation owns its typed decision cache.
func (pm *PolicyManager) SSHPolicy(baseURL string, node types.NodeView,
) (*tailcfg.SSHPolicy, error) {
	return pm.ReadView().SSHPolicy(baseURL, node)
}

// SSHCheckParams resolves the SSH check period for src logging in to dst
// as localUser by looking up the current policy. This avoids trusting URL
// parameters that a client could tamper with. First-match wins across
// the policy's SSH rules; a rule only matches when it lets src log in as
// localUser, as the client does when it picks the rule.
//
// Returns (duration, true) when a matching rule is found and
// (0, false) when none is. A (0, true) return means the matched rule
// uses a zero check period (re-check every session).
func (pm *PolicyManager) SSHCheckParams(
	src, dst types.NodeID,
	localUser string,
) (time.Duration, bool) {
	return pm.ReadView().SSHCheckParams(src, dst, localUser)
}

func (pm *PolicyManager) SetPolicy(polB []byte) (bool, error) {
	if len(polB) == 0 {
		return false, nil
	}

	pol, err := unmarshalPolicy(polB)
	if err != nil {
		return false, fmt.Errorf("parsing policy: %w", err)
	}

	pm.mu.Lock()
	defer pm.mu.Unlock()

	err = validateUserReferences(pol, pm.users)
	if err != nil {
		return false, fmt.Errorf("validating policy user references: %w", err)
	}

	// SetPolicy is the user-write boundary. Tests evaluate against a
	// sandbox compiled from the new policy + current users/nodes; if
	// they fail, return without mutating the live PolicyManager so the
	// failed write does not knock the running config offline.
	//
	// Aggregate ACL and SSH test failures via multierr so operators
	// see both classes in a single response instead of having to
	// fix-and-retry to discover the second one.
	testErr := multierr.New(
		evaluateTests(pol, pm.users, pm.nodes),
		evaluateSSHTests(pol, pm.users, pm.nodes),
	)
	if testErr != nil {
		return false, testErr
	}

	// Log policy metadata for debugging
	log.Debug().
		Int("policy.bytes", len(polB)).
		Int("acls.count", len(pol.ACLs)).
		Int("groups.count", len(pol.Groups)).
		Int("hosts.count", len(pol.Hosts)).
		Int("tagOwners.count", len(pol.TagOwners)).
		Int("nodeAttrs.count", len(pol.NodeAttrs)).
		Int("autoApprovers.routes.count", len(pol.AutoApprovers.Routes)).
		Int("tests.count", len(pol.Tests)).
		Msg("Policy parsed successfully")

	prev := pm.pol
	pm.pol = pol

	changed, err := pm.updateLocked()
	if err != nil {
		// pm still holds what prev compiled to.
		pm.pol = prev

		return false, err
	}

	return changed, nil
}

func (pm *PolicyManager) ReadView() ReadView {
	if pm == nil {
		return ReadView{}
	}

	pm.mu.RLock()
	defer pm.mu.RUnlock()

	return pm.view
}

func (pm *PolicyManager) PacketRules() []packetfilter.Rule { return pm.ReadView().PacketRules() }

func (pm *PolicyManager) PacketRulesForNode(
	node types.NodeView,
) ([]packetfilter.Rule, error) {
	return pm.ReadView().PacketRulesForNode(node)
}

func (pm *PolicyManager) PeerRulesForNode(
	node types.NodeView,
) ([]packetfilter.Rule, error) {
	return pm.ReadView().PeerRulesForNode(node)
}

func (pm *PolicyManager) BuildPeerMap(nodes views.Slice[types.NodeView],
) map[types.NodeID][]types.NodeID {
	view := pm.ReadView()
	if !view.Valid() {
		return nil
	}

	return view.generation.buildPeerMap(nodes)
}

func (pm *PolicyManager) SetNodesAndBuildPeerMap(
	nodes views.Slice[types.NodeView],
) (ReadView, map[types.NodeID][]types.NodeID, error) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	_, err := pm.setNodesLocked(nodes)
	if err != nil {
		return ReadView{}, nil, err
	}

	return pm.view, pm.view.generation.buildPeerMap(nodes), nil
}

func ruleIncludesInternet(rule packetfilter.Rule) bool {
	destinations := rule.DestinationSet()

	return destinations.ContainsPrefix(tsaddr.AllIPv4()) ||
		destinations.ContainsPrefix(tsaddr.AllIPv6()) ||
		destinations.ContainsSet(util.TheInternet())
}

//nolint:gocyclo // Preserve the existing global and dynamic bitset algorithms together.
func (g *compiledGeneration) buildPeerMap(
	nodes views.Slice[types.NodeView],
) map[types.NodeID][]types.NodeID {
	index := g.peer

	same := nodes.Len() == g.nodes.Len()
	if same {
		for i, node := range nodes.All() {
			own := g.nodes.At(i)
			if node.ID() != own.ID() || node.HasPolicyChange(own) ||
				node.HasNetworkChanges(own) {
				same = false
				break
			}
		}
	}

	if !same {
		index = g.buildRuleIndex(nodes, false)
	}

	rules := index.rules
	// Precompute each node's subnet routes and exit-node status once; the
	// O(n^2) pair scans below would otherwise recompute them for every pair.
	type nodeRoutes struct {
		subnet []netip.Prefix
		isExit bool
	}

	routeInfo := make(map[types.NodeID]nodeRoutes, nodes.Len())
	for _, n := range nodes.All() {
		routeInfo[n.ID()] = nodeRoutes{subnet: n.SubnetRoutes(), isExit: n.IsExitNode()}
	}

	// If we have a global filter, use it for all nodes (normal case).
	// Via grants require the per-node path because the global filter
	// skips via grants (compileFilterRules: if len(grant.Via) > 0 { continue }).
	if !hasPerNodeGrants(g.grants) {
		ret := make(map[types.NodeID][]types.NodeID, nodes.Len())

		// A matcher lets a reach b when a satisfies its source side and b
		// its destination side, exactly as [types.Node.CanAccess] tests
		// them, and each side depends on one node only. So evaluate both
		// sides once per node, as bitsets over rules, instead of
		// once per pair: a can reach b iff a's source set and b's
		// destination set intersect. That turns the O(n^2 * matchers)
		// scan into O(n * matchers) set lookups plus O(n^2) word ANDs.
		// Bit k represents rules[k]: word k/64, position k%64.
		words := (len(rules) + 63) / 64 //nolint:mnd
		ids := make([]types.NodeID, nodes.Len())
		srcOf := make([][]uint64, nodes.Len()) // nil: source of no matcher
		dstOf := make([][]uint64, nodes.Len()) // nil: destination of no matcher

		for i, n := range nodes.All() {
			ids[i] = n.ID()
			if !n.Valid() {
				continue
			}

			ips, ri := n.IPs(), routeInfo[n.ID()]
			routed := len(ri.subnet) > 0

			for k := range rules {
				m := rules[k]

				if slices.ContainsFunc(ips, m.Sources().Contains) || (routed && slices.ContainsFunc(ri.subnet, m.Sources().OverlapsPrefix)) {
					if srcOf[i] == nil {
						srcOf[i] = make([]uint64, words)
					}

					srcOf[i][k/64] |= 1 << (k % 64) //nolint:mnd
				}

				if slices.ContainsFunc(ips, m.DestinationSet().Contains) || (routed && slices.ContainsFunc(ri.subnet, m.DestinationSet().OverlapsPrefix)) ||
					(ri.isExit && ruleIncludesInternet(m)) {
					if dstOf[i] == nil {
						dstOf[i] = make([]uint64, words)
					}

					dstOf[i][k/64] |= 1 << (k % 64) //nolint:mnd
				}
			}
		}

		canAccess := func(src, dst []uint64) bool {
			if src == nil || dst == nil {
				return false
			}

			for w := range src {
				if src[w]&dst[w] != 0 {
					return true
				}
			}

			return false
		}

		// Build the map of all peers according to the matchers.
		for i := range ids {
			for j := i + 1; j < len(ids); j++ {
				if ids[i] == ids[j] {
					continue
				}

				if canAccess(srcOf[i], dstOf[j]) || canAccess(srcOf[j], dstOf[i]) {
					ret[ids[i]] = append(ret[ids[i]], ids[j])
					ret[ids[j]] = append(ret[ids[j]], ids[i])
				}
			}
		}

		return ret
	}

	// Per-node rules can repeat across devices owned by the same user and
	// across via routers. Share their evaluation, while retaining which
	// nodes supplied each rule: a rule may connect a pair only when it
	// belongs to at least one end of that pair.
	ret := make(map[types.NodeID][]types.NodeID, nodes.Len())

	ids := make([]types.NodeID, nodes.Len())
	ips := make([][]netip.Addr, nodes.Len())
	routes := make([]nodeRoutes, nodes.Len())
	hasExit := false

	for i, node := range nodes.All() {
		ids[i], ips[i] = node.ID(), node.IPs()
		routes[i] = routeInfo[node.ID()]
		hasExit = hasExit || routes[i].isExit
	}

	// Scratch sets are reused per rule; adjacency stores only nonzero
	// words, so sparse peer groups do not allocate a full node-pair matrix.
	const wordBits = 64

	words := (nodes.Len() + wordBits - 1) / wordBits
	sources, destinations := make([]uint64, words), make([]uint64, words)
	adjacency := make([]map[int]uint64, nodes.Len())

	for ruleID, rule := range rules {
		owners := index.owners[ruleID].ordinals
		if index.owners[ruleID].unrestricted {
			owners = make([]int, nodes.Len())
			for i := range owners {
				owners[i] = i
			}
		}

		if len(owners) == 0 {
			continue
		}

		clear(sources)
		clear(destinations)

		internet := hasExit && ruleIncludesInternet(rule)

		for i := range ids {
			ri := routes[i]
			if slices.ContainsFunc(ips[i], rule.Sources().Contains) ||
				(len(ri.subnet) > 0 && slices.ContainsFunc(ri.subnet, rule.Sources().OverlapsPrefix)) {
				sources[i/wordBits] |= 1 << (i % wordBits)
			}

			if slices.ContainsFunc(ips[i], rule.DestinationSet().Contains) ||
				(len(ri.subnet) > 0 && slices.ContainsFunc(ri.subnet, rule.DestinationSet().OverlapsPrefix)) ||
				(ri.isExit && internet) {
				destinations[i/wordBits] |= 1 << (i % wordBits)
			}
		}

		for _, owner := range owners {
			src := sources[owner/wordBits]&(1<<(owner%wordBits)) != 0

			dst := destinations[owner/wordBits]&(1<<(owner%wordBits)) != 0
			if !src && !dst {
				continue
			}

			for w := range sources {
				var peers uint64
				if src {
					peers |= destinations[w]
				}

				if dst {
					peers |= sources[w]
				}

				if w == owner/wordBits {
					peers &^= 1 << (owner % wordBits)
				}

				if peers == 0 {
					continue
				}

				if adjacency[owner] == nil {
					adjacency[owner] = make(map[int]uint64)
				}

				adjacency[owner][w] |= peers
			}
		}
	}

	// Retain symmetric visibility and the original pair traversal order,
	// including pairs whose views happen to share a NodeID.
	for i := range ids {
		for j := i + 1; j < len(ids); j++ {
			fromI := adjacency[i][j/wordBits]&(1<<(j%wordBits)) != 0

			fromJ := adjacency[j][i/wordBits]&(1<<(i%wordBits)) != 0
			if fromI || fromJ {
				ret[ids[i]] = append(ret[ids[i]], ids[j])
				ret[ids[j]] = append(ret[ids[j]], ids[i])
			}
		}
	}

	return ret
}

// SetUsers replaces the user list and recompiles when it changed. Both results
// are false for an unchanged list, so callers can skip the peer-map rebuild
// and the client refresh that a user change would otherwise require.
func (pm *PolicyManager) SetUsers(users []types.User) (bool, bool, error) {
	if pm == nil {
		return false, false, nil
	}

	pm.mu.Lock()
	defer pm.mu.Unlock()

	if equalUsers(pm.users, users) {
		return false, false, nil
	}

	prev := pm.users
	pm.users = users

	// SSH policies and autogroup:self sources resolve users by name, and
	// the self sources are outside the filter hash, so updateLocked can
	// report no change while per-node results moved.

	policyChanged, err := pm.updateLocked()
	if err != nil {
		// Keep the old list, which pm is still compiled from, so a retry
		// with the same input recompiles instead of being treated as
		// unchanged.
		pm.users = prev

		return false, false, err
	}

	// SSH rules and per-node filters embed user identity outside the filter
	// hash, so a user change needs a client refresh even when it did not move.
	if pm.needsPerNodeFilter || (pm.pol != nil && len(pm.pol.SSHs) > 0) {
		policyChanged = true
	}

	return policyChanged, true, nil
}

// equalUsers compares user lists ignoring order and every field the policy
// does not read, so a row touch such as an OIDC login is not a change.
func equalUsers(a, b []types.User) bool {
	if len(a) != len(b) {
		return false
	}

	byID := func(l, r types.User) int { return cmp.Compare(l.ID, r.ID) }
	a, b = slices.SortedFunc(slices.Values(a), byID), slices.SortedFunc(slices.Values(b), byID)

	return slices.EqualFunc(a, b, func(l, r types.User) bool { return l.PolicyEqual(&r) })
}

// SetNodes updates the nodes in the policy manager and updates the filter rules.
func (pm *PolicyManager) SetNodes(nodes views.Slice[types.NodeView]) (bool, error) {
	if pm == nil {
		return false, nil
	}

	pm.mu.Lock()
	defer pm.mu.Unlock()

	return pm.setNodesLocked(nodes)
}

func (pm *PolicyManager) setNodesLocked(
	nodes views.Slice[types.NodeView],
) (bool, error) {
	policyChanged := pm.nodesHavePolicyAffectingChanges(nodes)

	// Invalidate cache entries for nodes that changed.
	// For autogroup:self: invalidate all nodes belonging to affected users (peer changes).
	// For global policies: invalidate only nodes whose properties changed (IPs, routes).

	prevNodes := pm.nodes
	pm.nodes = nodes

	// When policy-affecting node properties change, we must recompile filters because:
	// 1. User/group aliases (like "user1@") resolve to node IPs
	// 2. Tag aliases (like "tag:server") match nodes based on their tags
	// 3. Filter compilation needs nodes to generate rules
	//
	// For autogroup:self: return true when nodes change even if the global filter
	// hash didn't change. The global filter is empty for autogroup:self (each node
	// has its own filter), so the hash never changes. But peer relationships DO
	// change when nodes are added/removed, so we must signal this to trigger updates.
	// For global policies: the filter must be recompiled to include the new nodes.
	if policyChanged {
		// Recompile filter with the new node list
		_, err := pm.updateLocked()
		if err != nil {
			// Keep the old list, which pm is still compiled from, so a
			// retry with the same input recompiles, as in SetUsers. The
			// NodeStore writer only logs this error; the writing caller's
			// own SetNodes then retries and returns it.
			pm.nodes = prevNodes

			return false, err
		}

		// Always return true when nodes changed, even if filter hash didn't change
		// (can happen with autogroup:self or when nodes are added but don't affect rules).
		// A SetNodes that moves pm back to an older snapshot counts too; the
		// extra PolicyChange it causes is deduplicated downstream.
		pm.nodesGen.Add(1)

		return true, nil
	}

	return false, nil
}

// NodesGeneration returns how many SetNodes calls have reported a change.
// A value past the last one a caller acted on means some SetNodes since
// then, possibly run on another goroutine, moved the policy.
func (pm *PolicyManager) NodesGeneration() uint64 {
	if pm == nil {
		return 0
	}

	return pm.nodesGen.Load()
}

func nodeIDViewMap(s views.Slice[types.NodeView]) map[types.NodeID]types.NodeView {
	m := make(map[types.NodeID]types.NodeView, s.Len())
	for _, n := range s.All() {
		m[n.ID()] = n
	}

	return m
}

func (pm *PolicyManager) nodesHavePolicyAffectingChanges(newNodes views.Slice[types.NodeView],
) bool {
	if pm.nodes.Len() != newNodes.Len() {
		return true
	}

	oldNodes := nodeIDViewMap(pm.nodes)

	for _, newNode := range newNodes.All() {
		oldNode, exists := oldNodes[newNode.ID()]
		if !exists {
			return true
		}

		if newNode.HasPolicyChange(oldNode) {
			return true
		}

		// Via grants and autogroup:self compile filter rules per-node
		// that depend on the node's route state (SubnetRoutes, ExitRoutes).
		// Route changes are policy-affecting in this context because they
		// alter which filter rules get generated for the via-designated node.
		if newNode.HasNetworkChanges(oldNode) {
			return true
		}
	}

	return false
}

// NodeCanHaveTag checks if a node can have the specified tag during client-initiated
// registration or reauth flows (e.g., tailscale up --advertise-tags).
//
// This function is NOT used by the admin API's [state.State.SetNodeTags] - admins can
// set any existing tag on any node by calling [state.State.SetNodeTags] directly,
// which bypasses this authorization check.
func (pm *PolicyManager) NodeCanHaveTag(node types.NodeView, tag string) bool {
	if pm == nil {
		return false
	}

	pm.mu.RLock()
	defer pm.mu.RUnlock()

	// pm.pol is written by SetPolicy under pm.mu; reading it before the
	// lock races with concurrent policy reloads.
	if pm.pol == nil {
		return false
	}

	// Check if tag exists in policy
	owners, exists := pm.pol.TagOwners[Tag(tag)]
	if !exists {
		return false
	}

	// Check if node's owner can assign this tag via the pre-resolved tagOwnerMap.
	// The tagOwnerMap contains IP sets built from resolving TagOwners entries
	// (usernames/groups) to their nodes' IPs, so checking if the node's IP
	// is in the set answers "does this node's owner own this tag?"
	if ips, ok := pm.tagOwnerMap[Tag(tag)]; ok {
		if node.InIPSet(ips) {
			return true
		}
	}

	// For new nodes being registered, their IP may not yet be in the tagOwnerMap.
	// Fall back to checking the node's user directly against the TagOwners.
	// This handles the case where a user registers a new node with --advertise-tags.
	if node.User().Valid() {
		for _, owner := range owners {
			if pm.userMatchesOwner(node.User(), owner) {
				return true
			}
		}
	}

	return false
}

// UserCanHaveTag reports whether the given user is one of the tag's owners
// (directly or via a group). It is the user half of [PolicyManager.NodeCanHaveTag]:
// re-authentication authorises requested tags against the authenticating user,
// because a tag-owned node carries no user and its IP is not in any owner set,
// so only the user presenting the credential can prove ownership.
func (pm *PolicyManager) UserCanHaveTag(user types.UserView, tag string) bool {
	if pm == nil || !user.Valid() {
		return false
	}

	pm.mu.RLock()
	defer pm.mu.RUnlock()

	if pm.pol == nil {
		return false
	}

	owners, exists := pm.pol.TagOwners[Tag(tag)]
	if !exists {
		return false
	}

	for _, owner := range owners {
		if pm.userMatchesOwner(user, owner) {
			return true
		}
	}

	return false
}

// TagOwnedByTags reports whether a credential holding ownerTags is authorised to
// apply tag. It is true when tag is one of ownerTags, or when tag's tagOwners
// chain (tag-to-tag ownership) transitively includes one of ownerTags. This is
// the tag-level check used when an OAuth access token mints an auth key: the
// requested tags must each be owned by the token's tags, so an operator token
// tagged tag:k8s-operator may mint tag:k8s keys when the policy declares
// "tag:k8s": ["tag:k8s-operator"]. It is purely tag-relational and does not
// consult node IPs.
func (pm *PolicyManager) TagOwnedByTags(tag string, ownerTags []string) bool {
	if pm == nil {
		return false
	}

	owns := make(map[string]bool, len(ownerTags))
	for _, t := range ownerTags {
		owns[t] = true
	}

	// A credential may always apply a tag it directly holds; this needs no policy.
	if owns[tag] {
		return true
	}

	pm.mu.RLock()
	defer pm.mu.RUnlock()

	// Owned-by delegation requires the policy's tagOwners.
	if pm.pol == nil {
		return false
	}

	// Walk tag-to-tag ownership transitively, guarding against cycles.
	visited := make(map[Tag]bool)

	var walk func(t Tag) bool

	walk = func(t Tag) bool {
		if visited[t] {
			return false
		}

		visited[t] = true

		for _, owner := range pm.pol.TagOwners[t] {
			ot, ok := owner.(*Tag)
			if !ok {
				continue
			}

			if owns[string(*ot)] || walk(*ot) {
				return true
			}
		}

		return false
	}

	return walk(Tag(tag))
}

// userMatchesOwner checks if a user matches a tag owner entry.
// This is used as a fallback when the node's IP is not in the [PolicyManager.tagOwnerMap].
func (pm *PolicyManager) userMatchesOwner(user types.UserView, owner Owner) bool {
	switch o := owner.(type) {
	case *Username:
		if o == nil {
			return false
		}
		// Resolve the username to find the user it refers to
		resolvedUser, err := o.resolveUser(pm.users)
		if err != nil {
			return false
		}

		return user.ID() == resolvedUser.ID

	case *Group:
		if o == nil || pm.pol == nil {
			return false
		}
		// Resolve the group to get usernames
		usernames, ok := pm.pol.Groups[*o]
		if !ok {
			return false
		}
		// Check if the user matches any username in the group
		for _, uname := range usernames {
			resolvedUser, err := uname.resolveUser(pm.users)
			if err != nil {
				continue
			}

			if user.ID() == resolvedUser.ID {
				return true
			}
		}

		return false

	default:
		return false
	}
}

// TagExists reports whether the given tag is defined in the policy.
func (pm *PolicyManager) TagExists(tag string) bool {
	if pm == nil {
		return false
	}

	pm.mu.RLock()
	defer pm.mu.RUnlock()

	// pm.pol is written by SetPolicy under pm.mu; reading it before the
	// lock races with concurrent policy reloads.
	if pm.pol == nil {
		return false
	}

	_, exists := pm.pol.TagOwners[Tag(tag)]

	return exists
}

func (pm *PolicyManager) NodeCanApproveRoute(node types.NodeView, route netip.Prefix,
) bool {
	// Approval and storage must refer to the same canonical route.
	if pm == nil || !route.IsValid() || route != route.Masked() {
		return false
	}

	pm.mu.RLock()
	defer pm.mu.RUnlock()

	// If the route to-be-approved is an exit route, then we need to check
	// if the node is in allowed to approve it. This is treated differently
	// than the auto-approvers, as the auto-approvers are not allowed to
	// approve the whole /0 range.
	// However, an auto approver might be /0, meaning that they can approve
	// all routes available, just not exit nodes.
	if tsaddr.IsExitRoute(route) {
		if pm.exitApprovers.IsEmpty() {
			return false
		}

		return node.InIPSet(pm.exitApprovers)
	}

	if pm.autoApprovers == nil {
		return false
	}

	// A narrower entry can miss while a broader entry authorizes the node.
	ips := node.IPs()
	for _, approvers := range pm.autoApprovers.Supernets(route) {
		if slices.ContainsFunc(ips, approvers.Contains) {
			return true
		}
	}

	return false
}

// ViaRoutesForPeer computes via grant effects for a viewer-peer pair.
// For each via grant where the viewer matches the source, it checks whether the
// peer advertises any of the grant's destination prefixes. If the peer has the
// via tag, those prefixes go into [types.ViaRouteResult.Include]; otherwise
// into [types.ViaRouteResult.Exclude].
//
//nolint:gocyclo // three-pass via-grant resolution (match, primary election, regular-overlap)
type viaViewer struct {
	grants    []compiledGrant
	primaries []map[netip.Prefix]types.NodeID
}

func (v ReadView) prepareVia(
	viewer types.NodeView,
	nodes views.Slice[types.NodeView],
) viaViewer {
	var prepared viaViewer

	hasVia := false

	if !v.Valid() {
		return prepared
	}

	ips := viewer.IPs()
	for _, grant := range v.generation.grants {
		if !slices.ContainsFunc(ips, grant.sources.Viewer.Contains) {
			continue
		}

		prepared.grants = append(prepared.grants, grant)
		primaries := make(map[netip.Prefix]types.NodeID)

		if grant.via != nil {
			hasVia = true

			for _, node := range nodes.All() {
				if !node.Online() || node.Unhealthy() {
					continue
				}

				if !slices.ContainsFunc(
					grant.via.viaTags,
					func(tag Tag) bool { return node.HasTag(string(tag)) },
				) {
					continue
				}

				for _, route := range node.SubnetRoutes() {
					if current := primaries[route]; current == 0 ||
						node.ID() < current {
						primaries[route] = node.ID()
					}
				}
			}
		}

		prepared.primaries = append(prepared.primaries, primaries)
	}

	if !hasVia {
		return viaViewer{}
	}

	return prepared
}

func (pm *PolicyManager) ViaRoutesForPeer(viewer, peer types.NodeView,
) types.ViaRouteResult {
	v := pm.ReadView()
	if !v.Valid() {
		return types.ViaRouteResult{}
	}

	return v.prepareVia(viewer, v.generation.nodes).routesForPeer(viewer, peer)
}

func (v ReadView) ViaRoutesForViewer(
	viewer types.NodeView,
	nodes views.Slice[types.NodeView],
) map[types.NodeID]types.ViaRouteResult {
	result := make(map[types.NodeID]types.ViaRouteResult)

	prepared := v.prepareVia(viewer, nodes)
	for _, peer := range nodes.All() {
		result[peer.ID()] = prepared.routesForPeer(viewer, peer)
	}

	return result
}

//nolint:gocyclo // Preserve via matching, independent elections, and regular overrides.
func (prepared viaViewer) routesForPeer(
	viewer, peer types.NodeView,
) types.ViaRouteResult {
	var result types.ViaRouteResult

	if len(prepared.grants) == 0 || viewer.ID() == peer.ID() {
		return result
	}

	grants := prepared.grants
	for _, grant := range grants {
		if grant.via == nil {
			continue
		}

		// Filter rules and [tailcfg.Node.AllowedIPs] are different layers.
		// The filter rule carries the dst (the authorisation surface).
		// [tailcfg.Node.AllowedIPs] carries the advertised route (the
		// routing fact the viewer needs to pick this peer). This loop
		// builds the AllowedIPs side, so it emits routes — not dst
		// prefixes.
		peerSubnetRoutes := peer.SubnetRoutes()

		var matchedPrefixes []netip.Prefix

		for _, dstPrefix := range grant.viewerDsts {
			for _, route := range peerSubnetRoutes {
				if dstPrefix.Overlaps(route) {
					matchedPrefixes = append(matchedPrefixes, route)
				}
			}
		}

		// Per-viewer steering for autogroup:internet: a peer advertising
		// approved exit routes is the via-tagged node's analogue of
		// "advertises the destination". The downstream Include/Exclude
		// split below restricts the viewer to exit nodes carrying the
		// via tag.
		if grant.autoGroupInternet && peer.IsExitNode() {
			matchedPrefixes = append(matchedPrefixes, peer.ExitRoutes()...)
		}

		if len(matchedPrefixes) == 0 {
			continue
		}

		// Check if peer has any of the via tags.
		peerHasVia := false

		for _, viaTag := range grant.via.viaTags {
			if peer.HasTag(string(viaTag)) {
				peerHasVia = true

				break
			}
		}

		if peerHasVia {
			result.Include = append(result.Include, matchedPrefixes...)
		} else {
			result.Exclude = append(result.Exclude, matchedPrefixes...)
		}
	}

	// Detect prefixes that should fall back to HA primary election
	// rather than per-viewer via steering. Two conditions trigger this:
	//
	// 1. Multi-router via: a via grant's tag matches multiple peers
	//    advertising the same prefix.
	// 2. Regular grant overlap: a non-via grant also covers the same
	//    prefix for this viewer.
	//
	// When neither condition is met, per-viewer via steering applies.
	if len(result.Include) > 0 || len(result.Exclude) > 0 {
		// Multi-router via election: when a via grant's tag matches
		// multiple peers advertising the same prefix, only the
		// lowest-ID online, healthy peer (the via-group primary) keeps the
		// prefix in Include. The others move to Exclude. This mirrors HA
		// primary election scoped to the via tag group.
		//
		// Unlike the global [tailcfg.Node.PrimaryRoutes] election
		// (routes/primary.go), which picks one primary across ALL
		// advertisers of a prefix, this election is scoped to the via tag.
		// Two via grants with different tags (e.g., tag:ha-a vs tag:ha-b)
		// each elect their own winner independently.
		//
		// Only process via grants where the viewer matches the source,
		// otherwise grants for other viewer groups would incorrectly
		// demote the peer.
		// No previous via primary is retained, so an all-unhealthy group
		// has no winner, as in HA election without a previous candidate.
		for i, grant := range grants {
			if grant.via == nil {
				continue
			}

			// Elect per matched route, not per dst — a peer can only
			// be primary for a prefix it actually advertises, and one
			// dst may cover multiple distinct routes.
			for _, dstPrefix := range grant.viewerDsts {
				for _, included := range slices.Clone(result.Include) {
					if !dstPrefix.Overlaps(included) {
						continue
					}

					viaPrimaryID := prepared.primaries[i][included]

					if !tsaddr.IsExitRoute(included) &&
						(!peer.Online() || peer.Unhealthy() ||
							(viaPrimaryID != 0 && peer.ID() != viaPrimaryID)) {
						result.Include = slices.DeleteFunc(result.Include, func(p netip.Prefix) bool {
							return p == included
						},
						)
						if !slices.Contains(result.Exclude, included) {
							result.Exclude = append(result.Exclude, included)
						}
					}
				}
			}
		}

		// Check for regular (non-via) grants covering the same prefix.
		// When a regular grant also covers a prefix that a via grant
		// included, defer to global HA primary election (UsePrimary).
		// When a regular grant covers a prefix that a via grant excluded
		// (peer lacks via tag), remove the exclusion so
		// [state.State.RoutesForPeer] can apply normal
		// [policy.ReduceRoutes] + primary logic.
		for _, grant := range grants {
			if grant.via != nil {
				continue
			}

			// A non-via grant covering routes that a via grant included
			// defers to global HA primary election. Match by overlap so
			// a broader or narrower regular dst still catches the
			// routes the via grant added to Include.
			for _, dstPrefix := range grant.viewerDsts {
				for _, p := range result.Include {
					if dstPrefix.Overlaps(p) &&
						!slices.Contains(result.UsePrimary, p) {
						result.UsePrimary = append(result.UsePrimary, p)
					}
				}

				// Every address overlaps an exit route, so overlap
				// only decides for subnet routes.
				result.Exclude = slices.DeleteFunc(result.Exclude, func(p netip.Prefix) bool {
					return !tsaddr.IsExitRoute(p) && dstPrefix.Overlaps(p)
				},
				)
			}

			// A regular grant to the internet lets the viewer use any
			// exit node, not just the via-tagged ones.
			if grant.internet {
				result.Exclude = slices.DeleteFunc(result.Exclude, tsaddr.IsExitRoute)
			}
		}
	}

	return result
}

// grantReachesInternet reports whether a grant's destinations include
// the internet. Neither the wildcard nor autogroup:internet resolves
// to 0.0.0.0/0, so check the aliases themselves.
func grantReachesInternet(grant Grant) bool {
	return slices.ContainsFunc(grant.Destinations, func(d Alias) bool {
		if ag, ok := d.(*AutoGroup); ok {
			return ag.Is(AutoGroupInternet)
		}

		_, ok := d.(Asterix)

		return ok
	})
}

func (pm *PolicyManager) Version() int {
	return 2
}

func (pm *PolicyManager) DebugString() string {
	if pm == nil {
		return "PolicyManager is not setup"
	}

	// pm.pol, filter, matchers, and the derived maps are all written
	// under pm.mu by SetPolicy/SetUsers/SetNodes.
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	var sb strings.Builder

	fmt.Fprintf(&sb, "PolicyManager (v%d):\n\n", pm.Version())

	sb.WriteString("\n\n")

	if pm.pol != nil {
		pol, err := json.MarshalIndent(pm.pol, "", "  ")
		if err == nil {
			sb.WriteString("Policy:\n")
			sb.Write(pol)
			sb.WriteString("\n\n")
		}
	}

	autoApprovers := pm.autoApprovers
	if autoApprovers == nil {
		autoApprovers = new(bart.Table[ipset.Set])
	}

	fmt.Fprintf(&sb, "AutoApprover (%d):\n", autoApprovers.Size())

	for prefix, approveAddrs := range autoApprovers.AllSorted() {
		fmt.Fprintf(&sb, "\t%s:\n", prefix)

		for iprange := range approveAddrs.Ranges() {
			fmt.Fprintf(&sb, "\t\t%s\n", iprange)
		}
	}

	sb.WriteString("\n\n")

	fmt.Fprintf(&sb, "TagOwner (%d):\n", len(pm.tagOwnerMap))

	for prefix, tagOwners := range pm.tagOwnerMap {
		fmt.Fprintf(&sb, "\t%s:\n", prefix)

		for iprange := range tagOwners.Ranges() {
			fmt.Fprintf(&sb, "\t\t%s\n", iprange)
		}
	}

	sb.WriteString("\n\n")

	if pm.view.Valid() {
		filter, err := json.MarshalIndent(
			packetfilter.ToTailcfg(pm.view.PacketRules()), "", "  ",
		)
		if err == nil {
			sb.WriteString("Compiled filter:\n")
			sb.Write(filter)
			sb.WriteString("\n\n")
		}
	}

	sb.WriteString("\n\n")
	sb.WriteString("Nodes:\n")

	for _, node := range pm.nodes.All() {
		sb.WriteString(node.String())
		sb.WriteString("\n")
	}

	return sb.String()
}

// flattenTags resolves nested tag-owner references. Cycles
// (tag:a -> tag:b -> tag:a, or tag:a -> tag:a) drop the cycle-causing
// edge and contribute no addresses; non-cycle owners on the cycled tags
// still resolve. Undefined-tag references remain a hard error.
func flattenTags(tagOwners TagOwners, tag Tag, visiting map[Tag]bool, chain []Tag,
) (Owners, error) {
	if visiting[tag] {
		return nil, nil
	}

	visiting[tag] = true

	chain = append(chain, tag)
	defer delete(visiting, tag)

	var result Owners

	for _, owner := range tagOwners[tag] {
		switch o := owner.(type) {
		case *Tag:
			if _, ok := tagOwners[*o]; !ok {
				return nil, fmt.Errorf("tag %q %w %q", tag, ErrUndefinedTagReference, *o)
			}

			nested, err := flattenTags(tagOwners, *o, visiting, chain)
			if err != nil {
				return nil, err
			}

			result = append(result, nested...)
		default:
			result = append(result, owner)
		}
	}

	return result, nil
}

// flattenTagOwners flattens all [TagOwners] by resolving nested tags and detecting cycles.
// It will return a new [TagOwners] map where all the [Tag] types have been resolved to their underlying [Owners].
func flattenTagOwners(tagOwners TagOwners) (TagOwners, error) {
	ret := make(TagOwners)

	for tag := range tagOwners {
		flattened, err := flattenTags(tagOwners, tag, make(map[Tag]bool), nil)
		if err != nil {
			return nil, err
		}

		slices.SortFunc(flattened, func(a, b Owner) int {
			return cmp.Compare(a.String(), b.String())
		})
		ret[tag] = slices.CompactFunc(flattened, func(a, b Owner) bool {
			return a.String() == b.String()
		})
	}

	return ret, nil
}

// resolveTagOwners resolves the [TagOwners] to a map of [Tag] to [ipset.Set].
// The resulting map can be used to quickly look up the IPSet for a given [Tag].
// It is intended for internal use in a [PolicyManager].
func resolveTagOwners(p *Policy, users types.Users, nodes views.Slice[types.NodeView],
) (map[Tag]ipset.Set, error) {
	if p == nil {
		return make(map[Tag]ipset.Set), nil
	}

	if len(p.TagOwners) == 0 {
		return make(map[Tag]ipset.Set), nil
	}

	ret := make(map[Tag]ipset.Set)

	tagOwners, err := flattenTagOwners(p.TagOwners)
	if err != nil {
		return nil, err
	}

	for tag, owners := range tagOwners {
		var ips ipset.Builder

		for _, owner := range owners {
			switch o := owner.(type) {
			case *Tag:
				// After flattening, Tag types should not appear in the owners list.
				// If they do, skip them as they represent already-resolved references.

			case Alias:
				// If it does not resolve, that means the tag is not associated with any IP addresses.
				_ = o.resolveInto(p, users, nodes, &ips)

			default:
				// Should never happen - after flattening, all owners should be Alias types
				return nil, fmt.Errorf("%w: %v", ErrInvalidTagOwner, owner)
			}
		}

		ipSet, err := ips.Build()
		if err != nil {
			return nil, err
		}

		ret[tag] = ipSet
	}

	return ret, nil
}

// refreshNodeAttrsLocked installs a compiled per-node nodeAttrs CapMap and
// appends the IDs whose CapMap differs from the previous snapshot
// (including newly-targeted nodes and nodes that lost all attrs) to
// pm.nodeAttrsChanged. Append, not overwrite: a concurrent
// SetUsers/SetNodes between SetPolicy and a NodesWithChangedCapMap
// drain cannot clobber the policy-reload diff.
//
// Caller must hold pm.mu.
func (pm *PolicyManager) refreshNodeAttrsLocked(newMap map[types.NodeID]tailcfg.NodeCapMap,
) {
	newHashes := make(map[types.NodeID]deephash.Sum, len(newMap))
	for id, capMap := range newMap {
		newHashes[id] = deephash.Hash(&capMap)
	}

	// Walk the union of old and new node IDs and emit the delta.
	seen := make(map[types.NodeID]struct{}, len(newHashes)+len(pm.nodeAttrsHashes))

	var changed []types.NodeID

	for id, h := range newHashes {
		seen[id] = struct{}{}
		if pm.nodeAttrsHashes[id] != h {
			changed = append(changed, id)
		}
	}

	for id := range pm.nodeAttrsHashes {
		if _, ok := seen[id]; ok {
			continue
		}
		// Node lost all nodeAttrs since the last update.
		changed = append(changed, id)
	}

	pm.nodeAttrsMap = newMap
	pm.nodeAttrsHashes = newHashes
	pm.nodeAttrsChanged = append(pm.nodeAttrsChanged, changed...)

	if len(pm.nodeAttrsChanged) > 0 {
		pm.nodeAttrsPending.Store(true)
	}
}

// NodeCapMap returns the policy-derived CapMap for the given node, or
// nil when the node has no nodeAttrs entries that target it. The
// returned map is a defensive clone — caller mutations cannot reach
// the manager-owned cache.
func (pm *PolicyManager) NodeCapMap(id types.NodeID) tailcfg.NodeCapMap {
	return pm.ReadView().NodeCapMap(id)
}

func (pm *PolicyManager) NodeCapMaps() map[types.NodeID]tailcfg.NodeCapMap {
	view := pm.ReadView()
	if !view.Valid() {
		return nil
	}

	caps := make(map[types.NodeID]tailcfg.NodeCapMap, len(view.generation.nodeCaps))
	for id := range view.generation.nodeCaps {
		caps[id] = view.NodeCapMap(id)
	}

	return caps
}

// NodesWithChangedCapMap returns the IDs of nodes whose nodeAttrs
// CapMap shifted across one or more [PolicyManager.updateLocked] calls
// since the last drain. The buffer drains on return.
// [state.State.DrainSelfRefreshes] calls this whenever changes are
// dispatched to decide which nodes need a [change.SelfUpdate].
//
// [PolicyManager.refreshNodeAttrsLocked] APPENDS to the buffer; the drain
// returns the union of every change since the previous read. A concurrent
// [PolicyManager.SetUsers]/[PolicyManager.SetNodes] between
// [PolicyManager.SetPolicy] and a drain cannot silently lose the
// policy-reload diff.
func (pm *PolicyManager) NodesWithChangedCapMap() []types.NodeID {
	if pm == nil || !pm.nodeAttrsPending.Load() {
		return nil
	}

	pm.mu.Lock()
	defer pm.mu.Unlock()

	out := pm.nodeAttrsChanged
	pm.nodeAttrsChanged = nil
	pm.nodeAttrsPending.Store(false)

	return out
}
