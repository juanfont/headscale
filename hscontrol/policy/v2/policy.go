package v2

import (
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/juanfont/headscale/hscontrol/policy/matcher"
	"github.com/juanfont/headscale/hscontrol/policy/policyutil"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/juanfont/headscale/hscontrol/util/zlog/zf"
	"github.com/puzpuzpuz/xsync/v4"
	"github.com/rs/zerolog/log"
	"go4.org/netipx"
	"tailscale.com/net/tsaddr"
	"tailscale.com/tailcfg"
	"tailscale.com/types/views"
	"tailscale.com/util/deephash"
	"tailscale.com/util/multierr"
)

// ErrInvalidTagOwner is returned when a tag owner is not an [Alias] type.
var ErrInvalidTagOwner = errors.New("tag owner is not an Alias")

// ErrPolicyEmpty is returned by [PolicyManager.SetPolicy] for a zero-length policy.
var ErrPolicyEmpty = errors.New(`policy is empty, use "{}" to allow all`)

type PolicyManager struct {
	// RWMutex, not Mutex, so concurrent map generation does not serialise on
	// reads. The per-node caches are xsync.Maps so a read can fill them without
	// taking the write lock.
	mu    sync.RWMutex
	pol   *Policy
	users []types.User
	nodes views.Slice[types.NodeView]
	// nodesByID indexes nodes; see [PolicyManager.cacheableLocked].
	nodesByID map[types.NodeID]types.NodeView
	// nodeAddrs is every node's addresses, for
	// [policyutil.ReduceFilterRules].
	nodeAddrs *netipx.IPSet

	// resolvedPol is pol with its tags indexed and its groups resolved
	// against users and nodes, see [Policy.withNodesByTag] and
	// [Policy.withResolvedGroups]. Readers that resolve aliases on demand
	// go through it; pol itself is what is hashed.
	resolvedPol *Policy

	filterHash deephash.Sum
	filter     []tailcfg.FilterRule
	matchers   []matcher.Match

	tagOwnerMapHash deephash.Sum
	tagOwnerMap     map[Tag]*netipx.IPSet

	exitSetHash        deephash.Sum
	exitSet            *netipx.IPSet
	autoApproveMapHash deephash.Sum
	autoApproveMap     map[netip.Prefix]*netipx.IPSet

	// relayTargetIPs holds the IPs of nodes that are destinations of a
	// tailscale.com/cap/relay grant; viaTargetTags holds the tags used as
	// via targets. A node matching either, or that is a subnet router,
	// forces peers to recompute their netmap when its online state changes
	// (see [PolicyManager.NodeNeedsPeerRecompute]). Recomputed from the
	// compiled grants on every policy/user/node change.
	relayTargetIPs *netipx.IPSet
	viaTargetTags  map[Tag]struct{}

	// Lazy map of SSH policies
	sshPolicyMap *xsync.Map[types.NodeID, *tailcfg.SSHPolicy]

	// sshRules are the SSH rules with sources and destinations
	// pre-resolved, shared by every node's policy in sshPolicyMap so
	// the principal lists exist once rather than once per rule and
	// node. They are reset to nil wherever sshPolicyMap is cleared
	// and filled by the first SSHPolicy call after that; sshRulesMu
	// serialises that fill between readers of mu.
	sshRulesMu sync.Mutex
	sshRules   []compiledSSHRule

	// compiledGrants are the grants with sources pre-resolved.
	// The single source of truth for filter compilation. Both
	// global and per-node filter rules are derived from these.
	compiledGrants []compiledGrant
	userNodeIdx    userNodeIndex

	// Lazy map of per-node filter rules (reduced, for packet filters)
	filterRulesMap *xsync.Map[types.NodeID, []tailcfg.FilterRule]

	// Lazy map of per-node matchers derived from UNREDUCED filter
	// rules. Only populated on the slow path when needsPerNodeFilter
	// is true; the fast path returns pm.matchers directly.
	matchersForNodeMap *xsync.Map[types.NodeID, []matcher.Match]

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

	routerSession func(types.NodeID) (time.Time, bool)
}

// filterAndPolicy combines the compiled filter rules with policy content for hashing.
// This ensures filterHash changes when policy changes, even for autogroup:self where
// the compiled filter is always empty.
type filterAndPolicy struct {
	Filter []tailcfg.FilterRule
	Policy *Policy
}

// validateUserReferences reports ambiguous user@ tokens so writes can refuse them.
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

	for _, grant := range pol.Grants {
		for _, src := range grant.Sources {
			checkAlias(src)
		}

		for _, dst := range grant.Destinations {
			checkAlias(dst)
		}
	}

	for _, attr := range pol.NodeAttrs {
		for _, target := range attr.Targets {
			checkAlias(target)
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
func NewPolicyManager(b []byte, users []types.User, nodes views.Slice[types.NodeView]) (*PolicyManager, error) {
	policy, err := unmarshalPolicy(b)
	if err != nil {
		return nil, fmt.Errorf("parsing policy: %w", err)
	}

	err = validateUserReferences(policy, users)
	if err != nil {
		log.Error().Err(err).Msg("ambiguous policy users at boot")
	}

	pm := PolicyManager{
		pol:                policy,
		users:              users,
		nodes:              nodes,
		nodesByID:          nodeIDViewMap(nodes),
		sshPolicyMap:       xsync.NewMap[types.NodeID, *tailcfg.SSHPolicy](),
		filterRulesMap:     xsync.NewMap[types.NodeID, []tailcfg.FilterRule](),
		matchersForNodeMap: xsync.NewMap[types.NodeID, []matcher.Match](),
	}

	_, err = pm.updateLocked()
	if err != nil {
		return nil, err
	}

	warnMalformedNextDNSAttrs(policy)

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
	// One tag index and one resolution of every group serve this whole
	// compile; each step below would otherwise resolve them again for
	// every rule naming them.
	pol := pm.pol.withNodesByTag(pm.nodes).withResolvedGroups(pm.users, pm.nodes)

	// Compile all grants once. Both global and per-node filter
	// rules are derived from these compiled grants.
	grants := pol.compileGrants(pm.users, pm.nodes)

	relayTargetIPs, err := collectRelayTargetIPs(grants)
	if err != nil {
		return false, fmt.Errorf("collecting relay target IPs: %w", err)
	}

	// Order matters, tags might be used in autoapprovers, so we need to ensure
	// that the map for tag owners is resolved before resolving autoapprovers.
	// TODO(kradalby): Order might not matter after #2417
	tagMap, err := resolveTagOwners(pol, pm.users, pm.nodes)
	if err != nil {
		return false, fmt.Errorf("resolving tag owners map: %w", err)
	}

	autoMap, exitSet, err := resolveAutoApprovers(pol, pm.users, pm.nodes)
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
		nodeAttrs, err = pol.compileNodeAttrs(pm.users, pm.nodes)
		if err != nil {
			return false, fmt.Errorf("compiling nodeAttrs: %w", err)
		}
	}

	pm.resolvedPol = pol
	pm.compiledGrants = grants
	pm.userNodeIdx = buildUserNodeIndex(pm.nodes)
	pm.nodeAddrs = nodeAddrSet(pm.nodes)
	pm.needsPerNodeFilter = hasPerNodeGrants(pm.compiledGrants)
	pm.viaTargetTags = collectViaTargetTags(pm.compiledGrants)
	pm.relayTargetIPs = relayTargetIPs

	var filter []tailcfg.FilterRule
	if pm.pol == nil || (pm.pol.ACLs == nil && pm.pol.Grants == nil) {
		filter = tailcfg.FilterAllowAll
	} else {
		filter = globalFilterRules(pm.compiledGrants)
	}

	// Hash both the compiled filter AND the policy content together.
	// This ensures filterHash changes when policy changes, even for autogroup:self
	// where the compiled filter is always empty. This eliminates the need for
	// a separate policyHash field.
	filterHash := deephash.Hash(&filterAndPolicy{
		Filter: filter,
		Policy: pm.pol,
	})

	filterChanged := filterHash != pm.filterHash
	if filterChanged {
		log.Debug().
			Str("filter.hash.old", pm.filterHash.String()[:8]).
			Str("filter.hash.new", filterHash.String()[:8]).
			Int("filter.rules", len(pm.filter)).
			Int("filter.rules.new", len(filter)).
			Msg("Policy filter hash changed")
	}

	pm.filter = filter

	pm.filterHash = filterHash
	if filterChanged {
		pm.matchers = matcher.MatchesFromFilterRules(pm.filter)
	}

	tagOwnerMapHash := deephash.Hash(&tagMap)

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

	autoApproveMapHash := deephash.Hash(&autoMap)

	autoApproveChanged := autoApproveMapHash != pm.autoApproveMapHash
	if autoApproveChanged {
		log.Debug().
			Str("autoApprove.hash.old", pm.autoApproveMapHash.String()[:8]).
			Str("autoApprove.hash.new", autoApproveMapHash.String()[:8]).
			Int("autoApprovers.old", len(pm.autoApproveMap)).
			Int("autoApprovers.new", len(autoMap)).
			Msg("Auto-approvers hash changed")
	}

	pm.autoApproveMap = autoMap
	pm.autoApproveMapHash = autoApproveMapHash

	exitSetHash := deephash.Hash(&exitSet)

	exitSetChanged := exitSetHash != pm.exitSetHash
	if exitSetChanged {
		log.Debug().
			Str("exitSet.hash.old", pm.exitSetHash.String()[:8]).
			Str("exitSet.hash.new", exitSetHash.String()[:8]).
			Msg("Exit node set hash changed")
	}

	pm.exitSet = exitSet
	pm.exitSetHash = exitSetHash

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

	// Only clear caches if we're actually going to send updates
	// This prevents clearing caches when nothing changed, which would leave nodes
	// with stale filters until they reconnect. This is critical for autogroup:self
	// where even reloading the same policy would clear caches but not send updates.
	if needsUpdate {
		// Clear the SSH policy map to ensure it's recalculated with the new policy.
		// TODO(kradalby): This could potentially be optimized by only clearing the
		// policies for nodes that have changed. Particularly if the only difference is
		// that nodes has been added or removed.
		pm.sshPolicyMap.Clear()
		pm.sshRules = nil
		pm.filterRulesMap.Clear()
		pm.matchersForNodeMap.Clear()
	}

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

	if pm.relayTargetIPs != nil && node.InIPSet(pm.relayTargetIPs) {
		return true
	}

	return pm.isViaTargetLocked(node)
}

// NodeIsViaTarget reports whether a grant steers traffic through node.
func (pm *PolicyManager) NodeIsViaTarget(node types.NodeView) bool {
	if pm == nil || !node.Valid() {
		return false
	}

	pm.mu.RLock()
	defer pm.mu.RUnlock()

	return pm.isViaTargetLocked(node)
}

func (pm *PolicyManager) isViaTargetLocked(node types.NodeView) bool {
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
// SaaS wire format. Cache is invalidated on policy reload.
func (pm *PolicyManager) SSHPolicy(baseURL string, node types.NodeView) (*tailcfg.SSHPolicy, error) {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	if sshPol, ok := pm.sshPolicyMap.Load(node.ID()); ok {
		return sshPol, nil
	}

	rules, err := pm.sshRulesLocked(baseURL)
	if err != nil {
		return nil, fmt.Errorf("compiling SSH policy: %w", err)
	}

	sshPol := sshPolicyForNode(rules, node)

	if pm.cacheableLocked(node) {
		pm.sshPolicyMap.Store(node.ID(), sshPol)
	}

	return sshPol, nil
}

// sshRulesLocked returns the compiled SSH rules, compiling them on first
// access. It must be called with pm.mu held, for reading or writing;
// writers reset pm.sshRules directly. The rules keep the baseURL of the
// call that compiled them; [state.State] always passes the server URL.
func (pm *PolicyManager) sshRulesLocked(baseURL string) ([]compiledSSHRule, error) {
	pm.sshRulesMu.Lock()
	defer pm.sshRulesMu.Unlock()

	if pm.sshRules == nil {
		rules, err := pm.resolvedPol.compileSSHRules(baseURL, pm.users, pm.nodes)
		if err != nil {
			return nil, err
		}

		pm.sshRules = rules
	}

	return pm.sshRules, nil
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
	srcNodeID, dstNodeID types.NodeID,
	localUser string,
) (time.Duration, bool) {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	if pm.pol == nil || len(pm.pol.SSHs) == 0 {
		return 0, false
	}

	// Find the source and destination node views.
	var srcNode, dstNode types.NodeView

	for _, n := range pm.nodes.All() {
		nid := n.ID()
		if nid == srcNodeID {
			srcNode = n
		}

		if nid == dstNodeID {
			dstNode = n
		}

		if srcNode.Valid() && dstNode.Valid() {
			break
		}
	}

	if !srcNode.Valid() || !dstNode.Valid() {
		return 0, false
	}

	// Iterate SSH rules to find the first matching check rule.
	for _, rule := range pm.pol.SSHs {
		if rule.Action != SSHActionCheck {
			continue
		}

		// Resolve sources and check if src node matches.
		srcIPs, err := rule.Sources.Resolve(pm.resolvedPol, pm.users, pm.nodes)
		if err != nil || srcIPs == nil {
			continue
		}

		if !slices.ContainsFunc(srcNode.IPs(), srcIPs.Contains) {
			continue
		}

		if !pm.sshRuleAllowsUser(rule, srcNode, localUser) {
			continue
		}

		// Check if dst node matches any destination.
		hasOtherDests := false

		for _, dst := range rule.Destinations {
			if ag, isAG := dst.(*AutoGroup); isAG && ag.Is(AutoGroupSelf) {
				if sshNodesShareUser(srcNode, dstNode) {
					return checkPeriodFromRule(rule), true
				}

				continue
			}

			hasOtherDests = true

			dstIPs, err := dst.Resolve(pm.resolvedPol, pm.users, pm.nodes)
			if err != nil || dstIPs == nil {
				continue
			}

			if slices.ContainsFunc(dstNode.IPs(), dstIPs.Contains) {
				return checkPeriodFromRule(rule), true
			}
		}

		// Localpart self-access: a source outside dst still gets the rule
		// for its own user's nodes, or itself if tagged (compileSSHPolicy).
		if hasOtherDests && rule.Users.ContainsLocalpart() &&
			slices.ContainsFunc(dstNode.IPs(), srcIPs.Contains) {
			if dstNode.IsTagged() {
				if srcNodeID == dstNodeID {
					return checkPeriodFromRule(rule), true
				}
			} else if sshNodesShareUser(srcNode, dstNode) {
				return checkPeriodFromRule(rule), true
			}
		}
	}

	return 0, false
}

// sshNodesShareUser matches user-owned nodes with hydrated user associations.
// IsTagged alone does not guard User().ID(): the NodeStore can hold a
// non-tagged node whose UserID is set but whose User association is nil.
func sshNodesShareUser(srcNode, dstNode types.NodeView) bool {
	return !srcNode.IsTagged() && !dstNode.IsTagged() &&
		srcNode.User().Valid() && dstNode.User().Valid() &&
		srcNode.User().ID() == dstNode.User().ID()
}

// sshRuleAllowsUser reports whether rule lets src log in as localUser,
// mirroring the SSHUsers maps compileSSHPolicy emits: root when listed,
// other users via autogroup:nonroot or a literal name, and anyone, root
// included, whose name is the source user's localpart. Login "0" only the
// last way: the rule that maps root maps it to no local user.
func (pm *PolicyManager) sshRuleAllowsUser(rule SSH, srcNode types.NodeView, localUser string) bool {
	isRoot := localUser == "root"

	switch {
	case localUser == "":
		return false
	case localUser == uidZeroLogin:
	case isRoot && rule.Users.ContainsRoot(),
		!isRoot && rule.Users.ContainsNonRoot(),
		!isRoot && slices.Contains(rule.Users.NormalUsers(), SSHUser(localUser)):
		return true
	}

	if srcNode.IsTagged() || !srcNode.User().Valid() || !rule.Users.ContainsLocalpart() {
		return false
	}

	lp, ok := resolveLocalparts(rule.Users.LocalpartEntries(), pm.users)[srcNode.User().ID()]

	return ok && lp == localUser
}

func (pm *PolicyManager) SetPolicy(polB []byte) (bool, error) {
	if len(polB) == 0 {
		return false, ErrPolicyEmpty
	}

	pol, err := unmarshalPolicy(polB)
	if err != nil {
		return false, fmt.Errorf("parsing policy: %w", err)
	}

	pm.mu.RLock()
	users, nodes := pm.users, pm.nodes
	pm.mu.RUnlock()

	err = validateUserReferences(pol, users)
	if err != nil {
		return false, fmt.Errorf("validating policy user references: %w", err)
	}

	// SetPolicy is the user-write boundary. Tests evaluate against a
	// sandbox compiled from the new policy + current users/nodes; if
	// they fail, return without mutating the live PolicyManager so the
	// failed write does not knock the running config offline.
	//
	// They run before the write lock is taken: how long they take is up
	// to the policy author, and every map response and node write needs
	// the lock. A user or node that changes meanwhile counts as changed
	// right after the write.
	//
	// Aggregate ACL and SSH test failures via multierr so operators
	// see both classes in a single response instead of having to
	// fix-and-retry to discover the second one.
	testErr := multierr.New(
		evaluateTests(pol, users, nodes),
		evaluateSSHTests(pol, users, nodes),
	)
	if testErr != nil {
		return false, testErr
	}

	pm.mu.Lock()
	defer pm.mu.Unlock()

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

	// Reloading the same bytes leaves changed false, so each policy warns once.
	if changed {
		warnMalformedNextDNSAttrs(pol)
	}

	return changed, nil
}

// warnMalformedNextDNSAttrs logs, once per policy load, the nextdns: attrs
// the resolver skips, which the mapper does in silence on every DNS build.
func warnMalformedNextDNSAttrs(pol *Policy) {
	bad := pol.malformedNextDNSAttrs()
	if len(bad) == 0 {
		return
	}

	log.Warn().
		Strs(zf.NodeAttrs, bad).
		Msg("nextdns attrs have no effect: a profile must match [A-Za-z0-9._-]{1,64}")
}

// Filter returns the current filter rules for the entire tailnet and the associated matchers.
func (pm *PolicyManager) Filter() ([]tailcfg.FilterRule, []matcher.Match) {
	if pm == nil {
		return nil, nil
	}

	pm.mu.RLock()
	defer pm.mu.RUnlock()

	return pm.filter, pm.matchers
}

// BuildPeerMap constructs peer relationship maps for the given nodes.
// For global filters, it uses the global filter matchers for all nodes.
// For autogroup:self policies (empty global filter), it builds per-node
// peer maps using each node's specific filter rules.
//
// Compared to [policy.ReduceNodes], which builds the list per node, we end
// up with doing the full work for every node O(n^2), while this will reduce
// the list as we see relationships while building the map, making it
// O(n^2/2) in the end, but with less work per node.
//
//nolint:gocyclo // global and autogroup:self paths, each with a per-node matcher index
func (pm *PolicyManager) BuildPeerMap(nodes views.Slice[types.NodeView]) map[types.NodeID][]types.NodeID {
	if pm == nil {
		return nil
	}

	pm.mu.RLock()
	defer pm.mu.RUnlock()

	// Precompute each node's route ranges and exit-node status once; the
	// O(n^2) pair scans below would otherwise recompute them for every pair.
	type nodeRoutes struct {
		subnet []netipx.IPRange
		isExit bool
	}

	routeInfo := make(map[types.NodeID]nodeRoutes, nodes.Len())
	for _, n := range nodes.All() {
		routeInfo[n.ID()] = nodeRoutes{
			subnet: types.RouteRanges(n.SubnetRoutes()), isExit: n.IsExitNode(),
		}
	}

	// If we have a global filter, use it for all nodes (normal case).
	// Via grants require the per-node path because the global filter
	// skips via grants (compileFilterRules: if len(grant.Via) > 0 { continue }).
	if !pm.needsPerNodeFilter {
		ret := make(map[types.NodeID][]types.NodeID, nodes.Len())

		// A matcher lets a reach b when a satisfies its source side and b
		// its destination side, exactly as [types.Node.CanAccess] tests
		// them, and each side depends on one node only. So evaluate both
		// sides once per node, as bitsets over pm.matchers, instead of
		// once per pair: a can reach b iff a's source set and b's
		// destination set intersect. That turns the O(n^2 * matchers)
		// scan into O(n * matchers) set lookups plus O(n^2) word ANDs.
		// Bit k of a set stands for pm.matchers[k]: it lives in word k/64
		// at position k%64, so 64 matchers fit in one uint64.
		words := (len(pm.matchers) + 63) / 64 //nolint:mnd
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

			for k := range pm.matchers {
				m := &pm.matchers[k]

				if m.SrcsContainsIPs(ips...) || (routed && m.SrcsOverlapsRanges(ri.subnet)) {
					if srcOf[i] == nil {
						srcOf[i] = make([]uint64, words)
					}

					srcOf[i][k/64] |= 1 << (k % 64) //nolint:mnd
				}

				if m.DestsContainsIP(ips...) || (routed && m.DestsOverlapsRanges(ri.subnet)) ||
					(ri.isExit && m.DestsIsTheInternet()) {
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

	// For autogroup:self or via grants, build per-node peer relationships
	ret := make(map[types.NodeID][]types.NodeID, nodes.Len())

	// Pre-compute per-node matchers using unreduced compiled rules
	// We need unreduced rules to determine peer relationships correctly.
	// Reduced rules only show destinations where the node is the target,
	// but peer relationships require the full bidirectional access rules.
	nodeMatchers := make(map[types.NodeID][]matcher.Match, nodes.Len())
	for _, node := range nodes.All() {
		unreduced := pm.peerRulesForNodeLocked(node)
		nodeMatchers[node.ID()] = matcher.MatchesFromFilterRules(unreduced)
	}

	// Check each node pair for peer relationships.
	// Start j at i+1 to avoid checking the same pair twice and creating duplicates.
	// We use symmetric visibility: if EITHER node can access the other, BOTH see
	// each other. This matches the global filter path behavior and ensures that
	// one-way access rules (e.g., admin -> tagged server) still allow both nodes
	// to see each other as peers, which is required for network connectivity.
	for i := range nodes.Len() {
		nodeI := nodes.At(i)
		matchersI, hasFilterI := nodeMatchers[nodeI.ID()]
		riI := routeInfo[nodeI.ID()]

		for j := i + 1; j < nodes.Len(); j++ {
			nodeJ := nodes.At(j)
			matchersJ, hasFilterJ := nodeMatchers[nodeJ.ID()]
			riJ := routeInfo[nodeJ.ID()]

			// Check all access directions for symmetric peer visibility.
			// For via grants, rules exist on the via-designated node
			// (e.g., router-a) with sources being the client (group-a).
			// We need to check BOTH:
			//   1. nodeI.CanAccess(matchersI, nodeJ) — can nodeI reach nodeJ?
			//   2. nodeJ.CanAccess(matchersI, nodeI) — can nodeJ reach nodeI
			//      using nodeI's matchers? (reverse direction: the matchers
			//      on the via node accept traffic FROM the source)
			// Same for matchersJ in both directions.
			canIAccessJ := hasFilterI && nodeI.CanAccessWithRoutes(matchersI, nodeJ, riI.subnet, riJ.subnet, riJ.isExit)
			canJAccessI := hasFilterJ && nodeJ.CanAccessWithRoutes(matchersJ, nodeI, riJ.subnet, riI.subnet, riI.isExit)
			canJReachI := hasFilterI && nodeJ.CanAccessWithRoutes(matchersI, nodeI, riJ.subnet, riI.subnet, riI.isExit)
			canIReachJ := hasFilterJ && nodeI.CanAccessWithRoutes(matchersJ, nodeJ, riI.subnet, riJ.subnet, riJ.isExit)

			if canIAccessJ || canJAccessI || canJReachI || canIReachJ {
				ret[nodeI.ID()] = append(ret[nodeI.ID()], nodeJ.ID())
				ret[nodeJ.ID()] = append(ret[nodeJ.ID()], nodeI.ID())
			}
		}
	}

	return ret
}

// filterRulesForNodeLocked returns the unreduced compiled filter rules
// for a node, combining pre-compiled global rules with per-node self
// and via rules from the stored compiled grants.
func (pm *PolicyManager) filterRulesForNodeLocked(
	node types.NodeView,
) []tailcfg.FilterRule {
	return filterRulesForNode(
		pm.compiledGrants, node, pm.userNodeIdx,
	)
}

// peerRulesForNodeLocked returns the rules that decide a node's peers, see
// [peerRulesForNode].
func (pm *PolicyManager) peerRulesForNodeLocked(
	node types.NodeView,
) []tailcfg.FilterRule {
	return peerRulesForNode(pm.compiledGrants, node, pm.userNodeIdx)
}

// filterForNodeLocked returns the filter rules for a specific node,
// already reduced to only include rules relevant to that node.
//
// Fast path (!needsPerNodeFilter): reduces global filter per-node.
// Slow path (needsPerNodeFilter): combines global + self + via rules
// from the stored compiled grants, then reduces.
//
// Both paths derive from the same compiledGrants, ensuring there is
// no divergence between global and per-node filter output.
//
// Lock-free version for internal use when the lock is already held.
func (pm *PolicyManager) filterForNodeLocked(
	node types.NodeView,
) []tailcfg.FilterRule {
	if pm == nil {
		return nil
	}

	if rules, ok := pm.filterRulesMap.Load(node.ID()); ok {
		return rules
	}

	var unreduced []tailcfg.FilterRule
	if !pm.needsPerNodeFilter {
		unreduced = pm.filter
	} else {
		unreduced = append(
			pm.filterRulesForNodeLocked(node),
			exitNodeSelfRules(pm.compiledGrants, node, pm.userNodeIdx)...,
		)
	}

	reduced := policyutil.ReduceFilterRules(node, unreduced, pm.nodeAddrs)
	if pm.cacheableLocked(node) {
		pm.filterRulesMap.Store(node.ID(), reduced)
	}

	return reduced
}

// FilterForNode returns the filter rules for a specific node, already reduced
// to only include rules relevant to that node.
// If the policy uses autogroup:self, this returns node-specific compiled rules.
// Otherwise, it returns the global filter reduced for this node.
//
// Cache is invalidated by [PolicyManager.updateLocked] on policy reload,
// node-set change, or tag-state change.
func (pm *PolicyManager) FilterForNode(node types.NodeView) ([]tailcfg.FilterRule, error) {
	if pm == nil {
		return nil, nil
	}

	pm.mu.RLock()
	defer pm.mu.RUnlock()

	return pm.filterForNodeLocked(node), nil
}

// MatchersForNode returns the matchers that filter the routes a node sees.
// These are UNREDUCED matchers - they include all rules where the node could be either source or destination.
// This is different from [PolicyManager.FilterForNode] which returns REDUCED rules for packet filtering.
// Peers come from [PolicyManager.BuildPeerMap], which uses [viaPeerRule] where these matchers use the via rule.
//
// For global policies: returns the global matchers (same for all nodes)
// For autogroup:self: returns node-specific matchers from unreduced compiled rules.
//
// Per-node results are cached and invalidated on policy/node updates
// so building a node's map does not recompile them.
func (pm *PolicyManager) MatchersForNode(node types.NodeView) ([]matcher.Match, error) {
	if pm == nil {
		return nil, nil
	}

	pm.mu.RLock()
	defer pm.mu.RUnlock()

	// For global policies, return the shared global matchers.
	// Via grants require per-node matchers because the global matchers
	// are empty for via-grant-only policies.
	if !pm.needsPerNodeFilter {
		return pm.matchers, nil
	}

	if cached, ok := pm.matchersForNodeMap.Load(node.ID()); ok {
		return cached, nil
	}

	// For autogroup:self or via grants, derive matchers from
	// the stored compiled grants for this specific node.
	unreduced := pm.filterRulesForNodeLocked(node)
	matchers := matcher.MatchesFromFilterRules(unreduced)

	if pm.cacheableLocked(node) {
		pm.matchersForNodeMap.Store(node.ID(), matchers)
	}

	return matchers, nil
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

	// A via grant left without sources is not compiled, so the recompile
	// can clear the flag while clients still hold its rules.
	hadPerNodeFilter := pm.needsPerNodeFilter

	// SSH policies and autogroup:self sources resolve users by name, and
	// the self sources are outside the filter hash, so updateLocked can
	// report no change while per-node results moved.
	pm.sshPolicyMap.Clear()
	pm.sshRules = nil
	pm.filterRulesMap.Clear()
	pm.matchersForNodeMap.Clear()

	policyChanged, err := pm.updateLocked()
	if err != nil {
		// Keep the old list, which pm is still compiled from, so a retry
		// with the same input recompiles instead of being treated as
		// unchanged.
		pm.users = prev

		return false, false, err
	}

	err = validateUserReferences(pm.pol, users)
	if err != nil {
		log.Error().Err(err).Msg("ambiguous policy users after updating users")
	}

	// SSH rules and per-node filters embed user identity outside the filter
	// hash, so a user change needs a client refresh even when it did not move.
	if hadPerNodeFilter || pm.needsPerNodeFilter ||
		(pm.pol != nil && len(pm.pol.SSHs) > 0) {
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

	policyChanged := pm.nodesHavePolicyAffectingChanges(nodes)

	// Invalidate cache entries for nodes that changed.
	// For autogroup:self: invalidate all nodes belonging to affected users (peer changes).
	// For global policies: invalidate only nodes whose properties changed (IPs, routes).
	pm.invalidateNodeCache(nodes)

	prevNodes, prevByID := pm.nodes, pm.nodesByID
	pm.nodes = nodes
	pm.nodesByID = nodeIDViewMap(nodes)

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
		needsUpdate, err := pm.updateLocked()
		if err != nil {
			// Keep the old list, which pm is still compiled from, so a
			// retry with the same input recompiles, as in SetUsers. The
			// NodeStore writer only logs this error; the writing caller's
			// own SetNodes then retries and returns it.
			pm.nodes, pm.nodesByID = prevNodes, prevByID

			return false, err
		}

		if !needsUpdate {
			// This ensures fresh filter rules are generated for all nodes
			pm.sshPolicyMap.Clear()
			pm.sshRules = nil
			pm.filterRulesMap.Clear()
			pm.matchersForNodeMap.Clear()
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

// cacheableLocked reports whether a per-node result computed from node may
// be cached under its ID. SetNodes invalidates those caches by diffing its
// own copies of each node, so a result computed from any other view, such
// as a mapper's pre-write snapshot read while the NodeStore writer builds,
// would outlive the invalidation meant to remove it.
func (pm *PolicyManager) cacheableLocked(node types.NodeView) bool {
	own, ok := pm.nodesByID[node.ID()]

	return ok && !node.HasPolicyChange(own)
}

// nodeIDViewMap indexes a slice of node views by node ID. On duplicate IDs the
// last view wins, matching the open-coded loops it replaces.
func nodeIDViewMap(s views.Slice[types.NodeView]) map[types.NodeID]types.NodeView {
	m := make(map[types.NodeID]types.NodeView, s.Len())
	for _, n := range s.All() {
		m[n.ID()] = n
	}

	return m
}

func (pm *PolicyManager) nodesHavePolicyAffectingChanges(newNodes views.Slice[types.NodeView]) bool {
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
		if slices.ContainsFunc(node.IPs(), ips.Contains) {
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
// apply tag: tag is one of ownerTags, or tag's tagOwners list one of them.
// Ownership reaches one hop, as on Tailscale SaaS: a tag owned by a tag that
// ownerTags own is not reached. This is the tag-level check used when an
// OAuth access token mints an auth key: the requested tags must each be owned
// by the token's tags, so an operator token tagged tag:k8s-operator may mint
// tag:k8s keys when the policy declares "tag:k8s": ["tag:k8s-operator"]. It is
// purely tag-relational and does not consult node IPs.
func (pm *PolicyManager) TagOwnedByTags(tag string, ownerTags []string) bool {
	if pm == nil {
		return false
	}

	// A credential may always apply a tag it directly holds; this needs no policy.
	if slices.Contains(ownerTags, tag) {
		return true
	}

	pm.mu.RLock()
	defer pm.mu.RUnlock()

	if pm.pol == nil {
		return false
	}

	return slices.ContainsFunc(pm.pol.TagOwners[Tag(tag)], func(owner Owner) bool {
		ot, ok := owner.(*Tag)

		return ok && slices.Contains(ownerTags, string(*ot))
	})
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

func (pm *PolicyManager) NodeCanApproveRoute(node types.NodeView, route netip.Prefix) bool {
	if pm == nil {
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
		if pm.exitSet == nil {
			return false
		}

		return slices.ContainsFunc(node.IPs(), pm.exitSet.Contains)
	}

	// The fast path is that a node requests to approve a prefix
	// where there is an exact entry, e.g. 10.0.0.0/8, then
	// check and return quickly
	if approvers, ok := pm.autoApproveMap[route]; ok {
		canApprove := slices.ContainsFunc(node.IPs(), approvers.Contains)
		if canApprove {
			return true
		}
	}

	// The slow path is that the node tries to approve
	// 10.0.10.0/24, which is a part of 10.0.0.0/8, then we
	// cannot just lookup in the prefix map and have to check
	// if there is a "parent" prefix available.
	for prefix, approveAddrs := range pm.autoApproveMap {
		// Check if prefix is larger (so containing) and then overlaps
		// the route to see if the node can approve a subset of an autoapprover
		if prefix.Bits() <= route.Bits() && prefix.Overlaps(route) {
			canApprove := slices.ContainsFunc(node.IPs(), approveAddrs.Contains)
			if canApprove {
				return true
			}
		}
	}

	return false
}

// SetRouterSession installs the session check used by the via election: when
// a router's control session began and whether it may win. Runtime status
// changes bypass SetNodes; nil treats every router as available, with one
// session age. The callback runs with pm.mu held and must remain a lock-free
// snapshot read.
func (pm *PolicyManager) SetRouterSession(session func(types.NodeID) (time.Time, bool)) {
	if pm == nil {
		return
	}

	pm.mu.Lock()
	defer pm.mu.Unlock()

	pm.routerSession = session
}

// ViaRoutesForPeer computes via grant effects for a viewer-peer pair.
// For each via grant where the viewer matches the source, it checks whether the
// peer advertises any of the grant's destination prefixes. If the peer has the
// via tag, those prefixes go into [types.ViaRouteResult.Include]; otherwise
// into [types.ViaRouteResult.Exclude].
//
// Performance note: this holds [PolicyManager.mu] for its full duration. Hot
// callers should memoise by (policy-hash, viewer-id) rather than invoking
// this per-pair.
//
//nolint:gocyclo // three-pass via-grant resolution (match, primary election, regular-overlap)
func (pm *PolicyManager) ViaRoutesForPeer(viewer, peer types.NodeView) types.ViaRouteResult {
	var result types.ViaRouteResult

	if pm == nil {
		return result
	}

	pm.mu.RLock()
	defer pm.mu.RUnlock()

	// pm.pol is written by SetPolicy under pm.mu; reading it before the
	// lock races with concurrent policy reloads.
	if pm.pol == nil {
		return result
	}

	// Self-steering doesn't apply.
	if viewer.ID() == peer.ID() {
		return result
	}

	// Only via grants can add to the result, and ACLs never carry via.
	if !slices.ContainsFunc(pm.pol.Grants, Grant.HasVia) {
		return result
	}

	// A peer without routes has nothing to steer.
	if len(peer.SubnetRoutes()) == 0 && !peer.IsExitNode() {
		return result
	}

	// Clip so the appends below allocate: callers share pm.pol under RLock,
	// and writing into its spare capacity races between them.
	grants := slices.Clip(pm.pol.Grants)

	// Ports never steer routes, so an ACL is one grant here, not one per
	// destination that would match its sources once per destination.
	for _, acl := range pm.pol.ACLs {
		dsts := make(Aliases, 0, len(acl.Destinations))
		for _, d := range acl.Destinations {
			dsts = append(dsts, d.Alias)
		}

		grants = append(grants, Grant{Sources: acl.Sources, Destinations: dsts})
	}

	// matchViewer resolves a grant lazily and at most once: non-via
	// grants are only needed once a via grant has matched, and
	// destinations only for grants that match the viewer.
	viewerIPs := viewer.IPs()
	resolved := make([]bool, len(grants))
	viewerMatchesGrant := make([]bool, len(grants))
	resolvedDstPrefixes := make([][]netip.Prefix, len(grants))
	grantHasAutoGroupInternet := make([]bool, len(grants))

	matchViewer := func(i int) bool {
		if resolved[i] {
			return viewerMatchesGrant[i]
		}

		resolved[i] = true

		for _, src := range grants[i].Sources {
			ips, err := src.Resolve(pm.resolvedPol, pm.users, pm.nodes)
			if err != nil {
				continue
			}

			if ips != nil && slices.ContainsFunc(viewerIPs, ips.Contains) {
				viewerMatchesGrant[i] = true

				break
			}
		}

		if viewerMatchesGrant[i] {
			resolvedDstPrefixes[i], grantHasAutoGroupInternet[i] = resolveViaDestinations(
				pm.resolvedPol, pm.users, pm.nodes, grants[i].Destinations,
			)
		}

		return viewerMatchesGrant[i]
	}

	for i, grant := range grants {
		if !grant.HasVia() {
			continue
		}

		if !matchViewer(i) {
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

		// Emit each route once, however many dst prefixes overlap it:
		// the passes below walk Include and Exclude per grant, so their
		// size must be bounded by the peer's routes, not by the grant's
		// destinations.
		for _, route := range peerSubnetRoutes {
			if slices.ContainsFunc(resolvedDstPrefixes[i], route.Overlaps) {
				matchedPrefixes = append(matchedPrefixes, route)
			}
		}

		// Per-viewer steering for autogroup:internet: a peer advertising
		// approved exit routes is the via-tagged node's analogue of
		// "advertises the destination". The downstream Include/Exclude
		// split below restricts the viewer to exit nodes carrying the
		// via tag.
		if grantHasAutoGroupInternet[i] && peer.IsExitNode() {
			matchedPrefixes = append(matchedPrefixes, peer.ExitRoutes()...)
		}

		if len(matchedPrefixes) == 0 {
			continue
		}

		// Check if peer has any of the via tags.
		peerHasVia := false

		for _, viaTag := range grant.Via {
			if peer.HasTag(string(viaTag)) {
				peerHasVia = true

				break
			}
		}

		// Several grants, or repeated announcements, can match the same
		// route; keep one entry per route.
		for _, p := range matchedPrefixes {
			if peerHasVia {
				if !slices.Contains(result.Include, p) {
					result.Include = append(result.Include, p)
				}
			} else if !slices.Contains(result.Exclude, p) {
				result.Exclude = append(result.Exclude, p)
			}
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
		// multiple peers advertising the same prefix, only the available
		// peer with the oldest control session (lower ID on a tie) keeps
		// the prefix in Include, as the global election picks. The others
		// move to Exclude. With no available router, the lowest ID keeps the
		// prefix so the viewer still gets exactly one route.
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
		for i, grant := range grants {
			if !grant.HasVia() {
				continue
			}

			if !matchViewer(i) {
				continue
			}

			// Elect per matched route, not per dst — a peer can only
			// be primary for a prefix it actually advertises, and one
			// dst may cover multiple distinct routes. The election
			// does not depend on which dst matched, so each included
			// route is looked at once per grant.
			for _, included := range slices.Clone(result.Include) {
				if !slices.ContainsFunc(resolvedDstPrefixes[i], included.Overlaps) {
					continue
				}

				var (
					viaPrimaryID, viaFallbackID types.NodeID
					viaPrimarySince             time.Time
				)

				for _, viaTag := range grant.Via {
					for _, node := range pm.nodes.All() {
						if node.HasTag(string(viaTag)) &&
							slices.Contains(node.SubnetRoutes(), included) {
							if viaFallbackID == 0 || node.ID() < viaFallbackID {
								viaFallbackID = node.ID()
							}

							var since time.Time

							if pm.routerSession != nil {
								var ok bool
								if since, ok = pm.routerSession(node.ID()); !ok {
									continue
								}
							}

							if viaPrimaryID == 0 || since.Before(viaPrimarySince) ||
								(since.Equal(viaPrimarySince) && node.ID() < viaPrimaryID) {
								viaPrimaryID, viaPrimarySince = node.ID(), since
							}
						}
					}
				}

				if viaPrimaryID == 0 {
					viaPrimaryID = viaFallbackID
				}

				if viaPrimaryID != 0 && peer.ID() != viaPrimaryID {
					result.Include = slices.DeleteFunc(
						result.Include,
						func(p netip.Prefix) bool { return p == included },
					)
					if !slices.Contains(result.Exclude, included) {
						result.Exclude = append(result.Exclude, included)
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
		for i, grant := range grants {
			if grant.HasVia() {
				continue
			}

			if !matchViewer(i) {
				continue
			}

			reachesInternet := grantReachesInternet(grant, resolvedDstPrefixes[i])

			// A non-via grant covering routes that a via grant included
			// defers to global HA primary election. Match by overlap so
			// a broader or narrower regular dst still catches the
			// routes the via grant added to Include.
			for _, dstPrefix := range resolvedDstPrefixes[i] {
				for _, p := range result.Include {
					// Only a grant to the internet covers an exit route,
					// as [types.Node.CanAccessRoutes] decides.
					covers := dstPrefix.Overlaps(p) &&
						(reachesInternet || !tsaddr.IsExitRoute(p))
					if covers && !slices.Contains(result.UsePrimary, p) {
						result.UsePrimary = append(result.UsePrimary, p)
					}
				}

				// Every address overlaps an exit route, so overlap
				// only decides for subnet routes.
				result.Exclude = slices.DeleteFunc(result.Exclude, func(p netip.Prefix) bool {
					return !tsaddr.IsExitRoute(p) && dstPrefix.Overlaps(p)
				})
			}

			// A regular grant to the internet lets the viewer use any
			// exit node, not just the via-tagged ones.
			if reachesInternet {
				result.Exclude = slices.DeleteFunc(result.Exclude, tsaddr.IsExitRoute)
			}
		}
	}

	return result
}

// grantReachesInternet reports whether a grant's destinations, resolved
// to dsts, reach the internet by the test the grant's filter rule gets
// ([matcher.Match.DestsIsTheInternet]). Neither the wildcard nor
// autogroup:internet resolves to the internet here, so check those
// aliases themselves.
func grantReachesInternet(grant Grant, dsts []netip.Prefix) bool {
	internetAlias := slices.ContainsFunc(grant.Destinations, func(d Alias) bool {
		if ag, ok := d.(*AutoGroup); ok {
			return ag.Is(AutoGroupInternet)
		}

		_, ok := d.(Asterix)

		return ok
	})
	if internetAlias {
		return true
	}

	var b netipx.IPSetBuilder
	for _, p := range dsts {
		b.AddPrefix(p)
	}

	// Resolved prefixes are valid, so the builder cannot fail.
	set, _ := b.IPSet()

	return util.CoversTheInternet(set)
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

	fmt.Fprintf(&sb, "AutoApprover (%d):\n", len(pm.autoApproveMap))

	for prefix, approveAddrs := range pm.autoApproveMap {
		fmt.Fprintf(&sb, "\t%s:\n", prefix)

		for _, iprange := range approveAddrs.Ranges() {
			fmt.Fprintf(&sb, "\t\t%s\n", iprange)
		}
	}

	sb.WriteString("\n\n")

	fmt.Fprintf(&sb, "TagOwner (%d):\n", len(pm.tagOwnerMap))

	for prefix, tagOwners := range pm.tagOwnerMap {
		fmt.Fprintf(&sb, "\t%s:\n", prefix)

		for _, iprange := range tagOwners.Ranges() {
			fmt.Fprintf(&sb, "\t\t%s\n", iprange)
		}
	}

	sb.WriteString("\n\n")

	if pm.filter != nil {
		filter, err := json.MarshalIndent(pm.filter, "", "  ")
		if err == nil {
			sb.WriteString("Compiled filter:\n")
			sb.Write(filter)
			sb.WriteString("\n\n")
		}
	}

	sb.WriteString("\n\n")
	sb.WriteString("Matchers:\n")
	sb.WriteString("an internal structure used to filter nodes and routes\n")

	for _, match := range pm.matchers {
		sb.WriteString(match.DebugString())
		sb.WriteString("\n")
	}

	sb.WriteString("\n\n")
	sb.WriteString("Nodes:\n")

	for _, node := range pm.nodes.All() {
		sb.WriteString(node.String())
		sb.WriteString("\n")
	}

	return sb.String()
}

// invalidateAutogroupSelfCache intelligently clears only the cache entries that need to be
// invalidated when using autogroup:self policies. This is much more efficient than clearing
// the entire cache.
func (pm *PolicyManager) invalidateAutogroupSelfCache(oldNodes, newNodes views.Slice[types.NodeView]) {
	// Build maps for efficient lookup
	oldNodeMap := nodeIDViewMap(oldNodes)
	newNodeMap := nodeIDViewMap(newNodes)

	// Track which users are affected by changes.
	// Tagged nodes don't participate in autogroup:self (identity is tag-based),
	// so we skip them when collecting affected users, except when tag status changes
	// (which affects the user's device set).
	//
	// Ownership is keyed on TypedUserID (the UserID field), not the User
	// association view: the NodeStore holds nodes by value with User as a
	// *User pointer, and not every write path hydrates that association. A
	// non-tagged node always has UserID set, so it is the reliable owner key.
	affectedUsers := make(map[types.UserID]struct{})

	// Check for removed nodes (only non-tagged nodes affect autogroup:self)
	for nodeID, oldNode := range oldNodeMap {
		if _, exists := newNodeMap[nodeID]; !exists {
			if !oldNode.IsTagged() {
				affectedUsers[oldNode.TypedUserID()] = struct{}{}
			}
		}
	}

	// Check for added nodes (only non-tagged nodes affect autogroup:self)
	for nodeID, newNode := range newNodeMap {
		if _, exists := oldNodeMap[nodeID]; !exists {
			if !newNode.IsTagged() {
				affectedUsers[newNode.TypedUserID()] = struct{}{}
			}
		}
	}

	// Check for modified nodes (user changes, tag changes, IP changes)
	for nodeID, newNode := range newNodeMap {
		if oldNode, exists := oldNodeMap[nodeID]; exists {
			// Check if tag status changed — this affects the user's autogroup:self device set.
			// Use the non-tagged version to get the user ID safely.
			if oldNode.IsTagged() != newNode.IsTagged() {
				if !oldNode.IsTagged() {
					// Was untagged, now tagged: user lost a device
					affectedUsers[oldNode.TypedUserID()] = struct{}{}
				} else {
					// Was tagged, now untagged: user gained a device
					affectedUsers[newNode.TypedUserID()] = struct{}{}
				}

				continue
			}

			// Skip tagged nodes for remaining checks — they don't participate in autogroup:self
			if newNode.IsTagged() {
				continue
			}

			// Check if user changed (both versions are non-tagged here)
			if oldNode.TypedUserID() != newNode.TypedUserID() {
				affectedUsers[oldNode.TypedUserID()] = struct{}{}
				affectedUsers[newNode.TypedUserID()] = struct{}{}
			}

			// Check if IPs changed.
			if !slices.Equal(oldNode.IPs(), newNode.IPs()) {
				affectedUsers[newNode.TypedUserID()] = struct{}{}
			}
		}
	}

	// Clear cache entries for affected users only.
	// For autogroup:self, we need to clear all nodes belonging to affected users
	// because autogroup:self rules depend on the entire user's device set.
	pm.filterRulesMap.Range(func(nodeID types.NodeID, _ []tailcfg.FilterRule) bool {
		// Find the user for this cached node using the already-built indexes.
		node, ok := newNodeMap[nodeID]
		if !ok {
			node, ok = oldNodeMap[nodeID]
		}

		// Node not found in either old or new list, clear it.
		if !ok {
			pm.filterRulesMap.Delete(nodeID)
			pm.matchersForNodeMap.Delete(nodeID)

			return true
		}

		// Tagged nodes don't participate in autogroup:self, so their cache
		// doesn't need user-based invalidation; leave nodeUserID at zero.
		var nodeUserID types.UserID
		if !node.IsTagged() {
			nodeUserID = node.TypedUserID()
		}

		// If the owning user is affected, clear this cache entry.
		if _, affected := affectedUsers[nodeUserID]; affected {
			pm.filterRulesMap.Delete(nodeID)
			pm.matchersForNodeMap.Delete(nodeID)
		}

		return true
	})

	if len(affectedUsers) > 0 {
		log.Debug().
			Int("affected_users", len(affectedUsers)).
			Int("remaining_cache_entries", pm.filterRulesMap.Size()).
			Msg("Selectively cleared autogroup:self cache for affected users")
	}
}

// invalidateNodeCache invalidates cache entries based on what changed.
func (pm *PolicyManager) invalidateNodeCache(newNodes views.Slice[types.NodeView]) {
	if pm.needsPerNodeFilter {
		// For autogroup:self or via grants, a node's filter depends
		// on its peers. When any node changes, invalidate affected
		// users' caches.
		pm.invalidateAutogroupSelfCache(pm.nodes, newNodes)
	} else {
		// For global policies, a node's filter depends only on its
		// own properties. Only invalidate changed nodes.
		pm.invalidateGlobalPolicyCache(newNodes)
	}
}

// invalidateGlobalPolicyCache invalidates only nodes whose properties affecting
// [policyutil.ReduceFilterRules] changed. For global policies, each node's filter is independent.
func (pm *PolicyManager) invalidateGlobalPolicyCache(newNodes views.Slice[types.NodeView]) {
	oldNodeMap := nodeIDViewMap(pm.nodes)
	newNodeMap := nodeIDViewMap(newNodes)

	// Invalidate nodes whose properties changed
	for nodeID, newNode := range newNodeMap {
		oldNode, existed := oldNodeMap[nodeID]
		if !existed {
			// New node - no cache entry yet, will be lazily calculated
			continue
		}

		if newNode.HasPolicyChange(oldNode) {
			pm.filterRulesMap.Delete(nodeID)
			pm.matchersForNodeMap.Delete(nodeID)
		}
	}

	// Remove deleted nodes from cache
	pm.filterRulesMap.Range(func(nodeID types.NodeID, _ []tailcfg.FilterRule) bool {
		if _, exists := newNodeMap[nodeID]; !exists {
			pm.filterRulesMap.Delete(nodeID)
		}

		return true
	})

	pm.matchersForNodeMap.Range(func(nodeID types.NodeID, _ []matcher.Match) bool {
		if _, exists := newNodeMap[nodeID]; !exists {
			pm.matchersForNodeMap.Delete(nodeID)
		}

		return true
	})
}

// resolveTagOwners resolves the [TagOwners] to a map of [Tag] to [netipx.IPSet].
// The resulting map can be used to quickly look up the IPSet for a given [Tag].
// It is intended for internal use in a [PolicyManager].
//
// Only a tag's own users and groups count: owning a tag does not give the
// tags it owns, as on Tailscale SaaS. A tag listed as owner is answered by
// [PolicyManager.TagOwnedByTags].
func resolveTagOwners(p *Policy, users types.Users, nodes views.Slice[types.NodeView]) (map[Tag]*netipx.IPSet, error) {
	ret := make(map[Tag]*netipx.IPSet)
	if p == nil {
		return ret, nil
	}

	for tag, owners := range p.TagOwners {
		var ips netipx.IPSetBuilder

		for _, owner := range owners {
			switch o := owner.(type) {
			case *Tag:
				// validate refuses this; a policy built in code can still
				// name one.
				if _, ok := p.TagOwners[*o]; !ok {
					return nil, fmt.Errorf("tagOwners[%q]: %q: %w",
						string(tag), string(*o), ErrUndefinedTagReference)
				}
			case Alias:
				// If it does not resolve, that means the tag is not associated with any IP addresses.
				resolved, _ := o.Resolve(p, users, nodes)
				if resolved != nil {
					for _, pref := range resolved.Prefixes() {
						ips.AddPrefix(pref)
					}
				}

			default:
				return nil, fmt.Errorf("%w: %v", ErrInvalidTagOwner, owner)
			}
		}

		ipSet, err := ips.IPSet()
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
func (pm *PolicyManager) refreshNodeAttrsLocked(newMap map[types.NodeID]tailcfg.NodeCapMap) {
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

// NodeCapMap returns compiled policy capabilities for the given node, or nil
// when none target it. The map is a defensive clone; its values are shared
// and read-only.
func (pm *PolicyManager) NodeCapMap(id types.NodeID) tailcfg.NodeCapMap {
	if pm == nil {
		return nil
	}

	pm.mu.RLock()
	defer pm.mu.RUnlock()

	src := pm.nodeAttrsMap[id]
	if len(src) == 0 {
		return nil
	}

	out := make(tailcfg.NodeCapMap, len(src))
	maps.Copy(out, src)

	return out
}

// NodeCapMaps snapshots every node's policy CapMap. The outer map is
// caller-owned; inner maps are shared with the manager and read-only.
// NodeCapMapsForPeers limits copying when fewer peers are requested.
func (pm *PolicyManager) NodeCapMaps() map[types.NodeID]tailcfg.NodeCapMap {
	if pm == nil {
		return nil
	}

	pm.mu.RLock()
	defer pm.mu.RUnlock()

	out := make(map[types.NodeID]tailcfg.NodeCapMap, len(pm.nodeAttrsMap))
	maps.Copy(out, pm.nodeAttrsMap)

	return out
}

// NodeCapMapsForPeers snapshots requested peer caps under one lock. It may
// include unselected entries when copying the whole compiled table is less work.
// The outer map is caller-owned; inner maps are shared and read-only.
// Empty selections or no compiled policy capabilities return nil; missing IDs read nil.
func (pm *PolicyManager) NodeCapMapsForPeers(peers views.Slice[types.NodeView]) map[types.NodeID]tailcfg.NodeCapMap {
	if pm == nil || peers.Len() == 0 {
		return nil
	}

	pm.mu.RLock()
	defer pm.mu.RUnlock()

	if len(pm.nodeAttrsMap) == 0 {
		return nil
	}

	out := make(map[types.NodeID]tailcfg.NodeCapMap, min(peers.Len(), len(pm.nodeAttrsMap)))
	if peers.Len() >= len(pm.nodeAttrsMap) {
		maps.Copy(out, pm.nodeAttrsMap)
	} else {
		for _, peer := range peers.All() {
			if caps, ok := pm.nodeAttrsMap[peer.ID()]; ok {
				out[peer.ID()] = caps
			}
		}
	}

	return out
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
