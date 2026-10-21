package v2

import (
	"fmt"
	"maps"
	"net/netip"
	"slices"

	"github.com/juanfont/headscale/hscontrol/types"
	"go4.org/netipx"
	"tailscale.com/tailcfg"
	"tailscale.com/types/views"
)

// sshTests assertions evaluate on user-initiated writes; boot reload
// skips them so a stale reference does not block startup. Each entry
// names a src and one or more dst, and uses:
//
//   - accept: every listed user reaches every dst via an accept- or
//     check-action rule.
//   - deny: no listed user reaches any dst.
//   - check: every listed user reaches every dst via a check-action
//     rule specifically (accept-only matches fail the assertion).

// SSHPolicyTestResult is the outcome of a single [SSHPolicyTest].
type SSHPolicyTestResult struct {
	Src    string   `json:"src"`
	Passed bool     `json:"passed"`
	Errors []string `json:"errors,omitempty"`

	AcceptOK   map[string][]string `json:"accept_ok,omitempty"`
	AcceptFail map[string][]string `json:"accept_fail,omitempty"`
	DenyOK     map[string][]string `json:"deny_ok,omitempty"`
	DenyFail   map[string][]string `json:"deny_fail,omitempty"`
	CheckOK    map[string][]string `json:"check_ok,omitempty"`
	CheckFail  map[string][]string `json:"check_fail,omitempty"`

	// CheckDenied holds the check failures where a node was not reached at
	// all. A dst alias can cover nodes that fail in different ways, and one
	// node not reached makes the alias DENIED.
	CheckDenied map[string][]string `json:"check_denied,omitempty"`
}

// SSHPolicyTestResults aggregates one evaluation run.
type SSHPolicyTestResults struct {
	AllPassed bool                  `json:"all_passed"`
	Results   []SSHPolicyTestResult `json:"results"`
}

// Errors renders the per-test failure breakdown joined by newlines,
// bounded by [testFailures].
func (r SSHPolicyTestResults) Errors() string {
	if r.AllPassed {
		return ""
	}

	var failures testFailures

	for _, res := range r.Results {
		if res.Passed {
			continue
		}

		src := clipTestLabel(res.Src)

		for _, e := range res.Errors {
			failures.addf("%s: %s", src, clipTestLabel(e))
		}

		for _, user := range sortedUsers(res.AcceptFail) {
			for _, dst := range res.AcceptFail[user] {
				failures.addf(
					"%s/%s -> %s: expected ALLOWED, got DENIED",
					src, clipTestLabel(displayUser(user)), clipTestLabel(dst),
				)
			}
		}

		for _, user := range sortedUsers(res.DenyFail) {
			for _, dst := range res.DenyFail[user] {
				failures.addf(
					"%s/%s -> %s: expected DENIED, got ALLOWED",
					src, clipTestLabel(displayUser(user)), clipTestLabel(dst),
				)
			}
		}

		for _, user := range sortedUsers(res.CheckFail) {
			for _, dst := range res.CheckFail[user] {
				// The reason scans CheckDenied; skip it for lines that
				// are only counted.
				var reason string
				if !failures.full() {
					reason = checkFailReason(res, user, dst)
				}

				failures.addf(
					"%s/%s -> %s: expected ALLOWED via check, got %s",
					src, clipTestLabel(displayUser(user)), clipTestLabel(dst),
					reason,
				)
			}
		}
	}

	return failures.String()
}

func sortedUsers(m map[string][]string) []string {
	return slices.Sorted(maps.Keys(m))
}

// displayUser shows an empty username as `""` rather than blank.
func displayUser(u string) string {
	if u == "" {
		return `""`
	}

	return u
}

// checkFailReason annotates a check-fail with whether the user reached
// the dst via an accept rule or did not reach at all.
func checkFailReason(res SSHPolicyTestResult, user, dst string) string {
	if slices.Contains(res.CheckDenied[user], dst) {
		return "DENIED"
	}

	return "ALLOWED via accept"
}

// RunSSHTests evaluates the live policy's sshTests block and wraps any
// failure in [errSSHPolicyTestsFailed].
func (pm *PolicyManager) RunSSHTests() error {
	if pm == nil || pm.pol == nil || len(pm.pol.SSHTests) == 0 {
		return nil
	}

	pm.mu.RLock()
	defer pm.mu.RUnlock()

	cache := make(map[types.NodeID]*tailcfg.SSHPolicy)
	results := runSSHPolicyTests(pm.resolvedPol, pm.users, pm.nodes, cache)

	return wrapTestResult(errSSHPolicyTestsFailed, results.AllPassed, results.Errors)
}

// evaluateSSHTests runs the block against pol without mutating live state.
func evaluateSSHTests(
	pol *Policy,
	users []types.User,
	nodes views.Slice[types.NodeView],
) error {
	if pol == nil || len(pol.SSHTests) == 0 {
		return nil
	}

	pol = pol.withResolvedGroups(users, nodes)
	cache := make(map[types.NodeID]*tailcfg.SSHPolicy)
	results := runSSHPolicyTests(pol, users, nodes, cache)

	return wrapTestResult(errSSHPolicyTestsFailed, results.AllPassed, results.Errors)
}

// runSSHPolicyTests evaluates every sshTests entry. The cache is keyed
// by dst [types.NodeID] so repeat destinations only compile once per pass.
func runSSHPolicyTests(
	pol *Policy,
	users []types.User,
	nodes views.Slice[types.NodeView],
	cache map[types.NodeID]*tailcfg.SSHPolicy,
) SSHPolicyTestResults {
	results := SSHPolicyTestResults{
		AllPassed: true,
		Results:   make([]SSHPolicyTestResult, 0, len(pol.SSHTests)),
	}

	for _, test := range pol.SSHTests {
		res := runSSHPolicyTest(test, pol, users, nodes, cache)
		if !res.Passed {
			results.AllPassed = false
		}

		results.Results = append(results.Results, res)
	}

	return results
}

// runSSHPolicyTest evaluates one entry: resolve src → resolve dst →
// walk accept/deny/check arrays against each dst's compiled SSH policy.
func runSSHPolicyTest(
	test SSHPolicyTest,
	pol *Policy,
	users []types.User,
	nodes views.Slice[types.NodeView],
	cache map[types.NodeID]*tailcfg.SSHPolicy,
) SSHPolicyTestResult {
	srcLabel := ""
	if test.Src != nil {
		srcLabel = sshTestLabel(test.Src)
	}

	res := SSHPolicyTestResult{
		Src:    srcLabel,
		Passed: true,
	}

	srcAddrs, srcUserID, err := resolveSSHTestSource(test.Src, pol, users, nodes)
	if err != nil {
		res.Passed = false
		res.Errors = append(res.Errors,
			fmt.Sprintf("failed to resolve source %q: %v", srcLabel, err))

		return res
	}

	if len(srcAddrs) == 0 {
		res.Passed = false
		res.Errors = append(res.Errors,
			fmt.Sprintf("source %q resolved to no IP addresses", srcLabel))

		return res
	}

	// An entry with no assertion arrays would silently pass.
	if len(test.Accept) == 0 && len(test.Deny) == 0 && len(test.Check) == 0 {
		res.Passed = false
		res.Errors = append(res.Errors,
			"no accept, deny, or check assertions specified")

		return res
	}

	dsts, err := resolveSSHTestDests(test.Dst, pol, users, nodes, srcUserID)
	if err != nil {
		res.Passed = false
		res.Errors = append(res.Errors,
			fmt.Sprintf("failed to resolve destinations: %v", err))

		return res
	}

	for _, g := range []struct {
		users []SSHUser
		kind  sshAssertion
	}{
		{test.Accept, assertAccept},
		{test.Deny, assertDeny},
		{test.Check, assertCheck},
	} {
		for _, user := range g.users {
			evaluateAssertion(
				pol, users, nodes, cache,
				srcAddrs, dsts, user.String(),
				g.kind, &res,
			)
		}
	}

	return res
}

type sshAssertion int

const (
	assertAccept sshAssertion = iota
	assertDeny
	assertCheck
)

// evaluateAssertion records one user's outcome for each dst alias of an
// entry, under the alias as written: the report goes back to the policy
// author, who may not be allowed to list nodes. An alias passes when every
// node it selects does, for every src address; one selecting no node is not
// reached. Each distinct alias is evaluated once and reported at every
// occurrence, as Tailscale SaaS reports them.
func evaluateAssertion(
	pol *Policy,
	users []types.User,
	nodes views.Slice[types.NodeView],
	cache map[types.NodeID]*tailcfg.SSHPolicy,
	srcAddrs []netip.Addr,
	dsts []sshTestDst,
	user string,
	kind sshAssertion,
	res *SSHPolicyTestResult,
) {
	type outcome struct{ passed, notReached, failed bool }

	seen := make(map[string]outcome, len(dsts))

	for _, dst := range dsts {
		o, ok := seen[dst.label]
		if !ok {
			passed, notReached, err := sshTestAliasOutcome(
				pol, users, nodes, cache, srcAddrs, dst.nodes, user, kind,
			)
			if err != nil {
				res.Passed = false
				res.Errors = append(res.Errors,
					fmt.Sprintf("compiling SSH policy for %s: %v", dst.label, err))
			}

			o = outcome{passed, notReached, err != nil}
			seen[dst.label] = o
		}

		if o.failed {
			continue
		}

		if !o.passed {
			res.Passed = false
		}

		switch {
		case kind == assertAccept && o.passed:
			res.AcceptOK = appendUserDst(res.AcceptOK, user, dst.label)
		case kind == assertAccept:
			res.AcceptFail = appendUserDst(res.AcceptFail, user, dst.label)
		case kind == assertDeny && o.passed:
			res.DenyOK = appendUserDst(res.DenyOK, user, dst.label)
		case kind == assertDeny:
			res.DenyFail = appendUserDst(res.DenyFail, user, dst.label)
		case o.passed:
			res.CheckOK = appendUserDst(res.CheckOK, user, dst.label)
		default:
			res.CheckFail = appendUserDst(res.CheckFail, user, dst.label)

			if o.notReached {
				res.CheckDenied = appendUserDst(res.CheckDenied, user, dst.label)
			}
		}
	}
}

// sshTestAliasOutcome reports whether user's assertion holds on every node
// of one dst alias from every src address, and whether a failing node was
// not reached at all. All src addresses must agree: the first
// counter-example fails the node.
func sshTestAliasOutcome(
	pol *Policy,
	users []types.User,
	nodes views.Slice[types.NodeView],
	cache map[types.NodeID]*tailcfg.SSHPolicy,
	srcAddrs []netip.Addr,
	dstNodes []types.NodeView,
	user string,
	kind sshAssertion,
) (bool, bool, error) {
	if len(dstNodes) == 0 {
		return kind == assertDeny, true, nil
	}

	passed, notReached := true, false

	for _, dst := range dstNodes {
		dstPol, err := compiledSSHPolicy(pol, users, nodes, cache, dst)
		if err != nil {
			return false, false, err
		}

		for _, srcAddr := range srcAddrs {
			a, c := reachability(dstPol, srcAddr, user)

			var holds bool

			switch kind {
			case assertAccept:
				holds = a
			case assertDeny:
				holds = !a
			case assertCheck:
				holds = c
			}

			if !holds {
				passed = false
				notReached = notReached || !a

				break
			}
		}
	}

	return passed, notReached, nil
}

// appendUserDst appends dst to m[user], allocating m on first use.
func appendUserDst(m map[string][]string, user, dst string) map[string][]string {
	if m == nil {
		m = make(map[string][]string)
	}

	m[user] = append(m[user], dst)

	return m
}

// resolveSSHTestSource returns the src's principal addresses and, for
// user-shaped sources, the user ID (so autogroup:self can scope to it).
// [Tag], [Host], and IP sources return userID 0.
//
// SSH principals are always node addresses, so a src is represented by
// the node addresses it covers plus one address standing in for all
// the others, which no rule can match. The result is bounded by the
// node count; a CIDR, `*`, or autogroup:internet src is never walked
// address by address.
func resolveSSHTestSource(
	src Alias,
	pol *Policy,
	users []types.User,
	nodes views.Slice[types.NodeView],
) ([]netip.Addr, uint, error) {
	if src == nil {
		return nil, 0, nil
	}

	// Mirrors resolveTestSource: an unregistered user fails the test.
	if u, ok := src.(*Username); ok {
		_, err := u.resolveUser(users)
		if err != nil {
			return nil, 0, fmt.Errorf("resolving: %w", err)
		}
	}

	addrs, err := src.Resolve(pol, users, nodes)
	if err != nil {
		return nil, 0, fmt.Errorf("resolving: %w", err)
	}

	if addrs == nil || addrs.Empty() {
		return nil, 0, nil
	}

	var (
		out  []netip.Addr
		rest netipx.IPSetBuilder
	)

	for _, p := range addrs.Prefixes() {
		rest.AddPrefix(p)
	}

	for _, n := range nodes.All() {
		for _, ip := range n.IPs() {
			if addrs.Contains(ip) {
				out = append(out, ip)
				rest.Remove(ip)
			}
		}
	}

	restSet, err := rest.IPSet()
	if err != nil {
		return nil, 0, fmt.Errorf("resolving: %w", err)
	}

	if ranges := restSet.Ranges(); len(ranges) > 0 {
		out = append(out, ranges[0].From())
	}

	// Address order, as a full walk has: the first failing address
	// decides how a check failure is rendered.
	slices.SortFunc(out, netip.Addr.Compare)

	var userID uint

	u, ok := src.(*Username)
	if ok {
		resolved, rErr := u.resolveUser(users)
		if rErr == nil {
			userID = resolved.ID
		}
	}

	return out, userID, nil
}

// sshTestLabel names an sshTests alias as its author writes it: a single
// address bare, not as a /32 or /128 prefix.
func sshTestLabel(alias Alias) string {
	if p, ok := alias.(*Prefix); ok {
		return filterIP(netip.Prefix(*p))
	}

	return alias.String()
}

// sshTestDst is one dst alias of an sshTests entry and the nodes it
// selects.
type sshTestDst struct {
	label string
	nodes []types.NodeView
}

// resolveSSHTestDests resolves each dst alias of an entry, in order and
// once per occurrence, so the report can name every alias as written.
// Each distinct alias resolves once.
func resolveSSHTestDests(
	dsts SSHTestDestinations,
	pol *Policy,
	users []types.User,
	nodes views.Slice[types.NodeView],
	srcUserID uint,
) ([]sshTestDst, error) {
	selected := make(map[string][]types.NodeView, len(dsts))
	out := make([]sshTestDst, 0, len(dsts))

	for _, alias := range dsts {
		label := sshTestLabel(alias)

		dstNodes, ok := selected[label]
		if !ok {
			var err error

			dstNodes, err = sshTestDstNodes(alias, pol, users, nodes, srcUserID)
			if err != nil {
				return nil, err
			}

			selected[label] = dstNodes
		}

		out = append(out, sshTestDst{label: label, nodes: dstNodes})
	}

	return out, nil
}

// sshTestDstNodes returns the nodes one dst alias selects. autogroup:self
// cannot resolve without per-node context, so it walks the node set keyed
// on src's owning user. Other aliases resolve to an [netipx.IPSet] and
// match via [types.NodeView.InIPSet].
func sshTestDstNodes(
	alias Alias,
	pol *Policy,
	users []types.User,
	nodes views.Slice[types.NodeView],
	srcUserID uint,
) ([]types.NodeView, error) {
	var out []types.NodeView

	if ag, ok := alias.(*AutoGroup); ok && ag.Is(AutoGroupSelf) {
		// autogroup:self is the src user's untagged nodes; tagged and
		// address sources have no user.
		if srcUserID == 0 {
			return nil, nil
		}

		for _, n := range nodes.All() {
			if !n.IsTagged() && n.User().Valid() && n.User().ID() == srcUserID {
				out = append(out, n)
			}
		}

		return out, nil
	}

	ips, err := alias.Resolve(pol, users, nodes)
	if err != nil {
		return nil, fmt.Errorf("resolving destination %q: %w", sshTestLabel(alias), err)
	}

	if ips == nil || ips.Empty() {
		return nil, nil
	}

	set, err := prefixesToIPSet(ips.Prefixes())
	if err != nil {
		return nil, fmt.Errorf("building IPSet for %q: %w", sshTestLabel(alias), err)
	}

	for _, n := range nodes.All() {
		if n.InIPSet(set) {
			out = append(out, n)
		}
	}

	return out, nil
}

// prefixesToIPSet builds the [netipx.IPSet] that [types.NodeView.InIPSet]
// expects on the node side.
func prefixesToIPSet(prefixes []netip.Prefix) (*netipx.IPSet, error) {
	var b netipx.IPSetBuilder

	for _, p := range prefixes {
		b.AddPrefix(p)
	}

	return b.IPSet()
}

// compiledSSHPolicy returns the per-node compiled [tailcfg.SSHPolicy], caching
// on miss. baseURL is empty because reachability only checks for the
// presence of [tailcfg.SSHAction.HoldAndDelegate], not its value.
func compiledSSHPolicy(
	pol *Policy,
	users []types.User,
	nodes views.Slice[types.NodeView],
	cache map[types.NodeID]*tailcfg.SSHPolicy,
	node types.NodeView,
) (*tailcfg.SSHPolicy, error) {
	if sshPol, ok := cache[node.ID()]; ok {
		return sshPol, nil
	}

	sshPol, err := pol.compileSSHPolicy("", users, node, nodes)
	if err != nil {
		return nil, err
	}

	cache[node.ID()] = sshPol

	return sshPol, nil
}

// reachability reports whether srcAddr can log in as user via:
//
//   - any matching rule (acceptHit, satisfies accept assertions)
//   - a check-action rule (checkHit, satisfies check assertions)
func reachability(
	dstPolicy *tailcfg.SSHPolicy,
	srcAddr netip.Addr,
	user string,
) (bool, bool) {
	if dstPolicy == nil {
		return false, false
	}

	var acceptHit, checkHit bool

	for _, rule := range dstPolicy.Rules {
		if !principalContainsAddr(rule.Principals, srcAddr) {
			continue
		}

		if !sshUserMapAllows(rule.SSHUsers, user) {
			continue
		}

		if rule.Action == nil {
			continue
		}

		acceptHit = true

		if rule.Action.HoldAndDelegate != "" {
			checkHit = true
		}

		// Early-out only when both bits are set: a rule satisfying
		// accept does not always satisfy check.
		if acceptHit && checkHit {
			return acceptHit, checkHit
		}
	}

	return acceptHit, checkHit
}

// principalContainsAddr reports whether any principal's [tailcfg.SSHPrincipal.NodeIP]
// matches srcAddr exactly (the SSH compiler emits one principal per source IP).
func principalContainsAddr(
	principals []*tailcfg.SSHPrincipal,
	srcAddr netip.Addr,
) bool {
	for _, p := range principals {
		if p == nil {
			continue
		}

		if p.NodeIP == "" {
			continue
		}

		addr, err := netip.ParseAddr(p.NodeIP)
		if err != nil {
			continue
		}

		if addr == srcAddr {
			return true
		}
	}

	return false
}

// sshUserMapAllows reports whether [SSHUsers] permits user. The [SSHUsers]
// wire shape (see filter.go compileSSHPolicy):
//
//   - SSHUsers["root"] == "root" allows root; == "" disallows it.
//   - SSHUsers["*"] == "=" is the wildcard fallback for non-root users
//     (set when the rule lists autogroup:nonroot).
//   - SSHUsers[<literal>] == <literal> for every named user.
func sshUserMapAllows(m map[string]string, user string) bool {
	if user == "" {
		return false
	}

	if v, ok := m[user]; ok {
		return v != ""
	}

	if user == "root" {
		return false
	}

	// Wildcard fallback for non-root users.
	if v, ok := m["*"]; ok {
		return v != ""
	}

	return false
}
