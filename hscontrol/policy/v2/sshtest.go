package v2

import (
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"strings"

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
}

// SSHPolicyTestResults aggregates one evaluation run.
type SSHPolicyTestResults struct {
	AllPassed bool                  `json:"all_passed"`
	Results   []SSHPolicyTestResult `json:"results"`
}

// Errors renders the per-test failure breakdown joined by newlines.
func (r SSHPolicyTestResults) Errors() string {
	if r.AllPassed {
		return ""
	}

	var lines []string

	for _, res := range r.Results {
		if res.Passed {
			continue
		}

		for _, e := range res.Errors {
			lines = append(lines, fmt.Sprintf("%s: %s", res.Src, e))
		}

		for _, user := range sortedUsers(res.AcceptFail) {
			for _, dst := range res.AcceptFail[user] {
				lines = append(lines, fmt.Sprintf(
					"%s/%s -> %s: expected ALLOWED, got DENIED",
					res.Src, displayUser(user), dst,
				))
			}
		}

		for _, user := range sortedUsers(res.DenyFail) {
			for _, dst := range res.DenyFail[user] {
				lines = append(lines, fmt.Sprintf(
					"%s/%s -> %s: expected DENIED, got ALLOWED",
					res.Src, displayUser(user), dst,
				))
			}
		}

		for _, user := range sortedUsers(res.CheckFail) {
			for _, dst := range res.CheckFail[user] {
				lines = append(lines, fmt.Sprintf(
					"%s/%s -> %s: expected ALLOWED via check, got %s",
					res.Src, displayUser(user), dst,
					checkFailReason(res, user, dst),
				))
			}
		}
	}

	return strings.Join(lines, "\n")
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
	if slices.Contains(res.AcceptOK[user], dst) {
		return "ALLOWED via accept"
	}

	return "DENIED"
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
	results := runSSHPolicyTests(pm.pol, pm.users, pm.nodes, cache)

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
		srcLabel = test.Src.String()
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

	dstNodes, emptyDsts, err := resolveSSHTestDestNodes(test.Dst, pol, users, nodes, srcUserID)
	if err != nil {
		res.Passed = false
		res.Errors = append(res.Errors,
			fmt.Sprintf("failed to resolve destinations: %v", err))

		return res
	}

	// A dst resolving to zero nodes would silently pass.
	for _, dst := range emptyDsts {
		res.Passed = false
		res.Errors = append(res.Errors,
			fmt.Sprintf("dst alias %q resolved to no nodes", dst))
	}

	if len(dstNodes) == 0 {
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
				srcAddrs, dstNodes, user.String(),
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

// evaluateAssertion walks every (srcAddr, dstNode) pair for one user
// and records the outcome. Empty username fails — SSH login users
// cannot be empty even when parse accepted it.
func evaluateAssertion(
	pol *Policy,
	users []types.User,
	nodes views.Slice[types.NodeView],
	cache map[types.NodeID]*tailcfg.SSHPolicy,
	srcAddrs []netip.Addr,
	dstNodes []types.NodeView,
	user string,
	kind sshAssertion,
	res *SSHPolicyTestResult,
) {
dstLoop:
	for _, dst := range dstNodes {
		dstPol, err := compiledSSHPolicy(pol, users, nodes, cache, dst)
		if err != nil {
			res.Passed = false
			res.Errors = append(res.Errors,
				fmt.Sprintf("compiling SSH policy for %s: %v",
					dst.Hostname(), err))

			continue
		}

		dstLabel := dst.Hostname()

		acceptHit := false
		checkHit := false

		for _, srcAddr := range srcAddrs {
			a, c := reachability(dstPol, srcAddr, user)
			if a {
				acceptHit = true
			}

			if c {
				checkHit = true
			}

			// All src IPs must agree; one counter-example fails
			// the whole (user, dst) pair.
			switch kind {
			case assertAccept:
				if !a {
					res.Passed = false
					res.AcceptFail = appendUserDst(res.AcceptFail, user, dstLabel)

					continue dstLoop
				}
			case assertDeny:
				if a {
					res.Passed = false
					res.DenyFail = appendUserDst(res.DenyFail, user, dstLabel)

					continue dstLoop
				}
			case assertCheck:
				if !c {
					res.Passed = false
					res.CheckFail = appendUserDst(res.CheckFail, user, dstLabel)

					// Record whether the accept side passed so
					// the rendered error can say "ALLOWED via
					// accept" instead of "DENIED".
					if a {
						res.AcceptOK = appendUserDst(res.AcceptOK, user, dstLabel)
					}

					continue dstLoop
				}
			}
		}

		switch kind {
		case assertAccept:
			if acceptHit {
				res.AcceptOK = appendUserDst(res.AcceptOK, user, dstLabel)
			}
		case assertDeny:
			res.DenyOK = appendUserDst(res.DenyOK, user, dstLabel)
		case assertCheck:
			if checkHit {
				res.CheckOK = appendUserDst(res.CheckOK, user, dstLabel)
			}
		}
	}
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
func resolveSSHTestSource(
	src Alias,
	pol *Policy,
	users []types.User,
	nodes views.Slice[types.NodeView],
) ([]netip.Addr, uint, error) {
	if src == nil {
		return nil, 0, nil
	}

	addrs, err := src.Resolve(pol, users, nodes)
	if err != nil {
		return nil, 0, fmt.Errorf("resolving: %w", err)
	}

	if addrs == nil || addrs.Empty() {
		return nil, 0, nil
	}

	out := slices.Collect(addrs.Iter())

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

// resolveSSHTestDestNodes maps each dst alias to its destination
// [types.NodeView]s. autogroup:self needs special handling: it cannot
// resolve without per-node context, so it walks the node set keyed on
// src's owning user. Other aliases resolve to an [netipx.IPSet] and match
// via [types.NodeView.InIPSet].
func resolveSSHTestDestNodes(
	dsts SSHTestDestinations,
	pol *Policy,
	users []types.User,
	nodes views.Slice[types.NodeView],
	srcUserID uint,
) ([]types.NodeView, []string, error) {
	seen := make(map[types.NodeID]struct{})

	var (
		out       []types.NodeView
		emptyDsts []string
	)

	for _, alias := range dsts {
		dstLabel := alias.String()
		matched := false

		if ag, ok := alias.(*AutoGroup); ok && ag.Is(AutoGroupSelf) {
			// autogroup:self resolves to non-tagged nodes owned by
			// the same user as src; tagged/IP sources have no user.
			if srcUserID == 0 {
				emptyDsts = append(emptyDsts, dstLabel)

				continue
			}

			for _, n := range nodes.All() {
				if n.IsTagged() {
					continue
				}

				if !n.User().Valid() {
					continue
				}

				if n.User().ID() != srcUserID {
					continue
				}

				matched = true

				if _, dup := seen[n.ID()]; dup {
					continue
				}

				seen[n.ID()] = struct{}{}
				out = append(out, n)
			}

			if !matched {
				emptyDsts = append(emptyDsts, dstLabel)
			}

			continue
		}

		ips, err := alias.Resolve(pol, users, nodes)
		if err != nil {
			return nil, nil, fmt.Errorf("resolving destination %q: %w", dstLabel, err)
		}

		if ips == nil || ips.Empty() {
			emptyDsts = append(emptyDsts, dstLabel)

			continue
		}

		set, err := prefixesToIPSet(ips.Prefixes())
		if err != nil {
			return nil, nil, fmt.Errorf("building IPSet for %q: %w", dstLabel, err)
		}

		for _, n := range nodes.All() {
			if !n.InIPSet(set) {
				continue
			}

			matched = true

			if _, dup := seen[n.ID()]; dup {
				continue
			}

			seen[n.ID()] = struct{}{}
			out = append(out, n)
		}

		if !matched {
			emptyDsts = append(emptyDsts, dstLabel)
		}
	}

	return out, emptyDsts, nil
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
