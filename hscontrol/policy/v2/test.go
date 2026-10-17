package v2

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"github.com/go-json-experiment/json"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"go4.org/netipx"
	"tailscale.com/tailcfg"
	"tailscale.com/types/views"
)

// Tailscale's policy file `tests` block validates a policy against operator
// assertions: from a given src, named dst:port pairs must be accepted, and
// (optionally) other dst:port pairs must be denied. They run at user-write
// boundaries — `headscale policy set`, file-mode reload after a change,
// `headscale policy check` — and reject the write if any assertion fails.
// Boot-time reload of an already-stored policy does not run them, so a
// stale referenced entity (e.g. a deleted user) cannot lock the server out.
//
// The tests evaluate against the compiled global filter rules, which fold in
// both `acls` and `grants`, so the `tests` block validates the whole policy.

// errPolicyTestsFailed and errSSHPolicyTestsFailed share the
// "test(s) failed" prefix but stay distinct so callers can use
// [errors.Is] to tell ACL-test and SSH-test failures apart.
var (
	errPolicyTestsFailed    = errors.New("test(s) failed")
	errSSHPolicyTestsFailed = errors.New("test(s) failed")
	errTestDestinationNoIP  = errors.New("destination resolved to no IP addresses")
	errTestSourceUnknown    = errors.New("unknown user or host")
)

// PolicyTest is one entry in the policy's `tests` block.
type PolicyTest struct {
	// Src is a single source alias (user, group, tag, host, autogroup, or IP).
	// Tailscale only supports a single src per test entry.
	Src string `json:"src"`

	// Proto restricts the test to one protocol. Empty matches the default
	// set the client applies when proto is omitted (TCP/UDP/ICMP).
	Proto Protocol `json:"proto,omitempty"`

	// Accept lists destinations in `host:port` form that must be reachable
	// from Src. A test fails if any entry is denied by the compiled filter.
	Accept []string `json:"accept,omitempty"`

	// Deny lists destinations in `host:port` form that must NOT be reachable
	// from Src. A test fails if any entry is allowed by the compiled filter.
	Deny []string `json:"deny,omitempty"`
}

// SSHPolicyTest is one entry in the policy's `sshTests` block. The
// accept/deny/check arrays carry usernames, not destinations — every
// listed user is asserted against every entry in [SSHPolicyTest.Dst].
type SSHPolicyTest struct {
	// Src is a single source alias (user, group, tag, host, or IP).
	Src Alias `json:"src"`

	// Dst lists destinations the test exercises (tag, host, or SSH-
	// compatible autogroup). Ports, CIDRs, and autogroup:internet are
	// rejected at parse time.
	Dst SSHTestDestinations `json:"dst"`

	// Accept lists users that must reach every Dst via an accept- or
	// check-action rule.
	Accept []SSHUser `json:"accept,omitempty"`

	// Deny lists users that must NOT reach any Dst.
	Deny []SSHUser `json:"deny,omitempty"`

	// Check lists users that must reach every Dst via a check-action
	// rule specifically; an accept-action rule does not satisfy this.
	Check []SSHUser `json:"check,omitempty"`
}

// SSHTestDestinations is the typed list of destination aliases an
// sshTests entry targets. [validateSSHTestDestination] enforces the
// SSH-specific shape rules (no :port, no CIDR, no autogroup:internet,
// known tag).
type SSHTestDestinations []Alias

func (d *SSHTestDestinations) UnmarshalJSON(b []byte) error {
	var aliases []AliasEnc

	err := json.Unmarshal(b, &aliases, policyJSONOpts...)
	if err != nil {
		return err
	}

	*d = make([]Alias, len(aliases))
	for i, a := range aliases {
		(*d)[i] = a.Alias
	}

	return nil
}

// UnmarshalJSON parses each typed field. An empty src lands as a nil
// [Alias] so validation surfaces [ErrSSHTestEmptySrc] rather than a parser
// failure.
func (t *SSHPolicyTest) UnmarshalJSON(b []byte) error {
	var raw struct {
		Src    string              `json:"src"`
		Dst    SSHTestDestinations `json:"dst"`
		Accept []SSHUser           `json:"accept,omitempty"`
		Deny   []SSHUser           `json:"deny,omitempty"`
		Check  []SSHUser           `json:"check,omitempty"`
	}

	err := json.Unmarshal(b, &raw, policyJSONOpts...)
	if err != nil {
		return err
	}

	trimmedSrc := strings.TrimSpace(raw.Src)
	if trimmedSrc != "" {
		alias, parseErr := parseAlias(trimmedSrc)
		if parseErr != nil {
			return parseErr
		}

		t.Src = alias
	}

	t.Dst = raw.Dst
	t.Accept = raw.Accept
	t.Deny = raw.Deny
	t.Check = raw.Check

	return nil
}

// PolicyTestResult is the outcome of a single [PolicyTest].
type PolicyTestResult struct {
	Src    string   `json:"src"`
	Proto  Protocol `json:"proto,omitempty"`
	Passed bool     `json:"passed"`

	// Errors are non-assertion problems: src failed to resolve, dst was
	// malformed, etc. These cause the test to fail.
	Errors []string `json:"errors,omitempty"`

	// AcceptOK / AcceptFail / DenyOK / DenyFail partition the per-dst
	// outcomes for diagnostics.
	AcceptOK   []string `json:"accept_ok,omitempty"`
	AcceptFail []string `json:"accept_fail,omitempty"`
	DenyOK     []string `json:"deny_ok,omitempty"`
	DenyFail   []string `json:"deny_fail,omitempty"`
}

// PolicyTestResults aggregates a run.
type PolicyTestResults struct {
	AllPassed bool               `json:"all_passed"`
	Results   []PolicyTestResult `json:"results"`
}

// Errors renders the per-test failure breakdown joined by newlines.
// Tailscale SaaS itself only returns the literal "test(s) failed" — we
// keep the per-test detail because it is significantly more useful in
// CLI / config-reload paths where the user does not have a separate
// audit endpoint to consult.
//
// The breakdown is bounded by [testFailures].
func (r PolicyTestResults) Errors() string {
	if r.AllPassed {
		return ""
	}

	var failures testFailures

	for _, res := range r.Results {
		if res.Passed {
			continue
		}

		src := clipTestLabel(res.Src)

		protoSuffix := ""
		if res.Proto != "" {
			protoSuffix = fmt.Sprintf(" (%s)", res.Proto)
		}

		for _, e := range res.Errors {
			failures.addf("%s%s: %s", src, protoSuffix, clipTestLabel(e))
		}

		for _, dst := range res.AcceptFail {
			failures.addf(
				"%s -> %s%s: expected ALLOWED, got DENIED",
				src, clipTestLabel(dst), protoSuffix,
			)
		}

		for _, dst := range res.DenyFail {
			failures.addf(
				"%s -> %s%s: expected DENIED, got ALLOWED",
				src, clipTestLabel(dst), protoSuffix,
			)
		}
	}

	return failures.String()
}

// The policy author sizes both the labels on a failure line and the
// number of failures, so a breakdown rendered in full grows with their
// product. It is rendered on the write path and, for a stored policy
// whose tests stopped passing, at every boot, so both factors are capped.
const (
	maxTestFailureLines = 100
	maxTestLabelBytes   = 256
)

// testFailures collects the lines of a `tests` or `sshTests` failure
// breakdown. Failures past [maxTestFailureLines] are counted, not
// rendered.
type testFailures struct {
	lines   []string
	omitted int
}

func (f *testFailures) full() bool {
	return len(f.lines) >= maxTestFailureLines
}

func (f *testFailures) addf(format string, args ...any) {
	if f.full() {
		f.omitted++

		return
	}

	f.lines = append(f.lines, fmt.Sprintf(format, args...))
}

func (f *testFailures) String() string {
	lines := f.lines
	if f.omitted > 0 {
		lines = append(lines, fmt.Sprintf("... and %d more", f.omitted))
	}

	return strings.Join(lines, "\n")
}

// clipTestLabel shortens s to [maxTestLabelBytes] for a failure line.
func clipTestLabel(s string) string {
	if len(s) <= maxTestLabelBytes {
		return s
	}

	return strings.ToValidUTF8(s[:maxTestLabelBytes], "") + "..."
}

// TestFailure is one failing tests or sshTests entry: its src as written and
// its lines of the failure breakdown.
type TestFailure struct {
	Src    string
	Errors []string
}

// TestsFailedError is a failed tests or sshTests run. It reads as the whole
// breakdown; Failures holds it per entry.
type TestsFailedError struct {
	err      error
	Failures []TestFailure
}

func (e *TestsFailedError) Error() string { return e.err.Error() }

func (e *TestsFailedError) Unwrap() error { return e.err }

// failures is the breakdown apart per failing entry, so an API answer can
// name each entry's src.
func (r PolicyTestResults) failures() []TestFailure {
	var out []TestFailure

	for _, res := range r.Results {
		if !res.Passed {
			one := PolicyTestResults{Results: []PolicyTestResult{res}}
			out = append(out, TestFailure{Src: res.Src, Errors: strings.Split(one.Errors(), "\n")})
		}
	}

	return out
}

// testReport is the outcome of a tests or sshTests run.
type testReport interface {
	Errors() string
	failures() []TestFailure
}

// wrapTestResult returns nil when every test passed, otherwise wraps the
// rendered failure breakdown in sentinel. The report is rendered only on the
// failure path.
func wrapTestResult(sentinel error, allPassed bool, r testReport) error {
	if allPassed {
		return nil
	}

	return &TestsFailedError{
		err:      fmt.Errorf("%w:\n%s", sentinel, r.Errors()),
		Failures: r.failures(),
	}
}

// RunTests evaluates the policy's own `tests` block against the live compiled
// filter and returns a wrapped error when any test fails. Callers that need
// the per-test breakdown can call runPolicyTests directly.
func (pm *PolicyManager) RunTests() error {
	if pm == nil || pm.pol == nil || len(pm.pol.Tests) == 0 {
		return nil
	}

	pm.mu.RLock()
	defer pm.mu.RUnlock()

	results := runPolicyTests(pm.resolvedPol, pm.filter, pm.users, pm.nodes)

	return wrapTestResult(errPolicyTestsFailed, results.AllPassed, results)
}

// evaluateTests runs the `tests` block against a fresh compilation of pol.
// It is the user-write sandbox: the live [PolicyManager] state is left
// untouched, so a failing test rejects the write without side effects.
func evaluateTests(pol *Policy, users []types.User, nodes views.Slice[types.NodeView]) error {
	if pol == nil || len(pol.Tests) == 0 {
		return nil
	}

	pol = pol.withResolvedGroups(users, nodes)
	grants := pol.compileGrants(users, nodes)

	var filter []tailcfg.FilterRule
	if pol.ACLs == nil && pol.Grants == nil {
		filter = tailcfg.FilterAllowAll
	} else {
		filter = globalFilterRules(grants)
	}

	results := runPolicyTests(pol, filter, users, nodes)

	return wrapTestResult(errPolicyTestsFailed, results.AllPassed, results)
}

// runPolicyTests is the pure evaluation function: given a policy, the
// compiled filter rules derived from it, and the active users/nodes, run
// every test and return the aggregated outcome. It does not lock anything
// or mutate any input.
func runPolicyTests(pol *Policy, filter []tailcfg.FilterRule, users []types.User, nodes views.Slice[types.NodeView]) PolicyTestResults {
	results := PolicyTestResults{
		AllPassed: true,
		Results:   make([]PolicyTestResult, 0, len(pol.Tests)),
	}

	rules := parseTestRules(filter)

	for _, test := range pol.Tests {
		res := runPolicyTest(test, pol, rules, users, nodes)
		if !res.Passed {
			results.AllPassed = false
		}

		results.Results = append(results.Results, res)
	}

	return results
}

// runPolicyTest evaluates one [PolicyTest].
func runPolicyTest(
	test PolicyTest,
	pol *Policy,
	rules []testRule,
	users []types.User,
	nodes views.Slice[types.NodeView],
) PolicyTestResult {
	res := PolicyTestResult{
		Src:    test.Src,
		Proto:  test.Proto,
		Passed: true,
	}

	srcPrefixes, err := resolveTestSource(test.Src, pol, users, nodes)
	if err != nil {
		res.Passed = false
		res.Errors = append(res.Errors, fmt.Sprintf("failed to resolve source %q: %v", test.Src, err))

		return res
	}

	if len(srcPrefixes) == 0 {
		res.Passed = false
		res.Errors = append(res.Errors, fmt.Sprintf("source %q resolved to no IP addresses", test.Src))

		return res
	}

	check := func(dsts []string, wantAllowed bool, ok, fail *[]string) {
		for _, dst := range dsts {
			allowed, err := evalReachability(
				srcPrefixes, dst, test.Proto, pol, rules, users, nodes, wantAllowed,
			)
			if err != nil {
				res.Passed = false
				res.Errors = append(res.Errors, fmt.Sprintf("error testing %q: %v", dst, err))

				continue
			}

			if allowed == wantAllowed {
				*ok = append(*ok, dst)
			} else {
				res.Passed = false

				*fail = append(*fail, dst)
			}
		}
	}

	check(test.Accept, true, &res.AcceptOK, &res.AcceptFail)
	check(test.Deny, false, &res.DenyOK, &res.DenyFail)

	return res
}

// resolveTestSource resolves the Src alias of a [PolicyTest] into a slice of
// [netip.Prefix]. [parseAlias] + [Alias.Resolve] cover every alias type the rest
// of the policy engine supports, so tests inherit alias semantics for free.
func resolveTestSource(src string, pol *Policy, users []types.User, nodes views.Slice[types.NodeView]) ([]netip.Prefix, error) {
	alias, err := parseAlias(src)
	if err != nil {
		return nil, fmt.Errorf("invalid alias: %w", err)
	}

	// Tailscale SaaS finds no user or host behind these, so a test from
	// them fails, whether it accepts or denies.
	unknown := isAddressRange(pol, alias)

	switch a := alias.(type) {
	case Asterix:
		unknown = true
	case *AutoGroup:
		unknown = a.Is(AutoGroupTagged)
	}

	if unknown {
		return nil, fmt.Errorf("%w: %q", errTestSourceUnknown, src)
	}

	// Rules tolerate unregistered users; a test naming one must still
	// fail (SaaS: policytest-src-unknown-user-email).
	if u, ok := alias.(*Username); ok {
		_, err := u.resolveUser(users)
		if err != nil {
			return nil, fmt.Errorf("resolving: %w", err)
		}
	}

	addrs, err := alias.Resolve(pol, users, nodes)
	if err != nil {
		return nil, fmt.Errorf("resolving: %w", err)
	}

	if addrs == nil || addrs.Empty() {
		return nil, nil
	}

	return addrs.Prefixes(), nil
}

// evalReachability reports whether traffic from every srcPrefix to dst (in
// `host:port` form) is allowed by rules for the requested protocol. With
// everyNode, as an accept asks, each node behind dst must be reached, as on
// Tailscale SaaS; otherwise any address of dst will do, so a deny passes only
// when none is reached.
//
// Empty proto means the default set the client applies when proto is
// omitted (TCP/UDP/ICMP) — we accept a rule whose IPProto list contains
// any of those, or rules with no IPProto restriction at all.
func evalReachability(
	srcPrefixes []netip.Prefix,
	dst string,
	proto Protocol,
	pol *Policy,
	rules []testRule,
	users []types.User,
	nodes views.Slice[types.NodeView],
	everyNode bool,
) (bool, error) {
	awp, err := parseDestinationAlias(dst)
	if err != nil {
		return false, fmt.Errorf("invalid destination %q: %w", dst, err)
	}

	dstAddrs, err := awp.Resolve(pol, users, nodes)
	if err != nil {
		return false, fmt.Errorf("resolving destination: %w", err)
	}

	if dstAddrs == nil || dstAddrs.Empty() {
		return false, fmt.Errorf("%w: %q", errTestDestinationNoIP, dst)
	}

	targets := [][]netip.Prefix{dstAddrs.Prefixes()}
	if everyNode {
		targets = nodeTargets(dstAddrs, nodes)
	}

	// Tailscale's tests semantics: ALL src prefixes must reach the dst for
	// the test to consider it allowed. A partial allow is a fail.
	for _, src := range srcPrefixes {
		for _, target := range targets {
			if !srcReachesDst(src, target, awp.Ports, proto, rules) {
				return false, nil
			}
		}
	}

	return true, nil
}

// nodeTargets splits dst into the addresses of each node it holds and,
// when any is left, the addresses no node holds.
func nodeTargets(dst ResolvedAddresses, nodes views.Slice[types.NodeView]) [][]netip.Prefix {
	var (
		out  [][]netip.Prefix
		rest netipx.IPSetBuilder
	)

	for _, p := range dst.Prefixes() {
		rest.AddPrefix(p)
	}

	for _, n := range nodes.All() {
		var own []netip.Prefix

		for _, ip := range n.IPs() {
			if dst.Contains(ip) {
				own = append(own, netip.PrefixFrom(ip, ip.BitLen()))
				rest.Remove(ip)
			}
		}

		if len(own) > 0 {
			out = append(out, own)
		}
	}

	// The builder only holds valid prefixes, so it cannot fail.
	set, _ := rest.IPSet()
	if left := set.Prefixes(); len(left) > 0 {
		out = append(out, left)
	}

	return out
}

// parseDestinationAlias is a thin wrapper over [AliasWithPorts.UnmarshalJSON]
// so callers can hand it a bare `"host:port"` string without re-implementing
// the parse logic.
func parseDestinationAlias(dst string) (*AliasWithPorts, error) {
	var awp AliasWithPorts

	// [AliasWithPorts.UnmarshalJSON] expects a quoted JSON string, so wrap.
	err := awp.UnmarshalJSON([]byte(`"` + dst + `"`))
	if err != nil {
		return nil, err
	}

	return &awp, nil
}

// testRule is a [tailcfg.FilterRule] with its addresses parsed. A run
// compares every assertion with every rule, and the policy author chooses
// how many there are of both, so the filter is parsed once per run rather
// than once per comparison.
type testRule struct {
	srcs   testAddrs
	protos []int
	// dsts merges the rule's DstPorts entries by port range, so a
	// destination is looked up once per range instead of once per entry.
	dsts []testRuleDst
}

// testRuleDst holds every address a rule allows a port range on.
type testRuleDst struct {
	ips   testAddrs
	ports tailcfg.PortRange
}

// testAddrs is the sorted, non-overlapping [netipx.IPSet.Ranges] of a set.
type testAddrs []netipx.IPRange

// overlapsPrefix is [netipx.IPSet.OverlapsPrefix] without walking the set.
func (a testAddrs) overlapsPrefix(p netip.Prefix) bool {
	r := netipx.RangeOfPrefix(p)

	// The first range that does not end before r is the only candidate:
	// the ones after it start later still.
	i, _ := slices.BinarySearchFunc(
		a, r.From(), func(x netipx.IPRange, from netip.Addr) int {
			return x.To().Compare(from)
		},
	)

	return i < len(a) && a[i].From().Compare(r.To()) <= 0
}

// parseTestRules parses filter for [srcReachesDst].
// [tailcfg.FilterRule.SrcIPs] and [tailcfg.NetPortRange.IP] may be CIDR, single
// addresses, IP ranges (`a-b`), or `*`; we use [util.ParseIPSet] to cover all
// of those uniformly. Unparseable entries are skipped (the rule compiler emits
// well-formed strings, so this is defence-in-depth, not error handling).
func parseTestRules(filter []tailcfg.FilterRule) []testRule {
	rules := make([]testRule, 0, len(filter))

	for _, rule := range filter {
		var srcs netipx.IPSetBuilder

		for _, raw := range rule.SrcIPs {
			set, err := util.ParseIPSet(raw, nil)
			if err != nil {
				continue
			}

			srcs.AddSet(set)
		}

		dsts := make(map[tailcfg.PortRange]*netipx.IPSetBuilder)

		for _, dp := range rule.DstPorts {
			set, err := util.ParseIPSet(dp.IP, nil)
			if err != nil {
				continue
			}

			if dsts[dp.Ports] == nil {
				dsts[dp.Ports] = new(netipx.IPSetBuilder)
			}

			dsts[dp.Ports].AddSet(set)
		}

		parsed := testRule{
			srcs:   buildTestAddrs(&srcs),
			protos: rule.IPProto,
			dsts:   make([]testRuleDst, 0, len(dsts)),
		}

		for ports, b := range dsts {
			parsed.dsts = append(
				parsed.dsts, testRuleDst{ips: buildTestAddrs(b), ports: ports},
			)
		}

		rules = append(rules, parsed)
	}

	return rules
}

// buildTestAddrs returns the addresses added to b. The builder only fails on
// invalid input, which [util.ParseIPSet] has already refused.
func buildTestAddrs(b *netipx.IPSetBuilder) testAddrs {
	set, err := b.IPSet()
	if err != nil {
		return nil
	}

	return set.Ranges()
}

// srcReachesDst walks the parsed filter rules and reports whether
// traffic from src to any prefix in dstPrefixes on at least one of ports
// (or any port when ports is empty) is allowed under proto.
//
// An empty test proto means the Tailscale client default set
// {TCP, UDP, ICMP, ICMPv6} — the protocols the client tries when proto
// is omitted. The captured Tailscale matches show these four IANA
// numbers explicitly when no proto is set, so a rule restricted to any
// of them satisfies an empty-proto test.
func srcReachesDst(
	src netip.Prefix,
	dstPrefixes []netip.Prefix,
	ports []tailcfg.PortRange,
	proto Protocol,
	rules []testRule,
) bool {
	requestedProtos := proto.toIANAProtocolNumbers()
	if len(requestedProtos) == 0 {
		requestedProtos = []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP}
	}

	for _, rule := range rules {
		if !rule.srcs.overlapsPrefix(src) {
			continue
		}

		if !ruleMatchesProto(rule, requestedProtos) {
			continue
		}

		if ruleAllowsAnyDest(rule, dstPrefixes, ports) {
			return true
		}
	}

	return false
}

// ruleMatchesProto reports whether the rule permits any of requestedProtos.
// An unset [tailcfg.FilterRule.IPProto] means "any protocol" and matches
// everything. requestedProtos is the per-test protocol set: a single proto
// for an explicit [PolicyTest.Proto], or the default set when
// [PolicyTest.Proto] is empty.
func ruleMatchesProto(rule testRule, requestedProtos []int) bool {
	if len(rule.protos) == 0 {
		return true
	}

	for _, ruleProto := range rule.protos {
		if slices.Contains(requestedProtos, ruleProto) {
			return true
		}
	}

	return false
}

// ruleAllowsAnyDest reports whether at least one destination prefix in
// dstPrefixes is allowed by at least one of the rule's destinations
// for at least one of ports (or any port when ports is empty).
func ruleAllowsAnyDest(
	rule testRule,
	dstPrefixes []netip.Prefix,
	ports []tailcfg.PortRange,
) bool {
	for _, dst := range rule.dsts {
		if !portsAllowed(ports, dst.ports) {
			continue
		}

		if slices.ContainsFunc(dstPrefixes, dst.ips.overlapsPrefix) {
			return true
		}
	}

	return false
}

// portsAllowed reports whether at least one requested port is contained
// in allowed. Empty requested means "any port".
func portsAllowed(requested []tailcfg.PortRange, allowed tailcfg.PortRange) bool {
	if len(requested) == 0 {
		return true
	}

	for _, r := range requested {
		if r.First >= allowed.First && r.Last <= allowed.Last {
			return true
		}
	}

	return false
}
