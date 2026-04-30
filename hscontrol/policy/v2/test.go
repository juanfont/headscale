package v2

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
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

// errPolicyTestsFailed wraps the rendered failure body so callers can
// type-assert when they need to react differently to test failures vs. parse
// errors. The Error() prefix is "test(s) failed", the same string Tailscale
// SaaS returns in the api_response_body.message — see
// hscontrol/policy/v2/testdata/policytest_results/.
var (
	errPolicyTestsFailed   = errors.New("test(s) failed")
	errTestDestinationNoIP = errors.New("destination resolved to no IP addresses")
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

// PolicyTestResult is the outcome of a single PolicyTest.
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
func (r PolicyTestResults) Errors() string {
	if r.AllPassed {
		return ""
	}

	var lines []string

	for _, res := range r.Results {
		if res.Passed {
			continue
		}

		protoSuffix := ""
		if res.Proto != "" {
			protoSuffix = fmt.Sprintf(" (%s)", res.Proto)
		}

		for _, e := range res.Errors {
			lines = append(lines, fmt.Sprintf("%s%s: %s", res.Src, protoSuffix, e))
		}

		for _, dst := range res.AcceptFail {
			lines = append(lines, fmt.Sprintf("%s -> %s%s: expected ALLOWED, got DENIED", res.Src, dst, protoSuffix))
		}

		for _, dst := range res.DenyFail {
			lines = append(lines, fmt.Sprintf("%s -> %s%s: expected DENIED, got ALLOWED", res.Src, dst, protoSuffix))
		}
	}

	return strings.Join(lines, "\n")
}

// RunTests evaluates the policy's own `tests` block against the live compiled
// filter and returns a wrapped error when any test fails. Callers that need
// the per-test breakdown can call runPolicyTests directly.
func (pm *PolicyManager) RunTests() error {
	if pm == nil || pm.pol == nil || len(pm.pol.Tests) == 0 {
		return nil
	}

	pm.mu.Lock()
	defer pm.mu.Unlock()

	results := runPolicyTests(pm.pol, pm.filter, pm.users, pm.nodes)
	if results.AllPassed {
		return nil
	}

	return fmt.Errorf("%w:\n%s", errPolicyTestsFailed, results.Errors())
}

// evaluateTests runs the `tests` block against a fresh compilation of pol.
// It is the user-write sandbox: the live PolicyManager state is left
// untouched, so a failing test rejects the write without side effects.
func evaluateTests(pol *Policy, users []types.User, nodes views.Slice[types.NodeView]) error {
	if pol == nil || len(pol.Tests) == 0 {
		return nil
	}

	grants := pol.compileGrants(users, nodes)

	var filter []tailcfg.FilterRule
	if pol.ACLs == nil && pol.Grants == nil {
		filter = tailcfg.FilterAllowAll
	} else {
		filter = globalFilterRules(grants)
	}

	results := runPolicyTests(pol, filter, users, nodes)
	if results.AllPassed {
		return nil
	}

	return fmt.Errorf("%w:\n%s", errPolicyTestsFailed, results.Errors())
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

	for _, test := range pol.Tests {
		res := runPolicyTest(test, pol, filter, users, nodes)
		if !res.Passed {
			results.AllPassed = false
		}

		results.Results = append(results.Results, res)
	}

	return results
}

// runPolicyTest evaluates one PolicyTest.
func runPolicyTest(test PolicyTest, pol *Policy, filter []tailcfg.FilterRule, users []types.User, nodes views.Slice[types.NodeView]) PolicyTestResult {
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

	for _, dst := range test.Accept {
		allowed, err := evalReachability(srcPrefixes, dst, test.Proto, pol, filter, users, nodes)
		if err != nil {
			res.Passed = false
			res.Errors = append(res.Errors, fmt.Sprintf("error testing %q: %v", dst, err))

			continue
		}

		if allowed {
			res.AcceptOK = append(res.AcceptOK, dst)
		} else {
			res.Passed = false
			res.AcceptFail = append(res.AcceptFail, dst)
		}
	}

	for _, dst := range test.Deny {
		allowed, err := evalReachability(srcPrefixes, dst, test.Proto, pol, filter, users, nodes)
		if err != nil {
			res.Passed = false
			res.Errors = append(res.Errors, fmt.Sprintf("error testing %q: %v", dst, err))

			continue
		}

		if !allowed {
			res.DenyOK = append(res.DenyOK, dst)
		} else {
			res.Passed = false
			res.DenyFail = append(res.DenyFail, dst)
		}
	}

	return res
}

// resolveTestSource resolves the Src alias of a PolicyTest into a slice of
// netip.Prefix. parseAlias + Alias.Resolve cover every alias type the rest
// of the policy engine supports, so tests inherit alias semantics for free.
func resolveTestSource(src string, pol *Policy, users []types.User, nodes views.Slice[types.NodeView]) ([]netip.Prefix, error) {
	alias, err := parseAlias(src)
	if err != nil {
		return nil, fmt.Errorf("invalid alias: %w", err)
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

// evalReachability reports whether traffic from any srcPrefix to dst (in
// `host:port` form) is allowed by filter for the requested protocol.
//
// Empty proto means the default set the client applies when proto is
// omitted (TCP/UDP/ICMP) — we accept a rule whose IPProto list contains
// any of those, or rules with no IPProto restriction at all.
func evalReachability(srcPrefixes []netip.Prefix, dst string, proto Protocol, pol *Policy, filter []tailcfg.FilterRule, users []types.User, nodes views.Slice[types.NodeView]) (bool, error) {
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

	dstPrefixes := dstAddrs.Prefixes()

	// Tailscale's tests semantics: ALL src prefixes must reach the dst for
	// the test to consider it allowed. A partial allow is a fail.
	for _, src := range srcPrefixes {
		if !srcReachesDst(src, dstPrefixes, awp.Ports, proto, filter) {
			return false, nil
		}
	}

	return true, nil
}

// parseDestinationAlias is a thin wrapper over AliasWithPorts.UnmarshalJSON
// so callers can hand it a bare `"host:port"` string without re-implementing
// the parse logic.
func parseDestinationAlias(dst string) (*AliasWithPorts, error) {
	var awp AliasWithPorts

	// AliasWithPorts.UnmarshalJSON expects a quoted JSON string, so wrap.
	err := awp.UnmarshalJSON([]byte(`"` + dst + `"`))
	if err != nil {
		return nil, err
	}

	return &awp, nil
}

// srcReachesDst walks the compiled filter rules and reports whether
// traffic from src to any prefix in dstPrefixes on at least one of ports
// (or any port when ports is empty) is allowed under proto.
//
// An empty test proto means the Tailscale client default set
// {TCP, UDP, ICMP, ICMPv6} — the protocols the client tries when proto
// is omitted. The captured Tailscale matches show these four IANA
// numbers explicitly when no proto is set, so a rule restricted to any
// of them satisfies an empty-proto test.
func srcReachesDst(src netip.Prefix, dstPrefixes []netip.Prefix, ports []tailcfg.PortRange, proto Protocol, filter []tailcfg.FilterRule) bool {
	requestedProtos := proto.toIANAProtocolNumbers()
	if len(requestedProtos) == 0 {
		requestedProtos = []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP}
	}

	for _, rule := range filter {
		if !ruleMatchesSource(rule, src) {
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

// ruleMatchesSource reports whether the rule's source list contains src.
// SrcIPs may be CIDR, single addresses, IP ranges (`a-b`), or `*`; we use
// util.ParseIPSet to cover all of those uniformly. Unparseable entries
// are skipped (the rule compiler emits well-formed strings, so this is
// defence-in-depth, not error handling).
func ruleMatchesSource(rule tailcfg.FilterRule, src netip.Prefix) bool {
	for _, raw := range rule.SrcIPs {
		set, err := util.ParseIPSet(raw, nil)
		if err != nil {
			continue
		}

		if set.OverlapsPrefix(src) {
			return true
		}
	}

	return false
}

// ruleMatchesProto reports whether the rule permits any of requestedProtos.
// An unset rule.IPProto means "any protocol" and matches everything.
// requestedProtos is the per-test protocol set: a single proto for an
// explicit test.Proto, or the default set when test.Proto is empty.
func ruleMatchesProto(rule tailcfg.FilterRule, requestedProtos []int) bool {
	if len(rule.IPProto) == 0 {
		return true
	}

	for _, ruleProto := range rule.IPProto {
		if slices.Contains(requestedProtos, ruleProto) {
			return true
		}
	}

	return false
}

// ruleAllowsAnyDest reports whether at least one destination prefix in
// dstPrefixes is allowed by at least one of the rule's DstPorts entries
// for at least one of ports (or any port when ports is empty).
func ruleAllowsAnyDest(rule tailcfg.FilterRule, dstPrefixes []netip.Prefix, ports []tailcfg.PortRange) bool {
	for _, dp := range rule.DstPorts {
		if !destEntryMatchesPrefixes(dp, dstPrefixes) {
			continue
		}

		if portsAllowed(ports, dp.Ports) {
			return true
		}
	}

	return false
}

// destEntryMatchesPrefixes reports whether the rule's NetPortRange.IP
// (CIDR, single IP, IP range, or "*") covers any prefix in dstPrefixes.
func destEntryMatchesPrefixes(dp tailcfg.NetPortRange, dstPrefixes []netip.Prefix) bool {
	set, err := util.ParseIPSet(dp.IP, nil)
	if err != nil {
		return false
	}

	return slices.ContainsFunc(dstPrefixes, set.OverlapsPrefix)
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
