package v2

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"github.com/juanfont/headscale/hscontrol/types"
	"go4.org/netipx"
	"tailscale.com/tailcfg"
	"tailscale.com/types/views"
)

var errDestinationNoIPs = errors.New("destination resolved to no IP addresses")

// ACLTest represents a single ACL test case.
// It defines a source and lists of destinations that should be allowed or denied.
type ACLTest struct {
	// Src is the source alias (user, group, tag, host, or IP) to test from.
	Src string `json:"src"`

	// Proto is the protocol to test. If empty, defaults to TCP/UDP.
	Proto Protocol `json:"proto,omitempty"`

	// Accept is a list of destinations (in "host:port" format) that should be allowed.
	Accept []string `json:"accept,omitempty"`

	// Deny is a list of destinations (in "host:port" format) that should be denied.
	Deny []string `json:"deny,omitempty"`
}

// ACLTestResult represents the result of running a single ACL test.
type ACLTestResult struct {
	// Src is the source alias that was tested.
	Src string `json:"src"`

	// Proto is the protocol that was tested. Empty means TCP/UDP (default).
	Proto Protocol `json:"proto,omitempty"`

	// Passed indicates whether the test passed (all assertions correct).
	Passed bool `json:"passed"`

	// Errors contains any errors encountered during test execution.
	Errors []string `json:"errors,omitempty"`

	// AcceptOK lists destinations that were correctly allowed.
	AcceptOK []string `json:"accept_ok,omitempty"`

	// AcceptFail lists destinations that should have been allowed but were denied.
	AcceptFail []string `json:"accept_fail,omitempty"`

	// DenyOK lists destinations that were correctly denied.
	DenyOK []string `json:"deny_ok,omitempty"`

	// DenyFail lists destinations that should have been denied but were allowed.
	DenyFail []string `json:"deny_fail,omitempty"`
}

// ACLTestResults represents the aggregated results of running multiple ACL tests.
type ACLTestResults struct {
	// AllPassed indicates whether all tests passed.
	AllPassed bool `json:"all_passed"`

	// Results contains the individual test results.
	Results []ACLTestResult `json:"results"`
}

// Errors returns a combined error message from all failed tests.
// Each error is on a separate line for readability.
func (r ACLTestResults) Errors() string {
	var errs []string

	for _, result := range r.Results {
		if !result.Passed {
			// Build protocol suffix for error messages
			protoSuffix := ""
			if result.Proto != "" {
				protoSuffix = fmt.Sprintf(" (%s)", result.Proto)
			}

			for _, e := range result.Errors {
				errs = append(errs, fmt.Sprintf("%s%s: %s", result.Src, protoSuffix, e))
			}

			for _, dest := range result.AcceptFail {
				errs = append(errs, fmt.Sprintf("%s -> %s%s: expected ALLOWED, got DENIED", result.Src, dest, protoSuffix))
			}

			for _, dest := range result.DenyFail {
				errs = append(errs, fmt.Sprintf("%s -> %s%s: expected DENIED, got ALLOWED", result.Src, dest, protoSuffix))
			}
		}
	}

	return strings.Join(errs, "\n")
}

// RunTests runs multiple ACL tests and returns aggregated results.
func (pm *PolicyManager) RunTests(tests []ACLTest) ACLTestResults {
	results := ACLTestResults{
		AllPassed: true,
		Results:   make([]ACLTestResult, 0, len(tests)),
	}

	for _, test := range tests {
		result := pm.RunTest(test)

		results.Results = append(results.Results, result)
		if !result.Passed {
			results.AllPassed = false
		}
	}

	return results
}

// RunTest evaluates a single ACL test against the current policy.
// It resolves the source alias to IPs, then checks each accept/deny destination.
func (pm *PolicyManager) RunTest(test ACLTest) ACLTestResult {
	result := ACLTestResult{
		Src:    test.Src,
		Proto:  test.Proto,
		Passed: true,
	}

	if pm == nil || pm.pol == nil {
		result.Passed = false
		result.Errors = append(result.Errors, "no policy configured")

		return result
	}

	pm.mu.Lock()
	defer pm.mu.Unlock()

	// Resolve the source alias to an IP set
	srcIPs, srcErr := pm.resolveTestAlias(test.Src)
	if srcErr != nil {
		result.Passed = false
		result.Errors = append(result.Errors, fmt.Sprintf("failed to resolve source %q: %v", test.Src, srcErr))

		return result
	}

	if srcIPs == nil || len(srcIPs.Prefixes()) == 0 {
		result.Passed = false
		result.Errors = append(result.Errors, fmt.Sprintf("source %q resolved to no IP addresses", test.Src))

		return result
	}

	// Test each destination in Accept list
	for _, dest := range test.Accept {
		allowed, err := pm.testAccess(srcIPs, dest, test.Proto)
		if err != nil {
			result.Passed = false
			result.Errors = append(result.Errors, fmt.Sprintf("error testing %q: %v", dest, err))

			continue
		}

		if allowed {
			result.AcceptOK = append(result.AcceptOK, dest)
		} else {
			result.Passed = false
			result.AcceptFail = append(result.AcceptFail, dest)
		}
	}

	// Test each destination in Deny list
	for _, dest := range test.Deny {
		allowed, err := pm.testAccess(srcIPs, dest, test.Proto)
		if err != nil {
			result.Passed = false
			result.Errors = append(result.Errors, fmt.Sprintf("error testing %q: %v", dest, err))

			continue
		}

		if !allowed {
			result.DenyOK = append(result.DenyOK, dest)
		} else {
			result.Passed = false
			result.DenyFail = append(result.DenyFail, dest)
		}
	}

	return result
}

// resolveTestAlias resolves a test alias string to an IP set.
// It supports all standard alias types: user, group, tag, host, prefix, and autogroup.
func (pm *PolicyManager) resolveTestAlias(aliasStr string) (*netipx.IPSet, error) {
	alias, err := parseAlias(aliasStr)
	if err != nil {
		return nil, fmt.Errorf("invalid alias: %w", err)
	}

	ipSet, err := alias.Resolve(pm.pol, pm.users, pm.nodes)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve alias: %w", err)
	}

	return ipSet, nil
}

// testAccess checks if traffic from srcIPs to the destination is allowed.
// The destination is in "host:port" format (e.g., "server:22" or "10.0.0.1:80").
func (pm *PolicyManager) testAccess(srcIPs *netipx.IPSet, dest string, proto Protocol) (bool, error) {
	// Parse the destination as AliasWithPorts
	destWithPorts, err := pm.parseDestination(dest)
	if err != nil {
		return false, fmt.Errorf("invalid destination %q: %w", dest, err)
	}

	// Resolve destination alias to IPs
	destIPs, err := destWithPorts.Resolve(pm.pol, pm.users, pm.nodes)
	if err != nil {
		return false, fmt.Errorf("failed to resolve destination: %w", err)
	}

	if destIPs == nil || len(destIPs.Prefixes()) == 0 {
		return false, errDestinationNoIPs
	}

	// Check access using the matchers
	// We need to check if any rule allows srcIPs to reach destIPs
	return pm.checkMatcherAccess(srcIPs, destIPs, destWithPorts.Ports, proto), nil
}

// parseDestination parses a destination string in "host:port" format.
func (pm *PolicyManager) parseDestination(dest string) (*AliasWithPorts, error) {
	var awp AliasWithPorts

	// Use the existing AliasWithPorts unmarshaling logic
	err := awp.UnmarshalJSON([]byte(`"` + dest + `"`))
	if err != nil {
		return nil, err
	}

	return &awp, nil
}

// checkMatcherAccess checks if access is allowed from srcIPs to destIPs for the given ports.
// It uses the compiled filter rules (not just matchers) to properly check port restrictions.
// The proto parameter filters by protocol - rules with IPProto set will only match if the
// requested protocol is in the rule's protocol list.
func (pm *PolicyManager) checkMatcherAccess(srcIPs, destIPs *netipx.IPSet, ports []tailcfg.PortRange, proto Protocol) bool {
	// Get source prefixes
	srcPrefixes := srcIPs.Prefixes()
	if len(srcPrefixes) == 0 {
		return false
	}

	// ALL source prefixes must have access to the destination
	// If any source prefix cannot reach the destination, return false
	for _, srcPrefix := range srcPrefixes {
		if !pm.checkSingleSourceAccess(srcPrefix, destIPs, ports, proto) {
			return false
		}
	}

	return true
}

// checkSingleSourceAccess checks if a single source prefix has access to the destination.
func (pm *PolicyManager) checkSingleSourceAccess(srcPrefix netip.Prefix, destIPs *netipx.IPSet, ports []tailcfg.PortRange, proto Protocol) bool {
	// Check against filter rules (which include port information)
	for _, rule := range pm.filter {
		// Check if this source prefix matches the rule's source IPs
		srcMatches := false

		for _, ruleSrcIP := range rule.SrcIPs {
			// Parse the rule's source IP as a prefix
			rulePrefix, err := netip.ParsePrefix(ruleSrcIP)
			if err != nil {
				// Try parsing as single IP
				ruleAddr, err := netip.ParseAddr(ruleSrcIP)
				if err != nil {
					continue
				}

				rulePrefix = netip.PrefixFrom(ruleAddr, ruleAddr.BitLen())
			}

			// Check if the source prefix overlaps with the rule's source
			if srcPrefix.Overlaps(rulePrefix) {
				srcMatches = true

				break
			}
		}

		if !srcMatches {
			continue
		}

		// Check if protocol matches
		// If the rule has IPProto set, only match if the requested protocol is in the list
		if len(rule.IPProto) > 0 {
			var requestedProtos []int
			if proto == "" {
				requestedProtos = []int{ProtocolTCP, ProtocolUDP}
			} else {
				requestedProtos = proto.parseProtocol()
			}

			protoMatches := false

			for _, ruleProto := range rule.IPProto {
				if slices.Contains(requestedProtos, ruleProto) {
					protoMatches = true

					break
				}
			}

			if !protoMatches {
				continue
			}
		}

		// Check if any destination port range matches
		for _, dstPort := range rule.DstPorts {
			// Handle wildcard destination
			dstMatches := false

			if dstPort.IP == "*" {
				dstMatches = true
			} else {
				// Parse the rule's destination IP
				dstPrefix, err := netip.ParsePrefix(dstPort.IP)
				if err != nil {
					dstAddr, err := netip.ParseAddr(dstPort.IP)
					if err != nil {
						continue
					}

					dstPrefix = netip.PrefixFrom(dstAddr, dstAddr.BitLen())
				}

				// Check if destination IPs overlap
				for _, prefix := range destIPs.Prefixes() {
					if prefix.Overlaps(dstPrefix) {
						dstMatches = true

						break
					}
				}
			}

			if !dstMatches {
				continue
			}

			// Check if ports match
			if portsMatch(ports, dstPort.Ports) {
				return true
			}
		}
	}

	return false
}

// portsMatch checks if the requested ports are allowed by the rule's port range.
func portsMatch(requestedPorts []tailcfg.PortRange, allowedPorts tailcfg.PortRange) bool {
	// If no specific ports requested, check if any port is allowed
	if len(requestedPorts) == 0 {
		return true
	}

	// Check if any requested port is within the allowed range
	for _, requested := range requestedPorts {
		// Check if the requested port range is within the allowed range
		if requested.First >= allowedPorts.First && requested.Last <= allowedPorts.Last {
			return true
		}
	}

	return false
}

// RunTestsWithPolicy creates a temporary PolicyManager from the given policy bytes
// and runs the provided tests against it. This is useful for testing a proposed
// policy before saving it.
func RunTestsWithPolicy(policyBytes []byte, users types.Users, nodes views.Slice[types.NodeView], tests []ACLTest) (ACLTestResults, error) {
	pm, err := NewPolicyManager(policyBytes, users, nodes)
	if err != nil {
		return ACLTestResults{}, fmt.Errorf("failed to parse policy: %w", err)
	}

	return pm.RunTests(tests), nil
}
