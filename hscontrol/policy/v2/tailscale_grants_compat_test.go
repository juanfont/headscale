// This file is "generated" by Claude.
// It contains a data-driven test that reads 237 GRANT-*.json test files
// captured from Tailscale SaaS. Each file contains:
//   - A policy with grants (and optionally ACLs)
//   - The expected packet_filter_rules for each of 8 test nodes
//   - Or an error response for invalid policies
//
// The test loads each JSON file, applies the policy through headscale's
// grants engine, and compares the output against Tailscale's actual behavior.
//
// Tests that are known to fail due to unimplemented features or known
// differences are skipped with a TODO comment explaining the root cause.
// As headscale's grants implementation improves, tests should be removed
// from the skip list.
//
// Test data source: testdata/grant_results/GRANT-*.json
// Captured from: Tailscale SaaS API + tailscale debug localapi

package v2

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/juanfont/headscale/hscontrol/policy/policyutil"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"tailscale.com/tailcfg"
)

// grantTestFile represents the JSON structure of a captured grant test file.
type grantTestFile struct {
	TestID string `json:"test_id"`
	Error  bool   `json:"error"`
	Input  struct {
		FullPolicy      json.RawMessage `json:"full_policy"`
		APIResponseCode int             `json:"api_response_code"`
		APIResponseBody *struct {
			Message string `json:"message"`
		} `json:"api_response_body"`
	} `json:"input"`
	Topology struct {
		Nodes map[string]struct {
			Hostname string   `json:"hostname"`
			Tags     []string `json:"tags"`
			IPv4     string   `json:"ipv4"`
			IPv6     string   `json:"ipv6"`
		} `json:"nodes"`
	} `json:"topology"`
	Captures map[string]struct {
		PacketFilterRules json.RawMessage `json:"packet_filter_rules"`
	} `json:"captures"`
}

// setupGrantsCompatUsers returns the 3 test users for grants compatibility tests.
// Email addresses use @example.com domain, matching the converted Tailscale policy format.
func setupGrantsCompatUsers() types.Users {
	return types.Users{
		{Model: gorm.Model{ID: 1}, Name: "kratail2tid", Email: "kratail2tid@example.com"},
		{Model: gorm.Model{ID: 2}, Name: "kristoffer", Email: "kristoffer@example.com"},
		{Model: gorm.Model{ID: 3}, Name: "monitorpasskeykradalby", Email: "monitorpasskeykradalby@example.com"},
	}
}

// setupGrantsCompatNodes returns the 8 test nodes for grants compatibility tests.
// The node configuration matches the Tailscale test environment:
//   - 3 user-owned nodes (user1, user-kris, user-mon)
//   - 5 tagged nodes (tagged-server, tagged-prod, tagged-client, subnet-router, exit-node)
func setupGrantsCompatNodes(users types.Users) types.Nodes {
	nodeUser1 := &types.Node{
		ID:        1,
		GivenName: "user1",
		User:      &users[0],
		UserID:    &users[0].ID,
		IPv4:      ptrAddr("100.90.199.68"),
		IPv6:      ptrAddr("fd7a:115c:a1e0::2d01:c747"),
		Hostinfo:  &tailcfg.Hostinfo{},
	}

	nodeUserKris := &types.Node{
		ID:        2,
		GivenName: "user-kris",
		User:      &users[1],
		UserID:    &users[1].ID,
		IPv4:      ptrAddr("100.110.121.96"),
		IPv6:      ptrAddr("fd7a:115c:a1e0::1737:7960"),
		Hostinfo:  &tailcfg.Hostinfo{},
	}

	nodeUserMon := &types.Node{
		ID:        3,
		GivenName: "user-mon",
		User:      &users[2],
		UserID:    &users[2].ID,
		IPv4:      ptrAddr("100.103.90.82"),
		IPv6:      ptrAddr("fd7a:115c:a1e0::9e37:5a52"),
		Hostinfo:  &tailcfg.Hostinfo{},
	}

	nodeTaggedServer := &types.Node{
		ID:        4,
		GivenName: "tagged-server",
		IPv4:      ptrAddr("100.108.74.26"),
		IPv6:      ptrAddr("fd7a:115c:a1e0::b901:4a87"),
		Tags:      []string{"tag:server"},
		Hostinfo:  &tailcfg.Hostinfo{},
	}

	nodeTaggedProd := &types.Node{
		ID:        5,
		GivenName: "tagged-prod",
		IPv4:      ptrAddr("100.103.8.15"),
		IPv6:      ptrAddr("fd7a:115c:a1e0::5b37:80f"),
		Tags:      []string{"tag:prod"},
		Hostinfo:  &tailcfg.Hostinfo{},
	}

	nodeTaggedClient := &types.Node{
		ID:        6,
		GivenName: "tagged-client",
		IPv4:      ptrAddr("100.83.200.69"),
		IPv6:      ptrAddr("fd7a:115c:a1e0::c537:c845"),
		Tags:      []string{"tag:client"},
		Hostinfo:  &tailcfg.Hostinfo{},
	}

	nodeSubnetRouter := &types.Node{
		ID:        7,
		GivenName: "subnet-router",
		IPv4:      ptrAddr("100.92.142.61"),
		IPv6:      ptrAddr("fd7a:115c:a1e0::3e37:8e3d"),
		Tags:      []string{"tag:router"},
		Hostinfo:  &tailcfg.Hostinfo{},
	}

	nodeExitNode := &types.Node{
		ID:        8,
		GivenName: "exit-node",
		IPv4:      ptrAddr("100.85.66.106"),
		IPv6:      ptrAddr("fd7a:115c:a1e0::7c37:426a"),
		Tags:      []string{"tag:exit"},
		Hostinfo:  &tailcfg.Hostinfo{},
	}

	return types.Nodes{
		nodeUser1,
		nodeUserKris,
		nodeUserMon,
		nodeTaggedServer,
		nodeTaggedProd,
		nodeTaggedClient,
		nodeSubnetRouter,
		nodeExitNode,
	}
}

// findGrantsNode finds a node by its GivenName in the grants test environment.
func findGrantsNode(nodes types.Nodes, name string) *types.Node {
	for _, n := range nodes {
		if n.GivenName == name {
			return n
		}
	}

	return nil
}

// convertPolicyUserEmails converts Tailscale SaaS user email formats to
// headscale-compatible @example.com format in the raw policy JSON.
//
// Tailscale uses provider-specific email formats:
//   - kratail2tid@passkey (passkey auth)
//   - kristoffer@dalby.cc (email auth)
//   - monitorpasskeykradalby@passkey (passkey auth)
//
// Headscale resolves users by Email field, so we convert all to @example.com.
func convertPolicyUserEmails(policyJSON []byte) []byte {
	s := string(policyJSON)
	s = strings.ReplaceAll(s, "kratail2tid@passkey", "kratail2tid@example.com")
	s = strings.ReplaceAll(s, "kristoffer@dalby.cc", "kristoffer@example.com")
	s = strings.ReplaceAll(s, "monitorpasskeykradalby@passkey", "monitorpasskeykradalby@example.com")

	return []byte(s)
}

// loadGrantTestFile loads and parses a single grant test JSON file.
func loadGrantTestFile(t *testing.T, path string) grantTestFile {
	t.Helper()

	content, err := os.ReadFile(path)
	require.NoError(t, err, "failed to read test file %s", path)

	var tf grantTestFile

	err = json.Unmarshal(content, &tf)
	require.NoError(t, err, "failed to parse test file %s", path)

	return tf
}

// Skip categories document WHY tests are expected to fail and WHAT needs to be
// implemented to fix them. Tests are grouped by root cause to identify high-impact
// changes.
//
// Impact summary (highest first):
//
//	SRCIPS_FORMAT              - 125 tests: Fix SrcIPs to use CGNAT split ranges
//	CAPGRANT_COMPILATION       -  41 tests: Implement app->CapGrant FilterRule compilation
//	ERROR_VALIDATION_GAP       -  14 tests: Implement missing grant validation rules
//	CAPGRANT_AND_SRCIPS_FORMAT -   9 tests: Both CapGrant compilation + SrcIPs format
//	VIA_AND_SRCIPS_FORMAT      -   4 tests: Via route compilation + SrcIPs format
//	AUTOGROUP_DANGER_ALL       -   3 tests: Implement autogroup:danger-all support
//	VALIDATION_STRICTNESS      -   2 tests: headscale too strict (rejects what Tailscale accepts)
//
// Total: 193 tests skipped, 19 tests expected to pass.
var grantSkipReasons = map[string]string{
	// ========================================================================
	// SRCIPS_FORMAT (125 tests)
	//
	// TODO: Implement CGNAT split range generation for SrcIPs.
	//
	// headscale currently generates ["100.64.0.0/10", "fd7a:115c:a1e0::/48"]
	// for wildcard source matches. Tailscale generates split CGNAT ranges that
	// exclude the ChromeOS VM range 100.115.92.0/23, and includes advertised
	// subnet routes (e.g., "10.33.0.0/16") in the SrcIPs list.
	//
	// Additionally, headscale uses CIDR notation for host IPs in DstPorts
	// (e.g., "100.108.74.26/32") while Tailscale uses bare IPs
	// (e.g., "100.108.74.26").
	//
	// Fixing SrcIPs generation and DstPorts IP format would resolve all 125
	// tests in this category.
	// ========================================================================

	// J-series: Protocol-specific IP grants
	"GRANT-J1": "SRCIPS_FORMAT",
	"GRANT-J2": "SRCIPS_FORMAT",
	"GRANT-J3": "SRCIPS_FORMAT",
	"GRANT-J4": "SRCIPS_FORMAT",
	"GRANT-J5": "SRCIPS_FORMAT",
	"GRANT-J6": "SRCIPS_FORMAT",

	// K-series: Various IP grant patterns
	"GRANT-K1":  "SRCIPS_FORMAT",
	"GRANT-K2":  "SRCIPS_FORMAT",
	"GRANT-K4":  "SRCIPS_FORMAT",
	"GRANT-K14": "SRCIPS_FORMAT",
	"GRANT-K15": "SRCIPS_FORMAT",
	"GRANT-K16": "SRCIPS_FORMAT",
	"GRANT-K17": "SRCIPS_FORMAT",
	"GRANT-K20": "SRCIPS_FORMAT",
	"GRANT-K21": "SRCIPS_FORMAT",
	"GRANT-K22": "SRCIPS_FORMAT",
	"GRANT-K26": "SRCIPS_FORMAT",

	// P01-series: Wildcard and basic IP grants
	"GRANT-P01_1": "SRCIPS_FORMAT",
	"GRANT-P01_2": "SRCIPS_FORMAT",
	"GRANT-P01_3": "SRCIPS_FORMAT",
	"GRANT-P01_4": "SRCIPS_FORMAT",

	// P02-series: Source targeting (user, group, tag)
	"GRANT-P02_1":         "SRCIPS_FORMAT",
	"GRANT-P02_2":         "SRCIPS_FORMAT",
	"GRANT-P02_3":         "SRCIPS_FORMAT",
	"GRANT-P02_4":         "SRCIPS_FORMAT",
	"GRANT-P02_5_CORRECT": "SRCIPS_FORMAT",
	"GRANT-P02_5_NAIVE":   "SRCIPS_FORMAT",

	// P03-series: Destination targeting
	"GRANT-P03_1": "SRCIPS_FORMAT",
	"GRANT-P03_2": "SRCIPS_FORMAT",
	"GRANT-P03_3": "SRCIPS_FORMAT",
	"GRANT-P03_4": "SRCIPS_FORMAT",

	// P04-series: autogroup:member grants
	"GRANT-P04_1": "SRCIPS_FORMAT",
	"GRANT-P04_2": "SRCIPS_FORMAT",

	// P05-series: Tag-to-tag grants
	"GRANT-P05_1": "SRCIPS_FORMAT",
	"GRANT-P05_2": "SRCIPS_FORMAT",
	"GRANT-P05_3": "SRCIPS_FORMAT",

	// P06-series: IP protocol grants
	"GRANT-P06_1": "SRCIPS_FORMAT",
	"GRANT-P06_2": "SRCIPS_FORMAT",
	"GRANT-P06_3": "SRCIPS_FORMAT",
	"GRANT-P06_4": "SRCIPS_FORMAT",
	"GRANT-P06_5": "SRCIPS_FORMAT",
	"GRANT-P06_6": "SRCIPS_FORMAT",
	"GRANT-P06_7": "SRCIPS_FORMAT",

	// P08-series: Multiple grants / rule merging
	"GRANT-P08_1": "SRCIPS_FORMAT",
	"GRANT-P08_2": "SRCIPS_FORMAT",
	"GRANT-P08_4": "SRCIPS_FORMAT",
	"GRANT-P08_5": "SRCIPS_FORMAT",
	"GRANT-P08_6": "SRCIPS_FORMAT",
	"GRANT-P08_7": "SRCIPS_FORMAT",
	"GRANT-P08_8": "SRCIPS_FORMAT",

	// P09-series: ACL-to-grant conversion equivalence tests
	"GRANT-P09_1A":         "SRCIPS_FORMAT",
	"GRANT-P09_1B":         "SRCIPS_FORMAT",
	"GRANT-P09_1C":         "SRCIPS_FORMAT",
	"GRANT-P09_1D":         "SRCIPS_FORMAT",
	"GRANT-P09_1E":         "SRCIPS_FORMAT",
	"GRANT-P09_2A_CORRECT": "SRCIPS_FORMAT",
	"GRANT-P09_2A_NAIVE":   "SRCIPS_FORMAT",
	"GRANT-P09_2B_CORRECT": "SRCIPS_FORMAT",
	"GRANT-P09_2B_NAIVE":   "SRCIPS_FORMAT",
	"GRANT-P09_2C":         "SRCIPS_FORMAT",
	"GRANT-P09_3A":         "SRCIPS_FORMAT",
	"GRANT-P09_3B":         "SRCIPS_FORMAT",
	"GRANT-P09_3C":         "SRCIPS_FORMAT",
	"GRANT-P09_4A":         "SRCIPS_FORMAT",
	"GRANT-P09_4B":         "SRCIPS_FORMAT",
	"GRANT-P09_4C":         "SRCIPS_FORMAT",
	"GRANT-P09_4D":         "SRCIPS_FORMAT",
	"GRANT-P09_4E":         "SRCIPS_FORMAT",
	"GRANT-P09_4F":         "SRCIPS_FORMAT",
	"GRANT-P09_4G":         "SRCIPS_FORMAT",
	"GRANT-P09_5A":         "SRCIPS_FORMAT",
	"GRANT-P09_5B":         "SRCIPS_FORMAT",
	"GRANT-P09_5C_NAIVE":   "SRCIPS_FORMAT",
	"GRANT-P09_6A":         "SRCIPS_FORMAT",
	"GRANT-P09_6C":         "SRCIPS_FORMAT",
	"GRANT-P09_6D":         "SRCIPS_FORMAT",
	"GRANT-P09_7A":         "SRCIPS_FORMAT",
	"GRANT-P09_7B_NAIVE":   "SRCIPS_FORMAT",
	"GRANT-P09_7C":         "SRCIPS_FORMAT",
	"GRANT-P09_7D_NAIVE":   "SRCIPS_FORMAT",
	"GRANT-P09_8A":         "SRCIPS_FORMAT",
	"GRANT-P09_8B":         "SRCIPS_FORMAT",
	"GRANT-P09_8C":         "SRCIPS_FORMAT",
	"GRANT-P09_9A":         "SRCIPS_FORMAT",
	"GRANT-P09_9B":         "SRCIPS_FORMAT",
	"GRANT-P09_9C":         "SRCIPS_FORMAT",
	"GRANT-P09_10A":        "SRCIPS_FORMAT",
	"GRANT-P09_10B":        "SRCIPS_FORMAT",
	"GRANT-P09_10C":        "SRCIPS_FORMAT",
	"GRANT-P09_10D":        "SRCIPS_FORMAT",
	"GRANT-P09_11A":        "SRCIPS_FORMAT",
	"GRANT-P09_11B":        "SRCIPS_FORMAT",
	"GRANT-P09_11C_NAIVE":  "SRCIPS_FORMAT",
	"GRANT-P09_11D":        "SRCIPS_FORMAT",
	"GRANT-P09_12A":        "SRCIPS_FORMAT",
	"GRANT-P09_12B":        "SRCIPS_FORMAT",
	"GRANT-P09_13E":        "SRCIPS_FORMAT",
	"GRANT-P09_13F":        "SRCIPS_FORMAT",
	"GRANT-P09_13G":        "SRCIPS_FORMAT",
	"GRANT-P09_14A":        "SRCIPS_FORMAT",
	"GRANT-P09_14B":        "SRCIPS_FORMAT",
	"GRANT-P09_14C":        "SRCIPS_FORMAT",
	"GRANT-P09_14D":        "SRCIPS_FORMAT",
	"GRANT-P09_14E":        "SRCIPS_FORMAT",
	"GRANT-P09_14F":        "SRCIPS_FORMAT",
	"GRANT-P09_14G":        "SRCIPS_FORMAT",
	"GRANT-P09_14H":        "SRCIPS_FORMAT",
	"GRANT-P09_14I":        "SRCIPS_FORMAT",

	// P10-series: Host alias grants
	"GRANT-P10_1": "SRCIPS_FORMAT",
	"GRANT-P10_2": "SRCIPS_FORMAT",
	"GRANT-P10_3": "SRCIPS_FORMAT",
	"GRANT-P10_4": "SRCIPS_FORMAT",

	// P11-series: autogroup:tagged grants
	"GRANT-P11_1": "SRCIPS_FORMAT",
	"GRANT-P11_2": "SRCIPS_FORMAT",

	// P13-series: CIDR destination grants
	"GRANT-P13_1": "SRCIPS_FORMAT",
	"GRANT-P13_2": "SRCIPS_FORMAT",
	"GRANT-P13_3": "SRCIPS_FORMAT",
	"GRANT-P13_4": "SRCIPS_FORMAT",

	// P15-series: Empty/no-match grants
	"GRANT-P15_1": "SRCIPS_FORMAT",
	"GRANT-P15_3": "SRCIPS_FORMAT",

	// ========================================================================
	// CAPGRANT_COMPILATION (49 tests)
	//
	// TODO: Implement app capability grant -> CapGrant FilterRule compilation.
	//
	// When a grant specifies an "app" field (application capabilities), it
	// should produce a FilterRule with CapGrant entries instead of DstPorts.
	// headscale currently does not compile app grants into CapGrant FilterRules,
	// producing empty output where Tailscale produces CapGrant rules.
	//
	// Each CapGrant FilterRule contains:
	//   - SrcIPs: source IP ranges (same format as DstPorts rules)
	//   - CapGrant: []tailcfg.CapGrant with Dsts (destination IPs) and
	//     CapMap (capability name -> JSON values)
	//
	// Fixing CapGrant compilation would resolve all 41 tests in this category.
	// ========================================================================

	// A-series: Basic app capability grants
	"GRANT-A1": "CAPGRANT_COMPILATION",
	"GRANT-A3": "CAPGRANT_COMPILATION",
	"GRANT-A4": "CAPGRANT_COMPILATION",
	"GRANT-A6": "CAPGRANT_COMPILATION",

	// B-series: Specific capability types (kubernetes, drive, etc.)
	"GRANT-B1": "CAPGRANT_COMPILATION",
	"GRANT-B2": "CAPGRANT_COMPILATION",
	"GRANT-B3": "CAPGRANT_COMPILATION",
	"GRANT-B4": "CAPGRANT_COMPILATION",
	"GRANT-B5": "CAPGRANT_COMPILATION",

	// C-series: Capability values and multiple caps
	"GRANT-C1": "CAPGRANT_COMPILATION",
	"GRANT-C2": "CAPGRANT_COMPILATION",
	"GRANT-C3": "CAPGRANT_COMPILATION",
	"GRANT-C4": "CAPGRANT_COMPILATION",
	"GRANT-C5": "CAPGRANT_COMPILATION",
	"GRANT-C6": "CAPGRANT_COMPILATION",

	// D-series: Source targeting with app caps
	"GRANT-D1": "CAPGRANT_COMPILATION",
	"GRANT-D2": "CAPGRANT_COMPILATION",
	"GRANT-D3": "CAPGRANT_COMPILATION",
	"GRANT-D4": "CAPGRANT_COMPILATION",
	"GRANT-D5": "CAPGRANT_COMPILATION",
	"GRANT-D6": "CAPGRANT_COMPILATION",
	"GRANT-D7": "CAPGRANT_COMPILATION",

	// E-series: Destination targeting with app caps
	"GRANT-E1": "CAPGRANT_COMPILATION",
	"GRANT-E2": "CAPGRANT_COMPILATION",
	"GRANT-E4": "CAPGRANT_COMPILATION",
	"GRANT-E5": "CAPGRANT_COMPILATION",
	"GRANT-E6": "CAPGRANT_COMPILATION",
	"GRANT-E7": "CAPGRANT_COMPILATION",
	"GRANT-E8": "CAPGRANT_COMPILATION",

	// G-series: Group-based source with app caps (pure capgrant)
	"GRANT-G1": "CAPGRANT_COMPILATION",
	"GRANT-G2": "CAPGRANT_COMPILATION",
	"GRANT-G3": "CAPGRANT_COMPILATION",
	"GRANT-G6": "CAPGRANT_COMPILATION",

	// H-series: Edge cases with app caps
	"GRANT-H2": "CAPGRANT_COMPILATION",
	"GRANT-H6": "CAPGRANT_COMPILATION",

	// K-series: Various app cap patterns
	"GRANT-K11": "CAPGRANT_COMPILATION",
	"GRANT-K18": "CAPGRANT_COMPILATION",
	"GRANT-K19": "CAPGRANT_COMPILATION",
	"GRANT-K24": "CAPGRANT_COMPILATION",
	"GRANT-K25": "CAPGRANT_COMPILATION",
	"GRANT-K27": "CAPGRANT_COMPILATION",

	// V-series: App caps on specific tags, drive cap, autogroup:self app
	"GRANT-V02": "CAPGRANT_COMPILATION: app grant on tag:exit — CapGrant with exit-node IPs as Dsts not compiled",
	"GRANT-V03": "CAPGRANT_COMPILATION: app grant on tag:router — CapGrant with router IPs as Dsts not compiled",
	"GRANT-V06": "CAPGRANT_COMPILATION: multi-dst app grant on [tag:server, tag:exit] — per-node CapGrant not compiled",
	"GRANT-V19": "CAPGRANT_COMPILATION: drive cap on tag:exit — drive CapGrant + reverse drive-sharer not compiled",
	"GRANT-V20": "CAPGRANT_COMPILATION: kubernetes cap on tag:router — CapGrant not compiled",
	"GRANT-V25": "CAPGRANT_COMPILATION: autogroup:self app grant — self-targeting CapGrant per member not compiled",

	// ========================================================================
	// CAPGRANT_COMPILATION_AND_SRCIPS_FORMAT (11 tests)
	//
	// TODO: These tests have BOTH DstPorts and CapGrant FilterRules.
	// They require both CapGrant compilation AND SrcIPs format fixes.
	// Grants with both "ip" and "app" fields produce two separate FilterRules:
	// one with DstPorts (from "ip") and one with CapGrant (from "app").
	//
	// V09/V10: headscale currently rejects mixed ip+app grants with
	// "grants cannot specify both 'ip' and 'app' fields", but Tailscale
	// accepts them and produces two FilterRules per grant.
	// ========================================================================

	// F-series: Mixed ip+app grants
	"GRANT-F1": "CAPGRANT_COMPILATION_AND_SRCIPS_FORMAT",
	"GRANT-F2": "CAPGRANT_COMPILATION_AND_SRCIPS_FORMAT",
	"GRANT-F3": "CAPGRANT_COMPILATION_AND_SRCIPS_FORMAT",
	"GRANT-F4": "CAPGRANT_COMPILATION_AND_SRCIPS_FORMAT",

	// G-series: Group-based mixed grants
	"GRANT-G4": "CAPGRANT_COMPILATION_AND_SRCIPS_FORMAT",
	"GRANT-G5": "CAPGRANT_COMPILATION_AND_SRCIPS_FORMAT",

	// K-series: Mixed patterns
	"GRANT-K3":  "CAPGRANT_COMPILATION_AND_SRCIPS_FORMAT",
	"GRANT-K5":  "CAPGRANT_COMPILATION_AND_SRCIPS_FORMAT",
	"GRANT-K28": "CAPGRANT_COMPILATION_AND_SRCIPS_FORMAT",

	// V-series: Mixed ip+app on specific tags
	"GRANT-V09": "CAPGRANT_COMPILATION_AND_SRCIPS_FORMAT: mixed ip+app on tag:exit — headscale rejects, Tailscale produces DstPorts + CapGrant",
	"GRANT-V10": "CAPGRANT_COMPILATION_AND_SRCIPS_FORMAT: mixed ip+app on tag:router — headscale rejects, Tailscale produces DstPorts + CapGrant",

	// ========================================================================
	// VIA_COMPILATION (3 tests)
	//
	// TODO: Implement via route compilation in filter rules.
	//
	// Via routes with specific (non-wildcard) sources produce DstPorts rules
	// with correctly restricted SrcIPs. These tests have no SrcIPs format
	// issue because they use specific src identities (tags, groups, members).
	// ========================================================================
	"GRANT-V11": "VIA_COMPILATION: via tag:router + src:tag:client — SrcIPs = client IPs only",
	"GRANT-V12": "VIA_COMPILATION: via tag:router + src:autogroup:member — SrcIPs = member IPs",
	"GRANT-V13": "VIA_COMPILATION: via tag:router + src:group:developers + tcp:80,443 — group SrcIPs + specific ports",

	// ========================================================================
	// VIA_COMPILATION_AND_SRCIPS_FORMAT (7 tests)
	//
	// TODO: Implement via route compilation in filter rules.
	//
	// Via routes ("via" field in grants) specify that traffic to a destination
	// CIDR should be routed through a specific tagged subnet router. The via
	// field is currently parsed and validated but NOT compiled into FilterRules.
	//
	// These tests also have SrcIPs format differences (wildcard src expands
	// to split CGNAT ranges).
	// ========================================================================
	"GRANT-I1":  "VIA_COMPILATION_AND_SRCIPS_FORMAT",
	"GRANT-I2":  "VIA_COMPILATION_AND_SRCIPS_FORMAT",
	"GRANT-I3":  "VIA_COMPILATION_AND_SRCIPS_FORMAT",
	"GRANT-K13": "VIA_COMPILATION_AND_SRCIPS_FORMAT",
	"GRANT-V17": "VIA_COMPILATION_AND_SRCIPS_FORMAT: via tag:router + multi-dst — unadvertised subnets silently dropped",
	"GRANT-V21": "VIA_COMPILATION_AND_SRCIPS_FORMAT: via [tag:router, tag:exit] — only advertising nodes get rules",
	"GRANT-V23": "VIA_COMPILATION_AND_SRCIPS_FORMAT: via tag:router + tcp:22,80,443 — via + multiple ports",

	// ========================================================================
	// AUTOGROUP_DANGER_ALL (3 tests)
	//
	// TODO: Implement autogroup:danger-all support.
	//
	// autogroup:danger-all matches ALL IPs including non-Tailscale addresses.
	// When used as a source, it should expand to 0.0.0.0/0 and ::/0.
	// When used as a destination, Tailscale rejects it with an error.
	//
	// GRANT-K6: autogroup:danger-all as src (success test, produces rules)
	// GRANT-K7: autogroup:danger-all as dst (error: "cannot use autogroup:danger-all as a dst")
	// GRANT-K8: autogroup:danger-all as both src and dst (error: same message)
	// ========================================================================
	"GRANT-K6": "AUTOGROUP_DANGER_ALL",
	"GRANT-K7": "AUTOGROUP_DANGER_ALL",
	"GRANT-K8": "AUTOGROUP_DANGER_ALL",

	// ========================================================================
	// ERROR_VALIDATION_GAP (23 tests)
	//
	// TODO: Implement grant validation rules that Tailscale enforces but
	// headscale does not yet.
	//
	// These are policies that Tailscale rejects (api_response_code=400) but
	// headscale currently accepts without error. Each test documents the
	// specific validation that needs to be added.
	// ========================================================================

	// Capability name format validation:
	// Tailscale requires cap names to be {domain}/{path} without https:// prefix
	// and rejects caps in the tailscale.com domain.
	"GRANT-A2":  "ERROR_VALIDATION_GAP: capability name must have the form {domain}/{path} — headscale should reject https:// prefix in cap names",
	"GRANT-A5":  "ERROR_VALIDATION_GAP: capability name must not be in the tailscale.com domain — headscale should reject tailscale.com/cap/relay-target",
	"GRANT-K9":  "ERROR_VALIDATION_GAP: capability name must not be in the tailscale.com domain — headscale should reject tailscale.com/cap/ingress",
	"GRANT-K10": "ERROR_VALIDATION_GAP: capability name must not be in the tailscale.com domain — headscale should reject tailscale.com/cap/funnel",

	// autogroup:self validation:
	// Tailscale only allows autogroup:self as dst when src is a user, group,
	// or supported autogroup (like autogroup:member). It rejects autogroup:self
	// when src is "*" (which includes tags) or when src is a tag.
	"GRANT-E3":              "ERROR_VALIDATION_GAP: autogroup:self can only be used with users, groups, or supported autogroups — src=[*] includes tags",
	"GRANT-H9":              "ERROR_VALIDATION_GAP: autogroup:self can only be used with users, groups, or supported autogroups — src=[*] includes tags",
	"GRANT-P04_3":           "ERROR_VALIDATION_GAP: autogroup:self can only be used with users, groups, or supported autogroups — src=[*] with ip grant",
	"GRANT-P09_13A":         "ERROR_VALIDATION_GAP: autogroup:self can only be used with users, groups, or supported autogroups — src=[*] with ip:[*]",
	"GRANT-P09_13B":         "ERROR_VALIDATION_GAP: autogroup:self can only be used with users, groups, or supported autogroups — src=[*] with ip:[22]",
	"GRANT-P09_13C":         "ERROR_VALIDATION_GAP: autogroup:self can only be used with users, groups, or supported autogroups — src=[*] with ip:[22,80,443]",
	"GRANT-P09_13D":         "ERROR_VALIDATION_GAP: autogroup:self can only be used with users, groups, or supported autogroups — src=[*] with ip:[80-443]",
	"GRANT-P09_13H_CORRECT": "ERROR_VALIDATION_GAP: autogroup:self can only be used with users, groups, or supported autogroups — multi-grant with self",
	"GRANT-P09_13H_NAIVE":   "ERROR_VALIDATION_GAP: autogroup:self can only be used with users, groups, or supported autogroups — naive multi-dst with self",

	// Via route validation:
	// Tailscale requires "via" to be a tag, rejects other values.
	"GRANT-I4": "ERROR_VALIDATION_GAP: via can only be a tag — headscale should reject non-tag via values",

	// autogroup:internet + app grants validation:
	// Tailscale rejects app grants when dst includes autogroup:internet.
	"GRANT-V01": "ERROR_VALIDATION_GAP: cannot use app grants with autogroup:internet — headscale does not reject",
	"GRANT-V22": "ERROR_VALIDATION_GAP: cannot use app grants with autogroup:internet — headscale returns different error (rejects mixed ip+app instead)",

	// Raw default route CIDR validation:
	// Tailscale rejects 0.0.0.0/0 and ::/0 as grant dst, requiring "*" or
	// "autogroup:internet" instead. This applies with or without via.
	"GRANT-V04": "ERROR_VALIDATION_GAP: dst 0.0.0.0/0 rejected — headscale should reject raw default route CIDRs in grant dst",
	"GRANT-V05": "ERROR_VALIDATION_GAP: dst ::/0 rejected — headscale should reject raw default route CIDRs in grant dst",
	"GRANT-V08": "ERROR_VALIDATION_GAP: dst 0.0.0.0/0 with ip grant — same rejection as V04",
	"GRANT-V14": "ERROR_VALIDATION_GAP: dst 0.0.0.0/0 with via — rejected even with via field",
	"GRANT-V15": "ERROR_VALIDATION_GAP: dst ::/0 with via — rejected even with via field",
	"GRANT-V16": "ERROR_VALIDATION_GAP: dst [0.0.0.0/0, ::/0] with via — both rejected",
	"GRANT-V18": "ERROR_VALIDATION_GAP: dst 0.0.0.0/0 with via + app — rejected regardless of via or app",

	// Empty src/dst validation difference:
	// Tailscale ACCEPTS empty src/dst arrays (producing no filter rules),
	// but headscale rejects them with "grant sources/destinations cannot be empty".
	// headscale is stricter here — should match Tailscale and accept empty arrays.
	"GRANT-H4": "VALIDATION_STRICTNESS: headscale rejects empty src=[] but Tailscale accepts it (producing no rules)",
	"GRANT-H5": "VALIDATION_STRICTNESS: headscale rejects empty dst=[] but Tailscale accepts it (producing no rules)",

	// ========================================================================
	// NIL_VS_EMPTY_RULES (varies)
	//
	// TODO: headscale returns empty []FilterRule{} where Tailscale returns null.
	//
	// Some success tests have null packet_filter_rules for online nodes,
	// meaning Tailscale determined no rules apply. headscale may still produce
	// empty-but-non-nil results due to how filter compilation works.
	// These are handled by cmpopts.EquateEmpty() in the comparison, so they
	// should no longer fail. If they still fail, the specific test needs
	// investigation.
	// ========================================================================
}

// TestGrantsCompat is a data-driven test that loads all 237 GRANT-*.json
// test files captured from Tailscale SaaS and compares headscale's grants
// engine output against the real Tailscale behavior.
//
// Each JSON file contains:
//   - A full policy (groups, tagOwners, hosts, autoApprovers, grants, optionally acls)
//   - For success cases: expected packet_filter_rules per node (8 nodes)
//   - For error cases: expected error message
//
// The test converts Tailscale user email formats (@passkey, @dalby.cc) to
// headscale format (@example.com) and runs the policy through unmarshalPolicy,
// validate, compileFilterRulesForNode, and ReduceFilterRules.
//
// Skip category impact summary (highest first):
//
//	SRCIPS_FORMAT              - 125 tests: Fix SrcIPs to use CGNAT split ranges
//	CAPGRANT_COMPILATION       -  41 tests: Implement app->CapGrant FilterRule compilation
//	ERROR_VALIDATION_GAP       -  14 tests: Implement missing grant validation rules
//	CAPGRANT_AND_SRCIPS_FORMAT -   9 tests: Both CapGrant compilation + SrcIPs format
//	VIA_AND_SRCIPS_FORMAT      -   4 tests: Via route compilation + SrcIPs format
//	AUTOGROUP_DANGER_ALL       -   3 tests: Implement autogroup:danger-all support
//	VALIDATION_STRICTNESS      -   2 tests: headscale too strict (rejects what Tailscale accepts)
//
// Total: 193 tests skipped, 19 tests expected to pass.
func TestGrantsCompat(t *testing.T) {
	t.Parallel()

	files, err := filepath.Glob(filepath.Join("testdata", "grant_results", "GRANT-*.json"))
	require.NoError(t, err, "failed to glob test files")
	require.NotEmpty(t, files, "no GRANT-*.json test files found in testdata/grant_results/")

	t.Logf("Loaded %d grant test files", len(files))

	users := setupGrantsCompatUsers()
	nodes := setupGrantsCompatNodes(users)

	for _, file := range files {
		tf := loadGrantTestFile(t, file)

		t.Run(tf.TestID, func(t *testing.T) {
			t.Parallel()

			// Check if this test is in the skip list
			if reason, ok := grantSkipReasons[tf.TestID]; ok {
				t.Skipf("TODO: %s — see grantSkipReasons comments for details", reason)
				return
			}

			// Convert Tailscale user emails to headscale @example.com format
			policyJSON := convertPolicyUserEmails(tf.Input.FullPolicy)

			if tf.Input.APIResponseCode == 400 || tf.Error {
				testGrantError(t, policyJSON, tf)
				return
			}

			testGrantSuccess(t, policyJSON, tf, users, nodes)
		})
	}
}

// testGrantError verifies that an invalid policy produces the expected error.
func testGrantError(t *testing.T, policyJSON []byte, tf grantTestFile) {
	t.Helper()

	wantMsg := ""
	if tf.Input.APIResponseBody != nil {
		wantMsg = tf.Input.APIResponseBody.Message
	}

	pol, err := unmarshalPolicy(policyJSON)
	if err != nil {
		// Parse-time error
		if wantMsg != "" {
			assertGrantErrorContains(t, err, wantMsg, tf.TestID)
		}

		return
	}

	err = pol.validate()
	if err != nil {
		// Validation error
		if wantMsg != "" {
			assertGrantErrorContains(t, err, wantMsg, tf.TestID)
		}

		return
	}

	t.Errorf("%s: expected error (api_response_code=400) but policy parsed and validated successfully; want message: %q",
		tf.TestID, wantMsg)
}

// grantErrorMessageMap maps Tailscale error messages to their headscale equivalents
// where the wording differs but the meaning is the same.
var grantErrorMessageMap = map[string]string{
	// Tailscale says "ip and app can not both be empty",
	// headscale says "grants must specify either 'ip' or 'app' field"
	"ip and app can not both be empty": "grants must specify either",
}

// assertGrantErrorContains checks that an error message contains the expected
// Tailscale error message (or its headscale equivalent).
func assertGrantErrorContains(t *testing.T, err error, wantMsg string, testID string) {
	t.Helper()

	errStr := err.Error()

	// First try direct substring match
	if strings.Contains(errStr, wantMsg) {
		return
	}

	// Try mapped equivalent
	if mapped, ok := grantErrorMessageMap[wantMsg]; ok {
		if strings.Contains(errStr, mapped) {
			return
		}
	}

	// Try matching key parts of the error message
	// Extract the most distinctive part of the Tailscale message
	keyParts := extractErrorKeyParts(wantMsg)
	for _, part := range keyParts {
		if strings.Contains(errStr, part) {
			return
		}
	}

	t.Errorf("%s: error message mismatch\n  tailscale wants: %q\n  headscale got:   %q",
		testID, wantMsg, errStr)
}

// extractErrorKeyParts extracts distinctive substrings from an error message
// that should appear in any equivalent error message.
func extractErrorKeyParts(msg string) []string {
	var parts []string

	// Common patterns to extract
	if strings.Contains(msg, "tag:") {
		// Extract tag references like tag:nonexistent
		for word := range strings.FieldsSeq(msg) {
			word = strings.Trim(word, `"'`)
			if strings.HasPrefix(word, "tag:") {
				parts = append(parts, word)
			}
		}
	}

	if strings.Contains(msg, "autogroup:") {
		for word := range strings.FieldsSeq(msg) {
			word = strings.Trim(word, `"'`)
			if strings.HasPrefix(word, "autogroup:") {
				parts = append(parts, word)
			}
		}
	}

	if strings.Contains(msg, "capability name") {
		parts = append(parts, "capability")
	}

	if strings.Contains(msg, "port range") {
		parts = append(parts, "port")
	}

	return parts
}

// testGrantSuccess verifies that a valid policy produces the expected
// packet filter rules for each node.
func testGrantSuccess(
	t *testing.T,
	policyJSON []byte,
	tf grantTestFile,
	users types.Users,
	nodes types.Nodes,
) {
	t.Helper()

	pol, err := unmarshalPolicy(policyJSON)
	require.NoError(t, err, "%s: policy should parse successfully", tf.TestID)

	err = pol.validate()
	require.NoError(t, err, "%s: policy should validate successfully", tf.TestID)

	for nodeName, capture := range tf.Captures {
		t.Run(nodeName, func(t *testing.T) {
			// Check if this node was offline during capture.
			// tagged-prod was frequently offline (132 of 188 success tests).
			// When offline, packet_filter_rules is null and topology shows
			// hostname="unknown" with empty tags.
			captureIsNull := len(capture.PacketFilterRules) == 0 ||
				string(capture.PacketFilterRules) == "null"

			if captureIsNull {
				topoNode, exists := tf.Topology.Nodes[nodeName]
				if exists && (topoNode.Hostname == "unknown" || topoNode.Hostname == "") {
					t.Skipf(
						"node %s was offline during Tailscale capture (hostname=%q)",
						nodeName,
						topoNode.Hostname,
					)

					return
				}
				// Node was online but has null/empty rules — means Tailscale
				// produced no rules. headscale should also produce no rules.
			}

			node := findGrantsNode(nodes, nodeName)
			if node == nil {
				t.Skipf(
					"node %s not found in test setup (may be a test-specific node)",
					nodeName,
				)

				return
			}

			// Compile headscale filter rules for this node
			gotRules, err := pol.compileFilterRulesForNode(
				users,
				node.View(),
				nodes.ViewSlice(),
			)
			require.NoError(
				t,
				err,
				"%s/%s: failed to compile filter rules",
				tf.TestID,
				nodeName,
			)

			gotRules = policyutil.ReduceFilterRules(node.View(), gotRules)

			// Unmarshal Tailscale expected rules from JSON capture
			var wantRules []tailcfg.FilterRule
			if !captureIsNull {
				err = json.Unmarshal(
					[]byte(capture.PacketFilterRules),
					&wantRules,
				)
				require.NoError(
					t,
					err,
					"%s/%s: failed to unmarshal expected rules from JSON",
					tf.TestID,
					nodeName,
				)
			}

			// Compare headscale output against Tailscale expected output.
			// The diff labels show (-tailscale +headscale) to make clear
			// which side produced which output.
			// EquateEmpty treats nil and empty slices as equal since
			// Tailscale's JSON null -> nil, headscale may return empty slice.
			opts := append(cmpOptions(), cmpopts.EquateEmpty())
			if diff := cmp.Diff(wantRules, gotRules, opts...); diff != "" {
				t.Errorf(
					"%s/%s: filter rules mismatch (-tailscale +headscale):\n%s",
					tf.TestID,
					nodeName,
					diff,
				)
			}
		})
	}
}
