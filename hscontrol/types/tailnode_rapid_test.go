package types

import (
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"pgregory.net/rapid"
	"tailscale.com/net/tsaddr"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

// ============================================================================
// Generators for TailNode property tests
// ============================================================================

// genNodeID generates a random NodeID in a realistic range.
func genNodeID() *rapid.Generator[NodeID] {
	return rapid.Custom[NodeID](func(t *rapid.T) NodeID {
		return NodeID(rapid.Uint64Range(1, 1<<53).Draw(t, "nodeID"))
	})
}

// genUserID generates a random user ID pointer (non-nil, positive).
func genUserID() *rapid.Generator[*uint] {
	return rapid.Custom[*uint](func(t *rapid.T) *uint {
		uid := uint(rapid.IntRange(1, 100000).Draw(t, "userID"))
		return &uid
	})
}

// newKeys generates a triple of fresh random keys. These are not wrapped
// in a rapid.Generator because key generation is not deterministic from
// the bitstream (it uses crypto/rand), and rapid.Custom requires at
// least one Draw call. Instead, call this directly inside a Custom generator
// that already draws other values.
type keyTriple struct {
	Machine key.MachinePublic
	Node    key.NodePublic
	Disco   key.DiscoPublic
}

func newKeys() keyTriple {
	return keyTriple{
		Machine: key.NewMachine().Public(),
		Node:    key.NewNode().Public(),
		Disco:   key.NewDisco().Public(),
	}
}

// genGivenName generates a short valid DNS-like name (lowercase, alphanumeric).
func genGivenName() *rapid.Generator[string] {
	return rapid.Custom[string](func(t *rapid.T) string {
		return rapid.StringMatching(`[a-z][a-z0-9]{1,15}`).Draw(t, "givenName")
	})
}

// genBaseDomain generates a base domain that, combined with a given name,
// stays under MaxHostnameLength. Short domains to avoid FQDN overflow.
func genBaseDomain() *rapid.Generator[string] {
	return rapid.Custom[string](func(t *rapid.T) string {
		return rapid.StringMatching(`[a-z]{2,8}\.[a-z]{2,4}`).Draw(t, "baseDomain")
	})
}

// genExpiry generates either nil (no expiry) or a time in the future or past.
func genExpiry() *rapid.Generator[*time.Time] {
	return rapid.Custom[*time.Time](func(t *rapid.T) *time.Time {
		hasExpiry := rapid.Bool().Draw(t, "hasExpiry")
		if !hasExpiry {
			return nil
		}
		// Offset from now: negative = past (expired), positive = future (not expired)
		offsetSec := rapid.Int64Range(-86400*365, 86400*365).Draw(t, "offsetSec")
		exp := time.Now().Add(time.Duration(offsetSec) * time.Second)
		return &exp
	})
}

// genOnlineState generates an IsOnline pointer: nil, true, or false.
func genOnlineState() *rapid.Generator[*bool] {
	return rapid.Custom[*bool](func(t *rapid.T) *bool {
		variant := rapid.IntRange(0, 2).Draw(t, "onlineVariant")
		switch variant {
		case 0:
			return nil
		case 1:
			v := true
			return &v
		default:
			v := false
			return &v
		}
	})
}

// genLastSeen generates either nil or a time in the recent past.
func genLastSeen() *rapid.Generator[*time.Time] {
	return rapid.Custom[*time.Time](func(t *rapid.T) *time.Time {
		hasLastSeen := rapid.Bool().Draw(t, "hasLastSeen")
		if !hasLastSeen {
			return nil
		}
		offsetSec := rapid.Int64Range(1, 86400*30).Draw(t, "lastSeenOffset")
		ls := time.Now().Add(-time.Duration(offsetSec) * time.Second)
		return &ls
	})
}

// genPrimaryRoutes generates 0..maxLen subnet prefixes for use as primary routes.
func genPrimaryRoutes(maxLen int) *rapid.Generator[[]netip.Prefix] {
	return rapid.Custom[[]netip.Prefix](func(t *rapid.T) []netip.Prefix {
		n := rapid.IntRange(0, maxLen).Draw(t, "nPrimaryRoutes")
		routes := make([]netip.Prefix, n)
		for i := range routes {
			routes[i] = genSubnetPrefix().Draw(t, "primaryRoute")
		}
		return routes
	})
}

// genExitRouteConfig generates announced + approved routes that may include exit routes.
type exitRouteConfig struct {
	Announced      []netip.Prefix
	ApprovedRoutes []netip.Prefix
}

func genExitRouteConfig() *rapid.Generator[exitRouteConfig] {
	return rapid.Custom[exitRouteConfig](func(t *rapid.T) exitRouteConfig {
		hasExit := rapid.Bool().Draw(t, "hasExit")
		if !hasExit {
			return exitRouteConfig{}
		}
		// Include both v4 and v6 exit routes, both announced and approved
		announced := []netip.Prefix{tsaddr.AllIPv4(), tsaddr.AllIPv6()}
		approved := []netip.Prefix{tsaddr.AllIPv4(), tsaddr.AllIPv6()}
		return exitRouteConfig{
			Announced:      announced,
			ApprovedRoutes: approved,
		}
	})
}

// tailNodeInput bundles everything needed to call TailNode.
type tailNodeInput struct {
	Node          *Node
	PrimaryRoutes []netip.Prefix
	Config        *Config
	CapVer        tailcfg.CapabilityVersion
}

// genTailNodeInput builds a fully-formed input suitable for TailNode.
// It guarantees the node has at least one IP and a valid GivenName so
// that TailNode will not return an error.
func genTailNodeInput() *rapid.Generator[tailNodeInput] {
	return rapid.Custom[tailNodeInput](func(t *rapid.T) tailNodeInput {
		id := genNodeID().Draw(t, "id")
		keys := newKeys()
		givenName := genGivenName().Draw(t, "givenName")
		baseDomain := genBaseDomain().Draw(t, "baseDomain")

		// Always generate at least one IP so Prefixes() is non-empty
		v4 := genIPv4Addr().Draw(t, "ipv4")
		hasV6 := rapid.Bool().Draw(t, "hasV6")

		tags := genTags(4).Draw(t, "tags")
		expiry := genExpiry().Draw(t, "expiry")
		onlineState := genOnlineState().Draw(t, "online")
		lastSeen := genLastSeen().Draw(t, "lastSeen")
		primaryRoutes := genPrimaryRoutes(3).Draw(t, "primaryRoutes")
		exitCfg := genExitRouteConfig().Draw(t, "exitRoutes")

		// UserID: required for user-owned nodes; optional for tagged
		var userID *uint
		if len(tags) == 0 {
			// User-owned: must have a UserID
			userID = genUserID().Draw(t, "userID")
		} else {
			// Tagged: optionally has a "created by" UserID
			if rapid.Bool().Draw(t, "taggedHasUserID") {
				userID = genUserID().Draw(t, "taggedUserID")
			}
		}

		// Build hostinfo with exit routes announced
		var hostinfo *tailcfg.Hostinfo
		if len(exitCfg.Announced) > 0 {
			hostinfo = &tailcfg.Hostinfo{
				RoutableIPs: exitCfg.Announced,
			}
		}

		node := &Node{
			ID:             id,
			MachineKey:     keys.Machine,
			NodeKey:        keys.Node,
			DiscoKey:       keys.Disco,
			Hostname:       givenName,
			GivenName:      givenName,
			UserID:         userID,
			Tags:           tags,
			Expiry:         expiry,
			IsOnline:       onlineState,
			LastSeen:       lastSeen,
			Hostinfo:       hostinfo,
			ApprovedRoutes: exitCfg.ApprovedRoutes,
		}

		if hasV6 {
			v6 := genIPv6Addr().Draw(t, "ipv6")
			node.IPv6 = &v6
		}
		node.IPv4 = &v4

		cfg := &Config{
			BaseDomain:          baseDomain,
			RandomizeClientPort: rapid.Bool().Draw(t, "randomizePort"),
			Taildrop: TaildropConfig{
				Enabled: rapid.Bool().Draw(t, "taildrop"),
			},
		}

		capVer := tailcfg.CapabilityVersion(
			rapid.IntRange(80, 120).Draw(t, "capVer"),
		)

		return tailNodeInput{
			Node:          node,
			PrimaryRoutes: primaryRoutes,
			Config:        cfg,
			CapVer:        capVer,
		}
	})
}

// callTailNode is a helper that constructs the NodeView and calls TailNode,
// returning the result along with the mock route function's routes.
func callTailNode(inp tailNodeInput) (*tailcfg.Node, error) {
	nv := inp.Node.View()
	routeFunc := func(_ NodeID) []netip.Prefix {
		return inp.PrimaryRoutes
	}
	return nv.TailNode(inp.CapVer, routeFunc, inp.Config)
}

// ============================================================================
// Property 1: ID preservation
// ============================================================================

func TestRapid_TailNode_IDPreservation(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		inp := genTailNodeInput().Draw(t, "input")
		out, err := callTailNode(inp)
		if err != nil {
			t.Fatalf("TailNode error: %v", err)
		}

		expected := tailcfg.NodeID(inp.Node.ID)
		if out.ID != expected {
			t.Fatalf("ID mismatch: got %d, want %d", out.ID, expected)
		}
	})
}

// ============================================================================
// Property 2: StableID is base-10 string of ID
// ============================================================================

func TestRapid_TailNode_StableIDBase10(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		inp := genTailNodeInput().Draw(t, "input")
		out, err := callTailNode(inp)
		if err != nil {
			t.Fatalf("TailNode error: %v", err)
		}

		expected := tailcfg.StableNodeID(strconv.FormatUint(uint64(inp.Node.ID), 10))
		if out.StableID != expected {
			t.Fatalf("StableID mismatch: got %q, want %q", out.StableID, expected)
		}
	})
}

// ============================================================================
// Property 3: Addresses == Prefixes (host prefixes of node IPs)
// ============================================================================

func TestRapid_TailNode_AddressesEqualPrefixes(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		inp := genTailNodeInput().Draw(t, "input")
		out, err := callTailNode(inp)
		if err != nil {
			t.Fatalf("TailNode error: %v", err)
		}

		expectedPrefixes := inp.Node.Prefixes()
		if !slices.Equal(out.Addresses, expectedPrefixes) {
			t.Fatalf("Addresses mismatch:\n  got:  %v\n  want: %v",
				out.Addresses, expectedPrefixes)
		}
	})
}

// ============================================================================
// Property 4: Every Address is contained in AllowedIPs
// ============================================================================

func TestRapid_TailNode_AddressesSubsetOfAllowedIPs(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		inp := genTailNodeInput().Draw(t, "input")
		out, err := callTailNode(inp)
		if err != nil {
			t.Fatalf("TailNode error: %v", err)
		}

		for _, addr := range out.Addresses {
			if !slices.Contains(out.AllowedIPs, addr) {
				t.Fatalf("Address %s not found in AllowedIPs %v", addr, out.AllowedIPs)
			}
		}
	})
}

// ============================================================================
// Property 5: AllowedIPs is sorted by netip.Prefix.Compare
// ============================================================================

func TestRapid_TailNode_AllowedIPsSorted(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		inp := genTailNodeInput().Draw(t, "input")
		out, err := callTailNode(inp)
		if err != nil {
			t.Fatalf("TailNode error: %v", err)
		}

		if !slices.IsSortedFunc(out.AllowedIPs, netip.Prefix.Compare) {
			t.Fatalf("AllowedIPs not sorted: %v", out.AllowedIPs)
		}
	})
}

// ============================================================================
// Property 6: AllowedIPs = Prefixes() ∪ primaryRouteFunc(nodeID), sorted
//   TailNode uses the RouteFunc callback to get all routes (subnet+exit).
//   AllowedIPs is their concatenation, sorted. No dedup is done.
// ============================================================================

func TestRapid_TailNode_AllowedIPsComposition(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		inp := genTailNodeInput().Draw(t, "input")
		out, err := callTailNode(inp)
		if err != nil {
			t.Fatalf("TailNode error: %v", err)
		}

		// AllowedIPs = slices.Concat(Prefixes(), routeFunc(id)), sorted
		expected := slices.Concat(
			inp.Node.Prefixes(),
			inp.PrimaryRoutes,
		)
		slices.SortFunc(expected, netip.Prefix.Compare)

		if !slices.Equal(out.AllowedIPs, expected) {
			t.Fatalf("AllowedIPs composition mismatch:\n  got:    %v\n  expect: %v",
				out.AllowedIPs, expected)
		}
	})
}

// ============================================================================
// Property 7: MachineAuthorized == !Expired (complementary)
// ============================================================================

func TestRapid_TailNode_MachineAuthorizedComplementsExpired(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		inp := genTailNodeInput().Draw(t, "input")
		out, err := callTailNode(inp)
		if err != nil {
			t.Fatalf("TailNode error: %v", err)
		}

		if out.MachineAuthorized == out.Expired {
			t.Fatalf("MachineAuthorized (%v) must be complement of Expired (%v)",
				out.MachineAuthorized, out.Expired)
		}
	})
}

// Property 7b: Expired matches the node's own IsExpired calculation.
func TestRapid_TailNode_ExpiredMatchesIsExpired(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		inp := genTailNodeInput().Draw(t, "input")
		out, err := callTailNode(inp)
		if err != nil {
			t.Fatalf("TailNode error: %v", err)
		}

		expected := inp.Node.IsExpired()
		if out.Expired != expected {
			t.Fatalf("Expired=%v but node.IsExpired()=%v (expiry=%v)",
				out.Expired, expected, inp.Node.Expiry)
		}
	})
}

// ============================================================================
// Property 8: Tags-as-identity
//   - Tagged node -> User == TaggedDevices.ID
//   - User-owned node -> User == actual UserID
// ============================================================================

func TestRapid_TailNode_TagsAsIdentity(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		inp := genTailNodeInput().Draw(t, "input")
		out, err := callTailNode(inp)
		if err != nil {
			t.Fatalf("TailNode error: %v", err)
		}

		if inp.Node.IsTagged() {
			expected := tailcfg.UserID(int64(TaggedDevicesUserID))
			if out.User != expected {
				t.Fatalf("tagged node User=%d, want TaggedDevices=%d", out.User, expected)
			}
		} else {
			// User-owned: must have UserID
			if inp.Node.UserID == nil {
				t.Fatal("user-owned node has nil UserID (generator bug)")
			}
			expected := tailcfg.UserID(int64(*inp.Node.UserID))
			if out.User != expected {
				t.Fatalf("user-owned node User=%d, want %d", out.User, expected)
			}
		}
	})
}

// Property 8b: Tagged nodes always map to the same User value regardless of UserID.
func TestRapid_TailNode_TaggedUserIDConstant(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		inp := genTailNodeInput().Draw(t, "input")
		if !inp.Node.IsTagged() {
			return // skip user-owned
		}

		out, err := callTailNode(inp)
		if err != nil {
			t.Fatalf("TailNode error: %v", err)
		}

		// Value must be constant regardless of inp.Node.UserID
		if out.User != tailcfg.UserID(int64(TaggedDevicesUserID)) {
			t.Fatalf("tagged node User=%d varies, expected constant %d",
				out.User, TaggedDevicesUserID)
		}
	})
}

// ============================================================================
// Property 9: Name with BaseDomain has trailing dot, formatted correctly
// ============================================================================

func TestRapid_TailNode_NameFormat(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		inp := genTailNodeInput().Draw(t, "input")
		out, err := callTailNode(inp)
		if err != nil {
			t.Fatalf("TailNode error: %v", err)
		}

		if inp.Config.BaseDomain != "" {
			// Must end with trailing dot
			if !strings.HasSuffix(out.Name, ".") {
				t.Fatalf("Name %q should end with '.' when BaseDomain=%q",
					out.Name, inp.Config.BaseDomain)
			}

			// Must be givenName.baseDomain.
			expected := inp.Node.GivenName + "." + inp.Config.BaseDomain + "."
			if out.Name != expected {
				t.Fatalf("Name mismatch:\n  got:  %q\n  want: %q", out.Name, expected)
			}
		} else {
			// Without base domain, Name is just GivenName
			if out.Name != inp.Node.GivenName {
				t.Fatalf("Name=%q without BaseDomain, want GivenName=%q",
					out.Name, inp.Node.GivenName)
			}
		}
	})
}

// Property 9b: Name contains the GivenName as a prefix.
func TestRapid_TailNode_NameContainsGivenName(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		inp := genTailNodeInput().Draw(t, "input")
		out, err := callTailNode(inp)
		if err != nil {
			t.Fatalf("TailNode error: %v", err)
		}

		if !strings.HasPrefix(out.Name, inp.Node.GivenName) {
			t.Fatalf("Name %q does not start with GivenName %q",
				out.Name, inp.Node.GivenName)
		}
	})
}

// ============================================================================
// Property 10: Key preservation
// ============================================================================

func TestRapid_TailNode_KeyPreservation(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		inp := genTailNodeInput().Draw(t, "input")
		out, err := callTailNode(inp)
		if err != nil {
			t.Fatalf("TailNode error: %v", err)
		}

		if out.Key != inp.Node.NodeKey {
			t.Fatalf("NodeKey mismatch: got %v, want %v", out.Key, inp.Node.NodeKey)
		}
		if out.Machine != inp.Node.MachineKey {
			t.Fatalf("MachineKey mismatch: got %v, want %v", out.Machine, inp.Node.MachineKey)
		}
		if out.DiscoKey != inp.Node.DiscoKey {
			t.Fatalf("DiscoKey mismatch: got %v, want %v", out.DiscoKey, inp.Node.DiscoKey)
		}
	})
}

// ============================================================================
// Property 11: CapMap always has Admin and SSH capabilities
// ============================================================================

func TestRapid_TailNode_CapMapMandatoryEntries(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		inp := genTailNodeInput().Draw(t, "input")
		out, err := callTailNode(inp)
		if err != nil {
			t.Fatalf("TailNode error: %v", err)
		}

		if _, ok := out.CapMap[tailcfg.CapabilityAdmin]; !ok {
			t.Fatal("CapMap missing CapabilityAdmin")
		}
		if _, ok := out.CapMap[tailcfg.CapabilitySSH]; !ok {
			t.Fatal("CapMap missing CapabilitySSH")
		}
	})
}

// Property 11b: RandomizeClientPort config implies the cap is present, and vice versa.
func TestRapid_TailNode_CapMapRandomizeClientPort(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		inp := genTailNodeInput().Draw(t, "input")
		out, err := callTailNode(inp)
		if err != nil {
			t.Fatalf("TailNode error: %v", err)
		}

		_, hasCap := out.CapMap[tailcfg.NodeAttrRandomizeClientPort]
		if inp.Config.RandomizeClientPort && !hasCap {
			t.Fatal("RandomizeClientPort=true but cap not in CapMap")
		}
		if !inp.Config.RandomizeClientPort && hasCap {
			t.Fatal("RandomizeClientPort=false but cap present in CapMap")
		}
	})
}

// Property 11c: Taildrop.Enabled implies CapabilityFileSharing, and vice versa.
func TestRapid_TailNode_CapMapTaildrop(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		inp := genTailNodeInput().Draw(t, "input")
		out, err := callTailNode(inp)
		if err != nil {
			t.Fatalf("TailNode error: %v", err)
		}

		_, hasCap := out.CapMap[tailcfg.CapabilityFileSharing]
		if inp.Config.Taildrop.Enabled && !hasCap {
			t.Fatal("Taildrop.Enabled=true but CapabilityFileSharing not in CapMap")
		}
		if !inp.Config.Taildrop.Enabled && hasCap {
			t.Fatal("Taildrop.Enabled=false but CapabilityFileSharing present in CapMap")
		}
	})
}

// ============================================================================
// Property 12: LastSeen nil for online nodes, set only when offline
// ============================================================================

func TestRapid_TailNode_LastSeenNilForOnlineNodes(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		inp := genTailNodeInput().Draw(t, "input")
		out, err := callTailNode(inp)
		if err != nil {
			t.Fatalf("TailNode error: %v", err)
		}

		isOnlineSet := inp.Node.IsOnline != nil
		isOnline := isOnlineSet && *inp.Node.IsOnline

		if isOnline && out.LastSeen != nil {
			t.Fatalf("online node should have nil LastSeen, got %v", *out.LastSeen)
		}
	})
}

// Property 12b: LastSeen is set only when the node has a LastSeen value AND is offline.
func TestRapid_TailNode_LastSeenSetWhenOfflineWithLastSeen(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		inp := genTailNodeInput().Draw(t, "input")
		out, err := callTailNode(inp)
		if err != nil {
			t.Fatalf("TailNode error: %v", err)
		}

		hasLastSeen := inp.Node.LastSeen != nil
		isOnlineValid := inp.Node.IsOnline != nil
		isOffline := isOnlineValid && !*inp.Node.IsOnline

		shouldHaveLastSeen := hasLastSeen && isOnlineValid && isOffline
		if shouldHaveLastSeen && out.LastSeen == nil {
			t.Fatal("offline node with LastSeen should have LastSeen set in output")
		}
		if !shouldHaveLastSeen && out.LastSeen != nil {
			t.Fatalf("node should not have LastSeen set (hasLastSeen=%v, isOnlineValid=%v, isOffline=%v), got %v",
				hasLastSeen, isOnlineValid, isOffline, *out.LastSeen)
		}
	})
}

// Property 12c: When LastSeen is set, it matches the input node's LastSeen value.
func TestRapid_TailNode_LastSeenValuePreserved(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		inp := genTailNodeInput().Draw(t, "input")
		out, err := callTailNode(inp)
		if err != nil {
			t.Fatalf("TailNode error: %v", err)
		}

		if out.LastSeen != nil && inp.Node.LastSeen != nil {
			if !out.LastSeen.Equal(*inp.Node.LastSeen) {
				t.Fatalf("LastSeen value mismatch: got %v, want %v",
					*out.LastSeen, *inp.Node.LastSeen)
			}
		}
	})
}

// ============================================================================
// Cross-cutting properties
// ============================================================================

// Property: TailNode is deterministic — calling twice with the same input
// yields identical results.
func TestRapid_TailNode_Deterministic(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		inp := genTailNodeInput().Draw(t, "input")

		out1, err1 := callTailNode(inp)
		out2, err2 := callTailNode(inp)

		if (err1 != nil) != (err2 != nil) {
			t.Fatalf("non-deterministic error: %v vs %v", err1, err2)
		}
		if err1 != nil {
			return
		}

		// Check all identity fields
		if out1.ID != out2.ID {
			t.Fatalf("ID non-deterministic: %d vs %d", out1.ID, out2.ID)
		}
		if out1.StableID != out2.StableID {
			t.Fatalf("StableID non-deterministic: %q vs %q", out1.StableID, out2.StableID)
		}
		if out1.Name != out2.Name {
			t.Fatalf("Name non-deterministic: %q vs %q", out1.Name, out2.Name)
		}
		if out1.User != out2.User {
			t.Fatalf("User non-deterministic: %d vs %d", out1.User, out2.User)
		}
		if out1.Key != out2.Key {
			t.Fatalf("Key non-deterministic")
		}
		if !slices.Equal(out1.AllowedIPs, out2.AllowedIPs) {
			t.Fatalf("AllowedIPs non-deterministic")
		}
		if out1.Expired != out2.Expired {
			t.Fatalf("Expired non-deterministic")
		}
		if out1.MachineAuthorized != out2.MachineAuthorized {
			t.Fatalf("MachineAuthorized non-deterministic")
		}
	})
}

// Property: Cap version is passed through unchanged.
func TestRapid_TailNode_CapVersionPassthrough(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		inp := genTailNodeInput().Draw(t, "input")
		out, err := callTailNode(inp)
		if err != nil {
			t.Fatalf("TailNode error: %v", err)
		}

		if out.Cap != inp.CapVer {
			t.Fatalf("Cap mismatch: got %d, want %d", out.Cap, inp.CapVer)
		}
	})
}

// Property: Tags in the output match the input node's tags.
func TestRapid_TailNode_TagsPreserved(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		inp := genTailNodeInput().Draw(t, "input")
		out, err := callTailNode(inp)
		if err != nil {
			t.Fatalf("TailNode error: %v", err)
		}

		if !slices.Equal(out.Tags, inp.Node.Tags) {
			t.Fatalf("Tags mismatch:\n  got:  %v\n  want: %v",
				out.Tags, inp.Node.Tags)
		}
	})
}

// Property: PrimaryRoutes in the output match the route function's return.
func TestRapid_TailNode_PrimaryRoutesPreserved(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		inp := genTailNodeInput().Draw(t, "input")
		out, err := callTailNode(inp)
		if err != nil {
			t.Fatalf("TailNode error: %v", err)
		}

		// TailNode filters exit routes from PrimaryRoutes (for HA tracking).
		var expectedPrimary []netip.Prefix
		for _, r := range inp.PrimaryRoutes {
			if !tsaddr.IsExitRoute(r) {
				expectedPrimary = append(expectedPrimary, r)
			}
		}

		if !slices.Equal(out.PrimaryRoutes, expectedPrimary) {
			t.Fatalf("PrimaryRoutes mismatch:\n  got:  %v\n  want: %v",
				out.PrimaryRoutes, expectedPrimary)
		}
	})
}

// Property: Online field is a clone of input, not a shared pointer.
func TestRapid_TailNode_OnlineIsCloned(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		inp := genTailNodeInput().Draw(t, "input")
		out, err := callTailNode(inp)
		if err != nil {
			t.Fatalf("TailNode error: %v", err)
		}

		if inp.Node.IsOnline != nil && out.Online != nil {
			// Must be value-equal
			if *inp.Node.IsOnline != *out.Online {
				t.Fatalf("Online value mismatch: input=%v output=%v",
					*inp.Node.IsOnline, *out.Online)
			}
			// Must NOT be the same pointer (clone semantics)
			if inp.Node.IsOnline == out.Online {
				t.Fatal("Online pointer is shared, should be a clone")
			}
		}

		if inp.Node.IsOnline == nil && out.Online != nil {
			t.Fatal("Online should be nil when input IsOnline is nil")
		}
	})
}

// Property: KeyExpiry is UTC.
func TestRapid_TailNode_KeyExpiryUTC(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		inp := genTailNodeInput().Draw(t, "input")
		out, err := callTailNode(inp)
		if err != nil {
			t.Fatalf("TailNode error: %v", err)
		}

		if out.KeyExpiry.Location() != time.UTC {
			t.Fatalf("KeyExpiry not UTC: %v", out.KeyExpiry.Location())
		}
	})
}
