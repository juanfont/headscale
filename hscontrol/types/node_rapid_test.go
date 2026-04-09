package types

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"pgregory.net/rapid"
	"tailscale.com/net/tsaddr"
	"tailscale.com/tailcfg"
)

// ============================================================================
// Generators
// ============================================================================

// genAddrPort generates a random netip.AddrPort with an IPv4 or IPv6 address.
func genAddrPort() *rapid.Generator[netip.AddrPort] {
	return rapid.Custom[netip.AddrPort](func(t *rapid.T) netip.AddrPort {
		isV6 := rapid.Bool().Draw(t, "isV6")
		port := rapid.Uint16().Draw(t, "port")

		var addr netip.Addr

		if isV6 {
			var b [16]byte
			for i := range b {
				b[i] = byte(rapid.IntRange(0, 255).Draw(t, "byte"))
			}

			addr = netip.AddrFrom16(b)
		} else {
			var b [4]byte
			for i := range b {
				b[i] = byte(rapid.IntRange(0, 255).Draw(t, "byte"))
			}

			addr = netip.AddrFrom4(b)
		}

		return netip.AddrPortFrom(addr, port)
	})
}

// genEndpointSlice generates a slice of 0..maxLen AddrPorts.
func genEndpointSlice(maxLen int) *rapid.Generator[[]netip.AddrPort] {
	return rapid.SliceOfN(genAddrPort(), 0, maxLen)
}

// genIPv4Addr generates a random IPv4 address.
func genIPv4Addr() *rapid.Generator[netip.Addr] {
	return rapid.Custom[netip.Addr](func(t *rapid.T) netip.Addr {
		var b [4]byte
		for i := range b {
			b[i] = byte(rapid.IntRange(0, 255).Draw(t, "byte"))
		}

		return netip.AddrFrom4(b)
	})
}

// genIPv6Addr generates a random IPv6 address.
func genIPv6Addr() *rapid.Generator[netip.Addr] {
	return rapid.Custom[netip.Addr](func(t *rapid.T) netip.Addr {
		var b [16]byte
		for i := range b {
			b[i] = byte(rapid.IntRange(0, 255).Draw(t, "byte"))
		}

		return netip.AddrFrom16(b)
	})
}

// genSubnetPrefix generates a random prefix including /0 (exit routes).
// When bits==0, .Masked() produces 0.0.0.0/0 or ::/0 (exit routes).
// SubnetRoutes() is expected to filter these out, so tests that assert
// "no exit routes in SubnetRoutes" should still pass.
func genSubnetPrefix() *rapid.Generator[netip.Prefix] {
	return rapid.Custom[netip.Prefix](func(t *rapid.T) netip.Prefix {
		isV6 := rapid.Bool().Draw(t, "isV6")
		if isV6 {
			bits := rapid.IntRange(0, 128).Draw(t, "bits")
			addr := genIPv6Addr().Draw(t, "addr")

			return netip.PrefixFrom(addr, bits).Masked()
		}

		bits := rapid.IntRange(0, 32).Draw(t, "bits")
		addr := genIPv4Addr().Draw(t, "addr")

		return netip.PrefixFrom(addr, bits).Masked()
	})
}

// genTag generates a tag string in the form "tag:name".
func genTag() *rapid.Generator[string] {
	return rapid.Custom[string](func(t *rapid.T) string {
		name := rapid.StringMatching(`[a-z][a-z0-9]{0,15}`).Draw(t, "tagname")
		return "tag:" + name
	})
}

// genTags generates a slice of 0..maxLen unique tags.
func genTags(maxLen int) *rapid.Generator[[]string] {
	return rapid.Custom[[]string](func(t *rapid.T) []string {
		n := rapid.IntRange(0, maxLen).Draw(t, "numTags")
		seen := make(map[string]bool, n)

		result := make([]string, 0, n)
		for len(result) < n {
			tag := genTag().Draw(t, "tag")
			if !seen[tag] {
				seen[tag] = true
				result = append(result, tag)
			}
		}

		return result
	})
}

// genNodeWithIPs generates a Node with optional IPv4 and IPv6 addresses.
func genNodeWithIPs() *rapid.Generator[*Node] {
	return rapid.Custom[*Node](func(t *rapid.T) *Node {
		node := &Node{}
		hasV4 := rapid.Bool().Draw(t, "hasV4")
		hasV6 := rapid.Bool().Draw(t, "hasV6")

		if hasV4 {
			v4 := genIPv4Addr().Draw(t, "ipv4")
			node.IPv4 = &v4
		}

		if hasV6 {
			v6 := genIPv6Addr().Draw(t, "ipv6")
			node.IPv6 = &v6
		}

		return node
	})
}

// ============================================================================
// EndpointsChanged properties
// ============================================================================

// Property: EndpointsChanged(a, a) == false for any slice a.
func TestRapid_EndpointsChanged_Reflexive(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		endpoints := genEndpointSlice(10).Draw(t, "endpoints")

		if EndpointsChanged(endpoints, endpoints) {
			t.Fatalf("EndpointsChanged(x, x) = true for %v", endpoints)
		}
	})
}

// Property: EndpointsChanged(a, b) == EndpointsChanged(b, a).
func TestRapid_EndpointsChanged_Commutative(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		a := genEndpointSlice(8).Draw(t, "a")
		b := genEndpointSlice(8).Draw(t, "b")

		ab := EndpointsChanged(a, b)
		ba := EndpointsChanged(b, a)

		if ab != ba {
			t.Fatalf("EndpointsChanged not commutative: (%v, %v) = %v, reversed = %v",
				a, b, ab, ba)
		}
	})
}

// Property: EndpointsChanged(a, shuffle(a)) == false — permutations don't matter.
func TestRapid_EndpointsChanged_OrderIndependent(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		endpoints := genEndpointSlice(10).Draw(t, "endpoints")
		if len(endpoints) < 2 {
			return
		}

		// Create a shuffled copy by reversing
		shuffled := make([]netip.AddrPort, len(endpoints))
		copy(shuffled, endpoints)
		slices.Reverse(shuffled)

		if EndpointsChanged(endpoints, shuffled) {
			t.Fatalf("EndpointsChanged reports change for shuffled slice: %v vs %v",
				endpoints, shuffled)
		}
	})
}

// Property: Adding an element to a slice is always detected as a change.
func TestRapid_EndpointsChanged_DetectsAddition(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		endpoints := genEndpointSlice(8).Draw(t, "endpoints")
		extra := genAddrPort().Draw(t, "extra")

		longer := append(slices.Clone(endpoints), extra)

		if !EndpointsChanged(endpoints, longer) {
			t.Fatalf("EndpointsChanged should detect addition: %v vs %v",
				endpoints, longer)
		}
	})
}

// Property: EndpointsChanged(x, nil) == EndpointsChanged(x, []netip.AddrPort{})
// nil and empty slices should be treated identically.
func TestRapid_EndpointsChanged_NilEqualsEmpty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		endpoints := genEndpointSlice(8).Draw(t, "endpoints")

		withNil := EndpointsChanged(endpoints, nil)
		withEmpty := EndpointsChanged(endpoints, []netip.AddrPort{})

		if withNil != withEmpty {
			t.Fatalf("EndpointsChanged(x, nil) = %v but EndpointsChanged(x, []) = %v for x=%v",
				withNil, withEmpty, endpoints)
		}
	})
}

// ============================================================================
// Node.Prefixes properties
// ============================================================================

// Property: Prefixes returns /32 for IPv4 and /128 for IPv6 — always host prefixes.
func TestRapid_Prefixes_HostPrefixes(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		node := genNodeWithIPs().Draw(t, "node")

		prefixes := node.Prefixes()
		ips := node.IPs()

		for i, pfx := range prefixes {
			if pfx.Addr() != ips[i] {
				t.Fatalf("Prefixes()[%d] addr = %s, want %s", i, pfx.Addr(), ips[i])
			}

			expectedBits := ips[i].BitLen()
			if pfx.Bits() != expectedBits {
				t.Fatalf("Prefixes()[%d] bits = %d, want %d (host prefix)",
					i, pfx.Bits(), expectedBits)
			}
		}
	})
}

// Property: len(Prefixes()) == count of non-nil IPs (IPv4 + IPv6).
func TestRapid_Prefixes_CountMatchesIPs(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		node := genNodeWithIPs().Draw(t, "node")

		prefixes := node.Prefixes()
		ips := node.IPs()

		// Both nil means no IPs
		if len(ips) == 0 {
			if prefixes != nil {
				t.Fatalf("Prefixes() = %v for node with no IPs, want nil", prefixes)
			}

			return
		}

		if len(prefixes) != len(ips) {
			t.Fatalf("len(Prefixes()) = %d, want %d (matching IPs count)",
				len(prefixes), len(ips))
		}
	})
}

// ============================================================================
// Node.SubnetRoutes properties
// ============================================================================

// Property: SubnetRoutes never contains 0.0.0.0/0 or ::/0.
func TestRapid_SubnetRoutes_NoExitRoutes(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		nRoutes := rapid.IntRange(0, 8).Draw(t, "nRoutes")

		announced := make([]netip.Prefix, nRoutes)
		for i := range announced {
			// Mix in some exit routes and some subnet routes
			if rapid.Bool().Draw(t, "isExit") {
				if rapid.Bool().Draw(t, "isV4Exit") {
					announced[i] = tsaddr.AllIPv4()
				} else {
					announced[i] = tsaddr.AllIPv6()
				}
			} else {
				announced[i] = genSubnetPrefix().Draw(t, "route")
			}
		}

		node := &Node{
			Hostinfo:       &tailcfg.Hostinfo{RoutableIPs: announced},
			ApprovedRoutes: slices.Clone(announced), // approve all
		}

		subnets := node.SubnetRoutes()
		for _, route := range subnets {
			if tsaddr.IsExitRoute(route) {
				t.Fatalf("SubnetRoutes() contains exit route %s", route)
			}
		}
	})
}

// Property: Every subnet route is in ApprovedRoutes (and AnnouncedRoutes).
// The approved list is constructed with controlled overlap with announced
// to guarantee the intersection is non-trivially exercised.
func TestRapid_SubnetRoutes_SubsetOfApproved(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		// Generate announced routes (non-exit only).
		nAnnounced := rapid.IntRange(1, 6).Draw(t, "nAnnounced")

		announced := make([]netip.Prefix, nAnnounced)
		for i := range announced {
			announced[i] = genSubnetPrefix().Draw(t, "announced")
		}

		// Build approved with controlled overlap:
		// 1. Pick a random subset of announced to include (the intersection).
		// 2. Add some extra prefixes not in announced (to test filtering).
		nFromAnnounced := rapid.IntRange(0, nAnnounced).Draw(t, "nFromAnnounced")
		nExtra := rapid.IntRange(0, 4).Draw(t, "nExtra")

		approved := make([]netip.Prefix, 0, nFromAnnounced+nExtra)
		// Draw indices from announced to include
		for i := range nFromAnnounced {
			idx := rapid.IntRange(0, nAnnounced-1).Draw(t, fmt.Sprintf("approvedIdx%d", i))
			approved = append(approved, announced[idx])
		}
		// Add extra random prefixes
		for i := range nExtra {
			approved = append(approved, genSubnetPrefix().Draw(t, fmt.Sprintf("extraApproved%d", i)))
		}

		node := &Node{
			Hostinfo:       &tailcfg.Hostinfo{RoutableIPs: announced},
			ApprovedRoutes: approved,
		}

		subnets := node.SubnetRoutes()

		// Property: every returned route must be in both announced and approved.
		for _, route := range subnets {
			if !slices.Contains(announced, route) {
				t.Fatalf("SubnetRoutes() contains %s not in announced", route)
			}

			if !slices.Contains(approved, route) {
				t.Fatalf("SubnetRoutes() contains %s not in approved", route)
			}
		}

		// Compute expected intersection: non-exit announced that are also approved.
		expectedCount := 0

		for _, a := range announced {
			if tsaddr.IsExitRoute(a) {
				continue
			}

			if slices.Contains(approved, a) {
				expectedCount++
			}
		}

		if len(subnets) != expectedCount {
			t.Fatalf("SubnetRoutes() returned %d routes, want %d (intersection of announced and approved)\nannounced=%v\napproved=%v\nsubnets=%v",
				len(subnets), expectedCount, announced, approved, subnets)
		}
	})
}

// Property: SubnetRoutes is exactly the intersection of non-exit announced
// routes and approved routes, verified by constructing known overlapping sets.
// Uses unique prefixes to avoid ambiguity from duplicates.
func TestRapid_SubnetRoutes_IntersectionCorrectness(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		// Generate a pool of unique subnet prefixes.
		poolSize := rapid.IntRange(3, 8).Draw(t, "poolSize")
		pool := make([]netip.Prefix, 0, poolSize)
		seen := make(map[netip.Prefix]bool)

		for len(pool) < poolSize {
			pfx := genSubnetPrefix().Draw(t, fmt.Sprintf("pool%d", len(pool)))
			if !seen[pfx] {
				seen[pfx] = true
				pool = append(pool, pfx)
			}
		}

		// Partition pool indices into: shared, announced-only, approved-only.
		announced := make([]netip.Prefix, 0)
		approved := make([]netip.Prefix, 0)

		var expectedIntersection []netip.Prefix

		for i, pfx := range pool {
			choice := rapid.IntRange(0, 3).Draw(t, fmt.Sprintf("partition%d", i))
			switch choice {
			case 0: // shared — in both
				announced = append(announced, pfx)
				approved = append(approved, pfx)
				expectedIntersection = append(expectedIntersection, pfx)
			case 1: // announced-only
				announced = append(announced, pfx)
			case 2: // approved-only
				approved = append(approved, pfx)
			default: // in neither
			}
		}

		// Optionally add exit routes to announced+approved to test filtering.
		if rapid.Bool().Draw(t, "addExitRoutes") {
			announced = append(announced, tsaddr.AllIPv4())
			approved = append(approved, tsaddr.AllIPv4())
			// Exit routes must NOT appear in SubnetRoutes.
		}

		// Filter exit routes from expectedIntersection since
		// SubnetRoutes excludes them. genSubnetPrefix with bits=0
		// can produce exit routes via .Masked().
		var filteredExpected []netip.Prefix

		for _, pfx := range expectedIntersection {
			if !tsaddr.IsExitRoute(pfx) {
				filteredExpected = append(filteredExpected, pfx)
			}
		}

		expectedIntersection = filteredExpected

		node := &Node{
			Hostinfo:       &tailcfg.Hostinfo{RoutableIPs: announced},
			ApprovedRoutes: approved,
		}

		subnets := node.SubnetRoutes()

		// Verify: subnets must contain exactly expectedIntersection (same elements, order may differ).
		if len(subnets) != len(expectedIntersection) {
			t.Fatalf("SubnetRoutes() returned %d routes, want %d\nannounced=%v\napproved=%v\nsubnets=%v\nexpected=%v",
				len(subnets), len(expectedIntersection), announced, approved, subnets, expectedIntersection)
		}

		for _, expected := range expectedIntersection {
			if !slices.Contains(subnets, expected) {
				t.Fatalf("SubnetRoutes() missing expected route %s\nannounced=%v\napproved=%v\nsubnets=%v",
					expected, announced, approved, subnets)
			}
		}

		// No exit routes in output.
		for _, route := range subnets {
			if tsaddr.IsExitRoute(route) {
				t.Fatalf("SubnetRoutes() contains exit route %s", route)
			}
		}
	})
}

// ============================================================================
// Node.ExitRoutes properties
// ============================================================================

// Property: Every exit route passes tsaddr.IsExitRoute.
func TestRapid_ExitRoutes_OnlyExitRoutes(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		nRoutes := rapid.IntRange(0, 6).Draw(t, "nRoutes")

		announced := make([]netip.Prefix, nRoutes)
		for i := range announced {
			if rapid.Bool().Draw(t, "isExit") {
				if rapid.Bool().Draw(t, "isV4Exit") {
					announced[i] = tsaddr.AllIPv4()
				} else {
					announced[i] = tsaddr.AllIPv6()
				}
			} else {
				announced[i] = genSubnetPrefix().Draw(t, "route")
			}
		}

		node := &Node{
			Hostinfo:       &tailcfg.Hostinfo{RoutableIPs: announced},
			ApprovedRoutes: slices.Clone(announced),
		}

		exitRoutes := node.ExitRoutes()
		for _, route := range exitRoutes {
			if !tsaddr.IsExitRoute(route) {
				t.Fatalf("ExitRoutes() contains non-exit route %s", route)
			}
		}
	})
}

// Property: Every exit route is in ApprovedRoutes.
func TestRapid_ExitRoutes_SubsetOfApproved(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		nRoutes := rapid.IntRange(0, 6).Draw(t, "nRoutes")

		announced := make([]netip.Prefix, nRoutes)
		for i := range announced {
			if rapid.Bool().Draw(t, "isExit") {
				if rapid.Bool().Draw(t, "isV4Exit") {
					announced[i] = tsaddr.AllIPv4()
				} else {
					announced[i] = tsaddr.AllIPv6()
				}
			} else {
				announced[i] = genSubnetPrefix().Draw(t, "route")
			}
		}

		// Only approve a random subset of announced routes
		nApproved := rapid.IntRange(0, len(announced)).Draw(t, "nApproved")

		approved := make([]netip.Prefix, nApproved)
		for i := range approved {
			idx := rapid.IntRange(0, len(announced)-1).Draw(t, "approvedIdx")
			approved[i] = announced[idx]
		}

		node := &Node{
			Hostinfo:       &tailcfg.Hostinfo{RoutableIPs: announced},
			ApprovedRoutes: approved,
		}

		exitRoutes := node.ExitRoutes()
		for _, route := range exitRoutes {
			if !slices.Contains(approved, route) {
				t.Fatalf("ExitRoutes() contains %s which is not in ApprovedRoutes %v",
					route, approved)
			}
		}
	})
}

// Property: ExitRoutes ∪ SubnetRoutes covers all approved+announced routes.
// Every approved+announced route appears in either ExitRoutes or SubnetRoutes.
func TestRapid_Routes_ExitAndSubnetPartition(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		nRoutes := rapid.IntRange(0, 8).Draw(t, "nRoutes")

		announced := make([]netip.Prefix, nRoutes)
		for i := range announced {
			if rapid.Bool().Draw(t, "isExit") {
				if rapid.Bool().Draw(t, "isV4Exit") {
					announced[i] = tsaddr.AllIPv4()
				} else {
					announced[i] = tsaddr.AllIPv6()
				}
			} else {
				announced[i] = genSubnetPrefix().Draw(t, "route")
			}
		}

		node := &Node{
			Hostinfo:       &tailcfg.Hostinfo{RoutableIPs: announced},
			ApprovedRoutes: slices.Clone(announced),
		}

		exitRoutes := node.ExitRoutes()
		subnetRoutes := node.SubnetRoutes()

		for _, route := range announced {
			if !slices.Contains(node.ApprovedRoutes, route) {
				continue
			}

			inExit := slices.Contains(exitRoutes, route)

			inSubnet := slices.Contains(subnetRoutes, route)
			if !inExit && !inSubnet {
				t.Fatalf("route %s is approved+announced but in neither ExitRoutes nor SubnetRoutes", route)
			}
		}
	})
}

// ============================================================================
// Node.IsTagged properties
// ============================================================================

// Property: IsTagged() == (len(Tags) > 0).
func TestRapid_IsTagged_EquivNonEmptyTags(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		tags := genTags(5).Draw(t, "tags")
		node := &Node{Tags: tags}

		expected := len(tags) > 0
		if node.IsTagged() != expected {
			t.Fatalf("IsTagged() = %v for tags %v, want %v",
				node.IsTagged(), tags, expected)
		}
	})
}

// Property: Tagged nodes are not user-owned and vice versa (XOR).
func TestRapid_IsTagged_XorUserOwned(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		tags := genTags(5).Draw(t, "tags")
		node := &Node{Tags: tags}

		if node.IsTagged() && node.IsUserOwned() {
			t.Fatalf("node with tags %v is both tagged and user-owned", tags)
		}

		if !node.IsTagged() && !node.IsUserOwned() {
			t.Fatal("node is neither tagged nor user-owned")
		}
	})
}

// Property: A node with BOTH Tags and UserID set is still tagged, not user-owned.
// This is valid per tags-as-identity: UserID on tagged nodes is "created by" tracking.
func TestRapid_IsTagged_WithUserID_StillTagged(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		// Generate at least one tag.
		tags := genTags(5).Draw(t, "tags")
		if len(tags) == 0 {
			tags = []string{"tag:server"}
		}

		uid := uint(rapid.IntRange(1, 10000).Draw(t, "userID")) //nolint:gosec // positive bounded value
		node := &Node{
			Tags:   tags,
			UserID: &uid,
		}

		if !node.IsTagged() {
			t.Fatalf("node with Tags=%v and UserID=%d: IsTagged() = false, want true",
				tags, uid)
		}

		if node.IsUserOwned() {
			t.Fatalf("node with Tags=%v and UserID=%d: IsUserOwned() = true, want false (tags define ownership)",
				tags, uid)
		}
	})
}

// Property: HasTag(x) implies IsTagged().
func TestRapid_IsTagged_HasTagImpliesIsTagged(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		tags := genTags(5).Draw(t, "tags")
		node := &Node{Tags: tags}
		tag := genTag().Draw(t, "queryTag")

		if node.HasTag(tag) && !node.IsTagged() {
			t.Fatalf("HasTag(%q) = true but IsTagged() = false", tag)
		}
	})
}

// ============================================================================
// TailscaleUserID properties (NodeView)
// ============================================================================

// Property: Tagged nodes always return TaggedDevices constant (2147455555).
func TestRapid_TailscaleUserID_Tagged(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		tags := genTags(5).Draw(t, "tags")
		if len(tags) == 0 {
			tags = []string{"tag:test"}
		}

		uid := uint(rapid.IntRange(1, 1000).Draw(t, "userID")) //nolint:gosec // positive bounded value
		node := &Node{
			Tags:   tags,
			UserID: &uid,
		}
		nv := node.View()

		expected := tailcfg.UserID(int64(TaggedDevicesUserID)) //nolint:gosec // constant value

		got := nv.TailscaleUserID()
		if got != expected {
			t.Fatalf("TailscaleUserID() = %d for tagged node, want %d (TaggedDevices)",
				got, expected)
		}
	})
}

// Property: User-owned nodes return their actual UserID.
func TestRapid_TailscaleUserID_UserOwned(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		uid := uint(rapid.IntRange(1, 1000).Draw(t, "userID")) //nolint:gosec // positive bounded value
		node := &Node{
			Tags:   nil, // user-owned
			UserID: &uid,
		}
		nv := node.View()

		expected := tailcfg.UserID(int64(uid)) //nolint:gosec // positive bounded value

		got := nv.TailscaleUserID()
		if got != expected {
			t.Fatalf("TailscaleUserID() = %d for user-owned node, want %d",
				got, expected)
		}
	})
}

// Property: TailscaleUserID for tagged nodes is constant regardless of UserID value.
func TestRapid_TailscaleUserID_TaggedConstant(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		uid1 := uint(rapid.IntRange(1, 1000).Draw(t, "uid1")) //nolint:gosec // positive bounded value
		uid2 := uint(rapid.IntRange(1, 1000).Draw(t, "uid2")) //nolint:gosec // positive bounded value
		tags := []string{"tag:server"}

		nv1 := (&Node{Tags: tags, UserID: &uid1}).View()
		nv2 := (&Node{Tags: tags, UserID: &uid2}).View()

		if nv1.TailscaleUserID() != nv2.TailscaleUserID() {
			t.Fatalf("tagged nodes with different UserIDs should have same TailscaleUserID: %d vs %d",
				nv1.TailscaleUserID(), nv2.TailscaleUserID())
		}
	})
}

// ============================================================================
// BUG HUNT: TailscaleUserID on orphaned node (no tags AND no UserID)
// ============================================================================

// BUG HUNT: TailscaleUserID on a node with no tags AND no UserID.
// This is an "orphaned" state that should not exist but could due to bugs.
// UserID().Get() will panic if UserID is nil and node is not tagged.
func TestRapid_TailscaleUserID_OrphanedNodePanic(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		// Generate a node with no tags and no UserID — an "orphaned" state
		// that violates the tags-XOR-user invariant.
		node := &Node{
			Tags:   nil,
			UserID: nil,
		}
		nv := node.View()

		// Use recover to catch panics — this documents the crash.
		var panicVal any

		func() {
			defer func() {
				panicVal = recover()
			}()

			_ = nv.TailscaleUserID()
		}()

		if panicVal != nil {
			t.Fatalf("BUG: TailscaleUserID() panicked on orphaned node (Tags=nil, UserID=nil): %v", panicVal)
		}

		// BUG: TailscaleUserID() returns UserID(0) silently for orphaned nodes.
		// UserID 0 could collide with a real user ID or cause incorrect behavior.
		// A non-tagged node with nil UserID is an invalid state that should
		// be caught, not silently produce a zero value.
		got := nv.TailscaleUserID()
		t.Fatalf("BUG: TailscaleUserID() on orphaned node (Tags=nil, UserID=nil) "+
			"returned %d silently instead of panicking or returning an error — "+
			"this invalid state should not produce a usable UserID", got)
	})
}

// ============================================================================
// BUG HUNT: Owner().Name() on node with nil User and nil Tags
// ============================================================================

// BUG HUNT: Owner().Name() chains through UserView.Name() which dereferences
// a nil pointer when the node has User=nil and Tags=nil.
// Owner() returns nv.User() which is UserView{ж: nil}, and Name()
// accesses ж.Name — a nil pointer dereference.
func TestRapid_OwnerName_NilUserNilTagsPanic(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		// Generate random node IDs/hostnames but always nil User and nil Tags.
		hostname := rapid.StringMatching(`[a-z][a-z0-9]{1,10}`).Draw(t, "hostname")
		node := &Node{
			Hostname: hostname,
			Tags:     nil,
			User:     nil,
			UserID:   nil,
		}
		nv := node.View()

		// Owner() on a non-tagged node with nil User returns UserView{ж: nil}.
		// Calling Name() on that should panic with nil pointer dereference.
		var panicVal any

		func() {
			defer func() {
				panicVal = recover()
			}()

			owner := nv.Owner()
			_ = owner.Name()
		}()

		// BUG: Owner().Name() panics on orphaned nodes (User=nil, Tags=nil).
		// This is a nil pointer dereference through UserView.Name().
		if panicVal != nil {
			t.Fatalf("BUG: Owner().Name() panics on orphaned node "+
				"(User=nil, Tags=nil, hostname=%q): %v — "+
				"callers must check Owner().Valid() first",
				hostname, panicVal)
		}

		// If no panic (e.g. if a guard was added), the result should be empty.
		owner := nv.Owner()
		if !owner.Valid() {
			return // acceptable: invalid owner
		}

		_ = owner.Name() // safe to call since owner is valid
	})
}

// ============================================================================
// HasNetworkChanges reflexivity
// ============================================================================

// Property: node.View().HasNetworkChanges(node.View()) should always be false.
// A node compared to itself should never report network changes.
func TestRapid_HasNetworkChanges_Reflexive(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		node := genNodeWithIPs().Draw(t, "node")

		// Add some routes to make the test more interesting
		nRoutes := rapid.IntRange(0, 4).Draw(t, "nRoutes")

		announced := make([]netip.Prefix, nRoutes)
		for i := range announced {
			announced[i] = genSubnetPrefix().Draw(t, "route")
		}

		node.Hostinfo = &tailcfg.Hostinfo{RoutableIPs: announced}
		node.ApprovedRoutes = slices.Clone(announced)

		nv := node.View()

		if nv.HasNetworkChanges(nv) {
			t.Fatalf("HasNetworkChanges(self) = true for node with IPs=%v, AnnouncedRoutes=%v",
				node.IPs(), node.AnnouncedRoutes())
		}
	})
}

// ============================================================================
// HasPolicyChange reflexivity
// ============================================================================

// Property: node.View().HasPolicyChange(node.View()) should always be false.
// A node compared to itself should never report policy changes.
func TestRapid_HasPolicyChange_Reflexive(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		node := genNodeWithIPs().Draw(t, "node")

		// Add tags or userID for richer test coverage
		tags := genTags(4).Draw(t, "tags")

		node.Tags = tags
		if len(tags) == 0 {
			uid := uint(rapid.IntRange(1, 10000).Draw(t, "userID")) //nolint:gosec // positive bounded value
			node.UserID = &uid
		}

		nv := node.View()

		if nv.HasPolicyChange(nv) {
			t.Fatalf("HasPolicyChange(self) = true for node with Tags=%v, UserID=%v, IPs=%v",
				node.Tags, node.UserID, node.IPs())
		}
	})
}

// ============================================================================
// GetFQDN properties
// ============================================================================

// Property: Empty GivenName always returns an error.
func TestRapid_GetFQDN_EmptyGivenNameErrors(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		baseDomain := rapid.StringMatching(`[a-z]{2,8}\.[a-z]{2,4}`).Draw(t, "baseDomain")
		node := &Node{GivenName: ""}

		_, err := node.GetFQDN(baseDomain)
		if err == nil {
			t.Fatal("GetFQDN with empty GivenName should return error")
		}
	})
}

// Property: Empty baseDomain returns just the GivenName (no trailing dot).
func TestRapid_GetFQDN_EmptyBaseDomainReturnsGivenName(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		givenName := genGivenName().Draw(t, "givenName")
		node := &Node{GivenName: givenName}

		fqdn, err := node.GetFQDN("")
		if err != nil {
			t.Fatalf("GetFQDN with empty baseDomain should not error: %v", err)
		}

		if fqdn != givenName {
			t.Fatalf("GetFQDN(\"\") = %q, want %q", fqdn, givenName)
		}
	})
}

// Property: Result with non-empty baseDomain always ends with ".".
func TestRapid_GetFQDN_WithBaseDomainEndsWithDot(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		givenName := genGivenName().Draw(t, "givenName")
		baseDomain := genBaseDomain().Draw(t, "baseDomain")
		node := &Node{GivenName: givenName}

		fqdn, err := node.GetFQDN(baseDomain)
		if err != nil {
			t.Fatalf("GetFQDN error: %v", err)
		}

		if !strings.HasSuffix(fqdn, ".") {
			t.Fatalf("GetFQDN(%q) = %q, should end with '.'", baseDomain, fqdn)
		}
	})
}

// Property: Result length never exceeds 255 (MaxHostnameLength).
// If it would, GetFQDN returns an error.
func TestRapid_GetFQDN_LengthNeverExceeds255(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		// Use potentially long names to exercise the length check
		givenName := rapid.StringMatching(`[a-z][a-z0-9]{0,62}`).Draw(t, "givenName")
		baseDomain := rapid.StringMatching(`[a-z]{0,200}\.[a-z]{2,4}`).Draw(t, "baseDomain")
		node := &Node{GivenName: givenName}

		fqdn, err := node.GetFQDN(baseDomain)
		if err != nil {
			// Error is acceptable — means it would have exceeded 255
			return
		}

		if len(fqdn) > MaxHostnameLength {
			t.Fatalf("GetFQDN returned %d-char hostname (max %d): %q",
				len(fqdn), MaxHostnameLength, fqdn)
		}
	})
}

// ============================================================================
// PeerChangeFromMapRequest roundtrip
// ============================================================================

// Property: PeerChangeFromMapRequest + ApplyPeerChange roundtrip preserves
// endpoints, DERP region, and node key from the MapRequest.
func TestRapid_PeerChangeFromMapRequest_Roundtrip(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		// Build a node with initial state
		nodeKeys := newKeys()
		reqKeys := newKeys()

		endpoints := genEndpointSlice(5).Draw(t, "endpoints")
		newEndpoints := genEndpointSlice(5).Draw(t, "newEndpoints")
		derpRegion := rapid.IntRange(1, 100).Draw(t, "derpRegion")
		newDerpRegion := rapid.IntRange(1, 100).Draw(t, "newDerpRegion")

		node := &Node{
			ID:        NodeID(rapid.Uint64Range(1, 10000).Draw(t, "nodeID")),
			NodeKey:   nodeKeys.Node,
			DiscoKey:  nodeKeys.Disco,
			Endpoints: endpoints,
			Hostinfo: &tailcfg.Hostinfo{
				NetInfo: &tailcfg.NetInfo{
					PreferredDERP: derpRegion,
				},
			},
		}

		req := tailcfg.MapRequest{
			NodeKey:   reqKeys.Node,
			DiscoKey:  reqKeys.Disco,
			Endpoints: newEndpoints,
			Hostinfo: &tailcfg.Hostinfo{
				NetInfo: &tailcfg.NetInfo{
					PreferredDERP: newDerpRegion,
				},
			},
		}

		// Compute peer change
		change := node.PeerChangeFromMapRequest(req)

		// Apply peer change
		node.ApplyPeerChange(&change)

		// Verify endpoints match after apply (if they changed)
		if EndpointsChanged(endpoints, newEndpoints) {
			if !slices.Equal(node.Endpoints, newEndpoints) {
				t.Fatalf("After roundtrip, endpoints = %v, want %v",
					node.Endpoints, newEndpoints)
			}
		}

		// Verify DERP region matches
		if derpRegion != newDerpRegion {
			if node.Hostinfo == nil || node.Hostinfo.NetInfo == nil {
				t.Fatal("After roundtrip, Hostinfo or NetInfo is nil")
			}

			if node.Hostinfo.NetInfo.PreferredDERP != newDerpRegion {
				t.Fatalf("After roundtrip, DERPRegion = %d, want %d",
					node.Hostinfo.NetInfo.PreferredDERP, newDerpRegion)
			}
		}

		// Verify NodeKey matches
		if nodeKeys.Node.String() != reqKeys.Node.String() {
			if node.NodeKey != reqKeys.Node {
				t.Fatalf("After roundtrip, NodeKey = %v, want %v",
					node.NodeKey, reqKeys.Node)
			}
		}

		// Verify DiscoKey matches
		if nodeKeys.Disco.String() != reqKeys.Disco.String() {
			if node.DiscoKey != reqKeys.Disco {
				t.Fatalf("After roundtrip, DiscoKey = %v, want %v",
					node.DiscoKey, reqKeys.Disco)
			}
		}
	})
}

// Property: PeerChangeFromMapRequest with identical node produces
// a PeerChange with no key/disco/endpoint changes (only LastSeen).
func TestRapid_PeerChangeFromMapRequest_IdenticalNoChange(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		keys := newKeys()
		endpoints := genEndpointSlice(5).Draw(t, "endpoints")
		derpRegion := rapid.IntRange(1, 100).Draw(t, "derpRegion")

		node := &Node{
			ID:        NodeID(rapid.Uint64Range(1, 10000).Draw(t, "nodeID")),
			NodeKey:   keys.Node,
			DiscoKey:  keys.Disco,
			Endpoints: endpoints,
			Hostinfo: &tailcfg.Hostinfo{
				NetInfo: &tailcfg.NetInfo{
					PreferredDERP: derpRegion,
				},
			},
		}

		// MapRequest with same values
		req := tailcfg.MapRequest{
			NodeKey:   keys.Node,
			DiscoKey:  keys.Disco,
			Endpoints: slices.Clone(endpoints),
			Hostinfo: &tailcfg.Hostinfo{
				NetInfo: &tailcfg.NetInfo{
					PreferredDERP: derpRegion,
				},
			},
		}

		change := node.PeerChangeFromMapRequest(req)

		if change.Key != nil {
			t.Fatalf("PeerChange.Key should be nil for identical node, got %v", change.Key)
		}

		if change.DiscoKey != nil {
			t.Fatalf("PeerChange.DiscoKey should be nil for identical node, got %v", change.DiscoKey)
		}

		if change.Endpoints != nil {
			t.Fatalf("PeerChange.Endpoints should be nil for identical node, got %v", change.Endpoints)
		}
		// DERPRegion should be 0 (no change) when same
		if change.DERPRegion != 0 {
			t.Fatalf("PeerChange.DERPRegion should be 0 for identical node, got %d", change.DERPRegion)
		}
		// LastSeen should always be set
		if change.LastSeen == nil {
			t.Fatal("PeerChange.LastSeen should always be set")
		}
	})
}

// ============================================================================
// Nodes.FilterByIP properties
// ============================================================================

// genNodes generates a slice of 0..maxLen nodes with random IPs.
func genNodes(maxLen int) *rapid.Generator[Nodes] {
	return rapid.Custom[Nodes](func(t *rapid.T) Nodes {
		n := rapid.IntRange(0, maxLen).Draw(t, "numNodes")

		nodes := make(Nodes, n)
		for i := range nodes {
			nodes[i] = genNodeWithIPs().Draw(t, fmt.Sprintf("node%d", i))
		}

		return nodes
	})
}

// Property: FilterByIP result is always a subset of the input.
func TestRapid_FilterByIP_SubsetOfInput(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		nodes := genNodes(10).Draw(t, "nodes")
		ip := genIPv4Addr().Draw(t, "ip")

		result := nodes.FilterByIP(ip)

		for _, rn := range result {
			if !slices.Contains(nodes, rn) {
				t.Fatalf("FilterByIP returned node not in input: %v", rn)
			}
		}
	})
}

// Property: Every node in FilterByIP result has the target IP.
func TestRapid_FilterByIP_AllHaveIP(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		nodes := genNodes(10).Draw(t, "nodes")
		ip := genIPv4Addr().Draw(t, "ip")

		result := nodes.FilterByIP(ip)

		for _, node := range result {
			hasIP := (node.IPv4 != nil && *node.IPv4 == ip) ||
				(node.IPv6 != nil && *node.IPv6 == ip)
			if !hasIP {
				t.Fatalf("FilterByIP returned node without target IP %s: IPv4=%v, IPv6=%v",
					ip, node.IPv4, node.IPv6)
			}
		}
	})
}

// Property: Nodes with the target IP are never excluded (no false negatives).
func TestRapid_FilterByIP_NoFalseNegatives(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		nodes := genNodes(10).Draw(t, "nodes")
		ip := genIPv4Addr().Draw(t, "ip")

		result := nodes.FilterByIP(ip)

		// Count nodes in input that have the IP
		expectedCount := 0

		for _, node := range nodes {
			if (node.IPv4 != nil && *node.IPv4 == ip) ||
				(node.IPv6 != nil && *node.IPv6 == ip) {
				expectedCount++
			}
		}

		if len(result) != expectedCount {
			t.Fatalf("FilterByIP returned %d nodes, but %d nodes have IP %s",
				len(result), expectedCount, ip)
		}
	})
}
