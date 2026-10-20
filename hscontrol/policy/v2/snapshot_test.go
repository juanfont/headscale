package v2

import (
	"fmt"
	"net/netip"
	"runtime"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/ipset"
	"github.com/juanfont/headscale/hscontrol/policy/packetfilter"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
	"tailscale.com/types/ipproto"
	"tailscale.com/types/views"
	"tailscale.com/util/deephash"
)

func TestReadViewSSHRejectsForeignNodes(t *testing.T) {
	users := sshTestUsers()
	nodes := sshTestNodes(users)
	pm, err := NewPolicyManager([]byte(`{
		"tagOwners":{"tag:server":["alice@"]},
		"ssh":[{"action":"check","src":["alice@"],"dst":["tag:server"],"users":["root"]}]
	}`), users, nodes.ViewSlice())
	require.NoError(t, err)

	view := pm.ReadView()
	missing := nodes[2].Clone()
	missing.ID = 999
	stale := nodes[2].Clone()
	stale.Tags = []string{"tag:prod"}
	newAddress := nodes[2].Clone()
	newAddress.IPv4 = ap("100.64.0.99")

	for _, node := range []types.NodeView{{}, missing.View(), stale.View(), newAddress.View()} {
		wire, err := view.SSHPolicy("", node)
		require.Error(t, err)
		assert.Nil(t, wire)
	}

	_, err = (ReadView{}).SSHPolicy("", nodes[2].View())
	require.ErrorIs(t, err, errInvalidPolicyReadView)

	for _, ids := range [][2]types.NodeID{{999, 3}, {1, 999}} {
		_, ok := view.SSHCheckParams(ids[0], ids[1], "root")
		require.False(t, ok)
	}

	_, ok := (ReadView{}).SSHCheckParams(1, 3, "root")
	require.False(t, ok)

	wire, err := view.SSHPolicy("", nodes[2].View())
	require.NoError(t, err)
	require.Len(t, wire.Rules, 1, "invalid lookups must not poison the generation cache")
}

func TestReadViewSSHCachesTypedDecisions(t *testing.T) {
	users := sshTestUsers()
	nodes := sshTestNodes(users)
	pm, err := NewPolicyManager([]byte(`{
		"tagOwners":{"tag:server":["alice@"]},
		"ssh":[{"action":"check","src":["alice@"],"dst":["tag:server"],
			"users":["root","localpart:*@headscale.net"],"acceptEnv":["LANG"],"checkPeriod":"2h"}]
	}`), users, nodes.ViewSlice())
	require.NoError(t, err)

	view := pm.ReadView()
	period, ok := view.SSHCheckParams(1, 3, "alice")
	require.True(t, ok)
	require.Equal(t, 2*time.Hour, period)
	require.Equal(t, 1, view.caches.ssh.Size(), "check lookup must populate the shared typed cache")

	first, err := pm.SSHPolicy("https://first", nodes[2].View())
	require.NoError(t, err)
	require.Len(t, first.Rules, 2)
	first.Rules[0].Principals[0].NodeIP = "192.0.2.1"
	first.Rules[0].SSHUsers["root"] = ""
	first.Rules[0].AcceptEnv[0] = "SECRET"
	first.Rules[0].Action.HoldAndDelegate = "changed"
	first.Rules[0].Action.SessionDuration = time.Hour
	require.Equal(t, "100.64.0.1", first.Rules[1].Principals[0].NodeIP)
	require.Equal(t, []string{"LANG"}, first.Rules[1].AcceptEnv)

	second, err := view.SSHPolicy("https://second", nodes[2].View())
	require.NoError(t, err)
	require.Equal(t, "100.64.0.1", second.Rules[0].Principals[0].NodeIP)
	require.Equal(t, "root", second.Rules[0].SSHUsers["root"])
	require.Equal(t, []string{"LANG"}, second.Rules[0].AcceptEnv)
	require.Zero(t, second.Rules[0].Action.SessionDuration)
	require.Equal(t, "https://second/machine/ssh/action/$SRC_NODE_ID/to/$DST_NODE_ID?local_user=$LOCAL_USER", second.Rules[0].Action.HoldAndDelegate)
	require.Equal(t, 1, view.caches.ssh.Size(), "base URLs must not duplicate compiled decisions")

	period, ok = pm.SSHCheckParams(1, 3, "root")
	require.True(t, ok)
	require.Equal(t, 2*time.Hour, period)
}

func TestReadViewSSHSurvivesGenerationReplacement(t *testing.T) {
	users := sshTestUsers()
	nodes := sshTestNodes(users)
	policy := []byte(`{
		"tagOwners":{"tag:server":["alice@"]},
		"ssh":[{"action":"check","src":["alice@"],"dst":["tag:server"],
			"users":["root","localpart:*@headscale.net"],"checkPeriod":"2h"}]
	}`)
	pm, err := NewPolicyManager(policy, users, nodes.ViewSlice())
	require.NoError(t, err)

	old := pm.ReadView()
	_, err = pm.SetPolicy([]byte(`{"ssh":[]}`))
	require.NoError(t, err)

	revoked, err := pm.SSHPolicy("", nodes[2].View())
	require.NoError(t, err)
	require.NotNil(t, revoked.Rules)
	require.Empty(t, revoked.Rules)

	_, ok := pm.SSHCheckParams(1, 3, "root")
	require.False(t, ok)

	// Populate the old generation only after the new generation's cache is populated.
	retained, err := old.SSHPolicy("", nodes[2].View())
	require.NoError(t, err)
	require.Len(t, retained.Rules, 2)

	period, ok := old.SSHCheckParams(1, 3, "alice")
	require.True(t, ok)
	require.Equal(t, 2*time.Hour, period)

	_, err = pm.SetPolicy(policy)
	require.NoError(t, err)

	beforeNodes := pm.ReadView()

	replacement := make(types.Nodes, 0, len(nodes)-1)
	for _, node := range nodes {
		if node.ID == 1 {
			continue
		}

		updated := node.Clone()
		if updated.ID == 3 {
			updated.Tags = []string{"tag:prod"}
		}

		replacement = append(replacement, updated)
	}

	_, err = pm.SetNodes(replacement.ViewSlice())
	require.NoError(t, err)

	_, ok = pm.SSHCheckParams(1, 3, "root")
	require.False(t, ok)

	_, err = pm.SSHPolicy("", nodes[2].View())
	require.Error(t, err, "old destination identity must not use the new generation")

	period, ok = beforeNodes.SSHCheckParams(1, 3, "root")
	require.True(t, ok)
	require.Equal(t, 2*time.Hour, period)

	beforeFailure := pm.ReadView()
	_, err = pm.SetPolicy([]byte(`{"ssh":[{"action":"invalid"}]}`))
	require.Error(t, err)
	require.Same(t, beforeFailure.generation, pm.ReadView().generation)
	require.Same(t, beforeFailure.caches, pm.ReadView().caches)
}

//nolint:testifylint // Concurrent readers cannot call FailNow.
func TestReadViewSSHConcurrentReplacement(t *testing.T) {
	users := sshTestUsers()
	nodes := sshTestNodes(users)
	allowed := []byte(`{
		"tagOwners":{"tag:server":["alice@"]},
		"ssh":[{"action":"check","src":["alice@"],"dst":["tag:server"],"users":["root"]}],
		"sshTests":[{"src":"alice@","dst":["tag:server"],"accept":["root"]}]
	}`)
	pm, err := NewPolicyManager(allowed, users, nodes.ViewSlice())
	require.NoError(t, err)

	old := pm.ReadView()

	var workers sync.WaitGroup

	for range 4 {
		workers.Go(func() {
			for range 20 {
				view := pm.ReadView()
				wire, err := view.SSHPolicy("https://reader", nodes[2].View())
				assert.NoError(t, err)

				if wire != nil {
					_, ok := view.SSHCheckParams(1, 3, "root")
					assert.Equal(t, len(wire.Rules) != 0, ok)

					if len(wire.Rules) > 0 {
						wire.Rules[0].SSHUsers["root"] = "changed"
						wire.Rules[0].Action.HoldAndDelegate = "changed"
					}
				}

				period, ok := old.SSHCheckParams(1, 3, "root")
				assert.True(t, ok)
				assert.Equal(t, 12*time.Hour, period)
				assert.NoError(t, pm.RunSSHTests())
			}
		})
	}

	for range 10 {
		_, err = pm.SetPolicy([]byte(`{"ssh":[]}`))
		assert.NoError(t, err)

		_, err = pm.SetPolicy(allowed)
		assert.NoError(t, err)
	}

	workers.Wait()
}

func TestReturnedRuleSliceIsolation(t *testing.T) {
	nodes := types.Nodes{{ID: 1, IPv4: ap("100.64.0.1")}}
	pm, err := NewPolicyManager(
		[]byte(`{"grants":[{"src":["*"],"dst":["*"],"ip":["*"]}]}`),
		nil,
		nodes.ViewSlice(),
	)
	require.NoError(t, err)
	first, err := pm.PacketRulesForNode(nodes[0].View())
	require.NoError(t, err)
	require.NotEmpty(t, first)
	first[0] = packetfilter.Rule{}
	second, err := pm.PacketRulesForNode(nodes[0].View())
	require.NoError(t, err)
	require.False(
		t,
		second[0].DestinationSet().IsEmpty(),
		"caller mutation must not revoke cached permissions",
	)
}

func TestSelfFragmentsSharedByGrantAndUser(t *testing.T) {
	users := types.Users{{ID: 1, Name: "u1"}, {ID: 2, Name: "u2"}}

	nodes := types.Nodes{
		node("one", "100.64.0.1", "fd7a:115c:a1e0::1", users[0]),
		node("two", "100.64.0.2", "fd7a:115c:a1e0::2", users[0]),
		node("three", "100.64.0.3", "fd7a:115c:a1e0::3", users[1]),
	}
	for i, node := range nodes {
		node.ID = types.NodeID(i + 1)
	}

	pm, err := NewPolicyManager(
		[]byte(
			`{"grants":[{"src":["autogroup:member"],"dst":["autogroup:self"],"ip":["*"]}]}`,
		),
		users,
		nodes.ViewSlice(),
	)
	require.NoError(t, err)

	view := pm.ReadView()
	require.Len(
		t,
		view.generation.self,
		2,
		"one shared fragment per existing grant/user",
	)
	require.Equal(t, view.generation.peer.byNode[1], view.generation.peer.byNode[2])

	for range 3 {
		for _, node := range nodes {
			_, err := view.PacketRulesForNode(node.View())
			require.NoError(t, err)
		}
	}

	require.Len(t, view.generation.self, 2)
	first, err := view.PeerRulesForNode(nodes[0].View())
	require.NoError(t, err)
	require.True(t, nodes[0].View().CanAccess(first, nodes[1].View()))
	require.False(t, nodes[0].View().CanAccess(first, nodes[2].View()))
}

func TestReadViewSharesFinalRulesAcrossIndexes(t *testing.T) {
	users := types.Users{{ID: 1, Name: "u1"}, {ID: 2, Name: "u2"}}

	nodes := types.Nodes{
		node("one", "100.64.0.1", "fd7a:115c:a1e0::1", users[0]),
		node("two", "100.64.0.2", "fd7a:115c:a1e0::2", users[0]),
		node("three", "100.64.0.3", "fd7a:115c:a1e0::3", users[1]),
		{Tags: []string{"tag:exit"}, IPv4: ap("100.64.0.4")},
	}
	for i, n := range nodes {
		n.ID = types.NodeID(i + 1)
	}

	exit := nodes[3]
	exit.ApprovedRoutes = []netip.Prefix{mp("0.0.0.0/0"), mp("::/0")}
	exit.Hostinfo = &tailcfg.Hostinfo{RoutableIPs: slices.Clone(exit.ApprovedRoutes)}
	pm, err := NewPolicyManager([]byte(`{
		"tagOwners":{"tag:exit":[]},
		"grants":[
			{"src":["*"],"dst":["*"],"ip":["tcp:443"]},
			{"src":["autogroup:member"],"dst":["autogroup:self"],"ip":["tcp:22"]}
		]
	}`), users, nodes.ViewSlice())
	require.NoError(t, err)

	view := pm.ReadView()
	packet, err := view.PacketRulesForNode(exit.View())
	require.NoError(t, err)
	require.Len(t, packet, 3)

	for _, n := range nodes[:3] {
		peer, err := view.PeerRulesForNode(n.View())
		require.NoError(t, err)
		require.Len(t, peer, 2)

		for _, rule := range peer {
			match := slices.IndexFunc(packet, rule.Equal)
			require.NotEqual(t, -1, match)
			require.Greater(t, len(slices.Collect(rule.DestinationSet().Prefixes())), 1)
			// Set equality with == checks shared storage, not only equal coverage.
			//nolint:testifylint // Compare immutable backing storage identities.
			require.True(t, rule.DestinationSet() == packet[match].DestinationSet(),
				"equal final peer and packet rules must share their destination union")
		}
	}

	global := view.PacketRules()
	require.Len(t, global, 1)
	//nolint:testifylint // Compare immutable backing storage identities.
	require.True(t, global[0].DestinationSet() == packet[0].DestinationSet())

	peer, err := view.PeerRulesForNode(nodes[0].View())
	require.NoError(t, err)

	port := []tailcfg.PortRange{{First: 22, Last: 22}}
	destination := []netip.Prefix{mp("100.64.0.2/32")}
	require.True(t, srcReachesDst(mp("100.64.0.1/32"), destination, port, ProtocolNameTCP, peer))
	require.False(t, srcReachesDst(mp("100.64.0.3/32"), destination, port, ProtocolNameTCP, peer))
	peer, err = view.PeerRulesForNode(exit.View())
	require.NoError(t, err)
	require.Len(t, peer, 1, "exit extras must not expand peer visibility")
}

func TestReadViewFinalRuleSharingPreservesOwnersAndContents(t *testing.T) {
	users := types.Users{{ID: 1, Name: "u1"}, {ID: 2, Name: "u2"}}
	routes := []netip.Prefix{mp("10.0.0.0/24"), mp("2001:db8::/64")}
	nodes := types.Nodes{
		{ID: 1, User: &users[0], IPv4: ap("100.64.0.1")},
		{
			ID: 2, Tags: []string{"tag:a"}, ApprovedRoutes: routes,
			Hostinfo: &tailcfg.Hostinfo{RoutableIPs: routes},
		},
		{
			ID: 3, Tags: []string{"tag:b"}, ApprovedRoutes: routes,
			Hostinfo: &tailcfg.Hostinfo{RoutableIPs: routes},
		},
		{ID: 4, User: &users[1], IPv4: ap("100.64.0.4")},
	}

	for _, tt := range []struct {
		name, source, destinations, protocol string
		equal                                bool
	}{
		{"equal after merging", "u1@", `"10.0.0.0/24","2001:db8::/64"`, "tcp:443", true},
		{"different source", "u2@", `"10.0.0.0/24","2001:db8::/64"`, "tcp:443", false},
		{"different destination", "u1@", `"10.0.0.0/25","2001:db8::/64"`, "tcp:443", false},
		{"different order", "u1@", `"2001:db8::/64","10.0.0.0/24"`, "tcp:443", false},
		{"duplicate destination", "u1@", `"10.0.0.0/24","2001:db8::/64","10.0.0.0/24"`, "tcp:443", false},
		{"different port", "u1@", `"10.0.0.0/24","2001:db8::/64"`, "tcp:8443", false},
		{"different protocol", "u1@", `"10.0.0.0/24","2001:db8::/64"`, "udp:443", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			pm, err := NewPolicyManager([]byte(fmt.Sprintf(`{
				"tagOwners":{"tag:a":[],"tag:b":[]},
				"grants":[
					{"src":["u1@"],"dst":["10.0.0.0/24"],"via":["tag:a"],"ip":["tcp:443"]},
					{"src":["u1@"],"dst":["2001:db8::/64"],"via":["tag:a"],"ip":["tcp:443"]},
					{"src":[%q],"dst":[%s],"via":["tag:b"],"ip":[%q]}
				]
			}`, tt.source, tt.destinations, tt.protocol)), users, nodes.ViewSlice())
			require.NoError(t, err)

			view := pm.ReadView()
			first, err := view.PeerRulesForNode(nodes[1].View())
			require.NoError(t, err)
			second, err := view.PeerRulesForNode(nodes[2].View())
			require.NoError(t, err)
			require.Len(t, first, 1)
			require.Len(t, second, 1)
			require.Equal(t, tt.equal, first[0].Equal(second[0]))
			require.Equal(t, tt.equal, first[0].DestinationSet() == second[0].DestinationSet(),
				"share complete equal rules only after owner-aware merging")
			require.Len(t, view.generation.peer.rules, 2)
			require.NotEqual(t, view.generation.peer.byNode[2], view.generation.peer.byNode[3],
				"content sharing must preserve separate owner applicability")
			client, err := view.PeerRulesForNode(nodes[0].View())
			require.NoError(t, err)
			require.Empty(t, client)
			require.Empty(t, view.PacketRules())
		})
	}
}

func TestReadViewFinalCapabilitySharingPreservesPayloads(t *testing.T) {
	users := types.Users{{ID: 1, Name: "u1"}}
	nodes := types.Nodes{node("one", "100.64.0.1", "fd7a:115c:a1e0::1", users[0])}
	nodes[0].ID = 1
	pm, err := NewPolicyManager([]byte(`{"grants":[
		{"src":["u1@"],"dst":["u1@"],"app":{"example.com/cap":[{"enabled":true}]}},
		{"src":["u1@"],"dst":["u1@"],"app":{"example.com/cap":[{"enabled":true}]}},
		{"src":["u1@"],"dst":["u1@"],"app":{"example.com/cap":[{"enabled":false}]}}
	]}`), users, nodes.ViewSlice())
	require.NoError(t, err)

	rules := pm.ReadView().PacketRules()
	require.Len(t, rules, 3, "capability grants must remain separate")
	require.True(t, rules[0].Equal(rules[1]))
	require.False(t, rules[0].Equal(rules[2]))
	require.Greater(t, len(slices.Collect(rules[0].DestinationSet().Prefixes())), 1)
	//nolint:testifylint // Compare immutable backing storage identities.
	require.True(t, rules[0].DestinationSet() == rules[1].DestinationSet())
	//nolint:testifylint // Compare immutable backing storage identities.
	require.False(t, rules[0].DestinationSet() == rules[2].DestinationSet())

	returned := rules[0].CapGrants()
	returned[0].CapMap["example.com/cap"][0] = "changed"
	delete(returned[0].CapMap, "example.com/cap")

	for i, want := range []tailcfg.RawMessage{
		`{"enabled":true}`, `{"enabled":true}`, `{"enabled":false}`,
	} {
		require.Equal(t, want, rules[i].CapGrants()[0].CapMap["example.com/cap"][0])
	}
}

func TestSelfSourceMembershipIncludesBothFamilies(t *testing.T) {
	users := types.Users{{ID: 1, Name: "u1"}}

	nodes := types.Nodes{
		node("one", "100.64.0.1", "fd7a:115c:a1e0::1", users[0]),
		node("two", "100.64.0.2", "fd7a:115c:a1e0::2", users[0]),
		node("tagged", "100.64.0.3", "fd7a:115c:a1e0::3", users[0]),
	}
	for i, node := range nodes {
		node.ID = types.NodeID(i + 1)
	}

	nodes[2].Tags = []string{"tag:server"}
	pol, err := unmarshalPolicy(
		[]byte(
			`{"tagOwners":{"tag:server":[]},"grants":[{"src":["autogroup:member"],"dst":["autogroup:self"],"ip":["*"]}]}`,
		),
	)
	require.NoError(t, err)
	// Exercise compiler membership separately from the parser's source-kind restriction.
	pol.Grants[0].Sources = Aliases{new(p("100.64.0.1/32"))}
	view := newReadView(
		pol,
		users,
		nodes.ViewSlice(),
		pol.compileGrants(users, nodes.ViewSlice()),
		nil,
	)
	rules, err := view.PeerRulesForNode(nodes[0].View())
	require.NoError(t, err)
	require.Len(t, rules, 1)
	require.True(t, rules[0].Sources().Contains(*ap("100.64.0.1")))
	require.True(t, rules[0].Sources().Contains(*ap("fd7a:115c:a1e0::1")))
	require.False(t, rules[0].Sources().Contains(*ap("100.64.0.2")))
	require.False(t, rules[0].DestinationSet().Contains(*ap("100.64.0.3")))
}

func TestSelfDestinationsPreservePortBeforeFamilyOrder(t *testing.T) {
	users := types.Users{{ID: 1, Name: "u1"}}

	nodes := types.Nodes{
		node("one", "100.64.0.1", "fd7a:115c:a1e0::1", users[0]),
		node("two", "100.64.0.2", "fd7a:115c:a1e0::2", users[0]),
	}
	for i, node := range nodes {
		node.ID = types.NodeID(i + 1)
	}

	pol, err := unmarshalPolicy([]byte(
		`{"grants":[{"src":["autogroup:member"],"dst":["autogroup:self"],"ip":["*"]}]}`,
	))
	require.NoError(t, err)

	pol.Grants[0].InternetProtocols = []ProtocolPort{{
		Protocol: ProtocolNameTCP,
		Ports:    []tailcfg.PortRange{{First: 22, Last: 22}, {First: 80, Last: 80}},
	}}
	view := newReadView(pol, users, nodes.ViewSlice(),
		pol.compileGrants(users, nodes.ViewSlice()), nil)
	rules, err := view.PeerRulesForNode(nodes[0].View())
	require.NoError(t, err)

	wire := packetfilter.ToTailcfg(rules)
	require.Len(t, wire, 1)
	require.Equal(t, []tailcfg.NetPortRange{
		{IP: "100.64.0.1", Ports: tailcfg.PortRange{First: 22, Last: 22}},
		{IP: "fd7a:115c:a1e0::1", Ports: tailcfg.PortRange{First: 22, Last: 22}},
		{IP: "100.64.0.1", Ports: tailcfg.PortRange{First: 80, Last: 80}},
		{IP: "fd7a:115c:a1e0::1", Ports: tailcfg.PortRange{First: 80, Last: 80}},
		{IP: "100.64.0.2", Ports: tailcfg.PortRange{First: 22, Last: 22}},
		{IP: "fd7a:115c:a1e0::2", Ports: tailcfg.PortRange{First: 22, Last: 22}},
		{IP: "100.64.0.2", Ports: tailcfg.PortRange{First: 80, Last: 80}},
		{IP: "fd7a:115c:a1e0::2", Ports: tailcfg.PortRange{First: 80, Last: 80}},
	}, wire[0].DstPorts)
}

func TestTypedRulesPreserveOwnerGate(t *testing.T) {
	nodes := types.Nodes{
		{ID: 9001, IPv4: ap("100.64.0.1")},
		{ID: 17, IPv4: ap("100.64.0.2")},
		{ID: 1, IPv4: ap("100.64.0.3")},
	}
	source := singletonPrefix(mp("100.64.0.1/32"))
	fragments := []ownedFragment{
		{
			fragment: ruleFragment{
				sources: source,
				destinations: []packetfilter.Destination{
					{
						Addresses: singletonPrefix(mp("100.64.0.2/32")),
						Ports:     tailcfg.PortRangeAny,
					},
				},
				protocols: Protocol(0).IPProtocols(),
			},
			owners: ownerApplicability{ordinals: []int{1}},
		},
		{
			fragment: ruleFragment{
				sources: source,
				destinations: []packetfilter.Destination{
					{
						Addresses: singletonPrefix(mp("100.64.0.3/32")),
						Ports:     tailcfg.PortRangeAny,
					},
				},
				protocols: Protocol(0).IPProtocols(),
			},
			owners: ownerApplicability{ordinals: []int{2}},
		},
	}
	index := mergeFragments(fragments, nodes.ViewSlice())
	require.Len(t, index.rules, 2, "different owner applicability must prevent merging")
	require.Empty(t, index.forNode(9001))
	require.Len(t, index.forNode(17), 1)
	require.False(t, index.forNode(17)[0].DestinationSet().Contains(*ap("100.64.0.3")))
	// Force a merge-key collision; semantic confirmation must retain both owners.
	fragments[0].owners.unrestricted = true
	collisionIndex := mergeFragmentsWithHash(
		fragments,
		nodes.ViewSlice(),
		func(ownedFragment) deephash.Sum { return deephash.Sum{} },
	)
	require.Len(t, collisionIndex.rules, 2)
}

func TestRuleIndexUnrestrictedMembershipRetainedGrowth(t *testing.T) {
	const ruleCount = 256

	nodes := make(types.Nodes, 512)
	for i := range nodes {
		nodes[i] = &types.Node{ID: types.NodeID(i + 1)}
	}

	fragments := make([]ownedFragment, ruleCount)
	for i := range fragments {
		fragments[i] = ownedFragment{
			fragment: ruleFragment{
				sources: singletonPrefix(netip.PrefixFrom(
					netip.AddrFrom4([4]byte{192, 0, 2, byte(i)}), 32,
				)),
				destinations: []packetfilter.Destination{
					{Addresses: ipset.All(), Ports: tailcfg.PortRangeAny},
				},
			},
			owners: ownerApplicability{unrestricted: true},
		}
	}

	retainedBytes := func(nodeCount int) float64 {
		lastKnownID := nodes[nodeCount-1].ID
		views := nodes[:nodeCount].ViewSlice()
		// Warm hash metadata before measuring generation-owned storage.
		_ = mergeFragments(fragments, views)

		var indexes [4]ruleIndex

		runtime.GC()

		var before, after runtime.MemStats

		runtime.ReadMemStats(&before)

		for i := range indexes {
			indexes[i] = mergeFragments(fragments, views)
		}

		runtime.GC()
		runtime.ReadMemStats(&after)

		retained := (float64(after.HeapAlloc) - float64(before.HeapAlloc)) /
			float64(len(indexes))
		for _, index := range indexes {
			require.Len(t, index.forNode(lastKnownID), ruleCount)
			require.Empty(t, index.forNode(lastKnownID+1))
		}

		runtime.KeepAlive(indexes)
		runtime.KeepAlive(views)
		runtime.KeepAlive(fragments)

		return retained
	}

	small, large := retainedBytes(16), retainedBytes(len(nodes))
	t.Logf("retained bytes/index: 16 nodes=%.0f, 512 nodes=%.0f", small, large)
	// Node membership may grow; 256 unrestricted IDs per node may not.
	require.Less(t, large-small, float64(128<<10),
		"unrestricted rule storage must not grow as nodes times rules")
	runtime.KeepAlive(nodes)
	runtime.KeepAlive(fragments)
}

func TestRuleIndexSelectionPreservesOrderAndOwnership(t *testing.T) {
	nodes := types.Nodes{{ID: 9001}, {ID: 17}, {ID: 17}, {ID: 42}}

	fragments := []ownedFragment{
		{owners: ownerApplicability{ordinals: []int{1, 2}}},
		{owners: ownerApplicability{unrestricted: true}},
		{owners: ownerApplicability{ordinals: []int{0}}},
		{owners: ownerApplicability{unrestricted: true}},
		{owners: ownerApplicability{ordinals: []int{1, 2}}},
	}
	for i := range fragments {
		fragments[i].fragment = ruleFragment{
			sources: singletonPrefix(netip.PrefixFrom(
				netip.AddrFrom4([4]byte{192, 0, 2, byte(i + 1)}), 32,
			)),
			destinations: []packetfilter.Destination{
				{
					Addresses: singletonPrefix(mp("100.64.0.1/32")),
					Ports: tailcfg.PortRange{
						First: uint16(80 + i), Last: uint16(80 + i),
					},
				},
			},
			protocols: []ipproto.Proto{17, 6, 17},
		}
	}

	fragments[3].fragment.destinations = nil
	fragments[3].fragment.capabilities = []packetfilter.CapabilityGrant{{
		Addresses: singletonPrefix(mp("100.64.0.1/32")),
		CapMap:    tailcfg.PeerCapMap{"example.com/access": {`{"role":"reader"}`}},
	}}

	index := mergeFragmentsWithHash(fragments, nodes.ViewSlice(),
		func(ownedFragment) deephash.Sum { return deephash.Sum{} })

	for _, test := range []struct {
		id      types.NodeID
		sources []string
	}{
		{17, []string{"192.0.2.1", "192.0.2.2", "192.0.2.4", "192.0.2.5"}},
		{9001, []string{"192.0.2.2", "192.0.2.3", "192.0.2.4"}},
		{42, []string{"192.0.2.2", "192.0.2.4"}},
		{99, nil},
	} {
		rules := index.forNode(test.id)
		wire := packetfilter.ToTailcfg(rules)
		require.Len(t, wire, len(test.sources))

		for i, source := range test.sources {
			require.Equal(t, []string{source}, wire[i].SrcIPs)

			if source == "192.0.2.4" {
				require.Equal(t, fragments[3].fragment.capabilities, rules[i].CapGrants())
			} else {
				require.Equal(t, []int{6, 17}, wire[i].IPProto)
				require.Len(t, wire[i].DstPorts, 1)
				require.Equal(t, "100.64.0.1", wire[i].DstPorts[0].IP)

				port := uint16(79 + netip.MustParseAddr(source).As4()[3])
				require.Equal(t, tailcfg.PortRange{First: port, Last: port}, wire[i].DstPorts[0].Ports)
			}
		}

		if len(rules) > 0 {
			rules[0] = packetfilter.Rule{}

			require.NotEqual(t, packetfilter.KindInvalid, index.forNode(test.id)[0].Kind())
		}
	}

	restricted := mergeFragments([]ownedFragment{fragments[0]}, nodes.ViewSlice())
	require.Empty(t, restricted.forNode(42), "known nodes with no applicable IDs stay empty")
	require.Empty(t, restricted.forNode(99), "unknown nodes stay empty")
}

type partialSourceAlias struct {
	Alias

	addresses ipset.Set
	err       error
	calls     *int
}

func (a *partialSourceAlias) Resolve(
	*Policy,
	types.Users,
	views.Slice[types.NodeView],
) (ipset.Set, error) {
	*a.calls++
	return a.addresses, a.err
}

func TestSourceProjectionPartialErrors(t *testing.T) {
	calls := 0
	partial := &partialSourceAlias{
		Alias:     new(p("100.64.0.1/32")),
		addresses: singletonPrefix(mp("100.64.0.1/32")),
		err:       ErrMultipleUsersFound,
		calls:     &calls,
	}
	routes := []netip.Prefix{mp("10.0.0.0/24")}
	nodes := types.Nodes{
		{
			ID:             1,
			IPv4:           ap("100.64.0.1"),
			Hostinfo:       &tailcfg.Hostinfo{RoutableIPs: routes},
			ApprovedRoutes: routes,
		},
	}
	cache := resolutionCache{
		&Policy{},
		nil,
		nodes.ViewSlice(),
		make(map[string]aliasResolution),
	}
	projections, err := cache.sources(Aliases{partial})
	require.NoError(t, err)
	require.True(t, projections.Raw.Contains(*ap("100.64.0.1")))
	require.True(t, projections.Packet.Contains(*ap("100.64.0.1")))
	require.True(t, projections.Viewer.IsEmpty())
	require.False(t, projections.Packet.Contains(*ap("192.0.2.1")))

	_, err = cache.sources(Aliases{partial})
	require.NoError(t, err)
	require.Equal(t, 1, calls, "cache errors together with partial results")

	wildcard, err := cache.sources(Aliases{partial, Asterix(0)})
	require.NoError(t, err)
	require.True(t, wildcard.Packet.Contains(*ap("10.0.0.1")))
	require.False(t, wildcard.Raw.Contains(*ap("10.0.0.1")))
	require.False(t, wildcard.Viewer.Contains(*ap("10.0.0.1")))
}

func TestCompiledGenerationRollback(t *testing.T) {
	users := types.Users{
		{ID: 1, Name: "u1"},
		{ID: 2, Name: "dup"},
		{ID: 3, Name: "dup"},
	}
	nodes := types.Nodes{node("one", "100.64.0.1", "fd7a:115c:a1e0::1", users[0])}
	nodes[0].ID = 1
	pm, err := NewPolicyManager(
		[]byte(`{"grants":[{"src":["*"],"dst":["*"],"ip":["*"]}]}`),
		users,
		nodes.ViewSlice(),
	)
	require.NoError(t, err)

	old := pm.ReadView()
	before, err := old.PacketRulesForNode(nodes[0].View())
	require.NoError(t, err)
	_, err = pm.SetPolicy(
		[]byte(
			`{"grants":[],"nodeAttrs":[{"target":["dup@"],"attr":["randomize-client-port"]}]}`,
		),
	)
	require.Error(t, err)
	require.Same(t, old.generation, pm.ReadView().generation)
	require.Same(t, old.caches, pm.ReadView().caches)
	after, err := old.PacketRulesForNode(nodes[0].View())
	require.NoError(t, err)
	require.True(t, before[0].Equal(after[0]))

	view, adjacency, err := pm.SetNodesAndBuildPeerMap(nodes.ViewSlice())
	require.NoError(t, err)
	require.True(t, view.Valid())
	require.Empty(t, adjacency)
}

func TestCapturedReadViewSurvivesPolicyReplacement(t *testing.T) {
	nodes := types.Nodes{{ID: 1, IPv4: ap("100.64.0.1")}}
	pm, err := NewPolicyManager([]byte(`{}`), nil, nodes.ViewSlice())
	require.NoError(t, err)

	old := pm.ReadView()
	before, err := old.PacketRulesForNode(nodes[0].View())
	require.NoError(t, err)
	require.NotEmpty(t, before)

	_, err = pm.SetPolicy([]byte(`{"grants":[]}`))
	require.NoError(t, err)
	current, err := pm.PacketRulesForNode(nodes[0].View())
	require.NoError(t, err)
	require.Empty(t, current)

	after, err := old.PacketRulesForNode(nodes[0].View())
	require.NoError(t, err)
	require.True(t, before[0].Equal(after[0]))

	stale := nodes[0].Clone()
	stale.IPv4 = ap("100.64.0.2")
	_, err = old.PacketRulesForNode(stale.View())
	require.NoError(t, err)
	fresh, err := old.PacketRulesForNode(nodes[0].View())
	require.NoError(t, err)
	require.True(t, before[0].Equal(fresh[0]))

	rules := old.PacketRules()
	rules[0] = packetfilter.Rule{}

	require.False(t, old.PacketRules()[0].Sources().IsEmpty())
	peer, err := old.PeerRulesForNode(nodes[0].View())
	require.NoError(t, err)

	peer[0] = packetfilter.Rule{}
	peer, err = old.PeerRulesForNode(nodes[0].View())
	require.NoError(t, err)
	require.False(t, peer[0].Sources().IsEmpty())
}

func TestReadViewOwnsConstructorInputs(t *testing.T) {
	users := types.Users{{ID: 1, Name: "u1"}}
	nodes := types.Nodes{node("one", "100.64.0.1", "fd7a:115c:a1e0::1", users[0])}
	nodes[0].ID = 1
	pm, err := NewPolicyManager(
		[]byte(`{"grants":[{"src":["u1@"],"dst":["autogroup:self"],"ip":["*"]}]}`),
		users,
		nodes.ViewSlice(),
	)
	require.NoError(t, err)

	view := pm.ReadView()
	original := nodes[0].Clone()
	nodes[0].IPv4 = ap("100.64.0.99")
	nodes[0].User.Name = "changed"
	users[0].Name = "changed"

	require.Equal(t, "100.64.0.1", view.generation.nodes.At(0).IPs()[0].String())
	require.Equal(t, "u1", view.generation.nodes.At(0).User().Name())
	rules, err := view.PacketRulesForNode(original.View())
	require.NoError(t, err)
	require.NotEmpty(t, rules)
}

func TestPacketFilterRevocationIsExplicit(t *testing.T) {
	nodes := types.Nodes{{ID: 1, IPv4: ap("100.64.0.1")}}
	pm, err := NewPolicyManager([]byte(`{}`), nil, nodes.ViewSlice())
	require.NoError(t, err)
	_, err = pm.SetPolicy([]byte(`{"grants":[]}`))
	require.NoError(t, err)
	rules, err := pm.PacketRulesForNode(nodes[0].View())
	require.NoError(t, err)

	wire := packetfilter.ToTailcfg(rules)
	require.NotNil(t, wire)
	require.Empty(t, wire)
}

func TestTypedReachabilityMatchesWireOracle(t *testing.T) {
	users, nodes := benchNodes(8)
	pol, err := unmarshalPolicy(
		[]byte(
			`{"grants":[{"src":["*"],"dst":["100.64.0.2"],"ip":["tcp:443","udp:53"]}]}`,
		),
	)
	require.NoError(t, err)

	view := newReadView(
		pol,
		users,
		nodes.ViewSlice(),
		pol.compileGrants(users, nodes.ViewSlice()),
		nil,
	)
	wire := pol.legacyCompileFilterRules(users, nodes.ViewSlice())

	for _, source := range []string{"100.64.0.1/32", "192.0.2.1/32"} {
		for _, destination := range []string{"100.64.0.2/32", "100.64.0.3/32"} {
			for _, port := range []uint16{22, 53, 443} {
				for _, protocol := range []ipproto.Proto{1, 6, 17, 47, 58, 132} {
					want := false

					for _, rule := range wire {
						sourceMatch := false
						for _, raw := range rule.SrcIPs {
							sourceMatch = sourceMatch ||
								referenceParse(raw).OverlapsPrefix(mp(source))
						}

						protocolMatch := slices.Contains(rule.IPProto, int(protocol))
						if len(rule.IPProto) == 0 {
							protocolMatch = slices.Contains(
								[]ipproto.Proto{1, 6, 17, 58},
								protocol,
							)
						}

						if sourceMatch && protocolMatch {
							for _, dst := range rule.DstPorts {
								want = want ||
									(referenceParse(dst.IP).OverlapsPrefix(mp(destination)) && port >= dst.Ports.First && port <= dst.Ports.Last)
							}
						}
					}

					got := srcReachesDst(
						mp(source),
						[]netip.Prefix{mp(destination)},
						[]tailcfg.PortRange{{First: port, Last: port}},
						Protocol(protocol),
						view.PacketRules(),
					)
					require.Equal(
						t,
						want,
						got,
						"%s to %s:%d/%d",
						source,
						destination,
						port,
						protocol,
					)
				}
			}
		}
	}
}

func TestReadViewSSHAndCapabilitiesAreOwned(t *testing.T) {
	users := types.Users{{ID: 1, Name: "u1"}}
	nodes := types.Nodes{
		node("one", "100.64.0.1", "fd7a:115c:a1e0::1", users[0]),
		{ID: 2, IPv4: ap("100.64.0.2"), Tags: []string{"tag:server"}},
	}
	nodes[0].ID = 1
	pol, err := unmarshalPolicy(
		[]byte(
			`{"tagOwners":{"tag:server":[]},"grants":[],"ssh":[{"action":"check","src":["u1@"],"dst":["tag:server"],"users":["root"]}]}`,
		),
	)
	require.NoError(t, err)

	caps := map[types.NodeID]tailcfg.NodeCapMap{
		2: {
			"example.com/cap":   {tailcfg.RawMessage(`{"enabled":true}`)},
			"suggest-exit-node": {tailcfg.RawMessage(`{"priority":1}`)},
		},
	}
	nodes[1].ApprovedRoutes = []netip.Prefix{mp("0.0.0.0/0"), mp("::/0")}
	nodes[1].Hostinfo = &tailcfg.Hostinfo{RoutableIPs: slices.Clone(nodes[1].ApprovedRoutes)}
	view := newReadView(
		pol,
		users,
		nodes.ViewSlice(),
		pol.compileGrants(users, nodes.ViewSlice()),
		caps,
	)
	first, err := view.SSHPolicy("https://first", nodes[1].View())
	require.NoError(t, err)
	require.NotEmpty(t, first.Rules)
	first.Rules[0].SSHUsers["root"] = "forbidden"
	first.Rules[0].Action.HoldAndDelegate = "changed"
	again, err := view.SSHPolicy("https://first", nodes[1].View())
	require.NoError(t, err)
	require.Equal(t, "root", again.Rules[0].SSHUsers["root"])
	require.Contains(t, again.Rules[0].Action.HoldAndDelegate, "https://first/")

	otherURL, err := view.SSHPolicy("https://second", nodes[1].View())
	require.NoError(t, err)
	require.Contains(t, otherURL.Rules[0].Action.HoldAndDelegate, "https://second/")

	duration, ok := view.SSHCheckParams(1, 2, "root")
	require.True(t, ok)
	require.Equal(t, SSHCheckPeriodDefault, duration)

	returned := view.NodeCapMap(2)
	returned["example.com/cap"][0] = "changed"
	caps[2]["example.com/cap"][0] = "changed-input"

	require.Equal(
		t,
		tailcfg.RawMessage(`{"enabled":true}`),
		view.NodeCapMap(2)["example.com/cap"][0],
	)
	peerCaps := view.PeerCapMap(nodes[1].View())
	peerCaps["suggest-exit-node"][0] = "changed"
	caps[2]["suggest-exit-node"][0] = "changed-input"

	require.Equal(t, tailcfg.RawMessage(`{"priority":1}`),
		view.PeerCapMap(nodes[1].View())["suggest-exit-node"][0])
	require.Equal(t, tailcfg.RawMessage(`{"priority":1}`),
		view.NodeCapMap(2)["suggest-exit-node"][0])
}

func TestViaRoutesForViewerUsesCapturedCandidates(t *testing.T) {
	users := types.Users{{ID: 1, Name: "u1"}}
	route := mp("10.0.0.0/24")
	nodes := types.Nodes{
		node("one", "100.64.0.1", "fd7a:115c:a1e0::1", users[0]),
		{
			ID:             10,
			IPv4:           ap("100.64.0.10"),
			Tags:           []string{"tag:router"},
			IsOnline:       new(true),
			Hostinfo:       &tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{route}},
			ApprovedRoutes: []netip.Prefix{route},
		},
		{
			ID:             20,
			IPv4:           ap("100.64.0.20"),
			Tags:           []string{"tag:router"},
			IsOnline:       new(true),
			Hostinfo:       &tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{route}},
			ApprovedRoutes: []netip.Prefix{route},
		},
	}
	nodes[0].ID = 1
	pm, err := NewPolicyManager(
		[]byte(
			`{"tagOwners":{"tag:router":[]},"grants":[{"src":["u1@"],"dst":["10.0.0.0/8"],"ip":["*"],"via":["tag:router"]}]}`,
		),
		users,
		nodes.ViewSlice(),
	)
	require.NoError(t, err)

	view := pm.ReadView()
	initial := view.ViaRoutesForViewer(nodes[0].View(), nodes.ViewSlice())
	require.Equal(t, []netip.Prefix{route}, initial[10].Include)
	require.Equal(t, []netip.Prefix{route}, initial[20].Exclude)

	captured := types.Nodes{nodes[0].Clone(), nodes[2].Clone()}
	retained := view.ViaRoutesForViewer(captured[0].View(), captured.ViewSlice())
	require.Equal(t, []netip.Prefix{route}, retained[20].Include)

	newer := types.Nodes{nodes[0].Clone(), nodes[2].Clone()}
	newer[1].Tags = []string{"tag:other"}
	_, err = pm.SetNodes(newer.ViewSlice())
	require.NoError(t, err)

	retained = view.ViaRoutesForViewer(captured[0].View(), captured.ViewSlice())
	require.Equal(t, []netip.Prefix{route}, retained[20].Include)

	t.Run("absent_group_does_not_demote_available_group", func(t *testing.T) {
		other, err := NewPolicyManager([]byte(`{
			"tagOwners":{"tag:router":[],"tag:absent":[]},
			"grants":[
				{"src":["u1@"],"dst":["10.0.0.0/8"],"ip":["*"],"via":["tag:router"]},
				{"src":["u1@"],"dst":["10.0.0.0/8"],"ip":["*"],"via":["tag:absent"]}
			]
		}`), users, captured.ViewSlice())
		require.NoError(t, err)

		got := other.ReadView().ViaRoutesForViewer(captured[0].View(), captured.ViewSlice())
		require.Equal(t, []netip.Prefix{route}, got[20].Include)
	})
}

func TestViaRoutesForViewerHealth(t *testing.T) {
	t.Parallel()

	route := mp("10.0.0.0/24")
	users := types.Users{{ID: 1, Name: "u1"}}

	nodes := types.Nodes{
		{ID: 1, IPv4: ap("100.64.0.1"), User: &users[0], UserID: &users[0].ID},
		{
			ID: 10, IPv4: ap("100.64.0.10"), Tags: []string{"tag:router"},
			IsOnline:       new(true),
			Hostinfo:       &tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{route}},
			ApprovedRoutes: []netip.Prefix{route},
		},
		{
			ID: 20, IPv4: ap("100.64.0.20"), Tags: []string{"tag:router"},
			IsOnline:       new(true),
			Hostinfo:       &tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{route}},
			ApprovedRoutes: []netip.Prefix{route},
		},
		{
			ID: 2, IPv4: ap("100.64.0.2"), Tags: []string{"tag:other"},
			IsOnline:       new(true),
			Hostinfo:       &tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{route}},
			ApprovedRoutes: []netip.Prefix{route},
		},
	}
	pm, err := NewPolicyManager([]byte(`{
		"tagOwners":{"tag:router":[],"tag:other":[]},
		"grants":[{"src":["u1@"],"dst":["10.0.0.0/24"],
		"ip":["*"],"via":["tag:router"]}]
	}`), users, nodes.ViewSlice())
	require.NoError(t, err)

	view := pm.ReadView()

	for _, tt := range []struct {
		name                        string
		lowOnline, highOnline       *bool
		lowUnhealthy, highUnhealthy bool
		want                        types.NodeID
	}{
		{"both_healthy", new(true), new(true), false, false, 10},
		{"lower_offline", new(false), new(true), false, false, 20},
		{"lower_unknown", nil, new(true), false, false, 20},
		{"lower_unhealthy", new(true), new(true), true, false, 20},
		{"higher_unhealthy", new(true), new(true), false, true, 10},
		{"higher_offline", new(true), new(false), false, false, 10},
		{"all_offline", new(false), new(false), false, false, 0},
		{"all_unknown", nil, nil, false, false, 0},
		{"all_unhealthy", new(true), new(true), true, true, 0},
		{"only_online_router_unhealthy", new(false), new(true), false, true, 0},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			captured := types.Nodes{
				nodes[0].Clone(), nodes[1].Clone(), nodes[2].Clone(), nodes[3].Clone(),
			}
			captured[1].IsOnline, captured[2].IsOnline = tt.lowOnline, tt.highOnline
			captured[1].Unhealthy, captured[2].Unhealthy = tt.lowUnhealthy, tt.highUnhealthy

			// Deliberately reverse the candidates; selection must use IDs and
			// fresh captured health, not input order or the policy generation.
			slices.Reverse(captured)
			got := view.ViaRoutesForViewer(nodes[0].View(), captured.ViewSlice())

			for _, id := range []types.NodeID{10, 20, 2} {
				if id == tt.want {
					require.Equal(
						t,
						[]netip.Prefix{route},
						got[id].Include,
						"router %d",
						id,
					)
					require.Empty(t, got[id].Exclude, "router %d", id)
				} else {
					require.Empty(t, got[id].Include, "router %d", id)
					require.Equal(
						t,
						[]netip.Prefix{route},
						got[id].Exclude,
						"router %d",
						id,
					)
				}

				require.Empty(t, got[id].UsePrimary, "router %d", id)
			}

			// A retained healthy capture must remain usable after another
			// response observes failover or an all-unhealthy group.
			again := view.ViaRoutesForViewer(nodes[0].View(), nodes.ViewSlice())
			require.Equal(t, []netip.Prefix{route}, again[10].Include)
			require.Equal(t, []netip.Prefix{route}, again[20].Exclude)
		})
	}
}

func TestViaRoutesForViewerHealthKeepsExactRoutesAndRegularOverride(t *testing.T) {
	t.Parallel()

	users := types.Users{{ID: 1, Name: "u1"}}
	parent := mp("10.0.0.0/16")
	child := mp("10.0.0.0/24")
	child6 := mp("2001:db8::/64")

	for _, regular := range []bool{false, true} {
		t.Run(
			map[bool]string{false: "via_only", true: "regular_override"}[regular],
			func(t *testing.T) {
				t.Parallel()

				nodes := types.Nodes{
					{
						ID:     1,
						IPv4:   ap("100.64.0.1"),
						User:   &users[0],
						UserID: &users[0].ID,
					},
					{
						ID:        10,
						IPv4:      ap("100.64.0.10"),
						Tags:      []string{"tag:router"},
						IsOnline:  new(true),
						Unhealthy: true,
						Hostinfo: &tailcfg.Hostinfo{
							RoutableIPs: []netip.Prefix{parent, child, child6},
						},
						ApprovedRoutes: []netip.Prefix{parent, child, child6},
					},
					{
						ID:       20,
						IPv4:     ap("100.64.0.20"),
						Tags:     []string{"tag:router"},
						IsOnline: new(true),
						Hostinfo: &tailcfg.Hostinfo{
							RoutableIPs: []netip.Prefix{child, child6},
						},
						ApprovedRoutes: []netip.Prefix{child, child6},
					},
					{
						ID:       2,
						IPv4:     ap("100.64.0.2"),
						Tags:     []string{"tag:other"},
						IsOnline: new(true),
						Hostinfo: &tailcfg.Hostinfo{
							RoutableIPs: []netip.Prefix{parent, child, child6},
						},
						ApprovedRoutes: []netip.Prefix{parent, child, child6},
					},
				}

				pol := `{"tagOwners":{"tag:router":[],"tag:other":[]},"grants":[
				{"src":["u1@"],"dst":["10.0.0.0/16","2001:db8::/32"],
				"ip":["*"],"via":["tag:router"]}`

				if regular {
					pol += `,{"src":["u1@"],"dst":["10.0.0.0/16","2001:db8::/32"],"ip":["*"]}`
				}

				pm, err := NewPolicyManager([]byte(pol+`]}`), users, nodes.ViewSlice())
				require.NoError(t, err)

				got := pm.ReadView().
					ViaRoutesForViewer(nodes[0].View(), nodes.ViewSlice())
				require.ElementsMatch(t, []netip.Prefix{child, child6}, got[20].Include)
				require.Empty(t, got[20].Exclude)
				require.Empty(t, got[10].Include)
				require.Empty(t, got[2].Include)

				if regular {
					require.ElementsMatch(
						t,
						[]netip.Prefix{child, child6},
						got[20].UsePrimary,
					)
					require.Empty(t, got[10].Exclude)
					require.Empty(t, got[2].Exclude)
				} else {
					require.Empty(t, got[20].UsePrimary)
					require.ElementsMatch(
						t,
						[]netip.Prefix{parent, child, child6},
						got[10].Exclude,
					)
					require.ElementsMatch(
						t,
						[]netip.Prefix{parent, child, child6},
						got[2].Exclude,
					)
				}
			},
		)
	}
}

func TestExitSelfExtrasFollowRecipientRules(t *testing.T) {
	users := types.Users{{ID: 1, Name: "u1"}, {ID: 2, Name: "u2"}}
	exits := []netip.Prefix{mp("0.0.0.0/0")}
	nodes := types.Nodes{node("one", "100.64.0.1", "fd7a:115c:a1e0::1", users[0]), node("two", "100.64.0.3", "fd7a:115c:a1e0::3", users[1]), {ID: 3, IPv4: ap("100.64.0.10"), Tags: []string{"tag:exit"}, Hostinfo: &tailcfg.Hostinfo{RoutableIPs: exits}, ApprovedRoutes: exits}}
	nodes[0].ID, nodes[1].ID = 1, 2
	pm, err := NewPolicyManager([]byte(`{"tagOwners":{"tag:exit":[]},"grants":[{"src":["autogroup:member"],"dst":["autogroup:self"],"ip":["tcp:443"]},{"src":["u1@"],"dst":["tag:exit"],"ip":["tcp:443"]}]}`), users, nodes.ViewSlice())
	require.NoError(t, err)
	rules, err := pm.PacketRulesForNode(nodes[2].View())
	require.NoError(t, err)
	require.Len(t, rules, 3)
	require.True(t, rules[0].DestinationSet().Contains(*ap("100.64.0.10")), "regular recipient rules precede exit-only self extras")
	require.True(t, rules[1].DestinationSet().Contains(*ap("100.64.0.1")))
	require.True(t, rules[2].DestinationSet().Contains(*ap("100.64.0.3")))

	peer, err := pm.PeerRulesForNode(nodes[2].View())
	require.NoError(t, err)
	require.Len(t, peer, 1, "exit extras must not enter peer selection")
}
