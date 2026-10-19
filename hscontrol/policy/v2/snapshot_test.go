package v2

import (
	"net/netip"
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
		2: {"example.com/cap": {tailcfg.RawMessage(`{"enabled":true}`)}},
	}
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
			Hostinfo:       &tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{route}},
			ApprovedRoutes: []netip.Prefix{route},
		},
		{
			ID:             20,
			IPv4:           ap("100.64.0.20"),
			Tags:           []string{"tag:router"},
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
