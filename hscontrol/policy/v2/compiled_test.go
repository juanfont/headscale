package v2

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"net/netip"
	"slices"
	"strconv"
	"testing"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
	"tailscale.com/tailcfg/peercap"
	"tailscale.com/types/views"
)

// compileOtherDestsReference retains the original implementation for exact-output
// differential tests and whole-helper benchmarks. Keep its body unchanged.
func (pol *Policy) compileOtherDestsReference(
	users types.Users,
	nodes views.Slice[types.NodeView],
	grant Grant,
	otherDests Aliases,
	resolvedSrcs []ResolvedAddresses,
	srcIPStrings []string,
) []tailcfg.FilterRule {
	var rules []tailcfg.FilterRule

	// DstPorts rules from InternetProtocols.
	for _, ipp := range grant.InternetProtocols {
		destPorts := pol.destinationsToNetPortRange(
			users, nodes, otherDests, ipp.Ports,
		)

		if len(destPorts) > 0 && len(srcIPStrings) > 0 {
			rules = append(rules, tailcfg.FilterRule{
				SrcIPs:   srcIPStrings,
				DstPorts: destPorts,
				IPProto:  ipp.Protocol.toIANAProtocolNumbers(),
			})
		}
	}

	// CapGrant rules from App.
	if grant.App != nil {
		capSrcIPStrs := srcIPStrings

		// When sources resolved to empty but App is set,
		// Tailscale still produces the CapGrant rule with
		// empty SrcIPs.
		if capSrcIPStrs == nil {
			capSrcIPStrs = []string{}
		}

		var (
			capGrants    []tailcfg.CapGrant
			dstIPStrings []string
		)

		for _, dst := range otherDests {
			ips, err := dst.Resolve(pol, users, nodes)
			if err != nil {
				continue
			}

			capGrants = append(capGrants, tailcfg.CapGrant{
				Dsts:   ips.Prefixes(),
				CapMap: grant.App,
			})

			dstIPStrings = append(dstIPStrings, ips.Strings()...)
		}

		if len(capGrants) > 0 {
			srcPrefixes := make([]netip.Prefix, 0, len(resolvedSrcs)*2)
			for _, ips := range resolvedSrcs {
				srcPrefixes = append(
					srcPrefixes, ips.Prefixes()...,
				)
			}

			rules = append(rules, tailcfg.FilterRule{
				SrcIPs:   capSrcIPStrs,
				CapGrant: capGrants,
			})

			dstsHaveWildcard := sourcesHaveWildcard(otherDests)
			if dstsHaveWildcard {
				dstIPStrings = append(
					dstIPStrings,
					approvedSubnetRoutes(nodes)...,
				)
			}

			rules = append(
				rules,
				companionCapGrantRules(
					dstIPStrings, srcPrefixes, grant.App,
				)...,
			)
		}
	}

	return rules
}

func compileOtherDestsFixture(
	tb testing.TB,
	userCount, nodeCount int,
) (*Policy, types.Users, types.Nodes) {
	tb.Helper()

	users := make(types.Users, userCount)
	usernames := make(Usernames, userCount)

	for i := range users {
		users[i] = types.User{ID: uint(i + 1), Name: fmt.Sprintf("u%d", i)}
		usernames[i] = Username(users[i].Name + "@")
	}

	pol := &Policy{
		Groups: Groups{
			"group:all":     usernames,
			"group:some":    usernames[:(userCount+1)/2],
			"group:empty":   {},
			"group:missing": {"missing@"},
		},
		Hosts: Hosts{
			"host4": Prefix(netip.MustParsePrefix("100.64.0.0/24")),
			"host6": Prefix(netip.MustParsePrefix("fd7a:115c:a1e0::1/128")),
		},
		TagOwners: TagOwners{
			"tag:a": {up("u0@")},
			"tag:b": {gp("group:some")},
		},
		Grants: []Grant{{
			Sources:      Aliases{Asterix(0), tp("tag:a")},
			Destinations: Aliases{gp("group:all"), hp("host4")},
			InternetProtocols: []ProtocolPort{
				{Protocol: "tcp", Ports: []tailcfg.PortRange{{First: 22, Last: 22}}},
				{Protocol: "udp", Ports: []tailcfg.PortRange{{First: 53, Last: 53}}},
				{Protocol: "tcp", Ports: []tailcfg.PortRange{{First: 80, Last: 81}}},
			},
			App: tailcfg.PeerCapMap{
				peercap.Taildrive: nil,
				peercap.Relay:     {},
				"example.com/cap": {
					tailcfg.RawMessage(`{"enabled":true,"ports":[22,80]}`),
				},
			},
		}},
	}
	data, err := json.Marshal(pol)
	require.NoError(tb, err)
	pol, err = unmarshalPolicy(data)
	require.NoError(tb, err)

	nodes := make(types.Nodes, nodeCount)
	for i := range nodes {
		u := users[i%len(users)]
		ip4 := netip.AddrFrom4(
			[4]byte{100, 64, byte(i / 256), byte(i % 256)},
		) //nolint:gosec
		ip6 := netip.MustParseAddr(fmt.Sprintf("fd7a:115c:a1e0::%x", i+1))

		n := &types.Node{
			ID:       types.NodeID(i + 1), //nolint:gosec
			Hostname: fmt.Sprintf("n%d", i),
			UserID:   new(u.ID),
			User:     new(u),
			IPv4:     new(ip4),
			IPv6:     new(ip6),
		}
		if i%5 == 0 {
			n.Tags = []string{"tag:a", "tag:b"}
		}

		if i%4 == 0 {
			n.Hostinfo = &tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{
				netip.MustParsePrefix("10.33.0.0/16"),
				netip.MustParsePrefix("10.33.0.0/24"),
				netip.MustParsePrefix("0.0.0.0/0"),
				netip.MustParsePrefix("::/0"),
			}}
			n.ApprovedRoutes = slices.Clone(n.Hostinfo.RoutableIPs)
		}

		nodes[i] = n
	}

	return pol, users, nodes
}

func assertCompileOtherDestsReference(
	t *testing.T,
	pol *Policy,
	users types.Users,
	nodes types.Nodes,
	grant Grant,
) {
	t.Helper()

	srcs, nonWild, err := resolveSources(pol, grant.Sources, users, nodes.ViewSlice())
	require.NoError(t, err)

	srcStrings := buildSrcIPStrings(srcs, nonWild,
		sourcesHaveWildcard(grant.Sources), sourcesHaveDangerAll(grant.Sources),
		nodes.ViewSlice())
	if grant.Sources != nil && len(grant.Sources) == 0 {
		srcStrings = []string{}
	}

	before, err := json.Marshal(grant)
	require.NoError(t, err)

	previousLogger, previousLevel := log.Logger, zerolog.GlobalLevel()
	defer func() {
		log.Logger = previousLogger

		zerolog.SetGlobalLevel(previousLevel)
	}()

	zerolog.SetGlobalLevel(zerolog.TraceLevel)

	var wantLog, gotLog bytes.Buffer

	log.Logger = zerolog.New(&wantLog)
	want := pol.compileOtherDestsReference(users, nodes.ViewSlice(), grant,
		grant.Destinations, srcs, srcStrings)
	log.Logger = zerolog.New(&gotLog)
	got := pol.compileOtherDests(users, nodes.ViewSlice(), grant,
		grant.Destinations, srcs, srcStrings)

	require.Equal(t, want, got, "ordered rules, duplicates, and nil/empty must match")
	require.Equal(t, wantLog.String(), gotLog.String(), "resolution logs must match")

	wantJSON, err := json.Marshal(want)
	require.NoError(t, err)
	gotJSON, err := json.Marshal(got)
	require.NoError(t, err)
	require.JSONEq(
		t,
		string(wantJSON),
		string(gotJSON),
		"wire output must match exactly",
	)

	after, err := json.Marshal(grant)
	require.NoError(t, err)
	require.Equal(
		t,
		string(before),
		string(after),
		"compilation must not mutate the grant",
	)
}

func TestCompileOtherDestsMatchesReference(t *testing.T) {
	for _, name := range []string{
		"mixed", "repeated", "wildcard", "nil-destinations", "empty-destinations",
		"nil-protocols", "empty-protocols", "app-only", "single-protocol",
		"single-protocol-app", "nil-sources", "empty-sources", "empty-app",
		"empty-group", "missing-user", "missing-host", "partial-group",
	} {
		t.Run(name, func(t *testing.T) {
			pol, users, nodes := compileOtherDestsFixture(t, 4, 24)
			grant := pol.Grants[0]

			switch name {
			case "mixed":
				grant.Destinations = Aliases{
					tp("tag:a"),
					hp("host6"),
					gp("group:some"),
					up("u1@"),
					pp("10.33.0.0/16"),
				}
			case "repeated":
				grant.Destinations = Aliases{
					gp("group:all"),
					gp("group:all"),
					hp("host4"),
					hp("host4"),
				}
			case "wildcard":
				grant.Destinations = Aliases{Asterix(0), hp("host4"), Asterix(0)}
			case "nil-destinations":
				grant.Destinations = nil
			case "empty-destinations":
				grant.Destinations = Aliases{}
			case "nil-protocols":
				grant.InternetProtocols, grant.App = nil, nil
			case "empty-protocols":
				grant.InternetProtocols, grant.App = []ProtocolPort{}, tailcfg.PeerCapMap{}
			case "app-only":
				grant.InternetProtocols = nil
			case "single-protocol":
				grant.InternetProtocols, grant.App = grant.InternetProtocols[:1], nil
			case "single-protocol-app":
				grant.InternetProtocols = grant.InternetProtocols[:1]
			case "nil-sources":
				grant.Sources = nil
			case "empty-sources":
				grant.Sources = Aliases{}
			case "empty-app":
				grant.App = tailcfg.PeerCapMap{}
			case "empty-group":
				grant.Destinations = Aliases{gp("group:empty")}
			case "missing-user":
				grant.Destinations = Aliases{up("missing@"), gp("group:missing")}
			case "missing-host":
				grant.Destinations = Aliases{
					hp("undefined"),
					hp("host4"),
					hp("undefined"),
				}
			case "partial-group":
				users = append(users, types.User{ID: 100, Name: users[0].Name})
				ips, err := grant.Destinations[0].Resolve(pol, users, nodes.ViewSlice())
				require.Error(t, err)
				require.NotNil(t, ips)
				require.False(
					t,
					ips.Empty(),
					"exercise a partial result alongside the error",
				)
			}

			assertCompileOtherDestsReference(t, pol, users, nodes, grant)
		})
	}
}

//nolint:gosec // Seeded random data makes the differential test reproducible.
func TestCompileOtherDestsRandomizedReference(t *testing.T) {
	rng := rand.New(rand.NewPCG(3556, 20261018))
	aliases := []string{
		"*", "autogroup:member", "autogroup:tagged", "group:all", "group:some",
		"group:empty", "group:missing", "tag:a", "tag:b", "host4", "host6",
		"u0@", "u1@", "missing@", "100.64.0.1", "10.33.0.0/16", "fd7a:115c:a1e0::1",
	}

	for iteration := range 200 {
		t.Run(strconv.Itoa(iteration), func(t *testing.T) {
			pol, users, nodes := compileOtherDestsFixture(t, 4, rng.IntN(32))
			for _, n := range nodes {
				if rng.IntN(4) == 0 {
					n.IPv4 = nil
				}

				if rng.IntN(4) == 0 {
					n.IPv6 = nil
				}

				if rng.IntN(5) == 0 {
					n.User = nil
				}

				if n.Hostinfo != nil && rng.IntN(2) == 0 {
					n.ApprovedRoutes = n.ApprovedRoutes[:1]
				}
			}

			grant := pol.Grants[0]

			grant.Destinations = make(Aliases, rng.IntN(12))
			for i := range grant.Destinations {
				name := aliases[rng.IntN(len(aliases))]
				if i > 0 && rng.IntN(2) == 0 {
					name = grant.Destinations[i-1].String()
				}

				alias, err := parseAlias(name)
				require.NoError(t, err)

				grant.Destinations[i] = alias
			}

			grant.InternetProtocols = make([]ProtocolPort, rng.IntN(5))
			for i := range grant.InternetProtocols {
				grant.InternetProtocols[i] = ProtocolPort{
					Protocol: Protocol([]string{"tcp", "udp", "icmp", ""}[rng.IntN(4)]),
				}
				for range rng.IntN(4) {
					port := uint16(rng.IntN(65536)) //nolint:gosec
					grant.InternetProtocols[i].Ports = append(
						grant.InternetProtocols[i].Ports,
						tailcfg.PortRange{First: port, Last: port},
					)
				}
			}

			switch rng.IntN(4) {
			case 0:
				grant.App = nil
				grant.Destinations = append(grant.Destinations, new(AutoGroupInternet))
			case 1:
				grant.App = tailcfg.PeerCapMap{}
			}

			switch rng.IntN(4) {
			case 0:
				grant.Sources = nil
			case 1:
				grant.Sources = Aliases{}
			case 2:
				grant.Sources = Aliases{up("missing@")}
			}

			if rng.IntN(3) == 0 {
				users = append(users, types.User{ID: 100, Name: users[0].Name})
				grant.Destinations = append(
					grant.Destinations,
					gp("group:all"),
					hp("undefined"),
				)
			}

			assertCompileOtherDestsReference(t, pol, users, nodes, grant)
		})
	}
}

type countedDestination struct {
	Alias

	calls int
}

func (dst *countedDestination) Resolve(
	pol *Policy,
	users types.Users,
	nodes views.Slice[types.NodeView],
) (ResolvedAddresses, error) {
	dst.calls++

	return dst.Alias.Resolve(pol, users, nodes)
}

func TestCompileOtherDestsResolvesOnce(t *testing.T) {
	pol, users, nodes := compileOtherDestsFixture(t, 4, 24)
	grant := pol.Grants[0]
	srcs, nonWild, err := resolveSources(pol, grant.Sources, users, nodes.ViewSlice())
	require.NoError(t, err)

	srcStrings := buildSrcIPStrings(srcs, nonWild, true, false, nodes.ViewSlice())
	dst := &countedDestination{Alias: gp("group:all")}
	grant.Destinations = Aliases{dst}

	want := pol.compileOtherDestsReference(users, nodes.ViewSlice(), grant,
		grant.Destinations, srcs, srcStrings)
	require.Equal(t, len(grant.InternetProtocols)+1, dst.calls)
	dst.calls = 0
	got := pol.compileOtherDests(users, nodes.ViewSlice(), grant,
		grant.Destinations, srcs, srcStrings)
	require.Equal(t, want, got)
	require.Equal(
		t,
		1,
		dst.calls,
		"share the real group resolution across protocols and app",
	)
}

var compileOtherDestsBenchmarkResult []tailcfg.FilterRule

func BenchmarkCompileOtherDests(b *testing.B) {
	for _, shape := range []struct {
		name   string
		users  int
		nodes  int
		dsts   []string
		single bool
	}{
		{name: "single-protocol", users: 8, nodes: 128, dsts: []string{"group:all", "host4"}, single: true},
		{name: "prefix-only", users: 8, nodes: 128, dsts: []string{"100.64.0.0/24", "fd7a:115c:a1e0::/64"}},
		{name: "wildcard-only", users: 8, nodes: 128, dsts: []string{"*"}},
		{name: "repeated", users: 8, nodes: 128, dsts: []string{"group:all", "host4", "group:all", "host4"}},
		{name: "unique", users: 8, nodes: 128, dsts: []string{"group:all", "group:some", "tag:a", "tag:b", "u0@", "u1@", "host4", "host6"}},
		{name: "large-group", users: 128, nodes: 1000, dsts: []string{"group:all", "group:some", "group:all", "group:some"}},
	} {
		b.Run(shape.name, func(b *testing.B) {
			pol, users, nodes := compileOtherDestsFixture(b, shape.users, shape.nodes)
			grant := pol.Grants[0]
			grant.Destinations = nil

			for _, name := range shape.dsts {
				alias, err := parseAlias(name)
				require.NoError(b, err)

				grant.Destinations = append(grant.Destinations, alias)
			}

			if shape.single {
				grant.InternetProtocols, grant.App = grant.InternetProtocols[:1], nil
			}

			srcs, nonWild, err := resolveSources(
				pol,
				grant.Sources,
				users,
				nodes.ViewSlice(),
			)
			require.NoError(b, err)

			srcStrings := buildSrcIPStrings(
				srcs,
				nonWild,
				true,
				false,
				nodes.ViewSlice(),
			)
			want := pol.compileOtherDestsReference(users, nodes.ViewSlice(), grant,
				grant.Destinations, srcs, srcStrings)
			require.NotEmpty(b, want)
			require.Equal(
				b,
				want,
				pol.compileOtherDests(users, nodes.ViewSlice(), grant,
					grant.Destinations, srcs, srcStrings),
			)

			for _, impl := range []struct {
				name string
				fn   func(types.Users, views.Slice[types.NodeView], Grant, Aliases, []ResolvedAddresses, []string) []tailcfg.FilterRule
			}{
				{name: "reference", fn: pol.compileOtherDestsReference},
				{name: "optimized", fn: pol.compileOtherDests},
			} {
				b.Run(impl.name, func(b *testing.B) {
					b.ReportAllocs()

					for b.Loop() {
						compileOtherDestsBenchmarkResult = impl.fn(
							users,
							nodes.ViewSlice(),
							grant,
							grant.Destinations,
							srcs,
							srcStrings,
						)
					}
				})
			}
		})
	}
}
