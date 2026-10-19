package v2

import (
	"fmt"
	"net/netip"
	"slices"

	"github.com/juanfont/headscale/hscontrol/ipset"
	"github.com/juanfont/headscale/hscontrol/policy/packetfilter"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/rs/zerolog/log"
	"tailscale.com/tailcfg"
	"tailscale.com/tailcfg/nodecap"
	"tailscale.com/tailcfg/peercap"
	"tailscale.com/types/ipproto"
	"tailscale.com/types/views"
)

// compileNodeAttrs returns the per-node CapMap derived from policy
// nodeAttrs plus the tailnet-wide [Policy.RandomizeClientPort] flag.
//
// Returns an error when a target alias fails to resolve so the caller
// surfaces a corrupt policy instead of silently granting a partial set
// of attrs.
func (pol *Policy) compileNodeAttrs(
	users types.Users,
	nodes views.Slice[types.NodeView],
) (map[types.NodeID]tailcfg.NodeCapMap, error) {
	empty := map[types.NodeID]tailcfg.NodeCapMap{}

	if pol == nil {
		return empty, nil
	}

	if len(pol.NodeAttrs) == 0 && !pol.RandomizeClientPort {
		return empty, nil
	}

	result := make(map[types.NodeID]tailcfg.NodeCapMap)
	stamp := func(id types.NodeID, attr nodecap.Cap) {
		capMap, ok := result[id]
		if !ok {
			capMap = tailcfg.NodeCapMap{}
			result[id] = capMap
		}

		// nil [tailcfg.RawMessage] matches the wire format from a
		// Tailscale-hosted control plane: capabilities without companion
		// data marshal as null rather than []. Storing nil keeps the
		// merge stable and lets the compat test diff cleanly against
		// captured netmaps.
		if _, exists := capMap[attr]; !exists {
			capMap[attr] = nil
		}
	}

	// Cache each node's IPs once per call. Without the cache, the
	// node-attr inner loop would call [types.NodeView.IPs] once per attr
	// per node — O(grants × nodes) allocations of a 2-element slice
	// for what is invariant per node within a single policy compile.
	type nodeIPs struct {
		id  types.NodeID
		ips []netip.Addr
	}

	nodeList := make([]nodeIPs, 0, nodes.Len())
	for _, n := range nodes.All() {
		nodeList = append(nodeList, nodeIPs{id: n.ID(), ips: n.IPs()})
	}

	if pol.RandomizeClientPort {
		for _, ni := range nodeList {
			stamp(ni.id, nodecap.RandomizeClientPort)
		}
	}

	for _, na := range pol.NodeAttrs {
		if len(na.Attrs) == 0 {
			continue
		}

		resolved, err := na.Targets.Resolve(pol, users, nodes)
		if err != nil {
			return nil, fmt.Errorf("nodeAttrs target %s: %w", na.Targets, err)
		}

		if resolved.IsEmpty() {
			continue
		}

		for _, ni := range nodeList {
			if !slices.ContainsFunc(ni.ips, resolved.Contains) {
				continue
			}

			for _, attr := range na.Attrs {
				stamp(ni.id, attr)
			}
		}
	}

	return result, nil
}

// resolvedSources preserves each consumer's resolution-error policy.
type resolvedSources struct {
	Raw    ipset.Set
	Viewer ipset.Set
	Packet ipset.Set
}

type aliasResolution struct {
	addresses ipset.Set
	err       error
}

type resolutionCache struct {
	pol     *Policy
	users   types.Users
	nodes   views.Slice[types.NodeView]
	aliases map[string]aliasResolution
}

func (c *resolutionCache) resolve(alias Alias) aliasResolution {
	// Alias syntax identifies its meaning inside these immutable inputs.
	key := fmt.Sprintf("%T:%s", alias, alias.String())
	if result, ok := c.aliases[key]; ok {
		return result
	}

	addresses, err := alias.Resolve(c.pol, c.users, c.nodes)
	result := aliasResolution{addresses, err}
	c.aliases[key] = result

	if err != nil {
		log.Trace().Err(err).Msg("resolving policy alias")
	}

	return result
}

func (c *resolutionCache) sources(aliases Aliases) (resolvedSources, error) {
	var raw, viewer ipset.Builder

	for _, alias := range aliases {
		if ag, ok := alias.(*AutoGroup); ok && ag.Is(AutoGroupSelf) {
			return resolvedSources{}, errSelfInSources
		}

		result := c.resolve(alias)
		raw.AddSet(result.addresses)

		if result.err == nil {
			viewer.AddSet(result.addresses)
		}
	}

	rawSet, err := raw.Build()
	if err != nil {
		return resolvedSources{}, err
	}

	viewerSet, err := viewer.Build()
	if err != nil {
		return resolvedSources{}, err
	}

	packet := rawSet

	if sourcesHaveWildcard(aliases) {
		var routes ipset.Builder
		routes.AddSet(rawSet)

		for _, node := range c.nodes.All() {
			for _, prefix := range node.SubnetRoutes() {
				routes.AddPrefix(prefix)
			}
		}

		packet, err = routes.Build()
		if err != nil {
			return resolvedSources{}, err
		}
	}

	if sourcesHaveDangerAll(aliases) {
		packet = ipset.All()
	}

	return resolvedSources{Raw: rawSet, Viewer: viewerSet, Packet: packet}, nil
}

type resolvedDestination struct {
	addresses ipset.Set
	err       error
	wildcard  bool
}

// ruleFragment is constructor input. Only final, owner-aware groups become Rules.
type ruleFragment struct {
	sources      ipset.Set
	destinations []packetfilter.Destination
	protocols    []ipproto.Proto
	capabilities []packetfilter.CapabilityGrant
}

type compiledGrant struct {
	sources   resolvedSources
	fragments []ruleFragment
	self      *selfGrantData
	via       *viaGrantData
	// Viewer destinations omit aliases that failed, including partial results.
	viewerDsts        []netip.Prefix
	internet          bool
	autoGroupInternet bool
}

type selfGrantData struct {
	internetProtocols []ProtocolPort
	app               tailcfg.PeerCapMap
}

type viaGrantData struct {
	viaTags              []Tag
	resolvedDsts         []netip.Prefix
	hasAutoGroupInternet bool
	internetProtocols    []ProtocolPort
}

// compileGrants resolves each alias once, retaining both its result and its error.
func (pol *Policy) compileGrants(
	users types.Users,
	nodes views.Slice[types.NodeView],
) []compiledGrant {
	if pol == nil || (pol.ACLs == nil && pol.Grants == nil) {
		return nil
	}

	cache := resolutionCache{pol, users, nodes, make(map[string]aliasResolution)}

	grants := slices.Clone(pol.Grants)
	for _, acl := range pol.ACLs {
		grants = append(grants, aclToGrants(acl)...)
	}

	compiled := make([]compiledGrant, 0, len(grants))
	for _, grant := range grants {
		sources, err := cache.sources(grant.Sources)
		if err != nil {
			log.Trace().Err(err).Msg("compiling grant")
			continue
		}

		cg := compiledGrant{sources: sources, internet: grantReachesInternet(grant)}

		var destinations []resolvedDestination

		for _, alias := range grant.Destinations {
			if ag, ok := alias.(*AutoGroup); ok {
				if ag.Is(AutoGroupSelf) {
					cg.self = &selfGrantData{grant.InternetProtocols, grant.App}
					continue
				}

				if ag.Is(AutoGroupInternet) {
					if cg.via == nil {
						cg.via = &viaGrantData{}
					}

					cg.via.hasAutoGroupInternet = true
					cg.autoGroupInternet = true
				}
			}

			result := cache.resolve(alias)
			_, wildcard := alias.(Asterix)

			destinations = append(
				destinations,
				resolvedDestination{result.addresses, result.err, wildcard},
			)
			if result.err == nil {
				if ag, ok := alias.(*AutoGroup); !ok || !ag.Is(AutoGroupInternet) {
					cg.viewerDsts = append(
						cg.viewerDsts,
						slices.Collect(result.addresses.Prefixes())...)
				}
			}
		}

		if len(grant.Via) > 0 {
			if cg.via == nil {
				cg.via = &viaGrantData{}
			}

			cg.via.viaTags = slices.Clone(grant.Via)
			cg.via.resolvedDsts = cg.viewerDsts
			cg.via.internetProtocols = grant.InternetProtocols
			cg.self = nil
		} else {
			// An internet destination alone is ordinary; the flag still serves via queries.
			cg.via = nil

			if len(grant.Sources) > 0 && len(grant.Destinations) > 0 {
				var companionExtra ipset.Builder

				if grant.App != nil && sourcesHaveWildcard(grant.Destinations) {
					for _, node := range nodes.All() {
						for _, prefix := range node.SubnetRoutes() {
							companionExtra.AddPrefix(prefix)
						}
					}
				}

				extra, _ := companionExtra.Build()
				cg.fragments = compileDestinations(
					sources.Packet,
					sources.Raw,
					destinations,
					grant.InternetProtocols,
					grant.App,
					extra,
				)
			}
		}

		compiled = append(compiled, cg)
	}

	return compiled
}

func compileDestinations(
	packet, raw ipset.Set,
	destinations []resolvedDestination,
	protocols []ProtocolPort,
	app tailcfg.PeerCapMap,
	companionExtra ipset.Set,
) []ruleFragment {
	// Ordinary canonical prefixes remain independently reducible across ports/protocols.
	var groups []ipset.Set

	for _, destination := range destinations {
		if destination.wildcard {
			groups = append(groups, ipset.All())
			continue
		}

		for prefix := range destination.addresses.Prefixes() {
			groups = append(groups, singletonPrefix(prefix))
		}
	}

	var fragments []ruleFragment

	if !packet.IsEmpty() {
		for _, protocol := range protocols {
			var entries []packetfilter.Destination

			for _, group := range groups {
				for _, ports := range protocol.Ports {
					entries = append(
						entries,
						packetfilter.Destination{Addresses: group, Ports: ports},
					)
				}
			}

			if len(entries) > 0 {
				fragments = append(
					fragments,
					ruleFragment{
						sources:      packet,
						destinations: entries,
						protocols:    protocol.Protocol.IPProtocols(),
					},
				)
			}
		}
	}

	if app != nil {
		var caps []packetfilter.CapabilityGrant

		var companionSources ipset.Builder

		for _, destination := range destinations {
			if destination.err != nil {
				continue
			}

			caps = append(
				caps,
				packetfilter.CapabilityGrant{
					Addresses: destination.addresses,
					CapMap:    app,
				},
			)
			companionSources.AddSet(destination.addresses)
		}

		if len(caps) > 0 {
			fragments = append(
				fragments,
				ruleFragment{sources: packet, capabilities: caps},
			)

			companionSources.AddSet(companionExtra)
			companionSet, _ := companionSources.Build()

			for _, companion := range companionCaps {
				if _, ok := app[companion.original]; ok {
					fragments = append(
						fragments,
						ruleFragment{
							sources: companionSet,
							capabilities: []packetfilter.CapabilityGrant{
								{
									Addresses: raw,
									CapMap: tailcfg.PeerCapMap{
										companion.companion: nil,
									},
								},
							},
						},
					)
				}
			}
		}
	}

	return fragments
}

type companionCap struct{ original, companion peercap.Cap }

var companionCaps = []companionCap{
	{peercap.Taildrive, peercap.TaildriveSharer},
	{peercap.Relay, peercap.RelayTarget},
}

func sourcesHaveWildcard(aliases Aliases) bool {
	return slices.ContainsFunc(
		aliases,
		func(alias Alias) bool { _, ok := alias.(Asterix); return ok },
	)
}

func sourcesHaveDangerAll(aliases Aliases) bool {
	return slices.ContainsFunc(
		aliases,
		func(alias Alias) bool { ag, ok := alias.(*AutoGroup); return ok && ag.Is(AutoGroupDangerAll) },
	)
}

func compileViaForNode(grant *compiledGrant, node types.NodeView) []ruleFragment {
	via := grant.via
	if via == nil || !slices.ContainsFunc(
		via.viaTags,
		func(tag Tag) bool { return node.HasTag(string(tag)) },
	) {
		return nil
	}

	var destinations []resolvedDestination

	for _, prefix := range via.resolvedDsts {
		if slices.ContainsFunc(node.SubnetRoutes(), prefix.Overlaps) {
			destinations = append(
				destinations,
				resolvedDestination{addresses: singletonPrefix(prefix)},
			)
		}
	}

	if via.hasAutoGroupInternet && node.IsExitNode() {
		for prefix := range util.TheInternet().Prefixes() {
			destinations = append(
				destinations,
				resolvedDestination{addresses: singletonPrefix(prefix)},
			)
		}
	}

	return compileDestinations(
		grant.sources.Packet,
		grant.sources.Raw,
		destinations,
		via.internetProtocols,
		nil,
		ipset.Set{},
	)
}

func collectRelayTargetIPs(grants []compiledGrant) (ipset.Set, error) {
	var builder ipset.Builder

	for _, grant := range grants {
		for _, fragment := range grant.fragments {
			for _, cap := range fragment.capabilities {
				if _, ok := cap.CapMap[peercap.Relay]; ok {
					builder.AddSet(cap.Addresses)
				}
			}
		}
	}

	return builder.Build()
}

func collectViaTargetTags(grants []compiledGrant) map[Tag]struct{} {
	tags := make(map[Tag]struct{})

	for _, grant := range grants {
		if grant.via != nil {
			for _, tag := range grant.via.viaTags {
				tags[tag] = struct{}{}
			}
		}
	}

	return tags
}

func hasPerNodeGrants(grants []compiledGrant) bool {
	return slices.ContainsFunc(
		grants,
		func(grant compiledGrant) bool { return grant.self != nil || grant.via != nil },
	)
}
