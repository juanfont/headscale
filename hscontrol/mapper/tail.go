package mapper

import (
	"fmt"
	"time"

	"github.com/juanfont/headscale/hscontrol/policy"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/samber/lo"
	"tailscale.com/net/tsaddr"
	"tailscale.com/tailcfg"
)

func tailNodes(
	nodes types.Nodes,
	capVer tailcfg.CapabilityVersion,
	polMan policy.PolicyManager,
	primaryRouteFunc routeFilterFunc,
	cfg *types.Config,
) ([]*tailcfg.Node, error) {
	tNodes := make([]*tailcfg.Node, len(nodes))

	for index, node := range nodes {
		node, err := tailNode(
			node,
			capVer,
			polMan,
			primaryRouteFunc,
			cfg,
		)
		if err != nil {
			return nil, err
		}

		tNodes[index] = node
	}

	return tNodes, nil
}

// tailNode converts a Node into a Tailscale Node.
func tailNode(
	node *types.Node,
	capVer tailcfg.CapabilityVersion,
	polMan policy.PolicyManager,
	primaryRouteFunc routeFilterFunc,
	cfg *types.Config,
) (*tailcfg.Node, error) {
	addrs := node.Prefixes()

	var derp int

	// TODO(kradalby): legacyDERP was removed in tailscale/tailscale@2fc4455e6dd9ab7f879d4e2f7cffc2be81f14077
	// and should be removed after 111 is the minimum capver.
	var legacyDERP string
	if node.Hostinfo != nil && node.Hostinfo.NetInfo != nil {
		legacyDERP = fmt.Sprintf("127.3.3.40:%d", node.Hostinfo.NetInfo.PreferredDERP)
		derp = node.Hostinfo.NetInfo.PreferredDERP
	} else {
		legacyDERP = "127.3.3.40:0" // Zero means disconnected or unknown.
	}

	var keyExpiry time.Time
	if node.Expiry != nil {
		keyExpiry = *node.Expiry
	} else {
		keyExpiry = time.Time{}
	}

	hostname, err := node.GetFQDN(cfg.BaseDomain)
	if err != nil {
		return nil, fmt.Errorf("tailNode, failed to create FQDN: %s", err)
	}

	var tags []string
	for _, tag := range node.RequestTags() {
		if polMan.NodeCanHaveTag(node, tag) {
			tags = append(tags, tag)
		}
	}
	tags = lo.Uniq(append(tags, node.ForcedTags...))

	routes := primaryRouteFunc(node.ID)
	allowed := append(node.Prefixes(), routes...)
	allowed = append(allowed, node.ExitRoutes()...)
	tsaddr.SortPrefixes(allowed)

	tNode := tailcfg.Node{
		ID:       tailcfg.NodeID(node.ID), // this is the actual ID
		StableID: node.ID.StableID(),
		Name:     hostname,
		Cap:      capVer,

		User: tailcfg.UserID(node.UserID),

		Key:       node.NodeKey,
		KeyExpiry: keyExpiry.UTC(),

		Machine:          node.MachineKey,
		DiscoKey:         node.DiscoKey,
		Addresses:        addrs,
		PrimaryRoutes:    routes,
		AllowedIPs:       allowed,
		Endpoints:        node.Endpoints,
		HomeDERP:         derp,
		LegacyDERPString: legacyDERP,
		Hostinfo:         node.Hostinfo.View(),
		Created:          node.CreatedAt.UTC(),

		Online: node.IsOnline,

		Tags: tags,

		MachineAuthorized: !node.IsExpired(),
		Expired:           node.IsExpired(),
	}

	tNode.CapMap = tailcfg.NodeCapMap{
		tailcfg.CapabilityFileSharing: []tailcfg.RawMessage{},
		tailcfg.CapabilityAdmin:       []tailcfg.RawMessage{},
		tailcfg.CapabilitySSH:         []tailcfg.RawMessage{},
	}

	if cfg.RandomizeClientPort {
		tNode.CapMap[tailcfg.NodeAttrRandomizeClientPort] = []tailcfg.RawMessage{}
	}

	if node.IsOnline == nil || !*node.IsOnline {
		// LastSeen is only set when node is
		// not connected to the control server.
		tNode.LastSeen = node.LastSeen
	}

	return &tNode, nil
}
