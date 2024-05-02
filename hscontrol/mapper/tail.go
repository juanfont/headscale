package mapper

import (
	"fmt"
	"net/netip"
	"time"

	"github.com/juanfont/headscale/hscontrol/policy"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/samber/lo"
	"tailscale.com/tailcfg"
)

func tailNodes(
	nodes types.Nodes,
	capVer tailcfg.CapabilityVersion,
	pol *policy.ACLPolicy,
	cfg *types.Config,
) ([]*tailcfg.Node, error) {
	tNodes := make([]*tailcfg.Node, len(nodes))

	for index, node := range nodes {
		node, err := tailNode(
			node,
			capVer,
			pol,
			cfg,
		)
		if err != nil {
			return nil, err
		}

		tNodes[index] = node
	}

	return tNodes, nil
}

// tailNode converts a Node into a Tailscale Node. includeRoutes is false for shared nodes
// as per the expected behaviour in the official SaaS.
func tailNode(
	node *types.Node,
	capVer tailcfg.CapabilityVersion,
	pol *policy.ACLPolicy,
	cfg *types.Config,
) (*tailcfg.Node, error) {
	addrs := node.Prefixes()

	allowedIPs := append(
		[]netip.Prefix{},
		addrs...) // we append the node own IP, as it is required by the clients

	primaryPrefixes := []netip.Prefix{}

	for _, route := range node.Routes {
		if route.Enabled {
			if route.IsPrimary {
				allowedIPs = append(allowedIPs, netip.Prefix(route.Prefix))
				primaryPrefixes = append(primaryPrefixes, netip.Prefix(route.Prefix))
			} else if route.IsExitRoute() {
				allowedIPs = append(allowedIPs, netip.Prefix(route.Prefix))
			}
		}
	}

	var derp string
	if node.Hostinfo != nil && node.Hostinfo.NetInfo != nil {
		derp = fmt.Sprintf("127.3.3.40:%d", node.Hostinfo.NetInfo.PreferredDERP)
	} else {
		derp = "127.3.3.40:0" // Zero means disconnected or unknown.
	}

	var keyExpiry time.Time
	if node.Expiry != nil {
		keyExpiry = *node.Expiry
	} else {
		keyExpiry = time.Time{}
	}

	hostname, err := node.GetFQDN(cfg.DNSConfig, cfg.BaseDomain)
	if err != nil {
		return nil, fmt.Errorf("tailNode, failed to create FQDN: %s", err)
	}

	tags, _ := pol.TagsOfNode(node)
	tags = lo.Uniq(append(tags, node.ForcedTags...))

	tNode := tailcfg.Node{
		ID:       tailcfg.NodeID(node.ID), // this is the actual ID
		StableID: node.ID.StableID(),
		Name:     hostname,
		Cap:      capVer,

		User: tailcfg.UserID(node.UserID),

		Key:       node.NodeKey,
		KeyExpiry: keyExpiry,

		Machine:    node.MachineKey,
		DiscoKey:   node.DiscoKey,
		Addresses:  addrs,
		AllowedIPs: allowedIPs,
		Endpoints:  node.Endpoints,
		DERP:       derp,
		Hostinfo:   node.Hostinfo.View(),
		Created:    node.CreatedAt,

		Online: node.IsOnline,

		Tags: tags,

		PrimaryRoutes: primaryPrefixes,

		MachineAuthorized: !node.IsExpired(),
		Expired:           node.IsExpired(),
	}

	//   - 74: 2023-09-18: Client understands NodeCapMap
	if capVer >= 74 {
		tNode.CapMap = tailcfg.NodeCapMap{
			tailcfg.CapabilityFileSharing: []tailcfg.RawMessage{},
			tailcfg.CapabilityAdmin:       []tailcfg.RawMessage{},
			tailcfg.CapabilitySSH:         []tailcfg.RawMessage{},
		}

		if cfg.RandomizeClientPort {
			tNode.CapMap[tailcfg.NodeAttrRandomizeClientPort] = []tailcfg.RawMessage{}
		}
	} else {
		tNode.Capabilities = []tailcfg.NodeCapability{
			tailcfg.CapabilityFileSharing,
			tailcfg.CapabilityAdmin,
			tailcfg.CapabilitySSH,
		}

		if cfg.RandomizeClientPort {
			tNode.Capabilities = append(tNode.Capabilities, tailcfg.NodeAttrRandomizeClientPort)
		}
	}

	//   - 72: 2023-08-23: TS-2023-006 UPnP issue fixed; UPnP can now be used again
	if capVer < 72 {
		tNode.Capabilities = append(tNode.Capabilities, tailcfg.NodeAttrDisableUPnP)
	}

	if node.IsOnline == nil || !*node.IsOnline {
		// LastSeen is only set when node is
		// not connected to the control server.
		tNode.LastSeen = node.LastSeen
	}

	return &tNode, nil
}
