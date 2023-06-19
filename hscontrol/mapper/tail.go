package mapper

import (
	"fmt"
	"net/netip"
	"strconv"
	"time"

	"github.com/juanfont/headscale/hscontrol/policy"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/samber/lo"
	"tailscale.com/tailcfg"
)

func tailNodes(
	machines types.Machines,
	pol *policy.ACLPolicy,
	dnsConfig *tailcfg.DNSConfig,
	baseDomain string,
) ([]*tailcfg.Node, error) {
	nodes := make([]*tailcfg.Node, len(machines))

	for index, machine := range machines {
		node, err := tailNode(
			machine,
			pol,
			dnsConfig,
			baseDomain,
		)
		if err != nil {
			return nil, err
		}

		nodes[index] = node
	}

	return nodes, nil
}

// tailNode converts a Machine into a Tailscale Node. includeRoutes is false for shared nodes
// as per the expected behaviour in the official SaaS.
func tailNode(
	machine types.Machine,
	pol *policy.ACLPolicy,
	dnsConfig *tailcfg.DNSConfig,
	baseDomain string,
) (*tailcfg.Node, error) {
	nodeKey, err := machine.NodePublicKey()
	if err != nil {
		return nil, err
	}

	// MachineKey is only used in the legacy protocol
	machineKey, err := machine.MachinePublicKey()
	if err != nil {
		return nil, err
	}

	discoKey, err := machine.DiscoPublicKey()
	if err != nil {
		return nil, err
	}

	addrs := machine.IPAddresses.Prefixes()

	allowedIPs := append(
		[]netip.Prefix{},
		addrs...) // we append the node own IP, as it is required by the clients

	primaryPrefixes := []netip.Prefix{}

	for _, route := range machine.Routes {
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
	if machine.HostInfo.NetInfo != nil {
		derp = fmt.Sprintf("127.3.3.40:%d", machine.HostInfo.NetInfo.PreferredDERP)
	} else {
		derp = "127.3.3.40:0" // Zero means disconnected or unknown.
	}

	var keyExpiry time.Time
	if machine.Expiry != nil {
		keyExpiry = *machine.Expiry
	} else {
		keyExpiry = time.Time{}
	}

	hostname, err := machine.GetFQDN(dnsConfig, baseDomain)
	if err != nil {
		return nil, err
	}

	hostInfo := machine.GetHostInfo()

	online := machine.IsOnline()

	tags, _ := pol.TagsOfMachine(machine)
	tags = lo.Uniq(append(tags, machine.ForcedTags...))

	node := tailcfg.Node{
		ID: tailcfg.NodeID(machine.ID), // this is the actual ID
		StableID: tailcfg.StableNodeID(
			strconv.FormatUint(machine.ID, util.Base10),
		), // in headscale, unlike tailcontrol server, IDs are permanent
		Name: hostname,

		User: tailcfg.UserID(machine.UserID),

		Key:       nodeKey,
		KeyExpiry: keyExpiry,

		Machine:    machineKey,
		DiscoKey:   discoKey,
		Addresses:  addrs,
		AllowedIPs: allowedIPs,
		Endpoints:  machine.Endpoints,
		DERP:       derp,
		Hostinfo:   hostInfo.View(),
		Created:    machine.CreatedAt,

		Tags: tags,

		PrimaryRoutes: primaryPrefixes,

		LastSeen:          machine.LastSeen,
		Online:            &online,
		KeepAlive:         true,
		MachineAuthorized: !machine.IsExpired(),

		Capabilities: []string{
			tailcfg.CapabilityFileSharing,
			tailcfg.CapabilityAdmin,
			tailcfg.CapabilitySSH,
		},
	}

	return &node, nil
}
