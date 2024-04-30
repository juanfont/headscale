package policy

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/rs/zerolog/log"
	"github.com/tailscale/hujson"
	"go4.org/netipx"
	"gopkg.in/yaml.v3"
	"tailscale.com/tailcfg"
)

var (
	ErrEmptyPolicy       = errors.New("empty policy")
	ErrInvalidAction     = errors.New("invalid action")
	ErrInvalidGroup      = errors.New("invalid group")
	ErrInvalidTag        = errors.New("invalid tag")
	ErrInvalidPortFormat = errors.New("invalid port format")
	ErrWildcardIsNeeded  = errors.New("wildcard as port is required for the protocol")
)

const (
	portRangeBegin     = 0
	portRangeEnd       = 65535
	expectedTokenItems = 2
)

var theInternetSet *netipx.IPSet

// theInternet returns the IPSet for the Internet.
// https://www.youtube.com/watch?v=iDbyYGrswtg
func theInternet() *netipx.IPSet {
	if theInternetSet != nil {
		return theInternetSet
	}

	var internetBuilder netipx.IPSetBuilder
	internetBuilder.AddPrefix(netip.MustParsePrefix("2000::/3"))
	internetBuilder.AddPrefix(netip.MustParsePrefix("0.0.0.0/0"))

	// Delete Private network addresses
	// https://datatracker.ietf.org/doc/html/rfc1918
	internetBuilder.RemovePrefix(netip.MustParsePrefix("fc00::/7"))
	internetBuilder.RemovePrefix(netip.MustParsePrefix("10.0.0.0/8"))
	internetBuilder.RemovePrefix(netip.MustParsePrefix("172.16.0.0/12"))
	internetBuilder.RemovePrefix(netip.MustParsePrefix("192.168.0.0/16"))

	// Delete Tailscale networks
	internetBuilder.RemovePrefix(netip.MustParsePrefix("fd7a:115c:a1e0::/48"))
	internetBuilder.RemovePrefix(netip.MustParsePrefix("100.64.0.0/10"))

	// Delete "cant find DHCP networks"
	internetBuilder.RemovePrefix(netip.MustParsePrefix("fe80::/10")) // link-loca
	internetBuilder.RemovePrefix(netip.MustParsePrefix("169.254.0.0/16"))

	theInternetSet, _ := internetBuilder.IPSet()
	return theInternetSet
}

// For some reason golang.org/x/net/internal/iana is an internal package.
const (
	protocolICMP     = 1   // Internet Control Message
	protocolIGMP     = 2   // Internet Group Management
	protocolIPv4     = 4   // IPv4 encapsulation
	protocolTCP      = 6   // Transmission Control
	protocolEGP      = 8   // Exterior Gateway Protocol
	protocolIGP      = 9   // any private interior gateway (used by Cisco for their IGRP)
	protocolUDP      = 17  // User Datagram
	protocolGRE      = 47  // Generic Routing Encapsulation
	protocolESP      = 50  // Encap Security Payload
	protocolAH       = 51  // Authentication Header
	protocolIPv6ICMP = 58  // ICMP for IPv6
	protocolSCTP     = 132 // Stream Control Transmission Protocol
	ProtocolFC       = 133 // Fibre Channel
)

// LoadACLPolicyFromPath loads the ACL policy from the specify path, and generates the ACL rules.
func LoadACLPolicyFromPath(path string) (*ACLPolicy, error) {
	log.Debug().
		Str("func", "LoadACLPolicy").
		Str("path", path).
		Msg("Loading ACL policy from path")

	policyFile, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer policyFile.Close()

	policyBytes, err := io.ReadAll(policyFile)
	if err != nil {
		return nil, err
	}

	log.Debug().
		Str("path", path).
		Bytes("file", policyBytes).
		Msg("Loading ACLs")

	switch filepath.Ext(path) {
	case ".yml", ".yaml":
		return LoadACLPolicyFromBytes(policyBytes, "yaml")
	}

	return LoadACLPolicyFromBytes(policyBytes, "hujson")
}

func LoadACLPolicyFromBytes(acl []byte, format string) (*ACLPolicy, error) {
	var policy ACLPolicy
	switch format {
	case "yaml":
		err := yaml.Unmarshal(acl, &policy)
		if err != nil {
			return nil, err
		}

	default:
		ast, err := hujson.Parse(acl)
		if err != nil {
			return nil, err
		}

		ast.Standardize()
		acl = ast.Pack()
		err = json.Unmarshal(acl, &policy)
		if err != nil {
			return nil, err
		}
	}

	if policy.IsZero() {
		return nil, ErrEmptyPolicy
	}

	return &policy, nil
}

func GenerateFilterAndSSHRulesForTests(
	policy *ACLPolicy,
	node *types.Node,
	peers types.Nodes,
) ([]tailcfg.FilterRule, *tailcfg.SSHPolicy, error) {
	// If there is no policy defined, we default to allow all
	if policy == nil {
		return tailcfg.FilterAllowAll, &tailcfg.SSHPolicy{}, nil
	}

	rules, err := policy.CompileFilterRules(append(peers, node))
	if err != nil {
		return []tailcfg.FilterRule{}, &tailcfg.SSHPolicy{}, err
	}

	log.Trace().Interface("ACL", rules).Str("node", node.GivenName).Msg("ACL rules")

	sshPolicy, err := policy.CompileSSHPolicy(node, peers)
	if err != nil {
		return []tailcfg.FilterRule{}, &tailcfg.SSHPolicy{}, err
	}

	return rules, sshPolicy, nil
}

// CompileFilterRules takes a set of nodes and an ACLPolicy and generates a
// set of Tailscale compatible FilterRules used to allow traffic on clients.
func (pol *ACLPolicy) CompileFilterRules(
	nodes types.Nodes,
) ([]tailcfg.FilterRule, error) {
	if pol == nil {
		return tailcfg.FilterAllowAll, nil
	}

	rules := []tailcfg.FilterRule{}

	for index, acl := range pol.ACLs {
		if acl.Action != "accept" {
			return nil, ErrInvalidAction
		}

		srcIPs := []string{}
		for srcIndex, src := range acl.Sources {
			srcs, err := pol.expandSource(src, nodes)
			if err != nil {
				return nil, fmt.Errorf("parsing policy, acl index: %d->%d: %w", index, srcIndex, err)
			}
			srcIPs = append(srcIPs, srcs...)
		}

		protocols, isWildcard, err := parseProtocol(acl.Protocol)
		if err != nil {
			return nil, fmt.Errorf("parsing policy, protocol err: %w ", err)
		}

		destPorts := []tailcfg.NetPortRange{}
		for _, dest := range acl.Destinations {
			alias, port, err := parseDestination(dest)
			if err != nil {
				return nil, err
			}

			expanded, err := pol.ExpandAlias(
				nodes,
				alias,
			)
			if err != nil {
				return nil, err
			}

			ports, err := expandPorts(port, isWildcard)
			if err != nil {
				return nil, err
			}

			dests := []tailcfg.NetPortRange{}
			for _, dest := range expanded.Prefixes() {
				for _, port := range *ports {
					pr := tailcfg.NetPortRange{
						IP:    dest.String(),
						Ports: port,
					}
					dests = append(dests, pr)
				}
			}
			destPorts = append(destPorts, dests...)
		}

		rules = append(rules, tailcfg.FilterRule{
			SrcIPs:   srcIPs,
			DstPorts: destPorts,
			IPProto:  protocols,
		})
	}

	return rules, nil
}

// ReduceFilterRules takes a node and a set of rules and removes all rules and destinations
// that are not relevant to that particular node.
func ReduceFilterRules(node *types.Node, rules []tailcfg.FilterRule) []tailcfg.FilterRule {
	ret := []tailcfg.FilterRule{}

	for _, rule := range rules {
		// record if the rule is actually relevant for the given node.
		dests := []tailcfg.NetPortRange{}

	DEST_LOOP:
		for _, dest := range rule.DstPorts {
			expanded, err := util.ParseIPSet(dest.IP, nil)
			// Fail closed, if we cant parse it, then we should not allow
			// access.
			if err != nil {
				continue DEST_LOOP
			}

			if node.InIPSet(expanded) {
				dests = append(dests, dest)
				continue DEST_LOOP
			}

			// If the node exposes routes, ensure they are note removed
			// when the filters are reduced.
			if node.Hostinfo != nil {
				if len(node.Hostinfo.RoutableIPs) > 0 {
					for _, routableIP := range node.Hostinfo.RoutableIPs {
						if expanded.OverlapsPrefix(routableIP) {
							dests = append(dests, dest)
							continue DEST_LOOP
						}
					}
				}
			}
		}

		if len(dests) > 0 {
			ret = append(ret, tailcfg.FilterRule{
				SrcIPs:   rule.SrcIPs,
				DstPorts: dests,
				IPProto:  rule.IPProto,
			})
		}
	}

	return ret
}

func (pol *ACLPolicy) CompileSSHPolicy(
	node *types.Node,
	peers types.Nodes,
) (*tailcfg.SSHPolicy, error) {
	if pol == nil {
		return nil, nil
	}

	rules := []*tailcfg.SSHRule{}

	acceptAction := tailcfg.SSHAction{
		Message:                  "",
		Reject:                   false,
		Accept:                   true,
		SessionDuration:          0,
		AllowAgentForwarding:     false,
		HoldAndDelegate:          "",
		AllowLocalPortForwarding: true,
	}

	rejectAction := tailcfg.SSHAction{
		Message:                  "",
		Reject:                   true,
		Accept:                   false,
		SessionDuration:          0,
		AllowAgentForwarding:     false,
		HoldAndDelegate:          "",
		AllowLocalPortForwarding: false,
	}

	for index, sshACL := range pol.SSHs {
		var dest netipx.IPSetBuilder
		for _, src := range sshACL.Destinations {
			expanded, err := pol.ExpandAlias(append(peers, node), src)
			if err != nil {
				return nil, err
			}
			dest.AddSet(expanded)
		}

		destSet, err := dest.IPSet()
		if err != nil {
			return nil, err
		}

		if !node.InIPSet(destSet) {
			continue
		}

		action := rejectAction
		switch sshACL.Action {
		case "accept":
			action = acceptAction
		case "check":
			checkAction, err := sshCheckAction(sshACL.CheckPeriod)
			if err != nil {
				return nil, fmt.Errorf("parsing SSH policy, parsing check duration, index: %d: %w", index, err)
			} else {
				action = *checkAction
			}
		default:
			return nil, fmt.Errorf("parsing SSH policy, unknown action %q, index: %d: %w", sshACL.Action, index, err)
		}

		principals := make([]*tailcfg.SSHPrincipal, 0, len(sshACL.Sources))
		for innerIndex, rawSrc := range sshACL.Sources {
			if isWildcard(rawSrc) {
				principals = append(principals, &tailcfg.SSHPrincipal{
					Any: true,
				})
			} else if isGroup(rawSrc) {
				users, err := pol.expandUsersFromGroup(rawSrc)
				if err != nil {
					return nil, fmt.Errorf("parsing SSH policy, expanding user from group, index: %d->%d: %w", index, innerIndex, err)
				}

				for _, user := range users {
					principals = append(principals, &tailcfg.SSHPrincipal{
						UserLogin: user,
					})
				}
			} else {
				expandedSrcs, err := pol.ExpandAlias(
					peers,
					rawSrc,
				)
				if err != nil {
					return nil, fmt.Errorf("parsing SSH policy, expanding alias, index: %d->%d: %w", index, innerIndex, err)
				}
				for _, expandedSrc := range expandedSrcs.Prefixes() {
					principals = append(principals, &tailcfg.SSHPrincipal{
						NodeIP: expandedSrc.Addr().String(),
					})
				}
			}
		}

		userMap := make(map[string]string, len(sshACL.Users))
		for _, user := range sshACL.Users {
			userMap[user] = "="
		}
		rules = append(rules, &tailcfg.SSHRule{
			Principals: principals,
			SSHUsers:   userMap,
			Action:     &action,
		})
	}

	return &tailcfg.SSHPolicy{
		Rules: rules,
	}, nil
}

func sshCheckAction(duration string) (*tailcfg.SSHAction, error) {
	sessionLength, err := time.ParseDuration(duration)
	if err != nil {
		return nil, err
	}

	return &tailcfg.SSHAction{
		Message:                  "",
		Reject:                   false,
		Accept:                   true,
		SessionDuration:          sessionLength,
		AllowAgentForwarding:     false,
		HoldAndDelegate:          "",
		AllowLocalPortForwarding: true,
	}, nil
}

func parseDestination(dest string) (string, string, error) {
	var tokens []string

	// Check if there is a IPv4/6:Port combination, IPv6 has more than
	// three ":".
	tokens = strings.Split(dest, ":")
	if len(tokens) < expectedTokenItems || len(tokens) > 3 {
		port := tokens[len(tokens)-1]

		maybeIPv6Str := strings.TrimSuffix(dest, ":"+port)
		log.Trace().Str("maybeIPv6Str", maybeIPv6Str).Msg("")

		filteredMaybeIPv6Str := maybeIPv6Str
		if strings.Contains(maybeIPv6Str, "/") {
			networkParts := strings.Split(maybeIPv6Str, "/")
			filteredMaybeIPv6Str = networkParts[0]
		}

		if maybeIPv6, err := netip.ParseAddr(filteredMaybeIPv6Str); err != nil && !maybeIPv6.Is6() {
			log.Trace().Err(err).Msg("trying to parse as IPv6")

			return "", "", fmt.Errorf(
				"failed to parse destination, tokens %v: %w",
				tokens,
				ErrInvalidPortFormat,
			)
		} else {
			tokens = []string{maybeIPv6Str, port}
		}
	}

	var alias string
	// We can have here stuff like:
	// git-server:*
	// 192.168.1.0/24:22
	// fd7a:115c:a1e0::2:22
	// fd7a:115c:a1e0::2/128:22
	// tag:montreal-webserver:80,443
	// tag:api-server:443
	// example-host-1:*
	if len(tokens) == expectedTokenItems {
		alias = tokens[0]
	} else {
		alias = fmt.Sprintf("%s:%s", tokens[0], tokens[1])
	}

	return alias, tokens[len(tokens)-1], nil
}

// parseProtocol reads the proto field of the ACL and generates a list of
// protocols that will be allowed, following the IANA IP protocol number
// https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
//
// If the ACL proto field is empty, it allows ICMPv4, ICMPv6, TCP, and UDP,
// as per Tailscale behaviour (see tailcfg.FilterRule).
//
// Also returns a boolean indicating if the protocol
// requires all the destinations to use wildcard as port number (only TCP,
// UDP and SCTP support specifying ports).
func parseProtocol(protocol string) ([]int, bool, error) {
	switch protocol {
	case "":
		return nil, false, nil
	case "igmp":
		return []int{protocolIGMP}, true, nil
	case "ipv4", "ip-in-ip":
		return []int{protocolIPv4}, true, nil
	case "tcp":
		return []int{protocolTCP}, false, nil
	case "egp":
		return []int{protocolEGP}, true, nil
	case "igp":
		return []int{protocolIGP}, true, nil
	case "udp":
		return []int{protocolUDP}, false, nil
	case "gre":
		return []int{protocolGRE}, true, nil
	case "esp":
		return []int{protocolESP}, true, nil
	case "ah":
		return []int{protocolAH}, true, nil
	case "sctp":
		return []int{protocolSCTP}, false, nil
	case "icmp":
		return []int{protocolICMP, protocolIPv6ICMP}, true, nil

	default:
		protocolNumber, err := strconv.Atoi(protocol)
		if err != nil {
			return nil, false, fmt.Errorf("parsing protocol number: %w", err)
		}
		needsWildcard := protocolNumber != protocolTCP &&
			protocolNumber != protocolUDP &&
			protocolNumber != protocolSCTP

		return []int{protocolNumber}, needsWildcard, nil
	}
}

// expandSource returns a set of Source IPs that would be associated
// with the given src alias.
func (pol *ACLPolicy) expandSource(
	src string,
	nodes types.Nodes,
) ([]string, error) {
	ipSet, err := pol.ExpandAlias(nodes, src)
	if err != nil {
		return []string{}, err
	}

	prefixes := []string{}

	for _, prefix := range ipSet.Prefixes() {
		prefixes = append(prefixes, prefix.String())
	}

	return prefixes, nil
}

// expandalias has an input of either
// - a user
// - a group
// - a tag
// - a host
// - an ip
// - a cidr
// - an autogroup
// and transform these in IPAddresses.
func (pol *ACLPolicy) ExpandAlias(
	nodes types.Nodes,
	alias string,
) (*netipx.IPSet, error) {
	if isWildcard(alias) {
		return util.ParseIPSet("*", nil)
	}

	build := netipx.IPSetBuilder{}

	log.Debug().
		Str("alias", alias).
		Msg("Expanding")

	// if alias is a group
	if isGroup(alias) {
		return pol.expandIPsFromGroup(alias, nodes)
	}

	// if alias is a tag
	if isTag(alias) {
		return pol.expandIPsFromTag(alias, nodes)
	}

	if isAutoGroup(alias) {
		return expandAutoGroup(alias)
	}

	// if alias is a user
	if ips, err := pol.expandIPsFromUser(alias, nodes); ips != nil {
		return ips, err
	}

	// if alias is an host
	// Note, this is recursive.
	if h, ok := pol.Hosts[alias]; ok {
		log.Trace().Str("host", h.String()).Msg("ExpandAlias got hosts entry")

		return pol.ExpandAlias(nodes, h.String())
	}

	// if alias is an IP
	if ip, err := netip.ParseAddr(alias); err == nil {
		return pol.expandIPsFromSingleIP(ip, nodes)
	}

	// if alias is an IP Prefix (CIDR)
	if prefix, err := netip.ParsePrefix(alias); err == nil {
		return pol.expandIPsFromIPPrefix(prefix, nodes)
	}

	log.Warn().Msgf("No IPs found with the alias %v", alias)

	return build.IPSet()
}

// excludeCorrectlyTaggedNodes will remove from the list of input nodes the ones
// that are correctly tagged since they should not be listed as being in the user
// we assume in this function that we only have nodes from 1 user.
func excludeCorrectlyTaggedNodes(
	aclPolicy *ACLPolicy,
	nodes types.Nodes,
	user string,
) types.Nodes {
	out := types.Nodes{}
	tags := []string{}
	for tag := range aclPolicy.TagOwners {
		owners, _ := expandOwnersFromTag(aclPolicy, user)
		ns := append(owners, user)
		if util.StringOrPrefixListContains(ns, user) {
			tags = append(tags, tag)
		}
	}
	// for each node if tag is in tags list, don't append it.
	for _, node := range nodes {
		found := false

		if node.Hostinfo == nil {
			continue
		}

		for _, t := range node.Hostinfo.RequestTags {
			if util.StringOrPrefixListContains(tags, t) {
				found = true

				break
			}
		}
		if len(node.ForcedTags) > 0 {
			found = true
		}
		if !found {
			out = append(out, node)
		}
	}

	return out
}

func expandPorts(portsStr string, isWild bool) (*[]tailcfg.PortRange, error) {
	if isWildcard(portsStr) {
		return &[]tailcfg.PortRange{
			{First: portRangeBegin, Last: portRangeEnd},
		}, nil
	}

	if isWild {
		return nil, ErrWildcardIsNeeded
	}

	ports := []tailcfg.PortRange{}
	for _, portStr := range strings.Split(portsStr, ",") {
		log.Trace().Msgf("parsing portstring: %s", portStr)
		rang := strings.Split(portStr, "-")
		switch len(rang) {
		case 1:
			port, err := strconv.ParseUint(rang[0], util.Base10, util.BitSize16)
			if err != nil {
				return nil, err
			}
			ports = append(ports, tailcfg.PortRange{
				First: uint16(port),
				Last:  uint16(port),
			})

		case expectedTokenItems:
			start, err := strconv.ParseUint(rang[0], util.Base10, util.BitSize16)
			if err != nil {
				return nil, err
			}
			last, err := strconv.ParseUint(rang[1], util.Base10, util.BitSize16)
			if err != nil {
				return nil, err
			}
			ports = append(ports, tailcfg.PortRange{
				First: uint16(start),
				Last:  uint16(last),
			})

		default:
			return nil, ErrInvalidPortFormat
		}
	}

	return &ports, nil
}

// expandOwnersFromTag will return a list of user. An owner can be either a user or a group
// a group cannot be composed of groups.
func expandOwnersFromTag(
	pol *ACLPolicy,
	tag string,
) ([]string, error) {
	noTagErr := fmt.Errorf(
		"%w. %v isn't owned by a TagOwner. Please add one first. https://tailscale.com/kb/1018/acls/#tag-owners",
		ErrInvalidTag,
		tag,
	)
	if pol == nil {
		return []string{}, noTagErr
	}
	var owners []string
	ows, ok := pol.TagOwners[tag]
	if !ok {
		return []string{}, noTagErr
	}
	for _, owner := range ows {
		if isGroup(owner) {
			gs, err := pol.expandUsersFromGroup(owner)
			if err != nil {
				return []string{}, err
			}
			owners = append(owners, gs...)
		} else {
			owners = append(owners, owner)
		}
	}

	return owners, nil
}

// expandUsersFromGroup will return the list of user inside the group
// after some validation.
func (pol *ACLPolicy) expandUsersFromGroup(
	group string,
) ([]string, error) {
	users := []string{}
	log.Trace().Caller().Interface("pol", pol).Msg("test")
	aclGroups, ok := pol.Groups[group]
	if !ok {
		return []string{}, fmt.Errorf(
			"group %v isn't registered. %w",
			group,
			ErrInvalidGroup,
		)
	}
	for _, group := range aclGroups {
		if isGroup(group) {
			return []string{}, fmt.Errorf(
				"%w. A group cannot be composed of groups. https://tailscale.com/kb/1018/acls/#groups",
				ErrInvalidGroup,
			)
		}
		grp, err := util.NormalizeToFQDNRulesConfigFromViper(group)
		if err != nil {
			return []string{}, fmt.Errorf(
				"failed to normalize group %q, err: %w",
				group,
				ErrInvalidGroup,
			)
		}
		users = append(users, grp)
	}

	return users, nil
}

func (pol *ACLPolicy) expandIPsFromGroup(
	group string,
	nodes types.Nodes,
) (*netipx.IPSet, error) {
	build := netipx.IPSetBuilder{}

	users, err := pol.expandUsersFromGroup(group)
	if err != nil {
		return &netipx.IPSet{}, err
	}
	for _, user := range users {
		filteredNodes := filterNodesByUser(nodes, user)
		for _, node := range filteredNodes {
			node.AppendToIPSet(&build)
		}
	}

	return build.IPSet()
}

func (pol *ACLPolicy) expandIPsFromTag(
	alias string,
	nodes types.Nodes,
) (*netipx.IPSet, error) {
	build := netipx.IPSetBuilder{}

	// check for forced tags
	for _, node := range nodes {
		if util.StringOrPrefixListContains(node.ForcedTags, alias) {
			node.AppendToIPSet(&build)
		}
	}

	// find tag owners
	owners, err := expandOwnersFromTag(pol, alias)
	if err != nil {
		if errors.Is(err, ErrInvalidTag) {
			ipSet, _ := build.IPSet()
			if len(ipSet.Prefixes()) == 0 {
				return ipSet, fmt.Errorf(
					"%w. %v isn't owned by a TagOwner and no forced tags are defined",
					ErrInvalidTag,
					alias,
				)
			}

			return build.IPSet()
		} else {
			return nil, err
		}
	}

	// filter out nodes per tag owner
	for _, user := range owners {
		nodes := filterNodesByUser(nodes, user)
		for _, node := range nodes {
			if node.Hostinfo == nil {
				continue
			}

			if util.StringOrPrefixListContains(node.Hostinfo.RequestTags, alias) {
				node.AppendToIPSet(&build)
			}
		}
	}

	return build.IPSet()
}

func (pol *ACLPolicy) expandIPsFromUser(
	user string,
	nodes types.Nodes,
) (*netipx.IPSet, error) {
	build := netipx.IPSetBuilder{}

	filteredNodes := filterNodesByUser(nodes, user)
	filteredNodes = excludeCorrectlyTaggedNodes(pol, filteredNodes, user)

	// shortcurcuit if we have no nodes to get ips from.
	if len(filteredNodes) == 0 {
		return nil, nil //nolint
	}

	for _, node := range filteredNodes {
		node.AppendToIPSet(&build)
	}

	return build.IPSet()
}

func (pol *ACLPolicy) expandIPsFromSingleIP(
	ip netip.Addr,
	nodes types.Nodes,
) (*netipx.IPSet, error) {
	log.Trace().Str("ip", ip.String()).Msg("ExpandAlias got ip")

	matches := nodes.FilterByIP(ip)

	build := netipx.IPSetBuilder{}
	build.Add(ip)

	for _, node := range matches {
		node.AppendToIPSet(&build)
	}

	return build.IPSet()
}

func (pol *ACLPolicy) expandIPsFromIPPrefix(
	prefix netip.Prefix,
	nodes types.Nodes,
) (*netipx.IPSet, error) {
	log.Trace().Str("prefix", prefix.String()).Msg("expandAlias got prefix")
	build := netipx.IPSetBuilder{}
	build.AddPrefix(prefix)

	// This is suboptimal and quite expensive, but if we only add the prefix, we will miss all the relevant IPv6
	// addresses for the hosts that belong to tailscale. This doesnt really affect stuff like subnet routers.
	for _, node := range nodes {
		for _, ip := range node.IPs() {
			// log.Trace().
			// 	Msgf("checking if node ip (%s) is part of prefix (%s): %v, is single ip prefix (%v), addr: %s", ip.String(), prefix.String(), prefix.Contains(ip), prefix.IsSingleIP(), prefix.Addr().String())
			if prefix.Contains(ip) {
				node.AppendToIPSet(&build)
			}
		}
	}

	return build.IPSet()
}

func expandAutoGroup(alias string) (*netipx.IPSet, error) {
	switch {
	case strings.HasPrefix(alias, "autogroup:internet"):
		return theInternet(), nil

	default:
		return nil, fmt.Errorf("unknown autogroup %q", alias)
	}
}

func isWildcard(str string) bool {
	return str == "*"
}

func isGroup(str string) bool {
	return strings.HasPrefix(str, "group:")
}

func isTag(str string) bool {
	return strings.HasPrefix(str, "tag:")
}

func isAutoGroup(str string) bool {
	return strings.HasPrefix(str, "autogroup:")
}

// TagsOfNode will return the tags of the current node.
// Invalid tags are tags added by a user on a node, and that user doesn't have authority to add this tag.
// Valid tags are tags added by a user that is allowed in the ACL policy to add this tag.
func (pol *ACLPolicy) TagsOfNode(
	node *types.Node,
) ([]string, []string) {
	validTags := make([]string, 0)
	invalidTags := make([]string, 0)

	// TODO(kradalby): Why is this sometimes nil? coming from tailNode?
	if node == nil {
		return validTags, invalidTags
	}

	validTagMap := make(map[string]bool)
	invalidTagMap := make(map[string]bool)
	if node.Hostinfo != nil {
		for _, tag := range node.Hostinfo.RequestTags {
			owners, err := expandOwnersFromTag(pol, tag)
			if errors.Is(err, ErrInvalidTag) {
				invalidTagMap[tag] = true

				continue
			}
			var found bool
			for _, owner := range owners {
				if node.User.Name == owner {
					found = true
				}
			}
			if found {
				validTagMap[tag] = true
			} else {
				invalidTagMap[tag] = true
			}
		}
		for tag := range invalidTagMap {
			invalidTags = append(invalidTags, tag)
		}
		for tag := range validTagMap {
			validTags = append(validTags, tag)
		}
	}

	return validTags, invalidTags
}

func filterNodesByUser(nodes types.Nodes, user string) types.Nodes {
	out := types.Nodes{}
	for _, node := range nodes {
		if node.User.Name == user {
			out = append(out, node)
		}
	}

	return out
}

// FilterNodesByACL returns the list of peers authorized to be accessed from a given node.
func FilterNodesByACL(
	node *types.Node,
	nodes types.Nodes,
	filter []tailcfg.FilterRule,
) types.Nodes {
	result := types.Nodes{}

	for index, peer := range nodes {
		if peer.ID == node.ID {
			continue
		}

		if node.CanAccess(filter, nodes[index]) || peer.CanAccess(filter, node) {
			result = append(result, peer)
		}
	}

	return result
}
