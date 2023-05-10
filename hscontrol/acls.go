package headscale

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

	"github.com/rs/zerolog/log"
	"github.com/tailscale/hujson"
	"go4.org/netipx"
	"gopkg.in/yaml.v3"
	"tailscale.com/envknob"
	"tailscale.com/tailcfg"
)

const (
	errEmptyPolicy       = Error("empty policy")
	errInvalidAction     = Error("invalid action")
	errInvalidGroup      = Error("invalid group")
	errInvalidTag        = Error("invalid tag")
	errInvalidPortFormat = Error("invalid port format")
	errWildcardIsNeeded  = Error("wildcard as port is required for the protocol")
)

const (
	Base8              = 8
	Base10             = 10
	BitSize16          = 16
	BitSize32          = 32
	BitSize64          = 64
	portRangeBegin     = 0
	portRangeEnd       = 65535
	expectedTokenItems = 2
)

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

var featureEnableSSH = envknob.RegisterBool("HEADSCALE_EXPERIMENTAL_FEATURE_SSH")

// LoadACLPolicy loads the ACL policy from the specify path, and generates the ACL rules.
func (h *Headscale) LoadACLPolicy(path string) error {
	log.Debug().
		Str("func", "LoadACLPolicy").
		Str("path", path).
		Msg("Loading ACL policy from path")

	policyFile, err := os.Open(path)
	if err != nil {
		return err
	}
	defer policyFile.Close()

	var policy ACLPolicy
	policyBytes, err := io.ReadAll(policyFile)
	if err != nil {
		return err
	}

	switch filepath.Ext(path) {
	case ".yml", ".yaml":
		log.Debug().
			Str("path", path).
			Bytes("file", policyBytes).
			Msg("Loading ACLs from YAML")

		err := yaml.Unmarshal(policyBytes, &policy)
		if err != nil {
			return err
		}

		log.Trace().
			Interface("policy", policy).
			Msg("Loaded policy from YAML")

	default:
		ast, err := hujson.Parse(policyBytes)
		if err != nil {
			return err
		}

		ast.Standardize()
		policyBytes = ast.Pack()
		err = json.Unmarshal(policyBytes, &policy)
		if err != nil {
			return err
		}
	}

	if policy.IsZero() {
		return errEmptyPolicy
	}

	h.aclPolicy = &policy

	return h.UpdateACLRules()
}

func (h *Headscale) UpdateACLRules() error {
	machines, err := h.ListMachines()
	if err != nil {
		return err
	}

	if h.aclPolicy == nil {
		return errEmptyPolicy
	}

	rules, err := h.aclPolicy.generateFilterRules(machines, h.cfg.OIDC.StripEmaildomain)
	if err != nil {
		return err
	}

	log.Trace().Interface("ACL", rules).Msg("ACL rules generated")
	h.aclRules = rules

	if featureEnableSSH() {
		sshRules, err := h.generateSSHRules()
		if err != nil {
			return err
		}
		log.Trace().Interface("SSH", sshRules).Msg("SSH rules generated")
		if h.sshPolicy == nil {
			h.sshPolicy = &tailcfg.SSHPolicy{}
		}
		h.sshPolicy.Rules = sshRules
	} else if h.aclPolicy != nil && len(h.aclPolicy.SSHs) > 0 {
		log.Info().Msg("SSH ACLs has been defined, but HEADSCALE_EXPERIMENTAL_FEATURE_SSH is not enabled, this is a unstable feature, check docs before activating")
	}

	return nil
}

// generateFilterRules takes a set of machines and an ACLPolicy and generates a
// set of Tailscale compatible FilterRules used to allow traffic on clients.
func (pol *ACLPolicy) generateFilterRules(
	machines []Machine,
	stripEmailDomain bool,
) ([]tailcfg.FilterRule, error) {
	rules := []tailcfg.FilterRule{}

	for index, acl := range pol.ACLs {
		if acl.Action != "accept" {
			return nil, errInvalidAction
		}

		srcIPs := []string{}
		for srcIndex, src := range acl.Sources {
			srcs, err := pol.getIPsFromSource(src, machines, stripEmailDomain)
			if err != nil {
				log.Error().
					Interface("src", src).
					Int("ACL index", index).
					Int("Src index", srcIndex).
					Msgf("Error parsing ACL")

				return nil, err
			}
			srcIPs = append(srcIPs, srcs...)
		}

		protocols, needsWildcard, err := parseProtocol(acl.Protocol)
		if err != nil {
			log.Error().
				Msgf("Error parsing ACL %d. protocol unknown %s", index, acl.Protocol)

			return nil, err
		}

		destPorts := []tailcfg.NetPortRange{}
		for destIndex, dest := range acl.Destinations {
			dests, err := pol.getNetPortRangeFromDestination(
				dest,
				machines,
				needsWildcard,
				stripEmailDomain,
			)
			if err != nil {
				log.Error().
					Interface("dest", dest).
					Int("ACL index", index).
					Int("dest index", destIndex).
					Msgf("Error parsing ACL")

				return nil, err
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

func (h *Headscale) generateSSHRules() ([]*tailcfg.SSHRule, error) {
	rules := []*tailcfg.SSHRule{}

	if h.aclPolicy == nil {
		return nil, errEmptyPolicy
	}

	machines, err := h.ListMachines()
	if err != nil {
		return nil, err
	}

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

	for index, sshACL := range h.aclPolicy.SSHs {
		action := rejectAction
		switch sshACL.Action {
		case "accept":
			action = acceptAction
		case "check":
			checkAction, err := sshCheckAction(sshACL.CheckPeriod)
			if err != nil {
				log.Error().
					Msgf("Error parsing SSH %d, check action with unparsable duration '%s'", index, sshACL.CheckPeriod)
			} else {
				action = *checkAction
			}
		default:
			log.Error().
				Msgf("Error parsing SSH %d, unknown action '%s'", index, sshACL.Action)

			return nil, err
		}

		principals := make([]*tailcfg.SSHPrincipal, 0, len(sshACL.Sources))
		for innerIndex, rawSrc := range sshACL.Sources {
			if isWildcard(rawSrc) {
				principals = append(principals, &tailcfg.SSHPrincipal{
					Any: true,
				})
			} else if isGroup(rawSrc) {
				users, err := h.aclPolicy.getUsersInGroup(rawSrc, h.cfg.OIDC.StripEmaildomain)
				if err != nil {
					log.Error().
						Msgf("Error parsing SSH %d, Source %d", index, innerIndex)

					return nil, err
				}

				for _, user := range users {
					principals = append(principals, &tailcfg.SSHPrincipal{
						UserLogin: user,
					})
				}
			} else {
				expandedSrcs, err := h.aclPolicy.expandAlias(
					machines,
					rawSrc,
					h.cfg.OIDC.StripEmaildomain,
				)
				if err != nil {
					log.Error().
						Msgf("Error parsing SSH %d, Source %d", index, innerIndex)

					return nil, err
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

	return rules, nil
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

// getIPsFromSource returns a set of Source IPs that would be associated
// with the given src alias.
func (pol *ACLPolicy) getIPsFromSource(
	src string,
	machines []Machine,
	stripEmaildomain bool,
) ([]string, error) {
	ipSet, err := pol.expandAlias(machines, src, stripEmaildomain)
	if err != nil {
		return []string{}, err
	}

	prefixes := []string{}

	for _, prefix := range ipSet.Prefixes() {
		prefixes = append(prefixes, prefix.String())
	}

	return prefixes, nil
}

// getNetPortRangeFromDestination returns a set of tailcfg.NetPortRange
// which are associated with the dest alias.
func (pol *ACLPolicy) getNetPortRangeFromDestination(
	dest string,
	machines []Machine,
	needsWildcard bool,
	stripEmaildomain bool,
) ([]tailcfg.NetPortRange, error) {
	var tokens []string

	log.Trace().Str("destination", dest).Msg("generating policy destination")

	// Check if there is a IPv4/6:Port combination, IPv6 has more than
	// three ":".
	tokens = strings.Split(dest, ":")
	if len(tokens) < expectedTokenItems || len(tokens) > 3 {
		port := tokens[len(tokens)-1]

		maybeIPv6Str := strings.TrimSuffix(dest, ":"+port)
		log.Trace().Str("maybeIPv6Str", maybeIPv6Str).Msg("")

		if maybeIPv6, err := netip.ParseAddr(maybeIPv6Str); err != nil && !maybeIPv6.Is6() {
			log.Trace().Err(err).Msg("trying to parse as IPv6")

			return nil, fmt.Errorf(
				"failed to parse destination, tokens %v: %w",
				tokens,
				errInvalidPortFormat,
			)
		} else {
			tokens = []string{maybeIPv6Str, port}
		}
	}

	log.Trace().Strs("tokens", tokens).Msg("generating policy destination")

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

	expanded, err := pol.expandAlias(
		machines,
		alias,
		stripEmaildomain,
	)
	if err != nil {
		return nil, err
	}
	ports, err := expandPorts(tokens[len(tokens)-1], needsWildcard)
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

	return dests, nil
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
			return nil, false, err
		}
		needsWildcard := protocolNumber != protocolTCP &&
			protocolNumber != protocolUDP &&
			protocolNumber != protocolSCTP

		return []int{protocolNumber}, needsWildcard, nil
	}
}

// expandalias has an input of either
// - a user
// - a group
// - a tag
// - a host
// - an ip
// - a cidr
// and transform these in IPAddresses.
func (pol *ACLPolicy) expandAlias(
	machines Machines,
	alias string,
	stripEmailDomain bool,
) (*netipx.IPSet, error) {
	if isWildcard(alias) {
		return parseIPSet("*", nil)
	}

	build := netipx.IPSetBuilder{}

	log.Debug().
		Str("alias", alias).
		Msg("Expanding")

	// if alias is a group
	if isGroup(alias) {
		return pol.getIPsFromGroup(alias, machines, stripEmailDomain)
	}

	// if alias is a tag
	if isTag(alias) {
		return pol.getIPsFromTag(alias, machines, stripEmailDomain)
	}

	// if alias is a user
	if ips, err := pol.getIPsForUser(alias, machines, stripEmailDomain); ips != nil {
		return ips, err
	}

	// if alias is an host
	// Note, this is recursive.
	if h, ok := pol.Hosts[alias]; ok {
		log.Trace().Str("host", h.String()).Msg("expandAlias got hosts entry")

		return pol.expandAlias(machines, h.String(), stripEmailDomain)
	}

	// if alias is an IP
	if ip, err := netip.ParseAddr(alias); err == nil {
		return pol.getIPsFromSingleIP(ip, machines)
	}

	// if alias is an IP Prefix (CIDR)
	if prefix, err := netip.ParsePrefix(alias); err == nil {
		return pol.getIPsFromIPPrefix(prefix, machines)
	}

	log.Warn().Msgf("No IPs found with the alias %v", alias)

	return build.IPSet()
}

// excludeCorrectlyTaggedNodes will remove from the list of input nodes the ones
// that are correctly tagged since they should not be listed as being in the user
// we assume in this function that we only have nodes from 1 user.
func excludeCorrectlyTaggedNodes(
	aclPolicy *ACLPolicy,
	nodes []Machine,
	user string,
	stripEmailDomain bool,
) []Machine {
	out := []Machine{}
	tags := []string{}
	for tag := range aclPolicy.TagOwners {
		owners, _ := getTagOwners(aclPolicy, user, stripEmailDomain)
		ns := append(owners, user)
		if contains(ns, user) {
			tags = append(tags, tag)
		}
	}
	// for each machine if tag is in tags list, don't append it.
	for _, machine := range nodes {
		hi := machine.GetHostInfo()

		found := false
		for _, t := range hi.RequestTags {
			if contains(tags, t) {
				found = true

				break
			}
		}
		if len(machine.ForcedTags) > 0 {
			found = true
		}
		if !found {
			out = append(out, machine)
		}
	}

	return out
}

func expandPorts(portsStr string, needsWildcard bool) (*[]tailcfg.PortRange, error) {
	if isWildcard(portsStr) {
		return &[]tailcfg.PortRange{
			{First: portRangeBegin, Last: portRangeEnd},
		}, nil
	}

	if needsWildcard {
		return nil, errWildcardIsNeeded
	}

	ports := []tailcfg.PortRange{}
	for _, portStr := range strings.Split(portsStr, ",") {
		log.Trace().Msgf("parsing portstring: %s", portStr)
		rang := strings.Split(portStr, "-")
		switch len(rang) {
		case 1:
			port, err := strconv.ParseUint(rang[0], Base10, BitSize16)
			if err != nil {
				return nil, err
			}
			ports = append(ports, tailcfg.PortRange{
				First: uint16(port),
				Last:  uint16(port),
			})

		case expectedTokenItems:
			start, err := strconv.ParseUint(rang[0], Base10, BitSize16)
			if err != nil {
				return nil, err
			}
			last, err := strconv.ParseUint(rang[1], Base10, BitSize16)
			if err != nil {
				return nil, err
			}
			ports = append(ports, tailcfg.PortRange{
				First: uint16(start),
				Last:  uint16(last),
			})

		default:
			return nil, errInvalidPortFormat
		}
	}

	return &ports, nil
}

func filterMachinesByUser(machines []Machine, user string) []Machine {
	out := []Machine{}
	for _, machine := range machines {
		if machine.User.Name == user {
			out = append(out, machine)
		}
	}

	return out
}

// getTagOwners will return a list of user. An owner can be either a user or a group
// a group cannot be composed of groups.
func getTagOwners(
	pol *ACLPolicy,
	tag string,
	stripEmailDomain bool,
) ([]string, error) {
	var owners []string
	ows, ok := pol.TagOwners[tag]
	if !ok {
		return []string{}, fmt.Errorf(
			"%w. %v isn't owned by a TagOwner. Please add one first. https://tailscale.com/kb/1018/acls/#tag-owners",
			errInvalidTag,
			tag,
		)
	}
	for _, owner := range ows {
		if isGroup(owner) {
			gs, err := pol.getUsersInGroup(owner, stripEmailDomain)
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

// getUsersInGroup will return the list of user inside the group
// after some validation.
func (pol *ACLPolicy) getUsersInGroup(
	group string,
	stripEmailDomain bool,
) ([]string, error) {
	users := []string{}
	log.Trace().Caller().Interface("pol", pol).Msg("test")
	aclGroups, ok := pol.Groups[group]
	if !ok {
		return []string{}, fmt.Errorf(
			"group %v isn't registered. %w",
			group,
			errInvalidGroup,
		)
	}
	for _, group := range aclGroups {
		if isGroup(group) {
			return []string{}, fmt.Errorf(
				"%w. A group cannot be composed of groups. https://tailscale.com/kb/1018/acls/#groups",
				errInvalidGroup,
			)
		}
		grp, err := NormalizeToFQDNRules(group, stripEmailDomain)
		if err != nil {
			return []string{}, fmt.Errorf(
				"failed to normalize group %q, err: %w",
				group,
				errInvalidGroup,
			)
		}
		users = append(users, grp)
	}

	return users, nil
}

func (pol *ACLPolicy) getIPsFromGroup(
	group string,
	machines Machines,
	stripEmailDomain bool,
) (*netipx.IPSet, error) {
	build := netipx.IPSetBuilder{}

	users, err := pol.getUsersInGroup(group, stripEmailDomain)
	if err != nil {
		return &netipx.IPSet{}, err
	}
	for _, user := range users {
		filteredMachines := filterMachinesByUser(machines, user)
		for _, machine := range filteredMachines {
			machine.IPAddresses.AppendToIPSet(&build)
		}
	}

	return build.IPSet()
}

func (pol *ACLPolicy) getIPsFromTag(
	alias string,
	machines Machines,
	stripEmailDomain bool,
) (*netipx.IPSet, error) {
	build := netipx.IPSetBuilder{}

	// check for forced tags
	for _, machine := range machines {
		if contains(machine.ForcedTags, alias) {
			machine.IPAddresses.AppendToIPSet(&build)
		}
	}

	// find tag owners
	owners, err := getTagOwners(pol, alias, stripEmailDomain)
	if err != nil {
		if errors.Is(err, errInvalidTag) {
			ipSet, _ := build.IPSet()
			if len(ipSet.Prefixes()) == 0 {
				return ipSet, fmt.Errorf(
					"%w. %v isn't owned by a TagOwner and no forced tags are defined",
					errInvalidTag,
					alias,
				)
			}

			return build.IPSet()
		} else {
			return nil, err
		}
	}

	// filter out machines per tag owner
	for _, user := range owners {
		machines := filterMachinesByUser(machines, user)
		for _, machine := range machines {
			hi := machine.GetHostInfo()
			if contains(hi.RequestTags, alias) {
				machine.IPAddresses.AppendToIPSet(&build)
			}
		}
	}

	return build.IPSet()
}

func (pol *ACLPolicy) getIPsForUser(
	user string,
	machines Machines,
	stripEmailDomain bool,
) (*netipx.IPSet, error) {
	build := netipx.IPSetBuilder{}

	filteredMachines := filterMachinesByUser(machines, user)
	filteredMachines = excludeCorrectlyTaggedNodes(pol, filteredMachines, user, stripEmailDomain)

	// shortcurcuit if we have no machines to get ips from.
	if len(filteredMachines) == 0 {
		return nil, nil //nolint
	}

	for _, machine := range filteredMachines {
		machine.IPAddresses.AppendToIPSet(&build)
	}

	return build.IPSet()
}

func (pol *ACLPolicy) getIPsFromSingleIP(
	ip netip.Addr,
	machines Machines,
) (*netipx.IPSet, error) {
	log.Trace().Str("ip", ip.String()).Msg("expandAlias got ip")

	matches := machines.FilterByIP(ip)

	build := netipx.IPSetBuilder{}
	build.Add(ip)

	for _, machine := range matches {
		machine.IPAddresses.AppendToIPSet(&build)
	}

	return build.IPSet()
}

func (pol *ACLPolicy) getIPsFromIPPrefix(
	prefix netip.Prefix,
	machines Machines,
) (*netipx.IPSet, error) {
	log.Trace().Str("prefix", prefix.String()).Msg("expandAlias got prefix")
	build := netipx.IPSetBuilder{}
	build.AddPrefix(prefix)

	// This is suboptimal and quite expensive, but if we only add the prefix, we will miss all the relevant IPv6
	// addresses for the hosts that belong to tailscale. This doesnt really affect stuff like subnet routers.
	for _, machine := range machines {
		for _, ip := range machine.IPAddresses {
			// log.Trace().
			// 	Msgf("checking if machine ip (%s) is part of prefix (%s): %v, is single ip prefix (%v), addr: %s", ip.String(), prefix.String(), prefix.Contains(ip), prefix.IsSingleIP(), prefix.Addr().String())
			if prefix.Contains(ip) {
				machine.IPAddresses.AppendToIPSet(&build)
			}
		}
	}

	return build.IPSet()
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
