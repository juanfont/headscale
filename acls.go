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

	rules, err := generateACLRules(machines, *h.aclPolicy, h.cfg.OIDC.StripEmaildomain)
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

func generateACLRules(machines []Machine, aclPolicy ACLPolicy, stripEmaildomain bool) ([]tailcfg.FilterRule, error) {
	rules := []tailcfg.FilterRule{}

	for index, acl := range aclPolicy.ACLs {
		if acl.Action != "accept" {
			return nil, errInvalidAction
		}

		srcIPs := []string{}
		for innerIndex, src := range acl.Sources {
			srcs, err := generateACLPolicySrcIP(machines, aclPolicy, src, stripEmaildomain)
			if err != nil {
				log.Error().
					Msgf("Error parsing ACL %d, Source %d", index, innerIndex)

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
		for innerIndex, dest := range acl.Destinations {
			dests, err := generateACLPolicyDest(
				machines,
				aclPolicy,
				dest,
				needsWildcard,
				stripEmaildomain,
			)
			if err != nil {
				log.Error().
					Msgf("Error parsing ACL %d, Destination %d", index, innerIndex)

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
			expandedSrcs, err := expandAlias(
				machines,
				*h.aclPolicy,
				rawSrc,
				h.cfg.OIDC.StripEmaildomain,
			)
			if err != nil {
				log.Error().
					Msgf("Error parsing SSH %d, Source %d", index, innerIndex)

				return nil, err
			}
			for _, expandedSrc := range expandedSrcs {
				principals = append(principals, &tailcfg.SSHPrincipal{
					NodeIP: expandedSrc,
				})
			}
		}

		userMap := make(map[string]string, len(sshACL.Users))
		for _, user := range sshACL.Users {
			userMap[user] = "="
		}
		rules = append(rules, &tailcfg.SSHRule{
			RuleExpires: nil,
			Principals:  principals,
			SSHUsers:    userMap,
			Action:      &action,
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

func generateACLPolicySrcIP(
	machines []Machine,
	aclPolicy ACLPolicy,
	src string,
	stripEmaildomain bool,
) ([]string, error) {
	return expandAlias(machines, aclPolicy, src, stripEmaildomain)
}

func generateACLPolicyDest(
	machines []Machine,
	aclPolicy ACLPolicy,
	dest string,
	needsWildcard bool,
	stripEmaildomain bool,
) ([]tailcfg.NetPortRange, error) {
	tokens := strings.Split(dest, ":")
	if len(tokens) < expectedTokenItems || len(tokens) > 3 {
		return nil, errInvalidPortFormat
	}

	var alias string
	// We can have here stuff like:
	// git-server:*
	// 192.168.1.0/24:22
	// tag:montreal-webserver:80,443
	// tag:api-server:443
	// example-host-1:*
	if len(tokens) == expectedTokenItems {
		alias = tokens[0]
	} else {
		alias = fmt.Sprintf("%s:%s", tokens[0], tokens[1])
	}

	expanded, err := expandAlias(
		machines,
		aclPolicy,
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
	for _, d := range expanded {
		for _, p := range *ports {
			pr := tailcfg.NetPortRange{
				IP:    d,
				Ports: p,
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
// and transform these in IPAddresses.
func expandAlias(
	machines []Machine,
	aclPolicy ACLPolicy,
	alias string,
	stripEmailDomain bool,
) ([]string, error) {
	ips := []string{}
	if alias == "*" {
		return []string{"*"}, nil
	}

	log.Debug().
		Str("alias", alias).
		Msg("Expanding")

	if strings.HasPrefix(alias, "group:") {
		users, err := expandGroup(aclPolicy, alias, stripEmailDomain)
		if err != nil {
			return ips, err
		}
		for _, n := range users {
			nodes := filterMachinesByUser(machines, n)
			for _, node := range nodes {
				ips = append(ips, node.IPAddresses.ToStringSlice()...)
			}
		}

		return ips, nil
	}

	if strings.HasPrefix(alias, "tag:") {
		// check for forced tags
		for _, machine := range machines {
			if contains(machine.ForcedTags, alias) {
				ips = append(ips, machine.IPAddresses.ToStringSlice()...)
			}
		}

		// find tag owners
		owners, err := expandTagOwners(aclPolicy, alias, stripEmailDomain)
		if err != nil {
			if errors.Is(err, errInvalidTag) {
				if len(ips) == 0 {
					return ips, fmt.Errorf(
						"%w. %v isn't owned by a TagOwner and no forced tags are defined",
						errInvalidTag,
						alias,
					)
				}

				return ips, nil
			} else {
				return ips, err
			}
		}

		// filter out machines per tag owner
		for _, user := range owners {
			machines := filterMachinesByUser(machines, user)
			for _, machine := range machines {
				hi := machine.GetHostInfo()
				if contains(hi.RequestTags, alias) {
					ips = append(ips, machine.IPAddresses.ToStringSlice()...)
				}
			}
		}

		return ips, nil
	}

	// if alias is a user
	nodes := filterMachinesByUser(machines, alias)
	nodes = excludeCorrectlyTaggedNodes(aclPolicy, nodes, alias, stripEmailDomain)

	for _, n := range nodes {
		ips = append(ips, n.IPAddresses.ToStringSlice()...)
	}
	if len(ips) > 0 {
		return ips, nil
	}

	// if alias is an host
	if h, ok := aclPolicy.Hosts[alias]; ok {
		return []string{h.String()}, nil
	}

	// if alias is an IP
	ip, err := netip.ParseAddr(alias)
	if err == nil {
		return []string{ip.String()}, nil
	}

	// if alias is an CIDR
	cidr, err := netip.ParsePrefix(alias)
	if err == nil {
		return []string{cidr.String()}, nil
	}

	log.Warn().Msgf("No IPs found with the alias %v", alias)

	return ips, nil
}

// excludeCorrectlyTaggedNodes will remove from the list of input nodes the ones
// that are correctly tagged since they should not be listed as being in the user
// we assume in this function that we only have nodes from 1 user.
func excludeCorrectlyTaggedNodes(
	aclPolicy ACLPolicy,
	nodes []Machine,
	user string,
	stripEmailDomain bool,
) []Machine {
	out := []Machine{}
	tags := []string{}
	for tag := range aclPolicy.TagOwners {
		owners, _ := expandTagOwners(aclPolicy, user, stripEmailDomain)
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
	if portsStr == "*" {
		return &[]tailcfg.PortRange{
			{First: portRangeBegin, Last: portRangeEnd},
		}, nil
	}

	if needsWildcard {
		return nil, errWildcardIsNeeded
	}

	ports := []tailcfg.PortRange{}
	for _, portStr := range strings.Split(portsStr, ",") {
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

// expandTagOwners will return a list of user. An owner can be either a user or a group
// a group cannot be composed of groups.
func expandTagOwners(
	aclPolicy ACLPolicy,
	tag string,
	stripEmailDomain bool,
) ([]string, error) {
	var owners []string
	ows, ok := aclPolicy.TagOwners[tag]
	if !ok {
		return []string{}, fmt.Errorf(
			"%w. %v isn't owned by a TagOwner. Please add one first. https://tailscale.com/kb/1018/acls/#tag-owners",
			errInvalidTag,
			tag,
		)
	}
	for _, owner := range ows {
		if strings.HasPrefix(owner, "group:") {
			gs, err := expandGroup(aclPolicy, owner, stripEmailDomain)
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

// expandGroup will return the list of user inside the group
// after some validation.
func expandGroup(
	aclPolicy ACLPolicy,
	group string,
	stripEmailDomain bool,
) ([]string, error) {
	outGroups := []string{}
	aclGroups, ok := aclPolicy.Groups[group]
	if !ok {
		return []string{}, fmt.Errorf(
			"group %v isn't registered. %w",
			group,
			errInvalidGroup,
		)
	}
	for _, group := range aclGroups {
		if strings.HasPrefix(group, "group:") {
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
		outGroups = append(outGroups, grp)
	}

	return outGroups, nil
}
