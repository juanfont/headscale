package headscale

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/rs/zerolog/log"
	"github.com/tailscale/hujson"
	"gopkg.in/yaml.v3"
	"inet.af/netaddr"
	"tailscale.com/tailcfg"
)

const (
	errEmptyPolicy       = Error("empty policy")
	errInvalidAction     = Error("invalid action")
	errInvalidGroup      = Error("invalid group")
	errInvalidTag        = Error("invalid tag")
	errInvalidPortFormat = Error("invalid port format")
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
	rules, err := h.generateACLRules()
	if err != nil {
		return err
	}
	log.Trace().Interface("ACL", rules).Msg("ACL rules generated")
	h.aclRules = rules

	return nil
}

func (h *Headscale) generateACLRules() ([]tailcfg.FilterRule, error) {
	rules := []tailcfg.FilterRule{}

	if h.aclPolicy == nil {
		return nil, errEmptyPolicy
	}

	machines, err := h.ListMachines()
	if err != nil {
		return nil, err
	}

	for index, acl := range h.aclPolicy.ACLs {
		if acl.Action != "accept" {
			return nil, errInvalidAction
		}

		srcIPs := []string{}
		for innerIndex, user := range acl.Users {
			srcs, err := h.generateACLPolicySrcIP(machines, *h.aclPolicy, user)
			if err != nil {
				log.Error().
					Msgf("Error parsing ACL %d, User %d", index, innerIndex)

				return nil, err
			}
			srcIPs = append(srcIPs, srcs...)
		}

		destPorts := []tailcfg.NetPortRange{}
		for innerIndex, ports := range acl.Ports {
			dests, err := h.generateACLPolicyDestPorts(machines, *h.aclPolicy, ports)
			if err != nil {
				log.Error().
					Msgf("Error parsing ACL %d, Port %d", index, innerIndex)

				return nil, err
			}
			destPorts = append(destPorts, dests...)
		}

		rules = append(rules, tailcfg.FilterRule{
			SrcIPs:   srcIPs,
			DstPorts: destPorts,
		})
	}

	return rules, nil
}

func (h *Headscale) generateACLPolicySrcIP(
	machines []Machine,
	aclPolicy ACLPolicy,
	u string,
) ([]string, error) {
	return expandAlias(machines, aclPolicy, u, h.cfg.OIDC.StripEmaildomain)
}

func (h *Headscale) generateACLPolicyDestPorts(
	machines []Machine,
	aclPolicy ACLPolicy,
	d string,
) ([]tailcfg.NetPortRange, error) {
	tokens := strings.Split(d, ":")
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
		h.cfg.OIDC.StripEmaildomain,
	)
	if err != nil {
		return nil, err
	}
	ports, err := expandPorts(tokens[len(tokens)-1])
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

// expandalias has an input of either
// - a namespace
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
		namespaces, err := expandGroup(aclPolicy, alias, stripEmailDomain)
		if err != nil {
			return ips, err
		}
		for _, n := range namespaces {
			nodes := filterMachinesByNamespace(machines, n)
			for _, node := range nodes {
				ips = append(ips, node.IPAddresses.ToStringSlice()...)
			}
		}

		return ips, nil
	}

	if strings.HasPrefix(alias, "tag:") {
		owners, err := expandTagOwners(aclPolicy, alias, stripEmailDomain)
		if err != nil {
			return ips, err
		}
		for _, namespace := range owners {
			machines := filterMachinesByNamespace(machines, namespace)
			for _, machine := range machines {
				hi := machine.GetHostInfo()
				for _, t := range hi.RequestTags {
					if alias == t {
						ips = append(ips, machine.IPAddresses.ToStringSlice()...)
					}
				}
			}
		}

		return ips, nil
	}

	// if alias is a namespace
	nodes := filterMachinesByNamespace(machines, alias)
	nodes = excludeCorrectlyTaggedNodes(aclPolicy, nodes, alias)

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
	ip, err := netaddr.ParseIP(alias)
	if err == nil {
		return []string{ip.String()}, nil
	}

	// if alias is an CIDR
	cidr, err := netaddr.ParseIPPrefix(alias)
	if err == nil {
		return []string{cidr.String()}, nil
	}

	log.Warn().Msgf("No IPs found with the alias %v", alias)

	return ips, nil
}

// excludeCorrectlyTaggedNodes will remove from the list of input nodes the ones
// that are correctly tagged since they should not be listed as being in the namespace
// we assume in this function that we only have nodes from 1 namespace.
func excludeCorrectlyTaggedNodes(
	aclPolicy ACLPolicy,
	nodes []Machine,
	namespace string,
) []Machine {
	out := []Machine{}
	tags := []string{}
	for tag, ns := range aclPolicy.TagOwners {
		if containsString(ns, namespace) {
			tags = append(tags, tag)
		}
	}
	// for each machine if tag is in tags list, don't append it.
	for _, machine := range nodes {
		hi := machine.GetHostInfo()

		found := false
		for _, t := range hi.RequestTags {
			if containsString(tags, t) {
				found = true

				break
			}
		}
		if !found {
			out = append(out, machine)
		}
	}

	return out
}

func expandPorts(portsStr string) (*[]tailcfg.PortRange, error) {
	if portsStr == "*" {
		return &[]tailcfg.PortRange{
			{First: portRangeBegin, Last: portRangeEnd},
		}, nil
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

func filterMachinesByNamespace(machines []Machine, namespace string) []Machine {
	out := []Machine{}
	for _, machine := range machines {
		if machine.Namespace.Name == namespace {
			out = append(out, machine)
		}
	}

	return out
}

// expandTagOwners will return a list of namespace. An owner can be either a namespace or a group
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

// expandGroup will return the list of namespace inside the group
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
