package headscale

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/rs/zerolog/log"

	"github.com/tailscale/hujson"
	"inet.af/netaddr"
	"tailscale.com/tailcfg"
)

const (
	errorEmptyPolicy        = Error("empty policy")
	errorInvalidAction      = Error("invalid action")
	errorInvalidUserSection = Error("invalid user section")
	errorInvalidGroup       = Error("invalid group")
	errorInvalidTag         = Error("invalid tag")
	errorInvalidNamespace   = Error("invalid namespace")
	errorInvalidPortFormat  = Error("invalid port format")
)

// LoadACLPolicy loads the ACL policy from the specify path, and generates the ACL rules
func (h *Headscale) LoadACLPolicy(path string) error {
	policyFile, err := os.Open(path)
	if err != nil {
		return err
	}
	defer policyFile.Close()

	var policy ACLPolicy
	b, err := io.ReadAll(policyFile)
	if err != nil {
		return err
	}

	ast, err := hujson.Parse(b)
	if err != nil {
		return err
	}
	ast.Standardize()
	b = ast.Pack()
	err = json.Unmarshal(b, &policy)
	if err != nil {
		return err
	}
	if policy.IsZero() {
		return errorEmptyPolicy
	}

	h.aclPolicy = &policy
	rules, err := h.generateACLRules()
	if err != nil {
		return err
	}
	h.aclRules = rules
	return nil
}

func (h *Headscale) generateACLRules() ([]tailcfg.FilterRule, error) {
	rules := []tailcfg.FilterRule{}

	for i, a := range h.aclPolicy.ACLs {
		if a.Action != "accept" {
			return nil, errorInvalidAction
		}

		r := tailcfg.FilterRule{}

		srcIPs := []string{}
		for j, u := range a.Users {
			srcs, err := h.generateACLPolicySrcIP(u)
			if err != nil {
				log.Error().
					Msgf("Error parsing ACL %d, User %d", i, j)
				return nil, err
			}
			srcIPs = append(srcIPs, srcs...)
		}
		r.SrcIPs = srcIPs

		destPorts := []tailcfg.NetPortRange{}
		for j, d := range a.Ports {
			dests, err := h.generateACLPolicyDestPorts(d)
			if err != nil {
				log.Error().
					Msgf("Error parsing ACL %d, Port %d", i, j)
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

func (h *Headscale) generateACLPolicySrcIP(u string) ([]string, error) {
	return h.expandAlias(u)
}

func (h *Headscale) generateACLPolicyDestPorts(d string) ([]tailcfg.NetPortRange, error) {
	tokens := strings.Split(d, ":")
	if len(tokens) < 2 || len(tokens) > 3 {
		return nil, errorInvalidPortFormat
	}

	var alias string
	// We can have here stuff like:
	// git-server:*
	// 192.168.1.0/24:22
	// tag:montreal-webserver:80,443
	// tag:api-server:443
	// example-host-1:*
	if len(tokens) == 2 {
		alias = tokens[0]
	} else {
		alias = fmt.Sprintf("%s:%s", tokens[0], tokens[1])
	}

	expanded, err := h.expandAlias(alias)
	if err != nil {
		return nil, err
	}
	ports, err := h.expandPorts(tokens[len(tokens)-1])
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

func (h *Headscale) expandAlias(s string) ([]string, error) {
	if s == "*" {
		return []string{"*"}, nil
	}

	if strings.HasPrefix(s, "group:") {
		if _, ok := h.aclPolicy.Groups[s]; !ok {
			return nil, errorInvalidGroup
		}
		ips := []string{}
		for _, n := range h.aclPolicy.Groups[s] {
			nodes, err := h.ListMachinesInNamespace(n)
			if err != nil {
				return nil, errorInvalidNamespace
			}
			for _, node := range nodes {
				ips = append(ips, node.IPAddress)
			}
		}
		return ips, nil
	}

	if strings.HasPrefix(s, "tag:") {
		if _, ok := h.aclPolicy.TagOwners[s]; !ok {
			return nil, errorInvalidTag
		}

		// This will have HORRIBLE performance.
		// We need to change the data model to better store tags
		machines := []Machine{}
		if err := h.db.Where("registered").Find(&machines).Error; err != nil {
			return nil, err
		}
		ips := []string{}
		for _, m := range machines {
			hostinfo := tailcfg.Hostinfo{}
			if len(m.HostInfo) != 0 {
				hi, err := m.HostInfo.MarshalJSON()
				if err != nil {
					return nil, err
				}
				err = json.Unmarshal(hi, &hostinfo)
				if err != nil {
					return nil, err
				}

				// FIXME: Check TagOwners allows this
				for _, t := range hostinfo.RequestTags {
					if s[4:] == t {
						ips = append(ips, m.IPAddress)
						break
					}
				}
			}
		}
		return ips, nil
	}

	n, err := h.GetNamespace(s)
	if err == nil {
		nodes, err := h.ListMachinesInNamespace(n.Name)
		if err != nil {
			return nil, err
		}
		ips := []string{}
		for _, n := range nodes {
			ips = append(ips, n.IPAddress)
		}
		return ips, nil
	}

	if h, ok := h.aclPolicy.Hosts[s]; ok {
		return []string{h.String()}, nil
	}

	ip, err := netaddr.ParseIP(s)
	if err == nil {
		return []string{ip.String()}, nil
	}

	cidr, err := netaddr.ParseIPPrefix(s)
	if err == nil {
		return []string{cidr.String()}, nil
	}

	return nil, errorInvalidUserSection
}

func (h *Headscale) expandPorts(s string) (*[]tailcfg.PortRange, error) {
	if s == "*" {
		return &[]tailcfg.PortRange{{First: 0, Last: 65535}}, nil
	}

	ports := []tailcfg.PortRange{}
	for _, p := range strings.Split(s, ",") {
		rang := strings.Split(p, "-")
		if len(rang) == 1 {
			pi, err := strconv.ParseUint(rang[0], 10, 16)
			if err != nil {
				return nil, err
			}
			ports = append(ports, tailcfg.PortRange{
				First: uint16(pi),
				Last:  uint16(pi),
			})
		} else if len(rang) == 2 {
			start, err := strconv.ParseUint(rang[0], 10, 16)
			if err != nil {
				return nil, err
			}
			last, err := strconv.ParseUint(rang[1], 10, 16)
			if err != nil {
				return nil, err
			}
			ports = append(ports, tailcfg.PortRange{
				First: uint16(start),
				Last:  uint16(last),
			})
		} else {
			return nil, errorInvalidPortFormat
		}
	}
	return &ports, nil
}
