package headscale

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/tailscale/hujson"
	"inet.af/netaddr"
	"tailscale.com/tailcfg"
)

const errorEmptyPolicy = Error("empty policy")
const errorInvalidAction = Error("invalid action")
const errorInvalidUserSection = Error("invalid user section")
const errorInvalidGroup = Error("invalid group")

func (h *Headscale) LoadPolicy(path string) error {
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
	err = hujson.Unmarshal(b, &policy)
	if policy.IsZero() {
		return errorEmptyPolicy
	}

	h.aclPolicy = &policy
	return err
}

func (h *Headscale) generateACLRules() (*[]tailcfg.FilterRule, error) {
	rules := []tailcfg.FilterRule{}

	for i, a := range h.aclPolicy.ACLs {
		if a.Action != "accept" {
			return nil, errorInvalidAction
		}

		r := tailcfg.FilterRule{}

		srcIPs := []string{}
		for j, u := range a.Users {
			fmt.Printf("acl %d, user %d: ", i, j)
			srcs, err := h.generateAclPolicySrcIP(u)
			fmt.Printf("  ->  %s\n", err)
			if err != nil {
				return nil, err
			}
			srcIPs = append(srcIPs, *srcs...)
		}
		r.SrcIPs = srcIPs

	}

	return &rules, nil
}

func (h *Headscale) generateAclPolicySrcIP(u string) (*[]string, error) {
	if u == "*" {
		fmt.Printf("%s -> wildcard", u)
		return &[]string{"*"}, nil
	}

	if strings.HasPrefix(u, "group:") {
		fmt.Printf("%s -> group", u)
		if _, ok := h.aclPolicy.Groups[u]; !ok {
			return nil, errorInvalidGroup
		}
		return nil, nil
	}

	if strings.HasPrefix(u, "tag:") {
		fmt.Printf("%s -> tag", u)
		return nil, nil
	}

	n, err := h.GetNamespace(u)
	if err == nil {
		fmt.Printf("%s -> namespace %s", u, n.Name)
		nodes, err := h.ListMachinesInNamespace(n.Name)
		if err != nil {
			return nil, err
		}
		ips := []string{}
		for _, n := range *nodes {
			ips = append(ips, n.IPAddress)
		}
		return &ips, nil
	}

	if h, ok := h.aclPolicy.Hosts[u]; ok {
		fmt.Printf("%s -> host %s", u, h)
		return &[]string{h.String()}, nil
	}

	ip, err := netaddr.ParseIP(u)
	if err == nil {
		fmt.Printf(" %s -> ip %s", u, ip)
		return &[]string{ip.String()}, nil
	}

	cidr, err := netaddr.ParseIPPrefix(u)
	if err == nil {
		fmt.Printf("%s -> cidr %s", u, cidr)
		return &[]string{cidr.String()}, nil
	}

	fmt.Printf("%s: cannot be mapped to anything\n", u)
	return nil, errorInvalidUserSection
}
