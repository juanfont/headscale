package policy

import (
	"encoding/json"
	"net/netip"
	"strings"

	"github.com/tailscale/hujson"
)

// ACLPolicy represents a Tailscale ACL Policy.
type ACLPolicy struct {
	Groups        Groups        `json:"groups"`
	Hosts         Hosts         `json:"hosts"`
	TagOwners     TagOwners     `json:"tagOwners"`
	ACLs          []ACL         `json:"acls"`
	Tests         []ACLTest     `json:"tests"`
	AutoApprovers AutoApprovers `json:"autoApprovers"`
	SSHs          []SSH         `json:"ssh"`
}

// ACL is a basic rule for the ACL Policy.
type ACL struct {
	Action       string   `json:"action"`
	Protocol     string   `json:"proto"`
	Sources      []string `json:"src"`
	Destinations []string `json:"dst"`
}

// Groups references a series of alias in the ACL rules.
type Groups map[string][]string

// Hosts are alias for IP addresses or subnets.
type Hosts map[string]netip.Prefix

// TagOwners specify what users (users?) are allow to use certain tags.
type TagOwners map[string][]string

// ACLTest is not implemented, but should be used to check if a certain rule is allowed.
type ACLTest struct {
	Source string   `json:"src"`
	Accept []string `json:"accept"`
	Deny   []string `json:"deny,omitempty"`
}

// AutoApprovers specify which users (users?), groups or tags have their advertised routes
// or exit node status automatically enabled.
type AutoApprovers struct {
	Routes   map[string][]string `json:"routes"`
	ExitNode []string            `json:"exitNode"`
}

// SSH controls who can ssh into which machines.
type SSH struct {
	Action       string   `json:"action"`
	Sources      []string `json:"src"`
	Destinations []string `json:"dst"`
	Users        []string `json:"users"`
	CheckPeriod  string   `json:"checkPeriod,omitempty"`
}

// UnmarshalJSON allows to parse the Hosts directly into netip objects.
func (hosts *Hosts) UnmarshalJSON(data []byte) error {
	newHosts := Hosts{}
	hostIPPrefixMap := make(map[string]string)
	ast, err := hujson.Parse(data)
	if err != nil {
		return err
	}
	ast.Standardize()
	data = ast.Pack()
	err = json.Unmarshal(data, &hostIPPrefixMap)
	if err != nil {
		return err
	}
	for host, prefixStr := range hostIPPrefixMap {
		if !strings.Contains(prefixStr, "/") {
			prefixStr += "/32"
		}
		prefix, err := netip.ParsePrefix(prefixStr)
		if err != nil {
			return err
		}
		newHosts[host] = prefix
	}
	*hosts = newHosts

	return nil
}

// IsZero is perhaps a bit naive here.
func (pol ACLPolicy) IsZero() bool {
	if len(pol.Groups) == 0 && len(pol.Hosts) == 0 && len(pol.ACLs) == 0 {
		return true
	}

	return false
}

// GetRouteApprovers returns the list of autoApproving users, groups or tags for a given IPPrefix.
func (autoApprovers *AutoApprovers) GetRouteApprovers(
	prefix netip.Prefix,
) ([]string, error) {
	if prefix.Bits() == 0 {
		return autoApprovers.ExitNode, nil // 0.0.0.0/0, ::/0 or equivalent
	}

	approverAliases := make([]string, 0)

	for autoApprovedPrefix, autoApproverAliases := range autoApprovers.Routes {
		autoApprovedPrefix, err := netip.ParsePrefix(autoApprovedPrefix)
		if err != nil {
			return nil, err
		}

		if prefix.Bits() >= autoApprovedPrefix.Bits() &&
			autoApprovedPrefix.Contains(prefix.Masked().Addr()) {
			approverAliases = append(approverAliases, autoApproverAliases...)
		}
	}

	return approverAliases, nil
}
