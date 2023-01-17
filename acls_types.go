package headscale

import (
	"encoding/json"
	"net/netip"
	"strings"

	"github.com/tailscale/hujson"
	"gopkg.in/yaml.v3"
)

// ACLPolicy represents a Tailscale ACL Policy.
type ACLPolicy struct {
	Groups        Groups        `json:"groups"        yaml:"groups"`
	Hosts         Hosts         `json:"hosts"         yaml:"hosts"`
	TagOwners     TagOwners     `json:"tagOwners"     yaml:"tagOwners"`
	ACLs          []ACL         `json:"acls"          yaml:"acls"`
	Tests         []ACLTest     `json:"tests"         yaml:"tests"`
	AutoApprovers AutoApprovers `json:"autoApprovers" yaml:"autoApprovers"`
	SSHs          []SSH         `json:"ssh"           yaml:"ssh"`
}

// ACL is a basic rule for the ACL Policy.
type ACL struct {
	Action       string   `json:"action" yaml:"action"`
	Protocol     string   `json:"proto"  yaml:"proto"`
	Sources      []string `json:"src"    yaml:"src"`
	Destinations []string `json:"dst"    yaml:"dst"`
}

// Groups references a series of alias in the ACL rules.
type Groups map[string][]string

// Hosts are alias for IP addresses or subnets.
type Hosts map[string]netip.Prefix

// TagOwners specify what users (users?) are allow to use certain tags.
type TagOwners map[string][]string

// ACLTest is not implemented, but should be use to check if a certain rule is allowed.
type ACLTest struct {
	Source string   `json:"src"            yaml:"src"`
	Accept []string `json:"accept"         yaml:"accept"`
	Deny   []string `json:"deny,omitempty" yaml:"deny,omitempty"`
}

// AutoApprovers specify which users (users?), groups or tags have their advertised routes
// or exit node status automatically enabled.
type AutoApprovers struct {
	Routes   map[string][]string `json:"routes"   yaml:"routes"`
	ExitNode []string            `json:"exitNode" yaml:"exitNode"`
}

// SSH controls who can ssh into which machines.
type SSH struct {
	Action       string   `json:"action"                yaml:"action"`
	Sources      []string `json:"src"                   yaml:"src"`
	Destinations []string `json:"dst"                   yaml:"dst"`
	Users        []string `json:"users"                 yaml:"users"`
	CheckPeriod  string   `json:"checkPeriod,omitempty" yaml:"checkPeriod,omitempty"`
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

// UnmarshalYAML allows to parse the Hosts directly into netip objects.
func (hosts *Hosts) UnmarshalYAML(data []byte) error {
	newHosts := Hosts{}
	hostIPPrefixMap := make(map[string]string)

	err := yaml.Unmarshal(data, &hostIPPrefixMap)
	if err != nil {
		return err
	}
	for host, prefixStr := range hostIPPrefixMap {
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
func (policy ACLPolicy) IsZero() bool {
	if len(policy.Groups) == 0 && len(policy.Hosts) == 0 && len(policy.ACLs) == 0 {
		return true
	}

	return false
}

// Returns the list of autoApproving users, groups or tags for a given IPPrefix.
func (autoApprovers *AutoApprovers) GetRouteApprovers(
	prefix netip.Prefix,
) ([]string, error) {
	if prefix.Bits() == 0 {
		return autoApprovers.ExitNode, nil // 0.0.0.0/0, ::/0 or equivalent
	}

	approverAliases := []string{}

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
