package headscale

import (
	"encoding/json"
	"strings"

	"github.com/tailscale/hujson"
	"gopkg.in/yaml.v3"
	"inet.af/netaddr"
)

// ACLPolicy represents a Tailscale ACL Policy.
type ACLPolicy struct {
	Groups    Groups    `json:"groups,omitempty"    yaml:"groups,omitempty"`
	Hosts     Hosts     `json:"hosts,omitempty"     yaml:"hosts,omitempty"`
	TagOwners TagOwners `json:"tagOwners,omitempty" yaml:"tagOwners,omitempty"`
	ACLs      []ACL     `json:"acls,omitempty"      yaml:"acls,omitempty"`
	Tests     []ACLTest `json:"tests,omitempty"     yaml:"tests,omitempty"`
}

// ACL is a basic rule for the ACL Policy.
type ACL struct {
	Action       string   `json:"action,omitempty" yaml:"action,omitempty"`
	Protocol     string   `json:"proto,omitempty"  yaml:"proto,omitempty"`
	Sources      []string `json:"src,omitempty"    yaml:"src,omitempty"`
	Destinations []string `json:"dst,omitempty"    yaml:"dst,omitempty"`
}

// Groups references a series of alias in the ACL rules.
type Groups map[string][]string

// Hosts are alias for IP addresses or subnets.
type Hosts map[string]netaddr.IPPrefix

// TagOwners specify what users (namespaces?) are allow to use certain tags.
type TagOwners map[string][]string

// ACLTest is not implemented, but should be use to check if a certain rule is allowed.
type ACLTest struct {
	Source string   `json:"src,omitempty"    yaml:"src,omitempty"`
	Accept []string `json:"accept,omitempty" yaml:"accept,omitempty"`
	Deny   []string `json:"deny,omitempty"   yaml:"deny,omitempty"`
}

// UnmarshalJSON allows to parse the Hosts directly into netaddr objects.
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
		prefix, err := netaddr.ParseIPPrefix(prefixStr)
		if err != nil {
			return err
		}
		newHosts[host] = prefix
	}
	*hosts = newHosts

	return nil
}

// UnmarshalYAML allows to parse the Hosts directly into netaddr objects.
func (hosts *Hosts) UnmarshalYAML(data []byte) error {
	newHosts := Hosts{}
	hostIPPrefixMap := make(map[string]string)

	err := yaml.Unmarshal(data, &hostIPPrefixMap)
	if err != nil {
		return err
	}
	for host, prefixStr := range hostIPPrefixMap {
		prefix, err := netaddr.ParseIPPrefix(prefixStr)
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
