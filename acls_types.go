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
	Groups    Groups    `json:"groups"    yaml:"groups"`
	Hosts     Hosts     `json:"hosts"     yaml:"hosts"`
	TagOwners TagOwners `json:"tagOwners" yaml:"tagOwners"`
	ACLs      []ACL     `json:"acls"      yaml:"acls"`
	Tests     []ACLTest `json:"tests"     yaml:"tests"`
}

// ACL is a basic rule for the ACL Policy.
type ACL struct {
	Action       string   `json:"action" yaml:"action"`
	Protocol     string   `json:"proto" yaml:"proto"`
	Sources      []string `json:"src"  yaml:"src"`
	Destinations []string `json:"dst"  yaml:"dst"`
}

// Groups references a series of alias in the ACL rules.
type Groups map[string][]string

// Hosts are alias for IP addresses or subnets.
type Hosts map[string]netaddr.IPPrefix

// TagOwners specify what users (namespaces?) are allow to use certain tags.
type TagOwners map[string][]string

// ACLTest is not implemented, but should be use to check if a certain rule is allowed.
type ACLTest struct {
	Source string   `json:"src"           yaml:"src"`
	Accept []string `json:"accept"          yaml:"accept"`
	Deny   []string `json:"deny,omitempty" yaml:"deny,omitempty"`
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
