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
	Groups    Groups    `json:"Groups"    yaml:"Groups"`
	Hosts     Hosts     `json:"Hosts"     yaml:"Hosts"`
	TagOwners TagOwners `json:"TagOwners" yaml:"TagOwners"`
	ACLs      []ACL     `json:"ACLs"      yaml:"ACLs"`
	Tests     []ACLTest `json:"Tests"     yaml:"Tests"`
}

// ACL is a basic rule for the ACL Policy.
type ACL struct {
	Action string   `json:"Action" yaml:"Action"`
	Users  []string `json:"Users"  yaml:"Users"`
	Ports  []string `json:"Ports"  yaml:"Ports"`
}

// Groups references a series of alias in the ACL rules.
type Groups map[string][]string

// Hosts are alias for IP addresses or subnets.
type Hosts map[string]netaddr.IPPrefix

// TagOwners specify what users (namespaces?) are allow to use certain tags.
type TagOwners map[string][]string

// ACLTest is not implemented, but should be use to check if a certain rule is allowed.
type ACLTest struct {
	User  string   `json:"User"           yaml:"User"`
	Allow []string `json:"Allow"          yaml:"Allow"`
	Deny  []string `json:"Deny,omitempty" yaml:"Deny,omitempty"`
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
