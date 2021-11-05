package headscale

import (
	"encoding/json"
	"strings"

	"github.com/tailscale/hujson"
	"inet.af/netaddr"
)

// ACLPolicy represents a Tailscale ACL Policy
type ACLPolicy struct {
	Groups    Groups    `json:"Groups"`
	Hosts     Hosts     `json:"Hosts"`
	TagOwners TagOwners `json:"TagOwners"`
	ACLs      []ACL     `json:"ACLs"`
	Tests     []ACLTest `json:"Tests"`
}

// ACL is a basic rule for the ACL Policy
type ACL struct {
	Action string   `json:"Action"`
	Users  []string `json:"Users"`
	Ports  []string `json:"Ports"`
}

// Groups references a series of alias in the ACL rules
type Groups map[string][]string

// Hosts are alias for IP addresses or subnets
type Hosts map[string]netaddr.IPPrefix

// TagOwners specify what users (namespaces?) are allow to use certain tags
type TagOwners map[string][]string

// ACLTest is not implemented, but should be use to check if a certain rule is allowed
type ACLTest struct {
	User  string   `json:"User"`
	Allow []string `json:"Allow"`
	Deny  []string `json:"Deny,omitempty"`
}

// UnmarshalJSON allows to parse the Hosts directly into netaddr objects
func (h *Hosts) UnmarshalJSON(data []byte) error {
	hosts := Hosts{}
	hs := make(map[string]string)
	ast, err := hujson.Parse(data)
	if err != nil {
		return err
	}
	ast.Standardize()
	data = ast.Pack()
	err = json.Unmarshal(data, &hs)
	if err != nil {
		return err
	}
	for k, v := range hs {
		if !strings.Contains(v, "/") {
			v = v + "/32"
		}
		prefix, err := netaddr.ParseIPPrefix(v)
		if err != nil {
			return err
		}
		hosts[k] = prefix
	}
	*h = hosts
	return nil
}

// IsZero is perhaps a bit naive here
func (p ACLPolicy) IsZero() bool {
	if len(p.Groups) == 0 && len(p.Hosts) == 0 && len(p.ACLs) == 0 {
		return true
	}
	return false
}
