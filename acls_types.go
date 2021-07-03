package headscale

import (
	"strings"

	"github.com/tailscale/hujson"
	"inet.af/netaddr"
)

type ACLPolicy struct {
	Groups    Groups    `json:"Groups"`
	Hosts     Hosts     `json:"Hosts"`
	TagOwners TagOwners `json:"TagOwners"`
	ACLs      []ACL     `json:"ACLs"`
	Tests     []ACLTest `json:"Tests"`
}

type ACL struct {
	Action string   `json:"Action"`
	Users  []string `json:"Users"`
	Ports  []string `json:"Ports"`
}

type Groups map[string][]string

type Hosts map[string]netaddr.IPPrefix

type TagOwners map[string][]string

type ACLTest struct {
	User  string   `json:"User"`
	Allow []string `json:"Allow"`
	Deny  []string `json:"Deny,omitempty"`
}

func (h *Hosts) UnmarshalJSON(data []byte) error {
	hosts := Hosts{}
	hs := make(map[string]string)
	err := hujson.Unmarshal(data, &hs)
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
