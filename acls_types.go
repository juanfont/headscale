package headscale

import (
	"strings"

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

type Hosts map[string]string

type TagOwners struct {
	TagMontrealWebserver []string `json:"tag:montreal-webserver"`
	TagAPIServer         []string `json:"tag:api-server"`
}

type ACLTest struct {
	User  string   `json:"User"`
	Allow []string `json:"Allow"`
	Deny  []string `json:"Deny,omitempty"`
}

// IsZero is perhaps a bit naive here
func (p ACLPolicy) IsZero() bool {
	if len(p.Groups) == 0 && len(p.Hosts) == 0 && len(p.ACLs) == 0 {
		return true
	}
	return false
}

func (p ACLPolicy) GetHosts() (*map[string]netaddr.IPPrefix, error) {
	hosts := make(map[string]netaddr.IPPrefix)
	for k, v := range p.Hosts {
		if !strings.Contains(v, "/") {
			v = v + "/32"
		}
		prefix, err := netaddr.ParseIPPrefix(v)
		if err != nil {
			return nil, err
		}
		hosts[k] = prefix
	}
	return &hosts, nil
}
