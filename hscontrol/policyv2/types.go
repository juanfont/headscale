package policyv2

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/tailscale/hujson"
	"go4.org/netipx"
	"tailscale.com/net/tsaddr"
	"tailscale.com/tailcfg"
	"tailscale.com/types/ptr"
)

var theInternetSet *netipx.IPSet

// theInternet returns the IPSet for the Internet.
// https://www.youtube.com/watch?v=iDbyYGrswtg
func theInternet() *netipx.IPSet {
	if theInternetSet != nil {
		return theInternetSet
	}

	var internetBuilder netipx.IPSetBuilder
	internetBuilder.AddPrefix(netip.MustParsePrefix("2000::/3"))
	internetBuilder.AddPrefix(tsaddr.AllIPv4())

	// Delete Private network addresses
	// https://datatracker.ietf.org/doc/html/rfc1918
	internetBuilder.RemovePrefix(netip.MustParsePrefix("fc00::/7"))
	internetBuilder.RemovePrefix(netip.MustParsePrefix("10.0.0.0/8"))
	internetBuilder.RemovePrefix(netip.MustParsePrefix("172.16.0.0/12"))
	internetBuilder.RemovePrefix(netip.MustParsePrefix("192.168.0.0/16"))

	// Delete Tailscale networks
	internetBuilder.RemovePrefix(tsaddr.TailscaleULARange())
	internetBuilder.RemovePrefix(tsaddr.CGNATRange())

	// Delete "cant find DHCP networks"
	internetBuilder.RemovePrefix(netip.MustParsePrefix("fe80::/10")) // link-loca
	internetBuilder.RemovePrefix(netip.MustParsePrefix("169.254.0.0/16"))

	theInternetSet, _ := internetBuilder.IPSet()
	return theInternetSet
}

const Wildcard = Asterix(0)

type Asterix int

func (a Asterix) Validate() error {
	return nil
}

func (a Asterix) String() string {
	return "*"
}

func (a Asterix) UnmarshalJSON(b []byte) error {
	return nil
}

func (a Asterix) Resolve(_ *Policy, _ types.Users, nodes types.Nodes) (*netipx.IPSet, error) {
	var ips netipx.IPSetBuilder

	ips.AddPrefix(tsaddr.AllIPv4())
	ips.AddPrefix(tsaddr.AllIPv6())

	return ips.IPSet()
}

// Username is a string that represents a username, it must contain an @.
type Username string

func (u Username) Validate() error {
	if isUser(string(u)) {
		return nil
	}
	return fmt.Errorf("Username has to contain @, got: %q", u)
}

func (u *Username) String() string {
	return string(*u)
}

func (u *Username) UnmarshalJSON(b []byte) error {
	*u = Username(strings.Trim(string(b), `"`))
	if err := u.Validate(); err != nil {
		return err
	}
	return nil
}

func (u Username) CanBeTagOwner() bool {
	return true
}

var (
	ErrorNoUserMatching       = errors.New("no user matching")
	ErrorMultipleUserMatching = errors.New("multiple users matching")
)

// resolveUser attempts to find a user in the provided [types.Users] slice that matches the Username.
// It prioritizes matching the ProviderIdentifier, and if not found, it falls back to matching the Email or Name.
// If no matching user is found, it returns an error indicating no user matching.
// If multiple matching users are found, it returns an error indicating multiple users matching.
// It returns the matched types.User and a nil error if exactly one match is found.
func (u Username) resolveUser(users types.Users) (types.User, error) {
	var potentialUsers []types.User

	for _, user := range users {
		if user.ProviderIdentifier.Valid && user.ProviderIdentifier.String == u.String() {
			// Prioritize ProviderIdentifier match and exit early
			return user, nil
		}

		if user.Email == u.String() || user.Name == u.String() {
			potentialUsers = append(potentialUsers, user)
		}
	}

	if len(potentialUsers) == 0 {
		return types.User{}, fmt.Errorf("user with token %q not found: %w", u.String(), ErrorNoUserMatching)
	}

	if len(potentialUsers) > 1 {
		return types.User{}, fmt.Errorf("multiple users with token %q found: %w", u.String(), ErrorMultipleUserMatching)
	}

	return potentialUsers[0], nil
}

func (u Username) Resolve(_ *Policy, users types.Users, nodes types.Nodes) (*netipx.IPSet, error) {
	var ips netipx.IPSetBuilder

	user, err := u.resolveUser(users)
	if err != nil {
		return nil, err
	}

	for _, node := range nodes {
		if node.IsTagged() {
			continue
		}

		if node.User.ID == user.ID {
			node.AppendToIPSet(&ips)
		}
	}

	return ips.IPSet()
}

// Group is a special string which is always prefixed with `group:`
type Group string

func (g Group) Validate() error {
	if isGroup(string(g)) {
		return nil
	}
	return fmt.Errorf(`Group has to start with "group:", got: %q`, g)
}

func (g *Group) UnmarshalJSON(b []byte) error {
	*g = Group(strings.Trim(string(b), `"`))
	if err := g.Validate(); err != nil {
		return err
	}
	return nil
}

func (g Group) CanBeTagOwner() bool {
	return true
}

func (g Group) Resolve(p *Policy, users types.Users, nodes types.Nodes) (*netipx.IPSet, error) {
	var ips netipx.IPSetBuilder

	for _, user := range p.Groups[g] {
		uips, err := user.Resolve(nil, users, nodes)
		if err != nil {
			return nil, err
		}

		ips.AddSet(uips)
	}

	return ips.IPSet()
}

// Tag is a special string which is always prefixed with `tag:`
type Tag string

func (t Tag) Validate() error {
	if isTag(string(t)) {
		return nil
	}
	return fmt.Errorf(`tag has to start with "tag:", got: %q`, t)
}

func (t *Tag) UnmarshalJSON(b []byte) error {
	*t = Tag(strings.Trim(string(b), `"`))
	if err := t.Validate(); err != nil {
		return err
	}
	return nil
}

func (t Tag) Resolve(p *Policy, _ types.Users, nodes types.Nodes) (*netipx.IPSet, error) {
	var ips netipx.IPSetBuilder

	for _, node := range nodes {
		if node.HasTag(string(t)) {
			node.AppendToIPSet(&ips)
		}
	}

	return ips.IPSet()
}

// Host is a string that represents a hostname.
type Host string

func (h Host) Validate() error {
	// TODO(kradalby): figure out if the same type of validating makes sense here
	return nil
}

func (h *Host) UnmarshalJSON(b []byte) error {
	*h = Host(strings.Trim(string(b), `"`))
	if err := h.Validate(); err != nil {
		return err
	}
	return nil
}

func (h Host) Resolve(p *Policy, _ types.Users, nodes types.Nodes) (*netipx.IPSet, error) {
	var ips netipx.IPSetBuilder

	pref, ok := p.Hosts[h]
	if !ok {
		return nil, fmt.Errorf("unable to resolve host: %q", h)
	}
	err := pref.Validate()
	if err != nil {
		return nil, err
	}

	ips.AddPrefix(netip.Prefix(pref))

	// If the IP is a single host, look for a node to ensure we add all the IPs of
	// the node to the IPSet.
	// appendIfNodeHasIP(nodes, &ips, pref)

	// TODO(kradalby): I am a bit unsure what is the correct way to do this,
	// should a host with a non single IP be able to resolve the full host (inc all IPs).
	ipsTemp, err := ips.IPSet()
	if err != nil {
		return nil, err
	}
	for _, node := range nodes {
		if node.InIPSet(ipsTemp) {
			node.AppendToIPSet(&ips)
		}
	}

	return ips.IPSet()
}

// func appendIfNodeHasIP(nodes types.Nodes, ips *netipx.IPSetBuilder, pref Prefix) {
// 	if netip.Prefix(pref).IsSingleIP() {
// 		addr := netip.Prefix(pref).Addr()
// 		for _, node := range nodes {
// 			log.Printf("node ips: %v", node.IPsAsString())
// 			log.Printf("checking: %s", addr.String())
// 			if node.HasIP(addr) {
// 				log.Printf("ADDING")
// 				node.AppendToIPSet(ips)
// 			}
// 		}
// 	}
// }

type Prefix netip.Prefix

func (p Prefix) Validate() error {
	if !netip.Prefix(p).IsValid() {
		return fmt.Errorf("Prefix %q is invalid", p)
	}

	return nil
}

func (p Prefix) String() string {
	return netip.Prefix(p).String()
}

func (p *Prefix) parseString(addr string) error {
	if !strings.Contains(addr, "/") {
		addr, err := netip.ParseAddr(addr)
		if err != nil {
			return err
		}
		addrPref, err := addr.Prefix(addr.BitLen())
		if err != nil {
			return err
		}

		*p = Prefix(addrPref)
		return nil
	}

	pref, err := netip.ParsePrefix(addr)
	if err != nil {
		return err
	}
	*p = Prefix(pref)
	return nil
}

func (p *Prefix) UnmarshalJSON(b []byte) error {
	err := p.parseString(strings.Trim(string(b), `"`))
	if err != nil {
		return err
	}
	if err := p.Validate(); err != nil {
		return err
	}
	return nil
}

// Resolve resolves the Prefix to an IPSet. The IPSet will contain all the IP
// addresses that the Prefix represents within Headscale. It is the product
// of the Prefix and the Policy, Users, and Nodes.
//
// See [Policy], [types.Users], and [types.Nodes] for more details.
func (p Prefix) Resolve(_ *Policy, _ types.Users, nodes types.Nodes) (*netipx.IPSet, error) {
	var ips netipx.IPSetBuilder

	ips.AddPrefix(netip.Prefix(p))
	// If the IP is a single host, look for a node to ensure we add all the IPs of
	// the node to the IPSet.
	// appendIfNodeHasIP(nodes, &ips, pref)

	// TODO(kradalby): I am a bit unsure what is the correct way to do this,
	// should a host with a non single IP be able to resolve the full host (inc all IPs).
	// Currently this is done because the old implementation did this, we might want to
	// drop it before releasing.
	// For example:
	// If a src or dst includes "64.0.0.0/2:*", it will include 100.64/16 range, which
	// means that it will need to fetch the IPv6 addrs of the node to include the full range.
	// Clearly, if a user sets the dst to be "64.0.0.0/2:*", it is likely more of a exit node
	// and this would be strange behaviour.
	ipsTemp, err := ips.IPSet()
	if err != nil {
		return nil, err
	}
	for _, node := range nodes {
		if node.InIPSet(ipsTemp) {
			node.AppendToIPSet(&ips)
		}
	}

	return ips.IPSet()
}

// AutoGroup is a special string which is always prefixed with `autogroup:`
type AutoGroup string

const (
	AutoGroupInternet = "autogroup:internet"
)

var autogroups = []string{AutoGroupInternet}

func (ag AutoGroup) Validate() error {
	for _, valid := range autogroups {
		if valid == string(ag) {
			return nil
		}
	}

	return fmt.Errorf("AutoGroup is invalid, got: %q, must be one of %v", ag, autogroups)
}

func (ag *AutoGroup) UnmarshalJSON(b []byte) error {
	*ag = AutoGroup(strings.Trim(string(b), `"`))
	if err := ag.Validate(); err != nil {
		return err
	}
	return nil
}

func (ag AutoGroup) Resolve(_ *Policy, _ types.Users, _ types.Nodes) (*netipx.IPSet, error) {
	switch ag {
	case AutoGroupInternet:
		return theInternet(), nil
	}

	return nil, nil
}

type Alias interface {
	Validate() error
	UnmarshalJSON([]byte) error

	// Resolve resolves the Alias to an IPSet. The IPSet will contain all the IP
	// addresses that the Alias represents within Headscale. It is the product
	// of the Alias and the Policy, Users and Nodes.
	// This is an interface definition and the implementation is independent of
	// the Alias type.
	Resolve(*Policy, types.Users, types.Nodes) (*netipx.IPSet, error)
}

type AliasWithPorts struct {
	Alias
	Ports []tailcfg.PortRange
}

func (ve *AliasWithPorts) UnmarshalJSON(b []byte) error {
	// TODO(kradalby): use encoding/json/v2 (go-json-experiment)
	dec := json.NewDecoder(bytes.NewReader(b))
	var v any
	if err := dec.Decode(&v); err != nil {
		return err
	}

	switch vs := v.(type) {
	case string:
		var portsPart string
		var err error

		if strings.Contains(vs, ":") {
			vs, portsPart, err = splitDestinationAndPort(vs)
			if err != nil {
				return err
			}

			ports, err := parsePortRange(portsPart)
			if err != nil {
				return err
			}
			ve.Ports = ports
		}

		ve.Alias = parseAlias(vs)
		if ve.Alias == nil {
			return fmt.Errorf("could not determine the type of %q", vs)
		}
		if err := ve.Alias.Validate(); err != nil {
			return err
		}

	default:
		return fmt.Errorf("type %T not supported", vs)
	}
	return nil
}

func isWildcard(str string) bool {
	return str == "*"
}

func isUser(str string) bool {
	return strings.Contains(str, "@")
}

func isGroup(str string) bool {
	return strings.HasPrefix(str, "group:")
}

func isTag(str string) bool {
	return strings.HasPrefix(str, "tag:")
}

func isAutoGroup(str string) bool {
	return strings.HasPrefix(str, "autogroup:")
}

func isHost(str string) bool {
	return !isUser(str) && !strings.Contains(str, ":")
}

func parseAlias(vs string) Alias {
	var pref Prefix
	err := pref.parseString(vs)
	if err == nil {
		return &pref
	}

	switch {
	case isWildcard(vs):
		return Wildcard
	case isUser(vs):
		return ptr.To(Username(vs))
	case isGroup(vs):
		return ptr.To(Group(vs))
	case isTag(vs):
		return ptr.To(Tag(vs))
	case isAutoGroup(vs):
		return ptr.To(AutoGroup(vs))
	}

	if isHost(vs) {
		return ptr.To(Host(vs))
	}

	return nil
}

// AliasEnc is used to deserialize a Alias.
type AliasEnc struct{ Alias }

func (ve *AliasEnc) UnmarshalJSON(b []byte) error {
	// TODO(kradalby): use encoding/json/v2 (go-json-experiment)
	dec := json.NewDecoder(bytes.NewReader(b))
	var v any
	if err := dec.Decode(&v); err != nil {
		return err
	}
	switch val := v.(type) {
	case string:
		ve.Alias = parseAlias(val)
		if ve.Alias == nil {
			return fmt.Errorf("could not determine the type of %q", val)
		}
		if err := ve.Alias.Validate(); err != nil {
			return err
		}
	default:
		return fmt.Errorf("type %T not supported", val)
	}
	return nil
}

type Aliases []Alias

func (a *Aliases) UnmarshalJSON(b []byte) error {
	var aliases []AliasEnc
	err := json.Unmarshal(b, &aliases)
	if err != nil {
		return err
	}

	*a = make([]Alias, len(aliases))
	for i, alias := range aliases {
		(*a)[i] = alias.Alias
	}
	return nil
}

func (a Aliases) Resolve(p *Policy, users types.Users, nodes types.Nodes) (*netipx.IPSet, error) {
	var ips netipx.IPSetBuilder

	for _, alias := range a {
		aips, err := alias.Resolve(p, users, nodes)
		if err != nil {
			return nil, err
		}

		ips.AddSet(aips)
	}

	return ips.IPSet()
}

type Owner interface {
	CanBeTagOwner() bool
	UnmarshalJSON([]byte) error
}

// OwnerEnc is used to deserialize a Owner.
type OwnerEnc struct{ Owner }

func (ve *OwnerEnc) UnmarshalJSON(b []byte) error {
	// TODO(kradalby): use encoding/json/v2 (go-json-experiment)
	dec := json.NewDecoder(bytes.NewReader(b))
	var v any
	if err := dec.Decode(&v); err != nil {
		return err
	}
	switch val := v.(type) {
	case string:

		switch {
		case isUser(val):
			ve.Owner = ptr.To(Username(val))
		case isGroup(val):
			ve.Owner = ptr.To(Group(val))
		}
	default:
		return fmt.Errorf("type %T not supported", val)
	}
	return nil
}

type Owners []Owner

func (o *Owners) UnmarshalJSON(b []byte) error {
	var owners []OwnerEnc
	err := json.Unmarshal(b, &owners)
	if err != nil {
		return err
	}

	*o = make([]Owner, len(owners))
	for i, owner := range owners {
		(*o)[i] = owner.Owner
	}
	return nil
}

type Usernames []Username

// Groups are a map of Group to a list of Username.
type Groups map[Group]Usernames

// UnmarshalJSON overrides the default JSON unmarshalling for Groups to ensure
// that each group name is validated using the isGroup function. This ensures
// that all group names conform to the expected format, which is always prefixed
// with "group:". If any group name is invalid, an error is returned.
func (g *Groups) UnmarshalJSON(b []byte) error {
	var rawGroups map[string]Usernames
	if err := json.Unmarshal(b, &rawGroups); err != nil {
		return err
	}

	*g = make(Groups)
	for key, value := range rawGroups {
		group := Group(key)
		if err := group.Validate(); err != nil {
			return err
		}
		(*g)[group] = value
	}
	return nil
}

// Hosts are alias for IP addresses or subnets.
type Hosts map[Host]Prefix

// TagOwners are a map of Tag to a list of the UserEntities that own the tag.
type TagOwners map[Tag]Owners

type AutoApprovers struct {
	// Technically we should also allow Tags here, not only Owners (group and user).
	// Initially we will only allow Owners.
	// TODO(kradalby): add support for Tags
	Routes   map[netip.Prefix]Owners `json:"routes"`
	ExitNode Owners                  `json:"exitNode"`
}

// resolveAutoApprovers resolves the AutoApprovers to a map of netip.Prefix to netipx.IPSet.
// The resulting map can be used to quickly look up if a node can self-approve a route.
// It is intended for internal use in a PolicyManager.
func resolveAutoApprovers(p *Policy, users types.Users, nodes types.Nodes) (map[netip.Prefix]*netipx.IPSet, error) {
	routes := make(map[netip.Prefix]*netipx.IPSetBuilder)

	for prefix, owners := range p.AutoApprovers.Routes {
		if _, ok := routes[prefix]; !ok {
			routes[prefix] = new(netipx.IPSetBuilder)
		}
		for _, owner := range owners {
			o, ok := owner.(Alias)
			if !ok {
				// Should never happen
				return nil, fmt.Errorf("owner %v is not an Alias", owner)
			}
			ips, err := o.Resolve(p, users, nodes)
			if err != nil {
				return nil, err
			}
			routes[prefix].AddSet(ips)
		}
	}

	var exitNodeSetBuilder netipx.IPSetBuilder
	if len(p.AutoApprovers.ExitNode) > 0 {
		for _, owner := range p.AutoApprovers.ExitNode {
			o, ok := owner.(Alias)
			if !ok {
				// Should never happen
				return nil, fmt.Errorf("owner %v is not an Alias", owner)
			}
			ips, err := o.Resolve(p, users, nodes)
			if err != nil {
				return nil, err
			}
			exitNodeSetBuilder.AddSet(ips)
		}
	}

	ret := make(map[netip.Prefix]*netipx.IPSet)
	for prefix, builder := range routes {
		ipSet, err := builder.IPSet()
		if err != nil {
			return nil, err
		}
		ret[prefix] = ipSet
	}

	if len(p.AutoApprovers.ExitNode) > 0 {
		exitNodeSet, err := exitNodeSetBuilder.IPSet()
		if err != nil {
			return nil, err
		}

		ret[tsaddr.AllIPv4()] = exitNodeSet
		ret[tsaddr.AllIPv6()] = exitNodeSet
	}

	return ret, nil
}

type ACL struct {
	Action       string           `json:"action"` // TODO(kradalby): add strict type
	Protocol     string           `json:"proto"`  // TODO(kradalby): add strict type
	Sources      Aliases          `json:"src"`
	Destinations []AliasWithPorts `json:"dst"`
}

// Policy represents a Tailscale Network Policy.
// TODO(kradalby):
// Add validation method checking:
// All users exists
// All groups and users are valid tag TagOwners
// Everything referred to in ACLs exists in other
// entities.
type Policy struct {
	// validated is set if the policy has been validated.
	// It is not safe to use before it is validated, and
	// callers using it should panic if not
	validated bool `json:"-"`

	Groups        Groups        `json:"groups"`
	Hosts         Hosts         `json:"hosts"`
	TagOwners     TagOwners     `json:"tagOwners"`
	ACLs          []ACL         `json:"acls"`
	AutoApprovers AutoApprovers `json:"autoApprovers"`
	SSHs          []SSH         `json:"ssh"`
}

// SSH controls who can ssh into which machines.
type SSH struct {
	Action       string        `json:"action"` // TODO(kradalby): add strict type
	Sources      SSHSrcAliases `json:"src"`
	Destinations SSHDstAliases `json:"dst"`
	Users        []SSHUser     `json:"users"`
	CheckPeriod  time.Duration `json:"checkPeriod,omitempty"`
}

// SSHSrcAliases is a list of aliases that can be used as sources in an SSH rule.
// It can be a list of usernames, groups, tags or autogroups.
type SSHSrcAliases []Alias

func (a *SSHSrcAliases) UnmarshalJSON(b []byte) error {
	var aliases []AliasEnc
	err := json.Unmarshal(b, &aliases)
	if err != nil {
		return err
	}

	*a = make([]Alias, len(aliases))
	for i, alias := range aliases {
		switch alias.Alias.(type) {
		case *Username, *Group, *Tag, *AutoGroup:
			(*a)[i] = alias.Alias
		default:
			return fmt.Errorf("type %T not supported", alias.Alias)
		}
	}
	return nil
}

func (a SSHSrcAliases) Resolve(p *Policy, users types.Users, nodes types.Nodes) (*netipx.IPSet, error) {
	var ips netipx.IPSetBuilder

	for _, alias := range a {
		aips, err := alias.Resolve(p, users, nodes)
		if err != nil {
			return nil, err
		}

		ips.AddSet(aips)
	}

	return ips.IPSet()
}

// SSHDstAliases is a list of aliases that can be used as destinations in an SSH rule.
// It can be a list of usernames, tags or autogroups.
type SSHDstAliases []Alias

func (a *SSHDstAliases) UnmarshalJSON(b []byte) error {
	var aliases []AliasEnc
	err := json.Unmarshal(b, &aliases)
	if err != nil {
		return err
	}

	*a = make([]Alias, len(aliases))
	for i, alias := range aliases {
		switch alias.Alias.(type) {
		case *Username, *Tag, *AutoGroup:
			(*a)[i] = alias.Alias
		default:
			return fmt.Errorf("type %T not supported", alias.Alias)
		}
	}
	return nil
}

type SSHUser string

func (u SSHUser) String() string {
	return string(u)
}

func policyFromBytes(b []byte) (*Policy, error) {
	var policy Policy
	ast, err := hujson.Parse(b)
	if err != nil {
		return nil, fmt.Errorf("parsing HuJSON: %w", err)
	}

	ast.Standardize()
	acl := ast.Pack()

	err = json.Unmarshal(acl, &policy)
	if err != nil {
		return nil, fmt.Errorf("parsing policy from bytes: %w", err)
	}

	return &policy, nil
}

const (
	expectedTokenItems = 2
)
