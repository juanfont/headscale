package v2

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"

	"slices"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/prometheus/common/model"
	"github.com/tailscale/hujson"
	"go4.org/netipx"
	"tailscale.com/net/tsaddr"
	"tailscale.com/tailcfg"
	"tailscale.com/types/ptr"
	"tailscale.com/util/multierr"
)

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

	// TODO(kradalby):
	// Should this actually only be the CGNAT spaces? I do not think so, because
	// we also want to include subnet routers right?
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

func (u Username) CanBeAutoApprover() bool {
	return true
}

// resolveUser attempts to find a user in the provided [types.Users] slice that matches the Username.
// It prioritizes matching the ProviderIdentifier, and if not found, it falls back to matching the Email or Name.
// If no matching user is found, it returns an error indicating no user matching.
// If multiple matching users are found, it returns an error indicating multiple users matching.
// It returns the matched types.User and a nil error if exactly one match is found.
func (u Username) resolveUser(users types.Users) (types.User, error) {
	var potentialUsers types.Users

	// At parsetime, we require all usernames to contain an "@" character, if the
	// username token does not naturally do so (like email), the user have to
	// add it to the end of the username. We strip it here as we do not expect the
	// usernames to be stored with the "@".
	uTrimmed := strings.TrimSuffix(u.String(), "@")

	for _, user := range users {
		if user.ProviderIdentifier.Valid && user.ProviderIdentifier.String == uTrimmed {
			// Prioritize ProviderIdentifier match and exit early
			return user, nil
		}

		if user.Email == uTrimmed || user.Name == uTrimmed {
			potentialUsers = append(potentialUsers, user)
		}
	}

	if len(potentialUsers) == 0 {
		return types.User{}, fmt.Errorf("user with token %q not found", u.String())
	}

	if len(potentialUsers) > 1 {
		return types.User{}, fmt.Errorf("multiple users with token %q found: %s", u.String(), potentialUsers.String())
	}

	return potentialUsers[0], nil
}

func (u Username) Resolve(_ *Policy, users types.Users, nodes types.Nodes) (*netipx.IPSet, error) {
	var ips netipx.IPSetBuilder
	var errs []error

	user, err := u.resolveUser(users)
	if err != nil {
		errs = append(errs, err)
	}

	for _, node := range nodes {
		if node.IsTagged() {
			continue
		}

		if node.User.ID == user.ID {
			node.AppendToIPSet(&ips)
		}
	}

	return buildIPSetMultiErr(&ips, errs)
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

func (g Group) CanBeAutoApprover() bool {
	return true
}

func (g Group) String() string {
	return string(g)
}

func (g Group) Resolve(p *Policy, users types.Users, nodes types.Nodes) (*netipx.IPSet, error) {
	var ips netipx.IPSetBuilder
	var errs []error

	for _, user := range p.Groups[g] {
		uips, err := user.Resolve(nil, users, nodes)
		if err != nil {
			errs = append(errs, err)
		}

		ips.AddSet(uips)
	}

	return buildIPSetMultiErr(&ips, errs)
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

func (t Tag) Resolve(p *Policy, users types.Users, nodes types.Nodes) (*netipx.IPSet, error) {
	var ips netipx.IPSetBuilder

	// TODO(kradalby): This is currently resolved twice, and should be resolved once.
	// It is added temporary until we sort out the story on how and when we resolve tags
	// from the three places they can be "approved":
	// - As part of a PreAuthKey (handled in HasTag)
	// - As part of ForcedTags (set via CLI) (handled in HasTag)
	// - As part of HostInfo.RequestTags and approved by policy (this is happening here)
	// Part of #2417
	tagMap, err := resolveTagOwners(p, users, nodes)
	if err != nil {
		return nil, err
	}

	for _, node := range nodes {
		if node.HasTag(string(t)) {
			node.AppendToIPSet(&ips)
		}

		// TODO(kradalby): remove as part of #2417, see comment above
		if tagMap != nil {
			if tagips, ok := tagMap[t]; ok && node.InIPSet(tagips) && node.Hostinfo != nil {
				for _, tag := range node.Hostinfo.RequestTags {
					if tag == string(t) {
						node.AppendToIPSet(&ips)
					}
				}
			}
		}
	}

	return ips.IPSet()
}

func (t Tag) CanBeAutoApprover() bool {
	return true
}

func (t Tag) String() string {
	return string(t)
}

// Host is a string that represents a hostname.
type Host string

func (h Host) Validate() error {
	if isHost(string(h)) {
		return nil
	}
	return fmt.Errorf("Hostname %q is invalid", h)
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
	var errs []error

	pref, ok := p.Hosts[h]
	if !ok {
		return nil, fmt.Errorf("unable to resolve host: %q", h)
	}
	err := pref.Validate()
	if err != nil {
		errs = append(errs, err)
	}

	ips.AddPrefix(netip.Prefix(pref))

	// If the IP is a single host, look for a node to ensure we add all the IPs of
	// the node to the IPSet.
	// appendIfNodeHasIP(nodes, &ips, pref)

	// TODO(kradalby): I am a bit unsure what is the correct way to do this,
	// should a host with a non single IP be able to resolve the full host (inc all IPs).
	ipsTemp, err := ips.IPSet()
	if err != nil {
		errs = append(errs, err)
	}
	for _, node := range nodes {
		if node.InIPSet(ipsTemp) {
			node.AppendToIPSet(&ips)
		}
	}

	return buildIPSetMultiErr(&ips, errs)
}

type Prefix netip.Prefix

func (p Prefix) Validate() error {
	if netip.Prefix(p).IsValid() {
		return nil
	}
	return fmt.Errorf("Prefix %q is invalid", p)
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
	var errs []error

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
		errs = append(errs, err)
	}
	for _, node := range nodes {
		if node.InIPSet(ipsTemp) {
			node.AppendToIPSet(&ips)
		}
	}

	return buildIPSetMultiErr(&ips, errs)
}

// AutoGroup is a special string which is always prefixed with `autogroup:`
type AutoGroup string

const (
	AutoGroupInternet AutoGroup = "autogroup:internet"
	AutoGroupNonRoot  AutoGroup = "autogroup:nonroot"

	// These are not yet implemented.
	AutoGroupSelf   AutoGroup = "autogroup:self"
	AutoGroupMember AutoGroup = "autogroup:member"
	AutoGroupTagged AutoGroup = "autogroup:tagged"
)

var autogroups = []AutoGroup{AutoGroupInternet}

func (ag AutoGroup) Validate() error {
	if slices.Contains(autogroups, ag) {
		return nil
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
		return util.TheInternet(), nil
	}

	return nil, nil
}

func (ag *AutoGroup) Is(c AutoGroup) bool {
	if ag == nil {
		return false
	}

	return *ag == c
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

		ve.Alias, err = parseAlias(vs)
		if err != nil {
			return err
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

func parseAlias(vs string) (Alias, error) {
	var pref Prefix
	err := pref.parseString(vs)
	if err == nil {
		return &pref, nil
	}

	switch {
	case isWildcard(vs):
		return Wildcard, nil
	case isUser(vs):
		return ptr.To(Username(vs)), nil
	case isGroup(vs):
		return ptr.To(Group(vs)), nil
	case isTag(vs):
		return ptr.To(Tag(vs)), nil
	case isAutoGroup(vs):
		return ptr.To(AutoGroup(vs)), nil
	}

	if isHost(vs) {
		return ptr.To(Host(vs)), nil
	}

	return nil, fmt.Errorf(`Invalid alias %q. An alias must be one of the following types:
- wildcard (*)
- user (containing an "@")
- group (starting with "group:")
- tag (starting with "tag:")
- autogroup (starting with "autogroup:")
- host

Please check the format and try again.`, vs)
}

// AliasEnc is used to deserialize a Alias.
type AliasEnc struct{ Alias }

func (ve *AliasEnc) UnmarshalJSON(b []byte) error {
	ptr, err := unmarshalPointer(
		b,
		parseAlias,
	)
	if err != nil {
		return err
	}
	ve.Alias = ptr
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
	var errs []error

	for _, alias := range a {
		aips, err := alias.Resolve(p, users, nodes)
		if err != nil {
			errs = append(errs, err)
		}

		ips.AddSet(aips)
	}

	return buildIPSetMultiErr(&ips, errs)
}

func buildIPSetMultiErr(ipBuilder *netipx.IPSetBuilder, errs []error) (*netipx.IPSet, error) {
	ips, err := ipBuilder.IPSet()
	return ips, multierr.New(append(errs, err)...)
}

// Helper function to unmarshal a JSON string into either an AutoApprover or Owner pointer
func unmarshalPointer[T any](
	b []byte,
	parseFunc func(string) (T, error),
) (T, error) {
	var s string
	err := json.Unmarshal(b, &s)
	if err != nil {
		var t T
		return t, err
	}

	return parseFunc(s)
}

type AutoApprover interface {
	CanBeAutoApprover() bool
	UnmarshalJSON([]byte) error
	String() string
}

type AutoApprovers []AutoApprover

func (aa *AutoApprovers) UnmarshalJSON(b []byte) error {
	var autoApprovers []AutoApproverEnc
	err := json.Unmarshal(b, &autoApprovers)
	if err != nil {
		return err
	}

	*aa = make([]AutoApprover, len(autoApprovers))
	for i, autoApprover := range autoApprovers {
		(*aa)[i] = autoApprover.AutoApprover
	}
	return nil
}

func parseAutoApprover(s string) (AutoApprover, error) {
	switch {
	case isUser(s):
		return ptr.To(Username(s)), nil
	case isGroup(s):
		return ptr.To(Group(s)), nil
	case isTag(s):
		return ptr.To(Tag(s)), nil
	}

	return nil, fmt.Errorf(`Invalid AutoApprover %q. An alias must be one of the following types:
- user (containing an "@")
- group (starting with "group:")
- tag (starting with "tag:")

Please check the format and try again.`, s)
}

// AutoApproverEnc is used to deserialize a AutoApprover.
type AutoApproverEnc struct{ AutoApprover }

func (ve *AutoApproverEnc) UnmarshalJSON(b []byte) error {
	ptr, err := unmarshalPointer(
		b,
		parseAutoApprover,
	)
	if err != nil {
		return err
	}
	ve.AutoApprover = ptr
	return nil
}

type Owner interface {
	CanBeTagOwner() bool
	UnmarshalJSON([]byte) error
}

// OwnerEnc is used to deserialize a Owner.
type OwnerEnc struct{ Owner }

func (ve *OwnerEnc) UnmarshalJSON(b []byte) error {
	ptr, err := unmarshalPointer(
		b,
		parseOwner,
	)
	if err != nil {
		return err
	}
	ve.Owner = ptr
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

func parseOwner(s string) (Owner, error) {
	switch {
	case isUser(s):
		return ptr.To(Username(s)), nil
	case isGroup(s):
		return ptr.To(Group(s)), nil
	}
	return nil, fmt.Errorf(`Invalid Owner %q. An alias must be one of the following types:
- user (containing an "@")
- group (starting with "group:")
- tag (starting with "tag:")

Please check the format and try again.`, s)
}

type Usernames []Username

// Groups are a map of Group to a list of Username.
type Groups map[Group]Usernames

func (g Groups) Contains(group *Group) error {
	if group == nil {
		return nil
	}

	for defined := range map[Group]Usernames(g) {
		if defined == *group {
			return nil
		}
	}

	return fmt.Errorf(`Group %q is not defined in the Policy, please define or remove the reference to it`, group)
}

// UnmarshalJSON overrides the default JSON unmarshalling for Groups to ensure
// that each group name is validated using the isGroup function. This ensures
// that all group names conform to the expected format, which is always prefixed
// with "group:". If any group name is invalid, an error is returned.
func (g *Groups) UnmarshalJSON(b []byte) error {
	var rawGroups map[string][]string
	if err := json.Unmarshal(b, &rawGroups); err != nil {
		return err
	}

	*g = make(Groups)
	for key, value := range rawGroups {
		group := Group(key)
		if err := group.Validate(); err != nil {
			return err
		}

		var usernames Usernames

		for _, u := range value {
			username := Username(u)
			if err := username.Validate(); err != nil {
				if isGroup(u) {
					return fmt.Errorf("Nested groups are not allowed, found %q inside %q", u, group)
				}

				return err
			}
			usernames = append(usernames, username)
		}

		(*g)[group] = usernames
	}
	return nil
}

// Hosts are alias for IP addresses or subnets.
type Hosts map[Host]Prefix

func (h *Hosts) UnmarshalJSON(b []byte) error {
	var rawHosts map[string]string
	if err := json.Unmarshal(b, &rawHosts); err != nil {
		return err
	}

	*h = make(Hosts)
	for key, value := range rawHosts {
		host := Host(key)
		if err := host.Validate(); err != nil {
			return err
		}

		var pref Prefix
		err := pref.parseString(value)
		if err != nil {
			return fmt.Errorf("Hostname %q contains an invalid IP address: %q", key, value)
		}

		(*h)[host] = pref
	}
	return nil
}

func (h Hosts) exist(name Host) bool {
	_, ok := h[name]
	return ok
}

// TagOwners are a map of Tag to a list of the UserEntities that own the tag.
type TagOwners map[Tag]Owners

func (to TagOwners) Contains(tagOwner *Tag) error {
	if tagOwner == nil {
		return nil
	}

	for defined := range map[Tag]Owners(to) {
		if defined == *tagOwner {
			return nil
		}
	}

	return fmt.Errorf(`Tag %q is not defined in the Policy, please define or remove the reference to it`, tagOwner)
}

// resolveTagOwners resolves the TagOwners to a map of Tag to netipx.IPSet.
// The resulting map can be used to quickly look up the IPSet for a given Tag.
// It is intended for internal use in a PolicyManager.
func resolveTagOwners(p *Policy, users types.Users, nodes types.Nodes) (map[Tag]*netipx.IPSet, error) {
	if p == nil {
		return nil, nil
	}

	ret := make(map[Tag]*netipx.IPSet)

	for tag, owners := range p.TagOwners {
		var ips netipx.IPSetBuilder

		for _, owner := range owners {
			o, ok := owner.(Alias)
			if !ok {
				// Should never happen
				return nil, fmt.Errorf("owner %v is not an Alias", owner)
			}
			// If it does not resolve, that means the tag is not associated with any IP addresses.
			resolved, _ := o.Resolve(p, users, nodes)
			ips.AddSet(resolved)
		}

		ipSet, err := ips.IPSet()
		if err != nil {
			return nil, err
		}

		ret[tag] = ipSet
	}

	return ret, nil
}

type AutoApproverPolicy struct {
	Routes   map[netip.Prefix]AutoApprovers `json:"routes"`
	ExitNode AutoApprovers                  `json:"exitNode"`
}

// resolveAutoApprovers resolves the AutoApprovers to a map of netip.Prefix to netipx.IPSet.
// The resulting map can be used to quickly look up if a node can self-approve a route.
// It is intended for internal use in a PolicyManager.
func resolveAutoApprovers(p *Policy, users types.Users, nodes types.Nodes) (map[netip.Prefix]*netipx.IPSet, *netipx.IPSet, error) {
	if p == nil {
		return nil, nil, nil
	}
	var err error

	routes := make(map[netip.Prefix]*netipx.IPSetBuilder)

	for prefix, autoApprovers := range p.AutoApprovers.Routes {
		if _, ok := routes[prefix]; !ok {
			routes[prefix] = new(netipx.IPSetBuilder)
		}
		for _, autoApprover := range autoApprovers {
			aa, ok := autoApprover.(Alias)
			if !ok {
				// Should never happen
				return nil, nil, fmt.Errorf("autoApprover %v is not an Alias", autoApprover)
			}
			// If it does not resolve, that means the autoApprover is not associated with any IP addresses.
			ips, _ := aa.Resolve(p, users, nodes)
			routes[prefix].AddSet(ips)
		}
	}

	var exitNodeSetBuilder netipx.IPSetBuilder
	if len(p.AutoApprovers.ExitNode) > 0 {
		for _, autoApprover := range p.AutoApprovers.ExitNode {
			aa, ok := autoApprover.(Alias)
			if !ok {
				// Should never happen
				return nil, nil, fmt.Errorf("autoApprover %v is not an Alias", autoApprover)
			}
			// If it does not resolve, that means the autoApprover is not associated with any IP addresses.
			ips, _ := aa.Resolve(p, users, nodes)
			exitNodeSetBuilder.AddSet(ips)
		}
	}

	ret := make(map[netip.Prefix]*netipx.IPSet)
	for prefix, builder := range routes {
		ipSet, err := builder.IPSet()
		if err != nil {
			return nil, nil, err
		}
		ret[prefix] = ipSet
	}

	var exitNodeSet *netipx.IPSet
	if len(p.AutoApprovers.ExitNode) > 0 {
		exitNodeSet, err = exitNodeSetBuilder.IPSet()
		if err != nil {
			return nil, nil, err
		}
	}

	return ret, exitNodeSet, nil
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

	Groups        Groups             `json:"groups"`
	Hosts         Hosts              `json:"hosts"`
	TagOwners     TagOwners          `json:"tagOwners"`
	ACLs          []ACL              `json:"acls"`
	AutoApprovers AutoApproverPolicy `json:"autoApprovers"`
	SSHs          []SSH              `json:"ssh"`
}

var (
	autogroupForSrc       = []AutoGroup{}
	autogroupForDst       = []AutoGroup{AutoGroupInternet}
	autogroupForSSHSrc    = []AutoGroup{}
	autogroupForSSHDst    = []AutoGroup{}
	autogroupForSSHUser   = []AutoGroup{AutoGroupNonRoot}
	autogroupNotSupported = []AutoGroup{AutoGroupSelf, AutoGroupMember, AutoGroupTagged}
)

func validateAutogroupSupported(ag *AutoGroup) error {
	if ag == nil {
		return nil
	}

	if slices.Contains(autogroupNotSupported, *ag) {
		return fmt.Errorf("autogroup %q is not supported in headscale", *ag)
	}

	return nil
}

func validateAutogroupForSrc(src *AutoGroup) error {
	if src == nil {
		return nil
	}

	if src.Is(AutoGroupInternet) {
		return fmt.Errorf(`"autogroup:internet" used in source, it can only be used in ACL destinations`)
	}

	if !slices.Contains(autogroupForSrc, *src) {
		return fmt.Errorf("autogroup %q is not supported for ACL sources, can be %v", *src, autogroupForSrc)
	}

	return nil
}

func validateAutogroupForDst(dst *AutoGroup) error {
	if dst == nil {
		return nil
	}

	if !slices.Contains(autogroupForDst, *dst) {
		return fmt.Errorf("autogroup %q is not supported for ACL destinations, can be %v", *dst, autogroupForDst)
	}

	return nil
}

func validateAutogroupForSSHSrc(src *AutoGroup) error {
	if src == nil {
		return nil
	}

	if src.Is(AutoGroupInternet) {
		return fmt.Errorf(`"autogroup:internet" used in SSH source, it can only be used in ACL destinations`)
	}

	if !slices.Contains(autogroupForSSHSrc, *src) {
		return fmt.Errorf("autogroup %q is not supported for SSH sources, can be %v", *src, autogroupForSSHSrc)
	}

	return nil
}

func validateAutogroupForSSHDst(dst *AutoGroup) error {
	if dst == nil {
		return nil
	}

	if dst.Is(AutoGroupInternet) {
		return fmt.Errorf(`"autogroup:internet" used in SSH destination, it can only be used in ACL destinations`)
	}

	if !slices.Contains(autogroupForSSHDst, *dst) {
		return fmt.Errorf("autogroup %q is not supported for SSH sources, can be %v", *dst, autogroupForSSHDst)
	}

	return nil
}

func validateAutogroupForSSHUser(user *AutoGroup) error {
	if user == nil {
		return nil
	}

	if !slices.Contains(autogroupForSSHUser, *user) {
		return fmt.Errorf("autogroup %q is not supported for SSH user, can be %v", *user, autogroupForSSHUser)
	}

	return nil
}

// validate reports if there are any errors in a policy after
// the unmarshaling process.
// It runs through all rules and checks if there are any inconsistencies
// in the policy that needs to be addressed before it can be used.
func (p *Policy) validate() error {
	if p == nil {
		panic("passed nil policy")
	}

	// All errors are collected and presented to the user,
	// when adding more validation, please add to the list of errors.
	var errs []error

	for _, acl := range p.ACLs {
		for _, src := range acl.Sources {
			switch src.(type) {
			case *Host:
				h := src.(*Host)
				if !p.Hosts.exist(*h) {
					errs = append(errs, fmt.Errorf(`Host %q is not defined in the Policy, please define or remove the reference to it`, *h))
				}
			case *AutoGroup:
				ag := src.(*AutoGroup)

				if err := validateAutogroupSupported(ag); err != nil {
					errs = append(errs, err)
					continue
				}

				if err := validateAutogroupForSrc(ag); err != nil {
					errs = append(errs, err)
					continue
				}
			case *Group:
				g := src.(*Group)
				if err := p.Groups.Contains(g); err != nil {
					errs = append(errs, err)
				}
			case *Tag:
				tagOwner := src.(*Tag)
				if err := p.TagOwners.Contains(tagOwner); err != nil {
					errs = append(errs, err)
				}
			}
		}

		for _, dst := range acl.Destinations {
			switch dst.Alias.(type) {
			case *Host:
				h := dst.Alias.(*Host)
				if !p.Hosts.exist(*h) {
					errs = append(errs, fmt.Errorf(`Host %q is not defined in the Policy, please define or remove the reference to it`, *h))
				}
			case *AutoGroup:
				ag := dst.Alias.(*AutoGroup)

				if err := validateAutogroupSupported(ag); err != nil {
					errs = append(errs, err)
					continue
				}

				if err := validateAutogroupForDst(ag); err != nil {
					errs = append(errs, err)
					continue
				}
			case *Group:
				g := dst.Alias.(*Group)
				if err := p.Groups.Contains(g); err != nil {
					errs = append(errs, err)
				}
			case *Tag:
				tagOwner := dst.Alias.(*Tag)
				if err := p.TagOwners.Contains(tagOwner); err != nil {
					errs = append(errs, err)
				}
			}
		}
	}

	for _, ssh := range p.SSHs {
		if ssh.Action != "accept" && ssh.Action != "check" {
			errs = append(errs, fmt.Errorf("SSH action %q is not valid, must be accept or check", ssh.Action))
		}

		for _, user := range ssh.Users {
			if strings.HasPrefix(string(user), "autogroup:") {
				maybeAuto := AutoGroup(user)
				if err := validateAutogroupForSSHUser(&maybeAuto); err != nil {
					errs = append(errs, err)
					continue
				}
			}
		}

		for _, src := range ssh.Sources {
			switch src.(type) {
			case *AutoGroup:
				ag := src.(*AutoGroup)

				if err := validateAutogroupSupported(ag); err != nil {
					errs = append(errs, err)
					continue
				}

				if err := validateAutogroupForSSHSrc(ag); err != nil {
					errs = append(errs, err)
					continue
				}
			case *Group:
				g := src.(*Group)
				if err := p.Groups.Contains(g); err != nil {
					errs = append(errs, err)
				}
			case *Tag:
				tagOwner := src.(*Tag)
				if err := p.TagOwners.Contains(tagOwner); err != nil {
					errs = append(errs, err)
				}
			}
		}
		for _, dst := range ssh.Destinations {
			switch dst.(type) {
			case *AutoGroup:
				ag := dst.(*AutoGroup)
				if err := validateAutogroupSupported(ag); err != nil {
					errs = append(errs, err)
					continue
				}

				if err := validateAutogroupForSSHDst(ag); err != nil {
					errs = append(errs, err)
					continue
				}
			case *Tag:
				tagOwner := dst.(*Tag)
				if err := p.TagOwners.Contains(tagOwner); err != nil {
					errs = append(errs, err)
				}
			}
		}
	}

	for _, tagOwners := range p.TagOwners {
		for _, tagOwner := range tagOwners {
			switch tagOwner.(type) {
			case *Group:
				g := tagOwner.(*Group)
				if err := p.Groups.Contains(g); err != nil {
					errs = append(errs, err)
				}
			}
		}
	}

	for _, approvers := range p.AutoApprovers.Routes {
		for _, approver := range approvers {
			switch approver.(type) {
			case *Group:
				g := approver.(*Group)
				if err := p.Groups.Contains(g); err != nil {
					errs = append(errs, err)
				}
			case *Tag:
				tagOwner := approver.(*Tag)
				if err := p.TagOwners.Contains(tagOwner); err != nil {
					errs = append(errs, err)
				}
			}
		}
	}

	for _, approver := range p.AutoApprovers.ExitNode {
		switch approver.(type) {
		case *Group:
			g := approver.(*Group)
			if err := p.Groups.Contains(g); err != nil {
				errs = append(errs, err)
			}
		case *Tag:
			tagOwner := approver.(*Tag)
			if err := p.TagOwners.Contains(tagOwner); err != nil {
				errs = append(errs, err)
			}
		}
	}

	if len(errs) > 0 {
		return multierr.New(errs...)
	}

	p.validated = true
	return nil
}

// SSH controls who can ssh into which machines.
type SSH struct {
	Action       string         `json:"action"`
	Sources      SSHSrcAliases  `json:"src"`
	Destinations SSHDstAliases  `json:"dst"`
	Users        []SSHUser      `json:"users"`
	CheckPeriod  model.Duration `json:"checkPeriod,omitempty"`
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
	var errs []error

	for _, alias := range a {
		aips, err := alias.Resolve(p, users, nodes)
		if err != nil {
			errs = append(errs, err)
		}

		ips.AddSet(aips)
	}

	return buildIPSetMultiErr(&ips, errs)
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
		case *Username, *Tag, *AutoGroup,
			// Asterix and Group is actually not supposed to be supported,
			// however we do not support autogroups at the moment
			// so we will leave it in as there is no other option
			// to dynamically give all access
			// https://tailscale.com/kb/1193/tailscale-ssh#dst
			// TODO(kradalby): remove this when we support autogroup:tagged and autogroup:member
			Asterix:
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

// unmarshalPolicy takes a byte slice and unmarshals it into a Policy struct.
// In addition to unmarshalling, it will also validate the policy.
// This is the only entrypoint of reading a policy from a file or other source.
func unmarshalPolicy(b []byte) (*Policy, error) {
	if b == nil || len(b) == 0 {
		return nil, nil
	}

	var policy Policy
	ast, err := hujson.Parse(b)
	if err != nil {
		return nil, fmt.Errorf("parsing HuJSON: %w", err)
	}

	ast.Standardize()
	acl := ast.Pack()

	if err = json.Unmarshal(acl, &policy); err != nil {
		return nil, fmt.Errorf("parsing policy from bytes: %w", err)
	}

	if err := policy.validate(); err != nil {
		return nil, err
	}

	return &policy, nil
}

const (
	expectedTokenItems = 2
)
