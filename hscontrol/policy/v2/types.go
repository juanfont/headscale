package v2

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/go-json-experiment/json"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/prometheus/common/model"
	"github.com/tailscale/hujson"
	"go4.org/netipx"
	"tailscale.com/net/tsaddr"
	"tailscale.com/tailcfg"
	"tailscale.com/types/ptr"
	"tailscale.com/types/views"
	"tailscale.com/util/multierr"
	"tailscale.com/util/slicesx"
)

// Global JSON options for consistent parsing across all struct unmarshaling
var policyJSONOpts = []json.Options{
	json.DefaultOptionsV2(),
	json.MatchCaseInsensitiveNames(true),
	json.RejectUnknownMembers(true),
}

const Wildcard = Asterix(0)

var ErrAutogroupSelfRequiresPerNodeResolution = errors.New("autogroup:self requires per-node resolution and cannot be resolved in this context")

var ErrCircularReference = errors.New("circular reference detected")

var ErrUndefinedTagReference = errors.New("references undefined tag")

type Asterix int

func (a Asterix) Validate() error {
	return nil
}

func (a Asterix) String() string {
	return "*"
}

// MarshalJSON marshals the Asterix to JSON.
func (a Asterix) MarshalJSON() ([]byte, error) {
	return []byte(`"*"`), nil
}

// MarshalJSON marshals the AliasWithPorts to JSON.
func (a AliasWithPorts) MarshalJSON() ([]byte, error) {
	if a.Alias == nil {
		return []byte(`""`), nil
	}

	var alias string
	switch v := a.Alias.(type) {
	case *Username:
		alias = string(*v)
	case *Group:
		alias = string(*v)
	case *Tag:
		alias = string(*v)
	case *Host:
		alias = string(*v)
	case *Prefix:
		alias = v.String()
	case *AutoGroup:
		alias = string(*v)
	case Asterix:
		alias = "*"
	default:
		return nil, fmt.Errorf("unknown alias type: %T", v)
	}

	// If no ports are specified
	if len(a.Ports) == 0 {
		return json.Marshal(alias)
	}

	// Check if it's the wildcard port range
	if len(a.Ports) == 1 && a.Ports[0].First == 0 && a.Ports[0].Last == 65535 {
		return json.Marshal(alias + ":*")
	}

	// Otherwise, format as "alias:ports"
	var ports []string
	for _, port := range a.Ports {
		if port.First == port.Last {
			ports = append(ports, strconv.FormatUint(uint64(port.First), 10))
		} else {
			ports = append(ports, fmt.Sprintf("%d-%d", port.First, port.Last))
		}
	}

	return json.Marshal(fmt.Sprintf("%s:%s", alias, strings.Join(ports, ",")))
}

func (a Asterix) UnmarshalJSON(b []byte) error {
	return nil
}

func (a Asterix) Resolve(_ *Policy, _ types.Users, nodes views.Slice[types.NodeView]) (*netipx.IPSet, error) {
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

// MarshalJSON marshals the Username to JSON.
func (u Username) MarshalJSON() ([]byte, error) {
	return json.Marshal(string(u))
}

// MarshalJSON marshals the Prefix to JSON.
func (p Prefix) MarshalJSON() ([]byte, error) {
	return json.Marshal(p.String())
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

func (u Username) Resolve(_ *Policy, users types.Users, nodes views.Slice[types.NodeView]) (*netipx.IPSet, error) {
	var ips netipx.IPSetBuilder
	var errs []error

	user, err := u.resolveUser(users)
	if err != nil {
		errs = append(errs, err)
	}

	for _, node := range nodes.All() {
		// Skip tagged nodes - they are identified by tags, not users
		if node.IsTagged() {
			continue
		}

		// Skip nodes without a user (defensive check for tests)
		if !node.User().Valid() {
			continue
		}

		if node.User().ID() == user.ID {
			node.AppendToIPSet(&ips)
		}
	}

	return buildIPSetMultiErr(&ips, errs)
}

// Group is a special string which is always prefixed with `group:`.
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

// String returns the string representation of the Group.
func (g Group) String() string {
	return string(g)
}

func (h Host) String() string {
	return string(h)
}

// MarshalJSON marshals the Host to JSON.
func (h Host) MarshalJSON() ([]byte, error) {
	return json.Marshal(string(h))
}

// MarshalJSON marshals the Group to JSON.
func (g Group) MarshalJSON() ([]byte, error) {
	return json.Marshal(string(g))
}

func (g Group) Resolve(p *Policy, users types.Users, nodes views.Slice[types.NodeView]) (*netipx.IPSet, error) {
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

// Tag is a special string which is always prefixed with `tag:`.
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

func (t Tag) Resolve(p *Policy, users types.Users, nodes views.Slice[types.NodeView]) (*netipx.IPSet, error) {
	var ips netipx.IPSetBuilder

	for _, node := range nodes.All() {
		// Check if node has this tag
		if node.HasTag(string(t)) {
			node.AppendToIPSet(&ips)
		}
	}

	return ips.IPSet()
}

func (t Tag) CanBeAutoApprover() bool {
	return true
}

func (t Tag) CanBeTagOwner() bool {
	return true
}

func (t Tag) String() string {
	return string(t)
}

// MarshalJSON marshals the Tag to JSON.
func (t Tag) MarshalJSON() ([]byte, error) {
	return json.Marshal(string(t))
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

func (h Host) Resolve(p *Policy, _ types.Users, nodes views.Slice[types.NodeView]) (*netipx.IPSet, error) {
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
	appendIfNodeHasIP(nodes, &ips, netip.Prefix(pref))

	// TODO(kradalby): I am a bit unsure what is the correct way to do this,
	// should a host with a non single IP be able to resolve the full host (inc all IPs).
	ipsTemp, err := ips.IPSet()
	if err != nil {
		errs = append(errs, err)
	}
	for _, node := range nodes.All() {
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
func (p Prefix) Resolve(_ *Policy, _ types.Users, nodes views.Slice[types.NodeView]) (*netipx.IPSet, error) {
	var ips netipx.IPSetBuilder
	var errs []error

	ips.AddPrefix(netip.Prefix(p))
	// If the IP is a single host, look for a node to ensure we add all the IPs of
	// the node to the IPSet.
	appendIfNodeHasIP(nodes, &ips, netip.Prefix(p))

	return buildIPSetMultiErr(&ips, errs)
}

// appendIfNodeHasIP appends the IPs of the nodes to the IPSet if the node has the
// IP address in the prefix.
func appendIfNodeHasIP(nodes views.Slice[types.NodeView], ips *netipx.IPSetBuilder, pref netip.Prefix) {
	if !pref.IsSingleIP() && !tsaddr.IsTailscaleIP(pref.Addr()) {
		return
	}

	for _, node := range nodes.All() {
		if node.HasIP(pref.Addr()) {
			node.AppendToIPSet(ips)
		}
	}
}

// AutoGroup is a special string which is always prefixed with `autogroup:`.
type AutoGroup string

const (
	AutoGroupInternet AutoGroup = "autogroup:internet"
	AutoGroupMember   AutoGroup = "autogroup:member"
	AutoGroupNonRoot  AutoGroup = "autogroup:nonroot"
	AutoGroupTagged   AutoGroup = "autogroup:tagged"
	AutoGroupSelf     AutoGroup = "autogroup:self"
)

var autogroups = []AutoGroup{
	AutoGroupInternet,
	AutoGroupMember,
	AutoGroupNonRoot,
	AutoGroupTagged,
	AutoGroupSelf,
}

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

func (ag AutoGroup) String() string {
	return string(ag)
}

// MarshalJSON marshals the AutoGroup to JSON.
func (ag AutoGroup) MarshalJSON() ([]byte, error) {
	return json.Marshal(string(ag))
}

func (ag AutoGroup) Resolve(p *Policy, users types.Users, nodes views.Slice[types.NodeView]) (*netipx.IPSet, error) {
	var build netipx.IPSetBuilder

	switch ag {
	case AutoGroupInternet:
		return util.TheInternet(), nil

	case AutoGroupMember:
		for _, node := range nodes.All() {
			// Skip if node is tagged
			if node.IsTagged() {
				continue
			}

			// Node is a member if it is not tagged
			node.AppendToIPSet(&build)
		}

		return build.IPSet()

	case AutoGroupTagged:
		for _, node := range nodes.All() {
			// Include if node is tagged
			if !node.IsTagged() {
				continue
			}

			node.AppendToIPSet(&build)
		}

		return build.IPSet()

	case AutoGroupSelf:
		// autogroup:self represents all devices owned by the same user.
		// This cannot be resolved in the general context and should be handled
		// specially during policy compilation per-node for security.
		return nil, ErrAutogroupSelfRequiresPerNodeResolution

	default:
		return nil, fmt.Errorf("unknown autogroup %q", ag)
	}
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
	Resolve(*Policy, types.Users, views.Slice[types.NodeView]) (*netipx.IPSet, error)
}

type AliasWithPorts struct {
	Alias
	Ports []tailcfg.PortRange
}

func (ve *AliasWithPorts) UnmarshalJSON(b []byte) error {
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
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
		} else {
			return errors.New(`hostport must contain a colon (":")`)
		}

		ve.Alias, err = parseAlias(vs)
		if err != nil {
			return err
		}
		if err := ve.Validate(); err != nil {
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
	err := json.Unmarshal(b, &aliases, policyJSONOpts...)
	if err != nil {
		return err
	}

	*a = make([]Alias, len(aliases))
	for i, alias := range aliases {
		(*a)[i] = alias.Alias
	}

	return nil
}

// MarshalJSON marshals the Aliases to JSON.
func (a Aliases) MarshalJSON() ([]byte, error) {
	if a == nil {
		return []byte("[]"), nil
	}

	aliases := make([]string, len(a))
	for i, alias := range a {
		switch v := alias.(type) {
		case *Username:
			aliases[i] = string(*v)
		case *Group:
			aliases[i] = string(*v)
		case *Tag:
			aliases[i] = string(*v)
		case *Host:
			aliases[i] = string(*v)
		case *Prefix:
			aliases[i] = v.String()
		case *AutoGroup:
			aliases[i] = string(*v)
		case Asterix:
			aliases[i] = "*"
		default:
			return nil, fmt.Errorf("unknown alias type: %T", v)
		}
	}

	return json.Marshal(aliases)
}

func (a Aliases) Resolve(p *Policy, users types.Users, nodes views.Slice[types.NodeView]) (*netipx.IPSet, error) {
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

// Helper function to unmarshal a JSON string into either an AutoApprover or Owner pointer.
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
	err := json.Unmarshal(b, &autoApprovers, policyJSONOpts...)
	if err != nil {
		return err
	}

	*aa = make([]AutoApprover, len(autoApprovers))
	for i, autoApprover := range autoApprovers {
		(*aa)[i] = autoApprover.AutoApprover
	}

	return nil
}

// MarshalJSON marshals the AutoApprovers to JSON.
func (aa AutoApprovers) MarshalJSON() ([]byte, error) {
	if aa == nil {
		return []byte("[]"), nil
	}

	approvers := make([]string, len(aa))
	for i, approver := range aa {
		switch v := approver.(type) {
		case *Username:
			approvers[i] = string(*v)
		case *Tag:
			approvers[i] = string(*v)
		case *Group:
			approvers[i] = string(*v)
		default:
			return nil, fmt.Errorf("unknown auto approver type: %T", v)
		}
	}

	return json.Marshal(approvers)
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
	String() string
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
	err := json.Unmarshal(b, &owners, policyJSONOpts...)
	if err != nil {
		return err
	}

	*o = make([]Owner, len(owners))
	for i, owner := range owners {
		(*o)[i] = owner.Owner
	}

	return nil
}

// MarshalJSON marshals the Owners to JSON.
func (o Owners) MarshalJSON() ([]byte, error) {
	if o == nil {
		return []byte("[]"), nil
	}

	owners := make([]string, len(o))
	for i, owner := range o {
		switch v := owner.(type) {
		case *Username:
			owners[i] = string(*v)
		case *Group:
			owners[i] = string(*v)
		case *Tag:
			owners[i] = string(*v)
		default:
			return nil, fmt.Errorf("unknown owner type: %T", v)
		}
	}

	return json.Marshal(owners)
}

func parseOwner(s string) (Owner, error) {
	switch {
	case isUser(s):
		return ptr.To(Username(s)), nil
	case isGroup(s):
		return ptr.To(Group(s)), nil
	case isTag(s):
		return ptr.To(Tag(s)), nil
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
	// First unmarshal as a generic map to validate group names first
	var rawMap map[string]any
	if err := json.Unmarshal(b, &rawMap); err != nil {
		return err
	}

	// Validate group names first before checking data types
	for key := range rawMap {
		group := Group(key)
		if err := group.Validate(); err != nil {
			return err
		}
	}

	// Then validate each field can be converted to []string
	rawGroups := make(map[string][]string)
	for key, value := range rawMap {
		switch v := value.(type) {
		case []any:
			// Convert []interface{} to []string
			var stringSlice []string
			for _, item := range v {
				if str, ok := item.(string); ok {
					stringSlice = append(stringSlice, str)
				} else {
					return fmt.Errorf(`Group "%s" contains invalid member type, expected string but got %T`, key, item)
				}
			}
			rawGroups[key] = stringSlice
		case string:
			return fmt.Errorf(`Group "%s" value must be an array of users, got string: "%s"`, key, v)
		default:
			return fmt.Errorf(`Group "%s" value must be an array of users, got %T`, key, v)
		}
	}

	*g = make(Groups)
	for key, value := range rawGroups {
		group := Group(key)
		// Group name already validated above
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
	if err := json.Unmarshal(b, &rawHosts, policyJSONOpts...); err != nil {
		return err
	}

	*h = make(Hosts)
	for key, value := range rawHosts {
		host := Host(key)
		if err := host.Validate(); err != nil {
			return err
		}

		var prefix Prefix
		if err := prefix.parseString(value); err != nil {
			return fmt.Errorf(`Hostname "%s" contains an invalid IP address: "%s"`, key, value)
		}

		(*h)[host] = prefix
	}

	return nil
}

// MarshalJSON marshals the Hosts to JSON.
func (h Hosts) MarshalJSON() ([]byte, error) {
	if h == nil {
		return []byte("{}"), nil
	}

	rawHosts := make(map[string]string)
	for host, prefix := range h {
		rawHosts[string(host)] = prefix.String()
	}

	return json.Marshal(rawHosts)
}

func (h Hosts) exist(name Host) bool {
	_, ok := h[name]
	return ok
}

// MarshalJSON marshals the TagOwners to JSON.
func (to TagOwners) MarshalJSON() ([]byte, error) {
	if to == nil {
		return []byte("{}"), nil
	}

	rawTagOwners := make(map[string][]string)
	for tag, owners := range to {
		tagStr := string(tag)
		ownerStrs := make([]string, len(owners))

		for i, owner := range owners {
			switch v := owner.(type) {
			case *Username:
				ownerStrs[i] = string(*v)
			case *Group:
				ownerStrs[i] = string(*v)
			case *Tag:
				ownerStrs[i] = string(*v)
			default:
				return nil, fmt.Errorf("unknown owner type: %T", v)
			}
		}

		rawTagOwners[tagStr] = ownerStrs
	}

	return json.Marshal(rawTagOwners)
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

type AutoApproverPolicy struct {
	Routes   map[netip.Prefix]AutoApprovers `json:"routes,omitempty"`
	ExitNode AutoApprovers                  `json:"exitNode,omitempty"`
}

// MarshalJSON marshals the AutoApproverPolicy to JSON.
func (ap AutoApproverPolicy) MarshalJSON() ([]byte, error) {
	// Marshal empty policies as empty object
	if ap.Routes == nil && ap.ExitNode == nil {
		return []byte("{}"), nil
	}

	type Alias AutoApproverPolicy

	// Create a new object to avoid marshalling nil slices as null instead of empty arrays
	obj := Alias(ap)

	// Initialize empty maps/slices to ensure they're marshalled as empty objects/arrays instead of null
	if obj.Routes == nil {
		obj.Routes = make(map[netip.Prefix]AutoApprovers)
	}

	if obj.ExitNode == nil {
		obj.ExitNode = AutoApprovers{}
	}

	return json.Marshal(&obj)
}

// resolveAutoApprovers resolves the AutoApprovers to a map of netip.Prefix to netipx.IPSet.
// The resulting map can be used to quickly look up if a node can self-approve a route.
// It is intended for internal use in a PolicyManager.
func resolveAutoApprovers(p *Policy, users types.Users, nodes views.Slice[types.NodeView]) (map[netip.Prefix]*netipx.IPSet, *netipx.IPSet, error) {
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

// Action represents the action to take for an ACL rule.
type Action string

const (
	ActionAccept Action = "accept"
)

// SSHAction represents the action to take for an SSH rule.
type SSHAction string

const (
	SSHActionAccept SSHAction = "accept"
	SSHActionCheck  SSHAction = "check"
)

// String returns the string representation of the Action.
func (a Action) String() string {
	return string(a)
}

// UnmarshalJSON implements JSON unmarshaling for Action.
func (a *Action) UnmarshalJSON(b []byte) error {
	str := strings.Trim(string(b), `"`)
	switch str {
	case "accept":
		*a = ActionAccept
	default:
		return fmt.Errorf("invalid action %q, must be %q", str, ActionAccept)
	}
	return nil
}

// MarshalJSON implements JSON marshaling for Action.
func (a Action) MarshalJSON() ([]byte, error) {
	return json.Marshal(string(a))
}

// String returns the string representation of the SSHAction.
func (a SSHAction) String() string {
	return string(a)
}

// UnmarshalJSON implements JSON unmarshaling for SSHAction.
func (a *SSHAction) UnmarshalJSON(b []byte) error {
	str := strings.Trim(string(b), `"`)
	switch str {
	case "accept":
		*a = SSHActionAccept
	case "check":
		*a = SSHActionCheck
	default:
		return fmt.Errorf("invalid SSH action %q, must be one of: accept, check", str)
	}
	return nil
}

// MarshalJSON implements JSON marshaling for SSHAction.
func (a SSHAction) MarshalJSON() ([]byte, error) {
	return json.Marshal(string(a))
}

// Protocol represents a network protocol with its IANA number and descriptions.
type Protocol string

const (
	ProtocolICMP     Protocol = "icmp"
	ProtocolIGMP     Protocol = "igmp"
	ProtocolIPv4     Protocol = "ipv4"
	ProtocolIPInIP   Protocol = "ip-in-ip"
	ProtocolTCP      Protocol = "tcp"
	ProtocolEGP      Protocol = "egp"
	ProtocolIGP      Protocol = "igp"
	ProtocolUDP      Protocol = "udp"
	ProtocolGRE      Protocol = "gre"
	ProtocolESP      Protocol = "esp"
	ProtocolAH       Protocol = "ah"
	ProtocolIPv6ICMP Protocol = "ipv6-icmp"
	ProtocolSCTP     Protocol = "sctp"
	ProtocolFC       Protocol = "fc"
	ProtocolWildcard Protocol = "*"
)

// String returns the string representation of the Protocol.
func (p Protocol) String() string {
	return string(p)
}

// Description returns the human-readable description of the Protocol.
func (p Protocol) Description() string {
	switch p {
	case ProtocolICMP:
		return "Internet Control Message Protocol"
	case ProtocolIGMP:
		return "Internet Group Management Protocol"
	case ProtocolIPv4:
		return "IPv4 encapsulation"
	case ProtocolTCP:
		return "Transmission Control Protocol"
	case ProtocolEGP:
		return "Exterior Gateway Protocol"
	case ProtocolIGP:
		return "Interior Gateway Protocol"
	case ProtocolUDP:
		return "User Datagram Protocol"
	case ProtocolGRE:
		return "Generic Routing Encapsulation"
	case ProtocolESP:
		return "Encapsulating Security Payload"
	case ProtocolAH:
		return "Authentication Header"
	case ProtocolIPv6ICMP:
		return "Internet Control Message Protocol for IPv6"
	case ProtocolSCTP:
		return "Stream Control Transmission Protocol"
	case ProtocolFC:
		return "Fibre Channel"
	case ProtocolWildcard:
		return "Wildcard (not supported - use specific protocol)"
	default:
		return "Unknown Protocol"
	}
}

// parseProtocol converts a Protocol to its IANA protocol numbers and wildcard requirement.
// Since validation happens during UnmarshalJSON, this method should not fail for valid Protocol values.
func (p Protocol) parseProtocol() ([]int, bool) {
	switch p {
	case "":
		// Empty protocol applies to TCP and UDP traffic only
		return []int{protocolTCP, protocolUDP}, false
	case ProtocolWildcard:
		// Wildcard protocol - defensive handling (should not reach here due to validation)
		return nil, false
	case ProtocolIGMP:
		return []int{protocolIGMP}, true
	case ProtocolIPv4, ProtocolIPInIP:
		return []int{protocolIPv4}, true
	case ProtocolTCP:
		return []int{protocolTCP}, false
	case ProtocolEGP:
		return []int{protocolEGP}, true
	case ProtocolIGP:
		return []int{protocolIGP}, true
	case ProtocolUDP:
		return []int{protocolUDP}, false
	case ProtocolGRE:
		return []int{protocolGRE}, true
	case ProtocolESP:
		return []int{protocolESP}, true
	case ProtocolAH:
		return []int{protocolAH}, true
	case ProtocolSCTP:
		return []int{protocolSCTP}, false
	case ProtocolICMP:
		return []int{protocolICMP, protocolIPv6ICMP}, true
	default:
		// Try to parse as a numeric protocol number
		// This should not fail since validation happened during unmarshaling
		protocolNumber, _ := strconv.Atoi(string(p))

		// Determine if wildcard is needed based on protocol number
		needsWildcard := protocolNumber != protocolTCP &&
			protocolNumber != protocolUDP &&
			protocolNumber != protocolSCTP

		return []int{protocolNumber}, needsWildcard
	}
}

// UnmarshalJSON implements JSON unmarshaling for Protocol.
func (p *Protocol) UnmarshalJSON(b []byte) error {
	str := strings.Trim(string(b), `"`)

	// Normalize to lowercase for case-insensitive matching
	*p = Protocol(strings.ToLower(str))

	// Validate the protocol
	if err := p.validate(); err != nil {
		return err
	}

	return nil
}

// validate checks if the Protocol is valid.
func (p Protocol) validate() error {
	switch p {
	case "", ProtocolICMP, ProtocolIGMP, ProtocolIPv4, ProtocolIPInIP,
		ProtocolTCP, ProtocolEGP, ProtocolIGP, ProtocolUDP, ProtocolGRE,
		ProtocolESP, ProtocolAH, ProtocolSCTP:
		return nil
	case ProtocolWildcard:
		// Wildcard "*" is not allowed - Tailscale rejects it
		return fmt.Errorf("proto name \"*\" not known; use protocol number 0-255 or protocol name (icmp, tcp, udp, etc.)")
	default:
		// Try to parse as a numeric protocol number
		str := string(p)

		// Check for leading zeros (not allowed by Tailscale)
		if str == "0" || (len(str) > 1 && str[0] == '0') {
			return fmt.Errorf("leading 0 not permitted in protocol number \"%s\"", str)
		}

		protocolNumber, err := strconv.Atoi(str)
		if err != nil {
			return fmt.Errorf("invalid protocol %q: must be a known protocol name or valid protocol number 0-255", p)
		}

		if protocolNumber < 0 || protocolNumber > 255 {
			return fmt.Errorf("protocol number %d out of range (0-255)", protocolNumber)
		}

		return nil
	}
}

// MarshalJSON implements JSON marshaling for Protocol.
func (p Protocol) MarshalJSON() ([]byte, error) {
	return json.Marshal(string(p))
}

// Protocol constants matching the IANA numbers
const (
	protocolICMP     = 1   // Internet Control Message
	protocolIGMP     = 2   // Internet Group Management
	protocolIPv4     = 4   // IPv4 encapsulation
	protocolTCP      = 6   // Transmission Control
	protocolEGP      = 8   // Exterior Gateway Protocol
	protocolIGP      = 9   // any private interior gateway (used by Cisco for their IGRP)
	protocolUDP      = 17  // User Datagram
	protocolGRE      = 47  // Generic Routing Encapsulation
	protocolESP      = 50  // Encap Security Payload
	protocolAH       = 51  // Authentication Header
	protocolIPv6ICMP = 58  // ICMP for IPv6
	protocolSCTP     = 132 // Stream Control Transmission Protocol
	protocolFC       = 133 // Fibre Channel
)

type ACL struct {
	Action       Action           `json:"action"`
	Protocol     Protocol         `json:"proto"`
	Sources      Aliases          `json:"src"`
	Destinations []AliasWithPorts `json:"dst"`
}

// UnmarshalJSON implements custom unmarshalling for ACL that ignores fields starting with '#'.
// headscale-admin uses # in some field names to add metadata, so we will ignore
// those to ensure it doesnt break.
// https://github.com/GoodiesHQ/headscale-admin/blob/214a44a9c15c92d2b42383f131b51df10c84017c/src/lib/common/acl.svelte.ts#L38
func (a *ACL) UnmarshalJSON(b []byte) error {
	// First unmarshal into a map to filter out comment fields
	var raw map[string]any
	if err := json.Unmarshal(b, &raw, policyJSONOpts...); err != nil {
		return err
	}

	// Remove any fields that start with '#'
	filtered := make(map[string]any)
	for key, value := range raw {
		if !strings.HasPrefix(key, "#") {
			filtered[key] = value
		}
	}

	// Marshal the filtered map back to JSON
	filteredBytes, err := json.Marshal(filtered)
	if err != nil {
		return err
	}

	// Create a type alias to avoid infinite recursion
	type aclAlias ACL
	var temp aclAlias

	// Unmarshal into the temporary struct using the v2 JSON options
	if err := json.Unmarshal(filteredBytes, &temp, policyJSONOpts...); err != nil {
		return err
	}

	// Copy the result back to the original struct
	*a = ACL(temp)
	return nil
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

	Groups        Groups             `json:"groups,omitempty"`
	Hosts         Hosts              `json:"hosts,omitempty"`
	TagOwners     TagOwners          `json:"tagOwners,omitempty"`
	ACLs          []ACL              `json:"acls,omitempty"`
	AutoApprovers AutoApproverPolicy `json:"autoApprovers"`
	SSHs          []SSH              `json:"ssh,omitempty"`
}

// MarshalJSON is deliberately not implemented for Policy.
// We use the default JSON marshalling behavior provided by the Go runtime.

var (
	// TODO(kradalby): Add these checks for tagOwners and autoApprovers.
	autogroupForSrc       = []AutoGroup{AutoGroupMember, AutoGroupTagged}
	autogroupForDst       = []AutoGroup{AutoGroupInternet, AutoGroupMember, AutoGroupTagged, AutoGroupSelf}
	autogroupForSSHSrc    = []AutoGroup{AutoGroupMember, AutoGroupTagged}
	autogroupForSSHDst    = []AutoGroup{AutoGroupMember, AutoGroupTagged, AutoGroupSelf}
	autogroupForSSHUser   = []AutoGroup{AutoGroupNonRoot}
	autogroupNotSupported = []AutoGroup{}
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
		return errors.New(`"autogroup:internet" used in source, it can only be used in ACL destinations`)
	}

	if src.Is(AutoGroupSelf) {
		return errors.New(`"autogroup:self" used in source, it can only be used in ACL destinations`)
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
		return errors.New(`"autogroup:internet" used in SSH source, it can only be used in ACL destinations`)
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
		return errors.New(`"autogroup:internet" used in SSH destination, it can only be used in ACL destinations`)
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
			switch src := src.(type) {
			case *Host:
				h := src
				if !p.Hosts.exist(*h) {
					errs = append(errs, fmt.Errorf(`Host %q is not defined in the Policy, please define or remove the reference to it`, *h))
				}
			case *AutoGroup:
				ag := src

				if err := validateAutogroupSupported(ag); err != nil {
					errs = append(errs, err)
					continue
				}

				if err := validateAutogroupForSrc(ag); err != nil {
					errs = append(errs, err)
					continue
				}
			case *Group:
				g := src
				if err := p.Groups.Contains(g); err != nil {
					errs = append(errs, err)
				}
			case *Tag:
				tagOwner := src
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

		// Validate protocol-port compatibility
		if err := validateProtocolPortCompatibility(acl.Protocol, acl.Destinations); err != nil {
			errs = append(errs, err)
		}
	}

	for _, ssh := range p.SSHs {
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
			switch src := src.(type) {
			case *AutoGroup:
				ag := src

				if err := validateAutogroupSupported(ag); err != nil {
					errs = append(errs, err)
					continue
				}

				if err := validateAutogroupForSSHSrc(ag); err != nil {
					errs = append(errs, err)
					continue
				}
			case *Group:
				g := src
				if err := p.Groups.Contains(g); err != nil {
					errs = append(errs, err)
				}
			case *Tag:
				tagOwner := src
				if err := p.TagOwners.Contains(tagOwner); err != nil {
					errs = append(errs, err)
				}
			}
		}
		for _, dst := range ssh.Destinations {
			switch dst := dst.(type) {
			case *AutoGroup:
				ag := dst
				if err := validateAutogroupSupported(ag); err != nil {
					errs = append(errs, err)
					continue
				}

				if err := validateAutogroupForSSHDst(ag); err != nil {
					errs = append(errs, err)
					continue
				}
			case *Tag:
				tagOwner := dst
				if err := p.TagOwners.Contains(tagOwner); err != nil {
					errs = append(errs, err)
				}
			}
		}
	}

	for _, tagOwners := range p.TagOwners {
		for _, tagOwner := range tagOwners {
			switch tagOwner := tagOwner.(type) {
			case *Group:
				g := tagOwner
				if err := p.Groups.Contains(g); err != nil {
					errs = append(errs, err)
				}
			case *Tag:
				t := tagOwner

				err := p.TagOwners.Contains(t)
				if err != nil {
					errs = append(errs, err)
				}
			}
		}
	}

	// Validate tag ownership chains for circular references and undefined tags.
	_, err := flattenTagOwners(p.TagOwners)
	if err != nil {
		errs = append(errs, err)
	}

	for _, approvers := range p.AutoApprovers.Routes {
		for _, approver := range approvers {
			switch approver := approver.(type) {
			case *Group:
				g := approver
				if err := p.Groups.Contains(g); err != nil {
					errs = append(errs, err)
				}
			case *Tag:
				tagOwner := approver
				if err := p.TagOwners.Contains(tagOwner); err != nil {
					errs = append(errs, err)
				}
			}
		}
	}

	for _, approver := range p.AutoApprovers.ExitNode {
		switch approver := approver.(type) {
		case *Group:
			g := approver
			if err := p.Groups.Contains(g); err != nil {
				errs = append(errs, err)
			}
		case *Tag:
			tagOwner := approver
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
	Action       SSHAction      `json:"action"`
	Sources      SSHSrcAliases  `json:"src"`
	Destinations SSHDstAliases  `json:"dst"`
	Users        SSHUsers       `json:"users"`
	CheckPeriod  model.Duration `json:"checkPeriod,omitempty"`
}

// SSHSrcAliases is a list of aliases that can be used as sources in an SSH rule.
// It can be a list of usernames, groups, tags or autogroups.
type SSHSrcAliases []Alias

// MarshalJSON marshals the Groups to JSON.
func (g Groups) MarshalJSON() ([]byte, error) {
	if g == nil {
		return []byte("{}"), nil
	}

	raw := make(map[string][]string)
	for group, usernames := range g {
		users := make([]string, len(usernames))
		for i, username := range usernames {
			users[i] = string(username)
		}
		raw[string(group)] = users
	}

	return json.Marshal(raw)
}

func (a *SSHSrcAliases) UnmarshalJSON(b []byte) error {
	var aliases []AliasEnc
	err := json.Unmarshal(b, &aliases, policyJSONOpts...)
	if err != nil {
		return err
	}

	*a = make([]Alias, len(aliases))
	for i, alias := range aliases {
		switch alias.Alias.(type) {
		case *Username, *Group, *Tag, *AutoGroup:
			(*a)[i] = alias.Alias
		default:
			return fmt.Errorf(
				"alias %T is not supported for SSH source",
				alias.Alias,
			)
		}
	}

	return nil
}

func (a *SSHDstAliases) UnmarshalJSON(b []byte) error {
	var aliases []AliasEnc
	err := json.Unmarshal(b, &aliases, policyJSONOpts...)
	if err != nil {
		return err
	}

	*a = make([]Alias, len(aliases))
	for i, alias := range aliases {
		switch alias.Alias.(type) {
		case *Username, *Tag, *AutoGroup, *Host,
			// Asterix and Group is actually not supposed to be supported,
			// however we do not support autogroups at the moment
			// so we will leave it in as there is no other option
			// to dynamically give all access
			// https://tailscale.com/kb/1193/tailscale-ssh#dst
			// TODO(kradalby): remove this when we support autogroup:tagged and autogroup:member
			Asterix:
			(*a)[i] = alias.Alias
		default:
			return fmt.Errorf(
				"alias %T is not supported for SSH destination",
				alias.Alias,
			)
		}
	}

	return nil
}

// MarshalJSON marshals the SSHDstAliases to JSON.
func (a SSHDstAliases) MarshalJSON() ([]byte, error) {
	if a == nil {
		return []byte("[]"), nil
	}

	aliases := make([]string, len(a))
	for i, alias := range a {
		switch v := alias.(type) {
		case *Username:
			aliases[i] = string(*v)
		case *Tag:
			aliases[i] = string(*v)
		case *AutoGroup:
			aliases[i] = string(*v)
		case *Host:
			aliases[i] = string(*v)
		case Asterix:
			aliases[i] = "*"
		default:
			return nil, fmt.Errorf("unknown SSH destination alias type: %T", v)
		}
	}

	return json.Marshal(aliases)
}

// MarshalJSON marshals the SSHSrcAliases to JSON.
func (a SSHSrcAliases) MarshalJSON() ([]byte, error) {
	if a == nil {
		return []byte("[]"), nil
	}

	aliases := make([]string, len(a))
	for i, alias := range a {
		switch v := alias.(type) {
		case *Username:
			aliases[i] = string(*v)
		case *Group:
			aliases[i] = string(*v)
		case *Tag:
			aliases[i] = string(*v)
		case *AutoGroup:
			aliases[i] = string(*v)
		case Asterix:
			aliases[i] = "*"
		default:
			return nil, fmt.Errorf("unknown SSH source alias type: %T", v)
		}
	}

	return json.Marshal(aliases)
}

func (a SSHSrcAliases) Resolve(p *Policy, users types.Users, nodes views.Slice[types.NodeView]) (*netipx.IPSet, error) {
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

type SSHUsers []SSHUser

func (u SSHUsers) ContainsRoot() bool {
	return slices.Contains(u, "root")
}

func (u SSHUsers) ContainsNonRoot() bool {
	return slices.Contains(u, SSHUser(AutoGroupNonRoot))
}

func (u SSHUsers) NormalUsers() []SSHUser {
	return slicesx.Filter(nil, u, func(user SSHUser) bool {
		return user != "root" && user != SSHUser(AutoGroupNonRoot)
	})
}

type SSHUser string

func (u SSHUser) String() string {
	return string(u)
}

// MarshalJSON marshals the SSHUser to JSON.
func (u SSHUser) MarshalJSON() ([]byte, error) {
	return json.Marshal(string(u))
}

// unmarshalPolicy takes a byte slice and unmarshals it into a Policy struct.
// In addition to unmarshalling, it will also validate the policy.
// This is the only entrypoint of reading a policy from a file or other source.
func unmarshalPolicy(b []byte) (*Policy, error) {
	if len(b) == 0 {
		return nil, nil
	}

	var policy Policy
	ast, err := hujson.Parse(b)
	if err != nil {
		return nil, fmt.Errorf("parsing HuJSON: %w", err)
	}

	ast.Standardize()
	if err = json.Unmarshal(ast.Pack(), &policy, policyJSONOpts...); err != nil {
		var serr *json.SemanticError
		if errors.As(err, &serr) && serr.Err == json.ErrUnknownName {
			ptr := serr.JSONPointer
			name := ptr.LastToken()
			return nil, fmt.Errorf("unknown field %q", name)
		}
		return nil, fmt.Errorf("parsing policy from bytes: %w", err)
	}

	if err := policy.validate(); err != nil {
		return nil, err
	}

	return &policy, nil
}

// validateProtocolPortCompatibility checks that only TCP, UDP, and SCTP protocols
// can have specific ports. All other protocols should only use wildcard ports.
func validateProtocolPortCompatibility(protocol Protocol, destinations []AliasWithPorts) error {
	// Only TCP, UDP, and SCTP support specific ports
	supportsSpecificPorts := protocol == ProtocolTCP || protocol == ProtocolUDP || protocol == ProtocolSCTP || protocol == ""

	if supportsSpecificPorts {
		return nil // No validation needed for these protocols
	}

	// For all other protocols, check that all destinations use wildcard ports
	for _, dst := range destinations {
		for _, portRange := range dst.Ports {
			// Check if it's not a wildcard port (0-65535)
			if !(portRange.First == 0 && portRange.Last == 65535) {
				return fmt.Errorf("protocol %q does not support specific ports; only \"*\" is allowed", protocol)
			}
		}
	}

	return nil
}

// usesAutogroupSelf checks if the policy uses autogroup:self in any ACL or SSH rules.
func (p *Policy) usesAutogroupSelf() bool {
	if p == nil {
		return false
	}

	// Check ACL rules
	for _, acl := range p.ACLs {
		for _, src := range acl.Sources {
			if ag, ok := src.(*AutoGroup); ok && ag.Is(AutoGroupSelf) {
				return true
			}
		}
		for _, dest := range acl.Destinations {
			if ag, ok := dest.Alias.(*AutoGroup); ok && ag.Is(AutoGroupSelf) {
				return true
			}
		}
	}

	// Check SSH rules
	for _, ssh := range p.SSHs {
		for _, src := range ssh.Sources {
			if ag, ok := src.(*AutoGroup); ok && ag.Is(AutoGroupSelf) {
				return true
			}
		}
		for _, dest := range ssh.Destinations {
			if ag, ok := dest.(*AutoGroup); ok && ag.Is(AutoGroupSelf) {
				return true
			}
		}
	}

	return false
}
