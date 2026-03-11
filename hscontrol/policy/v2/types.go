package v2

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/go-json-experiment/json"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/prometheus/common/model"
	"github.com/tailscale/hujson"
	"go4.org/netipx"
	"tailscale.com/net/tsaddr"
	"tailscale.com/tailcfg"
	"tailscale.com/types/views"
	"tailscale.com/util/multierr"
	"tailscale.com/util/slicesx"
)

// Global JSON options for consistent parsing across all struct unmarshaling.
var policyJSONOpts = []json.Options{
	json.DefaultOptionsV2(),
	json.MatchCaseInsensitiveNames(true),
	json.RejectUnknownMembers(true),
}

const Wildcard = Asterix(0)

var ErrAutogroupSelfRequiresPerNodeResolution = errors.New("autogroup:self requires per-node resolution and cannot be resolved in this context")

var ErrCircularReference = errors.New("circular reference detected")

var ErrUndefinedTagReference = errors.New("references undefined tag")

// SSH validation errors.
var (
	ErrSSHTagSourceToUserDest             = errors.New("tags in SSH source cannot access user-owned devices")
	ErrSSHUserDestRequiresSameUser        = errors.New("user destination requires source to contain only that same user")
	ErrSSHAutogroupSelfRequiresUserSource = errors.New("autogroup:self destination requires source to contain only users or groups, not tags or autogroup:tagged")
	ErrSSHTagSourceToAutogroupMember      = errors.New("tags in SSH source cannot access autogroup:member (user-owned devices)")
	ErrSSHWildcardDestination             = errors.New("wildcard (*) is not supported as SSH destination")
	ErrSSHCheckPeriodBelowMin             = errors.New("checkPeriod below minimum of 1 minute")
	ErrSSHCheckPeriodAboveMax             = errors.New("checkPeriod above maximum of 168 hours (1 week)")
	ErrSSHCheckPeriodOnNonCheck           = errors.New("checkPeriod is only valid with action \"check\"")
	ErrInvalidLocalpart                   = errors.New("invalid localpart format, must be localpart:*@<domain>")
)

// SSH check period constants per Tailscale docs:
// https://tailscale.com/kb/1193/tailscale-ssh
const (
	SSHCheckPeriodDefault = 12 * time.Hour
	SSHCheckPeriodMin     = time.Minute
	SSHCheckPeriodMax     = 168 * time.Hour
)

// ACL validation errors.
var (
	ErrACLAutogroupSelfInvalidSource = errors.New("autogroup:self destination requires sources to be users, groups, or autogroup:member only")
)

// Policy validation errors.
var (
	ErrUnknownAliasType            = errors.New("unknown alias type")
	ErrUnknownAutoApprover         = errors.New("unknown auto approver type")
	ErrUnknownOwnerType            = errors.New("unknown owner type")
	ErrInvalidUsername             = errors.New("username must contain @")
	ErrUserNotFound                = errors.New("user not found")
	ErrMultipleUsersFound          = errors.New("multiple users found")
	ErrInvalidGroupFormat          = errors.New("group must start with 'group:'")
	ErrInvalidTagFormat            = errors.New("tag must start with 'tag:'")
	ErrInvalidHostname             = errors.New("invalid hostname")
	ErrHostResolve                 = errors.New("error resolving host")
	ErrInvalidPrefix               = errors.New("invalid prefix")
	ErrInvalidAutogroup            = errors.New("invalid autogroup")
	ErrUnknownAutogroup            = errors.New("unknown autogroup")
	ErrHostportMissingColon        = errors.New("hostport must contain a colon")
	ErrTypeNotSupported            = errors.New("type not supported")
	ErrInvalidAlias                = errors.New("invalid alias format")
	ErrInvalidAutoApprover         = errors.New("invalid auto approver format")
	ErrInvalidOwner                = errors.New("invalid owner format")
	ErrGroupNotDefined             = errors.New("group not defined in policy")
	ErrInvalidGroupMember          = errors.New("invalid group member type")
	ErrGroupValueNotArray          = errors.New("group value must be an array of users")
	ErrNestedGroups                = errors.New("nested groups are not allowed")
	ErrInvalidHostIP               = errors.New("hostname contains invalid IP address")
	ErrTagNotDefined               = errors.New("tag not defined in policy")
	ErrAutoApproverNotAlias        = errors.New("auto approver is not an alias")
	ErrInvalidACLAction            = errors.New("invalid ACL action")
	ErrInvalidSSHAction            = errors.New("invalid SSH action")
	ErrInvalidProtocolNumber       = errors.New("invalid protocol number")
	ErrProtocolLeadingZero         = errors.New("leading 0 not permitted in protocol number")
	ErrProtocolOutOfRange          = errors.New("protocol number out of range (0-255)")
	ErrAutogroupNotSupported       = errors.New("autogroup not supported in headscale")
	ErrAutogroupInternetSrc        = errors.New("autogroup:internet can only be used in ACL destinations")
	ErrAutogroupSelfSrc            = errors.New("autogroup:self can only be used in ACL destinations")
	ErrAutogroupNotSupportedACLSrc = errors.New("autogroup not supported for ACL sources")
	ErrAutogroupNotSupportedACLDst = errors.New("autogroup not supported for ACL destinations")
	ErrAutogroupNotSupportedSSHSrc = errors.New("autogroup not supported for SSH sources")
	ErrAutogroupNotSupportedSSHDst = errors.New("autogroup not supported for SSH destinations")
	ErrAutogroupNotSupportedSSHUsr = errors.New("autogroup not supported for SSH user")
	ErrHostNotDefined              = errors.New("host not defined in policy")
	ErrSSHSourceAliasNotSupported  = errors.New("alias not supported for SSH source")
	ErrSSHDestAliasNotSupported    = errors.New("alias not supported for SSH destination")
	ErrUnknownSSHDestAlias         = errors.New("unknown SSH destination alias type")
	ErrUnknownSSHSrcAlias          = errors.New("unknown SSH source alias type")
	ErrUnknownField                = errors.New("unknown field")
	ErrProtocolNoSpecificPorts     = errors.New("protocol does not support specific ports")
)

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
		return nil, fmt.Errorf("%w: %T", ErrUnknownAliasType, v)
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

	// Use Tailscale's CGNAT range for IPv4 and ULA range for IPv6.
	// This matches Tailscale's behavior where wildcard (*) refers to
	// "any node in the tailnet" which uses these address ranges.
	ips.AddPrefix(tsaddr.CGNATRange())
	ips.AddPrefix(tsaddr.TailscaleULARange())

	return ips.IPSet()
}

// Username is a string that represents a username, it must contain an @.
type Username string

func (u *Username) Validate() error {
	if isUser(string(*u)) {
		return nil
	}

	return fmt.Errorf("%w, got: %q", ErrInvalidUsername, *u)
}

func (u *Username) String() string {
	return string(*u)
}

// MarshalJSON marshals the Username to JSON.
func (u *Username) MarshalJSON() ([]byte, error) {
	return json.Marshal(string(*u))
}

// MarshalJSON marshals the Prefix to JSON.
func (p *Prefix) MarshalJSON() ([]byte, error) {
	return json.Marshal(p.String())
}

func (u *Username) UnmarshalJSON(b []byte) error {
	*u = Username(strings.Trim(string(b), `"`))

	err := u.Validate()
	if err != nil {
		return err
	}

	return nil
}

func (u *Username) CanBeTagOwner() bool {
	return true
}

func (u *Username) CanBeAutoApprover() bool {
	return true
}

// resolveUser attempts to find a user in the provided [types.Users] slice that matches the Username.
// It prioritizes matching the ProviderIdentifier, and if not found, it falls back to matching the Email or Name.
// If no matching user is found, it returns an error indicating no user matching.
// If multiple matching users are found, it returns an error indicating multiple users matching.
// It returns the matched types.User and a nil error if exactly one match is found.
func (u *Username) resolveUser(users types.Users) (types.User, error) {
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
		return types.User{}, fmt.Errorf("%w: token %q", ErrUserNotFound, u.String())
	}

	if len(potentialUsers) > 1 {
		return types.User{}, fmt.Errorf("%w: token %q found: %s", ErrMultipleUsersFound, u.String(), potentialUsers.String())
	}

	return potentialUsers[0], nil
}

func (u *Username) Resolve(_ *Policy, users types.Users, nodes views.Slice[types.NodeView]) (*netipx.IPSet, error) {
	var (
		ips  netipx.IPSetBuilder
		errs []error
	)

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

func (g *Group) Validate() error {
	if isGroup(string(*g)) {
		return nil
	}

	return fmt.Errorf("%w, got: %q", ErrInvalidGroupFormat, *g)
}

func (g *Group) UnmarshalJSON(b []byte) error {
	*g = Group(strings.Trim(string(b), `"`))

	err := g.Validate()
	if err != nil {
		return err
	}

	return nil
}

func (g *Group) CanBeTagOwner() bool {
	return true
}

func (g *Group) CanBeAutoApprover() bool {
	return true
}

// String returns the string representation of the Group.
func (g *Group) String() string {
	return string(*g)
}

func (h *Host) String() string {
	return string(*h)
}

// MarshalJSON marshals the Host to JSON.
func (h *Host) MarshalJSON() ([]byte, error) {
	return json.Marshal(string(*h))
}

// MarshalJSON marshals the Group to JSON.
func (g *Group) MarshalJSON() ([]byte, error) {
	return json.Marshal(string(*g))
}

func (g *Group) Resolve(p *Policy, users types.Users, nodes views.Slice[types.NodeView]) (*netipx.IPSet, error) {
	var (
		ips  netipx.IPSetBuilder
		errs []error
	)

	for _, user := range p.Groups[*g] {
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

func (t *Tag) Validate() error {
	if isTag(string(*t)) {
		return nil
	}

	return fmt.Errorf("%w, got: %q", ErrInvalidTagFormat, *t)
}

func (t *Tag) UnmarshalJSON(b []byte) error {
	*t = Tag(strings.Trim(string(b), `"`))

	err := t.Validate()
	if err != nil {
		return err
	}

	return nil
}

func (t *Tag) Resolve(p *Policy, users types.Users, nodes views.Slice[types.NodeView]) (*netipx.IPSet, error) {
	var ips netipx.IPSetBuilder

	for _, node := range nodes.All() {
		// Check if node has this tag
		if node.HasTag(string(*t)) {
			node.AppendToIPSet(&ips)
		}
	}

	return ips.IPSet()
}

func (t *Tag) CanBeAutoApprover() bool {
	return true
}

func (t *Tag) CanBeTagOwner() bool {
	return true
}

func (t *Tag) String() string {
	return string(*t)
}

// MarshalJSON marshals the Tag to JSON.
func (t *Tag) MarshalJSON() ([]byte, error) {
	return json.Marshal(string(*t))
}

// Host is a string that represents a hostname.
type Host string

func (h *Host) Validate() error {
	if isHost(string(*h)) {
		return nil
	}

	return fmt.Errorf("%w: %q", ErrInvalidHostname, *h)
}

func (h *Host) UnmarshalJSON(b []byte) error {
	*h = Host(strings.Trim(string(b), `"`))

	err := h.Validate()
	if err != nil {
		return err
	}

	return nil
}

func (h *Host) Resolve(p *Policy, _ types.Users, nodes views.Slice[types.NodeView]) (*netipx.IPSet, error) {
	var (
		ips  netipx.IPSetBuilder
		errs []error
	)

	pref, ok := p.Hosts[*h]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrHostResolve, *h)
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

func (p *Prefix) Validate() error {
	if netip.Prefix(*p).IsValid() {
		return nil
	}

	return fmt.Errorf("%w: %s", ErrInvalidPrefix, p.String())
}

func (p *Prefix) String() string {
	return netip.Prefix(*p).String()
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

	if err := p.Validate(); err != nil { //nolint:noinlineerr
		return err
	}

	return nil
}

// Resolve resolves the Prefix to an IPSet. The IPSet will contain all the IP
// addresses that the Prefix represents within Headscale. It is the product
// of the Prefix and the Policy, Users, and Nodes.
//
// See [Policy], [types.Users], and [types.Nodes] for more details.
func (p *Prefix) Resolve(_ *Policy, _ types.Users, nodes views.Slice[types.NodeView]) (*netipx.IPSet, error) {
	var (
		ips  netipx.IPSetBuilder
		errs []error
	)

	ips.AddPrefix(netip.Prefix(*p))
	// If the IP is a single host, look for a node to ensure we add all the IPs of
	// the node to the IPSet.
	appendIfNodeHasIP(nodes, &ips, netip.Prefix(*p))

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

func (ag *AutoGroup) Validate() error {
	if slices.Contains(autogroups, *ag) {
		return nil
	}

	return fmt.Errorf("%w: got %q, must be one of %v", ErrInvalidAutogroup, *ag, autogroups)
}

func (ag *AutoGroup) UnmarshalJSON(b []byte) error {
	*ag = AutoGroup(strings.Trim(string(b), `"`))

	err := ag.Validate()
	if err != nil {
		return err
	}

	return nil
}

func (ag *AutoGroup) String() string {
	return string(*ag)
}

// MarshalJSON marshals the AutoGroup to JSON.
func (ag *AutoGroup) MarshalJSON() ([]byte, error) {
	return json.Marshal(string(*ag))
}

func (ag *AutoGroup) Resolve(p *Policy, users types.Users, nodes views.Slice[types.NodeView]) (*netipx.IPSet, error) {
	var build netipx.IPSetBuilder

	switch *ag {
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

	case AutoGroupNonRoot:
		// autogroup:nonroot represents non-root users on multi-user devices.
		// This is not supported in headscale and requires OS-level user detection.
		return nil, fmt.Errorf("%w: %q", ErrUnknownAutogroup, *ag)

	default:
		return nil, fmt.Errorf("%w: %q", ErrUnknownAutogroup, *ag)
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
	UnmarshalJSON(b []byte) error

	// Resolve resolves the Alias to an IPSet. The IPSet will contain all the IP
	// addresses that the Alias represents within Headscale. It is the product
	// of the Alias and the Policy, Users and Nodes.
	// This is an interface definition and the implementation is independent of
	// the Alias type.
	Resolve(pol *Policy, users types.Users, nodes views.Slice[types.NodeView]) (*netipx.IPSet, error)
}

type AliasWithPorts struct {
	Alias

	Ports []tailcfg.PortRange
}

func (ve *AliasWithPorts) UnmarshalJSON(b []byte) error {
	var v any

	err := json.Unmarshal(b, &v)
	if err != nil {
		return err
	}

	switch vs := v.(type) {
	case string:
		var (
			portsPart string
			err       error
		)

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
			return ErrHostportMissingColon
		}

		ve.Alias, err = parseAlias(vs)
		if err != nil {
			return err
		}

		if err := ve.Validate(); err != nil { //nolint:noinlineerr
			return err
		}

	default:
		return fmt.Errorf("%w: %T", ErrTypeNotSupported, vs)
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
		return new(Username(vs)), nil
	case isGroup(vs):
		return new(Group(vs)), nil
	case isTag(vs):
		return new(Tag(vs)), nil
	case isAutoGroup(vs):
		return new(AutoGroup(vs)), nil
	}

	if isHost(vs) {
		return new(Host(vs)), nil
	}

	return nil, fmt.Errorf("%w: %q", ErrInvalidAlias, vs)
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
func (a *Aliases) MarshalJSON() ([]byte, error) {
	if *a == nil {
		return []byte("[]"), nil
	}

	aliases := make([]string, len(*a))
	for i, alias := range *a {
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
			return nil, fmt.Errorf("%w: %T", ErrUnknownAliasType, v)
		}
	}

	return json.Marshal(aliases)
}

func (a *Aliases) Resolve(p *Policy, users types.Users, nodes views.Slice[types.NodeView]) (*netipx.IPSet, error) {
	var (
		ips  netipx.IPSetBuilder
		errs []error
	)

	for _, alias := range *a {
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
	UnmarshalJSON(b []byte) error
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
			return nil, fmt.Errorf("%w: %T", ErrUnknownAutoApprover, v)
		}
	}

	return json.Marshal(approvers)
}

func parseAutoApprover(s string) (AutoApprover, error) {
	switch {
	case isUser(s):
		return new(Username(s)), nil
	case isGroup(s):
		return new(Group(s)), nil
	case isTag(s):
		return new(Tag(s)), nil
	}

	return nil, fmt.Errorf("%w: %q", ErrInvalidAutoApprover, s)
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
	UnmarshalJSON(b []byte) error
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
			return nil, fmt.Errorf("%w: %T", ErrUnknownOwnerType, v)
		}
	}

	return json.Marshal(owners)
}

func parseOwner(s string) (Owner, error) {
	switch {
	case isUser(s):
		return new(Username(s)), nil
	case isGroup(s):
		return new(Group(s)), nil
	case isTag(s):
		return new(Tag(s)), nil
	}

	return nil, fmt.Errorf("%w: %q", ErrInvalidOwner, s)
}

type Usernames []Username

// Groups are a map of Group to a list of Username.
type Groups map[Group]Usernames

func (g *Groups) Contains(group *Group) error {
	if group == nil {
		return nil
	}

	for defined := range map[Group]Usernames(*g) {
		if defined == *group {
			return nil
		}
	}

	return fmt.Errorf("%w: %q", ErrGroupNotDefined, group)
}

// UnmarshalJSON overrides the default JSON unmarshalling for Groups to ensure
// that each group name is validated using the isGroup function. This ensures
// that all group names conform to the expected format, which is always prefixed
// with "group:". If any group name is invalid, an error is returned.
func (g *Groups) UnmarshalJSON(b []byte) error {
	// First unmarshal as a generic map to validate group names first
	var rawMap map[string]any

	err := json.Unmarshal(b, &rawMap)
	if err != nil {
		return err
	}

	// Validate group names first before checking data types
	for key := range rawMap {
		group := Group(key)

		err := group.Validate()
		if err != nil {
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
					return fmt.Errorf("%w: group %q expected string but got %T", ErrInvalidGroupMember, key, item)
				}
			}

			rawGroups[key] = stringSlice
		case string:
			return fmt.Errorf("%w: group %q got string: %q", ErrGroupValueNotArray, key, v)
		default:
			return fmt.Errorf("%w: group %q got %T", ErrGroupValueNotArray, key, v)
		}
	}

	*g = make(Groups)

	for key, value := range rawGroups {
		group := Group(key)
		// Group name already validated above
		var usernames Usernames

		for _, u := range value {
			username := Username(u)

			err := username.Validate()
			if err != nil {
				if isGroup(u) {
					return fmt.Errorf("%w: found %q inside %q", ErrNestedGroups, u, group)
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

	err := json.Unmarshal(b, &rawHosts, policyJSONOpts...)
	if err != nil {
		return err
	}

	*h = make(Hosts)

	for key, value := range rawHosts {
		host := Host(key)

		err := host.Validate()
		if err != nil {
			return err
		}

		var prefix Prefix

		err = prefix.parseString(value)
		if err != nil {
			return fmt.Errorf("%w: hostname %q address %q", ErrInvalidHostIP, key, value)
		}

		(*h)[host] = prefix
	}

	return nil
}

// MarshalJSON marshals the Hosts to JSON.
func (h *Hosts) MarshalJSON() ([]byte, error) {
	if *h == nil {
		return []byte("{}"), nil
	}

	rawHosts := make(map[string]string)
	for host, prefix := range *h {
		rawHosts[string(host)] = prefix.String()
	}

	return json.Marshal(rawHosts)
}

func (h *Hosts) exist(name Host) bool {
	_, ok := (*h)[name]
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
				return nil, fmt.Errorf("%w: %T", ErrUnknownOwnerType, v)
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

	return fmt.Errorf("%w: %q", ErrTagNotDefined, tagOwner)
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
				return nil, nil, fmt.Errorf("%w: %v", ErrAutoApproverNotAlias, autoApprover)
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
				return nil, nil, fmt.Errorf("%w: %v", ErrAutoApproverNotAlias, autoApprover)
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
func (a *Action) String() string {
	return string(*a)
}

// UnmarshalJSON implements JSON unmarshaling for Action.
func (a *Action) UnmarshalJSON(b []byte) error {
	str := strings.Trim(string(b), `"`)
	switch str {
	case "accept":
		*a = ActionAccept
	default:
		return fmt.Errorf("%w: %q, must be %q", ErrInvalidACLAction, str, ActionAccept)
	}

	return nil
}

// MarshalJSON implements JSON marshaling for Action.
func (a *Action) MarshalJSON() ([]byte, error) {
	return json.Marshal(string(*a))
}

// String returns the string representation of the SSHAction.
func (a *SSHAction) String() string {
	return string(*a)
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
		return fmt.Errorf("%w: %q, must be one of: accept, check", ErrInvalidSSHAction, str)
	}

	return nil
}

// MarshalJSON implements JSON marshaling for SSHAction.
func (a *SSHAction) MarshalJSON() ([]byte, error) {
	return json.Marshal(string(*a))
}

// Protocol represents a network protocol with its IANA number and descriptions.
type Protocol string

const (
	ProtocolNameICMP     Protocol = "icmp"
	ProtocolNameIGMP     Protocol = "igmp"
	ProtocolNameIPv4     Protocol = "ipv4"
	ProtocolNameIPInIP   Protocol = "ip-in-ip"
	ProtocolNameTCP      Protocol = "tcp"
	ProtocolNameEGP      Protocol = "egp"
	ProtocolNameIGP      Protocol = "igp"
	ProtocolNameUDP      Protocol = "udp"
	ProtocolNameGRE      Protocol = "gre"
	ProtocolNameESP      Protocol = "esp"
	ProtocolNameAH       Protocol = "ah"
	ProtocolNameIPv6ICMP Protocol = "ipv6-icmp"
	ProtocolNameSCTP     Protocol = "sctp"
	ProtocolNameFC       Protocol = "fc"
	ProtocolNameWildcard Protocol = "*"
)

// String returns the string representation of the Protocol.
func (p *Protocol) String() string {
	return string(*p)
}

// Description returns the human-readable description of the Protocol.
func (p *Protocol) Description() string {
	switch *p {
	case ProtocolNameICMP:
		return "Internet Control Message Protocol"
	case ProtocolNameIGMP:
		return "Internet Group Management Protocol"
	case ProtocolNameIPv4:
		return "IPv4 encapsulation"
	case ProtocolNameTCP:
		return "Transmission Control Protocol"
	case ProtocolNameEGP:
		return "Exterior Gateway Protocol"
	case ProtocolNameIGP:
		return "Interior Gateway Protocol"
	case ProtocolNameUDP:
		return "User Datagram Protocol"
	case ProtocolNameGRE:
		return "Generic Routing Encapsulation"
	case ProtocolNameESP:
		return "Encapsulating Security Payload"
	case ProtocolNameAH:
		return "Authentication Header"
	case ProtocolNameIPv6ICMP:
		return "Internet Control Message Protocol for IPv6"
	case ProtocolNameSCTP:
		return "Stream Control Transmission Protocol"
	case ProtocolNameFC:
		return "Fibre Channel"
	case ProtocolNameIPInIP:
		return "IP-in-IP Encapsulation"
	case ProtocolNameWildcard:
		return "Wildcard (not supported - use specific protocol)"
	default:
		return "Unknown Protocol"
	}
}

// parseProtocol converts a Protocol to its IANA protocol numbers.
// Since validation happens during UnmarshalJSON, this method should not fail for valid Protocol values.
func (p *Protocol) parseProtocol() []int {
	switch *p {
	case "":
		// Empty protocol applies to TCP, UDP, ICMP, and ICMPv6 traffic
		// This matches Tailscale's behavior for protocol defaults
		return []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP}
	case ProtocolNameWildcard:
		// Wildcard protocol - defensive handling (should not reach here due to validation)
		return nil
	case ProtocolNameIGMP:
		return []int{ProtocolIGMP}
	case ProtocolNameIPv4, ProtocolNameIPInIP:
		return []int{ProtocolIPv4}
	case ProtocolNameTCP:
		return []int{ProtocolTCP}
	case ProtocolNameEGP:
		return []int{ProtocolEGP}
	case ProtocolNameIGP:
		return []int{ProtocolIGP}
	case ProtocolNameUDP:
		return []int{ProtocolUDP}
	case ProtocolNameGRE:
		return []int{ProtocolGRE}
	case ProtocolNameESP:
		return []int{ProtocolESP}
	case ProtocolNameAH:
		return []int{ProtocolAH}
	case ProtocolNameSCTP:
		return []int{ProtocolSCTP}
	case ProtocolNameICMP:
		// ICMP only - use "ipv6-icmp" or protocol number 58 for ICMPv6
		return []int{ProtocolICMP}
	case ProtocolNameIPv6ICMP:
		return []int{ProtocolIPv6ICMP}
	case ProtocolNameFC:
		return []int{ProtocolFC}
	default:
		// Try to parse as a numeric protocol number
		// This should not fail since validation happened during unmarshaling
		protocolNumber, _ := strconv.Atoi(string(*p))
		return []int{protocolNumber}
	}
}

// UnmarshalJSON implements JSON unmarshaling for Protocol.
func (p *Protocol) UnmarshalJSON(b []byte) error {
	str := strings.Trim(string(b), `"`)

	// Normalize to lowercase for case-insensitive matching
	*p = Protocol(strings.ToLower(str))

	// Validate the protocol
	err := p.validate()
	if err != nil {
		return err
	}

	return nil
}

// validate checks if the Protocol is valid.
func (p *Protocol) validate() error {
	switch *p {
	case "", ProtocolNameICMP, ProtocolNameIGMP, ProtocolNameIPv4, ProtocolNameIPInIP,
		ProtocolNameTCP, ProtocolNameEGP, ProtocolNameIGP, ProtocolNameUDP, ProtocolNameGRE,
		ProtocolNameESP, ProtocolNameAH, ProtocolNameSCTP, ProtocolNameIPv6ICMP, ProtocolNameFC:
		return nil
	case ProtocolNameWildcard:
		// Wildcard "*" is not allowed - Tailscale rejects it
		return errUnknownProtocolWildcard
	default:
		// Try to parse as a numeric protocol number
		str := string(*p)

		// Check for leading zeros (not allowed by Tailscale)
		if str == "0" || (len(str) > 1 && str[0] == '0') {
			return fmt.Errorf("%w: %q", ErrProtocolLeadingZero, str)
		}

		protocolNumber, err := strconv.Atoi(str)
		if err != nil {
			return fmt.Errorf("%w: %q must be a known protocol name or valid protocol number 0-255", ErrInvalidProtocolNumber, *p)
		}

		if protocolNumber < 0 || protocolNumber > 255 {
			return fmt.Errorf("%w: %d", ErrProtocolOutOfRange, protocolNumber)
		}

		return nil
	}
}

// MarshalJSON implements JSON marshaling for Protocol.
func (p *Protocol) MarshalJSON() ([]byte, error) {
	return json.Marshal(string(*p))
}

// Protocol constants matching the IANA numbers.
const (
	ProtocolICMP     = 1   // Internet Control Message
	ProtocolIGMP     = 2   // Internet Group Management
	ProtocolIPv4     = 4   // IPv4 encapsulation
	ProtocolTCP      = 6   // Transmission Control
	ProtocolEGP      = 8   // Exterior Gateway Protocol
	ProtocolIGP      = 9   // any private interior gateway (used by Cisco for their IGRP)
	ProtocolUDP      = 17  // User Datagram
	ProtocolGRE      = 47  // Generic Routing Encapsulation
	ProtocolESP      = 50  // Encap Security Payload
	ProtocolAH       = 51  // Authentication Header
	ProtocolIPv6ICMP = 58  // ICMP for IPv6
	ProtocolSCTP     = 132 // Stream Control Transmission Protocol
	ProtocolFC       = 133 // Fibre Channel
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
	if err := json.Unmarshal(b, &raw, policyJSONOpts...); err != nil { //nolint:noinlineerr
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
	if err := json.Unmarshal(filteredBytes, &temp, policyJSONOpts...); err != nil { //nolint:noinlineerr
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

	errUnknownProtocolWildcard = errors.New("proto name \"*\" not known; use protocol number 0-255 or protocol name (icmp, tcp, udp, etc.)")
)

func validateAutogroupSupported(ag *AutoGroup) error {
	if ag == nil {
		return nil
	}

	if slices.Contains(autogroupNotSupported, *ag) {
		return fmt.Errorf("%w: %q", ErrAutogroupNotSupported, *ag)
	}

	return nil
}

func validateAutogroupForSrc(src *AutoGroup) error {
	if src == nil {
		return nil
	}

	if src.Is(AutoGroupInternet) {
		return ErrAutogroupInternetSrc
	}

	if src.Is(AutoGroupSelf) {
		return ErrAutogroupSelfSrc
	}

	if !slices.Contains(autogroupForSrc, *src) {
		return fmt.Errorf("%w: %q, can be %v", ErrAutogroupNotSupportedACLSrc, *src, autogroupForSrc)
	}

	return nil
}

func validateAutogroupForDst(dst *AutoGroup) error {
	if dst == nil {
		return nil
	}

	if !slices.Contains(autogroupForDst, *dst) {
		return fmt.Errorf("%w: %q, can be %v", ErrAutogroupNotSupportedACLDst, *dst, autogroupForDst)
	}

	return nil
}

func validateAutogroupForSSHSrc(src *AutoGroup) error {
	if src == nil {
		return nil
	}

	if src.Is(AutoGroupInternet) {
		return ErrAutogroupInternetSrc
	}

	if !slices.Contains(autogroupForSSHSrc, *src) {
		return fmt.Errorf("%w: %q, can be %v", ErrAutogroupNotSupportedSSHSrc, *src, autogroupForSSHSrc)
	}

	return nil
}

func validateAutogroupForSSHDst(dst *AutoGroup) error {
	if dst == nil {
		return nil
	}

	if dst.Is(AutoGroupInternet) {
		return ErrAutogroupInternetSrc
	}

	if !slices.Contains(autogroupForSSHDst, *dst) {
		return fmt.Errorf("%w: %q, can be %v", ErrAutogroupNotSupportedSSHDst, *dst, autogroupForSSHDst)
	}

	return nil
}

func validateAutogroupForSSHUser(user *AutoGroup) error {
	if user == nil {
		return nil
	}

	if !slices.Contains(autogroupForSSHUser, *user) {
		return fmt.Errorf("%w: %q, can be %v", ErrAutogroupNotSupportedSSHUsr, *user, autogroupForSSHUser)
	}

	return nil
}

// validateSSHSrcDstCombination validates that SSH source/destination combinations
// follow Tailscale's security model:
// - Destination can be: tags, autogroup:self (if source is users/groups), or same-user
// - Tags/autogroup:tagged CANNOT SSH to user destinations
// - Username destinations require the source to be that same single user only.
func validateSSHSrcDstCombination(sources SSHSrcAliases, destinations SSHDstAliases) error {
	// Categorize source types
	srcHasTaggedEntities := false
	srcHasGroups := false
	srcUsernames := make(map[string]bool)

	for _, src := range sources {
		switch v := src.(type) {
		case *Tag:
			srcHasTaggedEntities = true
		case *AutoGroup:
			if v.Is(AutoGroupTagged) {
				srcHasTaggedEntities = true
			} else if v.Is(AutoGroupMember) {
				srcHasGroups = true // autogroup:member is like a group of users
			}
		case *Group:
			srcHasGroups = true
		case *Username:
			srcUsernames[string(*v)] = true
		}
	}

	// Check destinations against source constraints
	for _, dst := range destinations {
		switch v := dst.(type) {
		case *Username:
			// Rule: Tags/autogroup:tagged CANNOT SSH to user destinations
			if srcHasTaggedEntities {
				return fmt.Errorf("%w (%s); use autogroup:tagged or specific tags as destinations instead",
					ErrSSHTagSourceToUserDest, *v)
			}
			// Rule: Username destination requires source to be that same single user only
			if srcHasGroups || len(srcUsernames) != 1 || !srcUsernames[string(*v)] {
				return fmt.Errorf("%w %q; use autogroup:self instead for same-user SSH access",
					ErrSSHUserDestRequiresSameUser, *v)
			}
		case *AutoGroup:
			// Rule: autogroup:self requires source to NOT contain tags
			if v.Is(AutoGroupSelf) && srcHasTaggedEntities {
				return ErrSSHAutogroupSelfRequiresUserSource
			}
			// Rule: autogroup:member (user-owned devices) cannot be accessed by tagged entities
			if v.Is(AutoGroupMember) && srcHasTaggedEntities {
				return ErrSSHTagSourceToAutogroupMember
			}
		}
	}

	return nil
}

// validateACLSrcDstCombination validates that ACL source/destination combinations
// follow Tailscale's security model:
// - autogroup:self destinations require ALL sources to be users, groups, autogroup:member, or wildcard (*)
// - Tags, autogroup:tagged, hosts, and raw IPs are NOT valid sources for autogroup:self
// - Wildcard (*) is allowed because autogroup:self evaluation narrows it per-node to the node's own IPs.
func validateACLSrcDstCombination(sources Aliases, destinations []AliasWithPorts) error {
	// Check if any destination is autogroup:self
	hasAutogroupSelf := false

	for _, dst := range destinations {
		if ag, ok := dst.Alias.(*AutoGroup); ok && ag.Is(AutoGroupSelf) {
			hasAutogroupSelf = true
			break
		}
	}

	if !hasAutogroupSelf {
		return nil // No autogroup:self, no validation needed
	}

	// Validate all sources are valid for autogroup:self
	for _, src := range sources {
		switch v := src.(type) {
		case *Username, *Group, Asterix:
			// Valid sources - users, groups, and wildcard (*) are allowed
			// Wildcard is allowed because autogroup:self evaluation narrows it per-node
			continue
		case *AutoGroup:
			if v.Is(AutoGroupMember) {
				continue // autogroup:member is valid
			}
			// autogroup:tagged and others are NOT valid
			return ErrACLAutogroupSelfInvalidSource
		case *Tag, *Host, *Prefix:
			// Tags, hosts, and IPs are NOT valid sources for autogroup:self
			return ErrACLAutogroupSelfInvalidSource
		default:
			// Unknown type - be conservative and reject
			return ErrACLAutogroupSelfInvalidSource
		}
	}

	return nil
}

// validate reports if there are any errors in a policy after
// the unmarshaling process.
// It runs through all rules and checks if there are any inconsistencies
// in the policy that needs to be addressed before it can be used.
//
//nolint:gocyclo // comprehensive policy validation
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
					errs = append(errs, fmt.Errorf("%w: %q", ErrHostNotDefined, *h))
				}
			case *AutoGroup:
				ag := src

				err := validateAutogroupSupported(ag)
				if err != nil {
					errs = append(errs, err)
					continue
				}

				err = validateAutogroupForSrc(ag)
				if err != nil {
					errs = append(errs, err)
					continue
				}
			case *Group:
				g := src

				err := p.Groups.Contains(g)
				if err != nil {
					errs = append(errs, err)
				}
			case *Tag:
				tagOwner := src

				err := p.TagOwners.Contains(tagOwner)
				if err != nil {
					errs = append(errs, err)
				}
			}
		}

		for _, dst := range acl.Destinations {
			switch h := dst.Alias.(type) {
			case *Host:
				if !p.Hosts.exist(*h) {
					errs = append(errs, fmt.Errorf("%w: %q", ErrHostNotDefined, *h))
				}
			case *AutoGroup:
				err := validateAutogroupSupported(h)
				if err != nil {
					errs = append(errs, err)
					continue
				}

				err = validateAutogroupForDst(h)
				if err != nil {
					errs = append(errs, err)
					continue
				}
			case *Group:
				err := p.Groups.Contains(h)
				if err != nil {
					errs = append(errs, err)
				}
			case *Tag:
				err := p.TagOwners.Contains(h)
				if err != nil {
					errs = append(errs, err)
				}
			}
		}

		// Validate protocol-port compatibility
		if err := validateProtocolPortCompatibility(acl.Protocol, acl.Destinations); err != nil { //nolint:noinlineerr
			errs = append(errs, err)
		}

		// Validate ACL source/destination combinations follow Tailscale's security model
		err := validateACLSrcDstCombination(acl.Sources, acl.Destinations)
		if err != nil {
			errs = append(errs, err)
		}
	}

	for _, ssh := range p.SSHs {
		for _, user := range ssh.Users {
			if strings.HasPrefix(string(user), "autogroup:") {
				maybeAuto := AutoGroup(user)

				err := validateAutogroupForSSHUser(&maybeAuto)
				if err != nil {
					errs = append(errs, err)
					continue
				}
			}

			if user.IsLocalpart() {
				_, err := user.ParseLocalpart()
				if err != nil {
					errs = append(errs, err)
					continue
				}
			}
		}

		for _, src := range ssh.Sources {
			switch src := src.(type) {
			case *AutoGroup:
				ag := src

				err := validateAutogroupSupported(ag)
				if err != nil {
					errs = append(errs, err)
					continue
				}

				err = validateAutogroupForSSHSrc(ag)
				if err != nil {
					errs = append(errs, err)
					continue
				}
			case *Group:
				g := src

				err := p.Groups.Contains(g)
				if err != nil {
					errs = append(errs, err)
				}
			case *Tag:
				tagOwner := src

				err := p.TagOwners.Contains(tagOwner)
				if err != nil {
					errs = append(errs, err)
				}
			}
		}

		for _, dst := range ssh.Destinations {
			switch dst := dst.(type) {
			case *AutoGroup:
				ag := dst

				err := validateAutogroupSupported(ag)
				if err != nil {
					errs = append(errs, err)
					continue
				}

				err = validateAutogroupForSSHDst(ag)
				if err != nil {
					errs = append(errs, err)
					continue
				}
			case *Tag:
				tagOwner := dst

				err := p.TagOwners.Contains(tagOwner)
				if err != nil {
					errs = append(errs, err)
				}
			}
		}

		// Validate SSH source/destination combinations follow Tailscale's security model
		err := validateSSHSrcDstCombination(ssh.Sources, ssh.Destinations)
		if err != nil {
			errs = append(errs, err)
		}

		// Validate checkPeriod
		if ssh.CheckPeriod != nil {
			switch {
			case ssh.Action != SSHActionCheck:
				errs = append(errs, ErrSSHCheckPeriodOnNonCheck)
			default:
				err := ssh.CheckPeriod.Validate()
				if err != nil {
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

				err := p.Groups.Contains(g)
				if err != nil {
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

				err := p.Groups.Contains(g)
				if err != nil {
					errs = append(errs, err)
				}
			case *Tag:
				tagOwner := approver

				err := p.TagOwners.Contains(tagOwner)
				if err != nil {
					errs = append(errs, err)
				}
			}
		}
	}

	for _, approver := range p.AutoApprovers.ExitNode {
		switch approver := approver.(type) {
		case *Group:
			g := approver

			err := p.Groups.Contains(g)
			if err != nil {
				errs = append(errs, err)
			}
		case *Tag:
			tagOwner := approver

			err := p.TagOwners.Contains(tagOwner)
			if err != nil {
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

// SSHCheckPeriod represents the check period for SSH "check" mode rules.
// nil means not specified (runtime default of 12h applies).
// Always=true means "always" (check on every request).
// Duration is an explicit period (min 1m, max 168h).
type SSHCheckPeriod struct {
	Always   bool
	Duration time.Duration
}

// UnmarshalJSON implements JSON unmarshaling for SSHCheckPeriod.
func (p *SSHCheckPeriod) UnmarshalJSON(b []byte) error {
	str := strings.Trim(string(b), `"`)
	if str == "always" {
		p.Always = true

		return nil
	}

	d, err := model.ParseDuration(str)
	if err != nil {
		return fmt.Errorf("parsing checkPeriod %q: %w", str, err)
	}

	p.Duration = time.Duration(d)

	return nil
}

// MarshalJSON implements JSON marshaling for SSHCheckPeriod.
func (p SSHCheckPeriod) MarshalJSON() ([]byte, error) {
	if p.Always {
		return []byte(`"always"`), nil
	}

	return fmt.Appendf(nil, "%q", p.Duration.String()), nil
}

// Validate checks that the SSHCheckPeriod is within allowed bounds.
func (p *SSHCheckPeriod) Validate() error {
	if p.Always {
		return nil
	}

	if p.Duration < SSHCheckPeriodMin {
		return fmt.Errorf(
			"%w: got %s",
			ErrSSHCheckPeriodBelowMin,
			p.Duration,
		)
	}

	if p.Duration > SSHCheckPeriodMax {
		return fmt.Errorf(
			"%w: got %s",
			ErrSSHCheckPeriodAboveMax,
			p.Duration,
		)
	}

	return nil
}

// SSH controls who can ssh into which machines.
type SSH struct {
	Action       SSHAction       `json:"action"`
	Sources      SSHSrcAliases   `json:"src"`
	Destinations SSHDstAliases   `json:"dst"`
	Users        SSHUsers        `json:"users"`
	CheckPeriod  *SSHCheckPeriod `json:"checkPeriod,omitempty"`
	AcceptEnv    []string        `json:"acceptEnv,omitempty"`
}

// SSHSrcAliases is a list of aliases that can be used as sources in an SSH rule.
// It can be a list of usernames, groups, tags or autogroups.
type SSHSrcAliases []Alias

// MarshalJSON marshals the Groups to JSON.
func (g *Groups) MarshalJSON() ([]byte, error) {
	if *g == nil {
		return []byte("{}"), nil
	}

	raw := make(map[string][]string)
	for group, usernames := range *g {
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
			return fmt.Errorf("%w: %T", ErrSSHSourceAliasNotSupported, alias.Alias)
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
		case *Username, *Tag, *AutoGroup, *Host:
			(*a)[i] = alias.Alias
		case Asterix:
			return fmt.Errorf("%w; use 'autogroup:member' for user-owned devices, "+
				"'autogroup:tagged' for tagged devices, or specific tags/users",
				ErrSSHWildcardDestination)
		default:
			return fmt.Errorf("%w: %T", ErrSSHDestAliasNotSupported, alias.Alias)
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
			// Marshal wildcard as "*" so it gets rejected during unmarshal
			// with a proper error message explaining alternatives
			aliases[i] = "*"
		default:
			return nil, fmt.Errorf("%w: %T", ErrUnknownSSHDestAlias, v)
		}
	}

	return json.Marshal(aliases)
}

// MarshalJSON marshals the SSHSrcAliases to JSON.
func (a *SSHSrcAliases) MarshalJSON() ([]byte, error) {
	if a == nil || *a == nil {
		return []byte("[]"), nil
	}

	aliases := make([]string, len(*a))
	for i, alias := range *a {
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
			return nil, fmt.Errorf("%w: %T", ErrUnknownSSHSrcAlias, v)
		}
	}

	return json.Marshal(aliases)
}

func (a *SSHSrcAliases) Resolve(p *Policy, users types.Users, nodes views.Slice[types.NodeView]) (*netipx.IPSet, error) {
	var (
		ips  netipx.IPSetBuilder
		errs []error
	)

	for _, alias := range *a {
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

// SSHUserLocalpartPrefix is the prefix for localpart SSH user entries.
// Format: localpart:*@<domain>
// See: https://tailscale.com/docs/features/tailscale-ssh#users
const SSHUserLocalpartPrefix = "localpart:"

func (u SSHUsers) ContainsRoot() bool {
	return slices.Contains(u, "root")
}

func (u SSHUsers) ContainsNonRoot() bool {
	return slices.Contains(u, SSHUser(AutoGroupNonRoot))
}

// ContainsLocalpart returns true if any entry has the localpart: prefix.
func (u SSHUsers) ContainsLocalpart() bool {
	return slices.ContainsFunc(u, func(user SSHUser) bool {
		return user.IsLocalpart()
	})
}

// NormalUsers returns all SSH users that are not root, autogroup:nonroot,
// or localpart: entries.
func (u SSHUsers) NormalUsers() []SSHUser {
	return slicesx.Filter(nil, u, func(user SSHUser) bool {
		return user != "root" && user != SSHUser(AutoGroupNonRoot) && !user.IsLocalpart()
	})
}

// LocalpartEntries returns only the localpart: prefixed entries.
func (u SSHUsers) LocalpartEntries() []SSHUser {
	return slicesx.Filter(nil, u, func(user SSHUser) bool {
		return user.IsLocalpart()
	})
}

type SSHUser string

func (u SSHUser) String() string {
	return string(u)
}

// IsLocalpart returns true if the SSHUser has the localpart: prefix.
func (u SSHUser) IsLocalpart() bool {
	return strings.HasPrefix(string(u), SSHUserLocalpartPrefix)
}

// ParseLocalpart validates and extracts the domain from a localpart: entry.
// The expected format is localpart:*@<domain>.
// Returns the domain part or an error if the format is invalid.
func (u SSHUser) ParseLocalpart() (string, error) {
	if !u.IsLocalpart() {
		return "", fmt.Errorf("%w: missing prefix %q in %q", ErrInvalidLocalpart, SSHUserLocalpartPrefix, u)
	}

	pattern := strings.TrimPrefix(string(u), SSHUserLocalpartPrefix)

	// Must be *@<domain>
	atIdx := strings.LastIndex(pattern, "@")
	if atIdx < 0 {
		return "", fmt.Errorf("%w: missing @ in %q", ErrInvalidLocalpart, u)
	}

	localPart := pattern[:atIdx]
	domain := pattern[atIdx+1:]

	if localPart != "*" {
		return "", fmt.Errorf("%w: local part must be *, got %q in %q", ErrInvalidLocalpart, localPart, u)
	}

	if domain == "" {
		return "", fmt.Errorf("%w: empty domain in %q", ErrInvalidLocalpart, u)
	}

	return domain, nil
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
		return nil, nil //nolint:nilnil // intentional: no policy when empty input
	}

	var policy Policy

	ast, err := hujson.Parse(b)
	if err != nil {
		return nil, fmt.Errorf("parsing HuJSON: %w", err)
	}

	ast.Standardize()

	if err = json.Unmarshal(ast.Pack(), &policy, policyJSONOpts...); err != nil { //nolint:noinlineerr
		if serr, ok := errors.AsType[*json.SemanticError](err); ok && errors.Is(serr.Err, json.ErrUnknownName) {
			ptr := serr.JSONPointer
			name := ptr.LastToken()

			return nil, fmt.Errorf("%w: %q", ErrUnknownField, name)
		}

		return nil, fmt.Errorf("parsing policy from bytes: %w", err)
	}

	if err := policy.validate(); err != nil { //nolint:noinlineerr
		return nil, err
	}

	return &policy, nil
}

// validateProtocolPortCompatibility checks that only TCP, UDP, and SCTP protocols
// can have specific ports. All other protocols should only use wildcard ports.
func validateProtocolPortCompatibility(protocol Protocol, destinations []AliasWithPorts) error {
	// Only TCP, UDP, and SCTP support specific ports
	supportsSpecificPorts := protocol == ProtocolNameTCP || protocol == ProtocolNameUDP || protocol == ProtocolNameSCTP || protocol == ""

	if supportsSpecificPorts {
		return nil // No validation needed for these protocols
	}

	// For all other protocols, check that all destinations use wildcard ports
	for _, dst := range destinations {
		for _, portRange := range dst.Ports {
			// Check if it's not a wildcard port (0-65535)
			if portRange.First != 0 || portRange.Last != 65535 {
				return fmt.Errorf("%w: %q, only \"*\" is allowed", ErrProtocolNoSpecificPorts, protocol)
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
