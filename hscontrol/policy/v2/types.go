package v2

import (
	"errors"
	"fmt"
	"iter"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-json-experiment/json"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/tailscale/hujson"
	"go4.org/netipx"
	"tailscale.com/net/tsaddr"
	"tailscale.com/tailcfg"
	"tailscale.com/types/views"
	"tailscale.com/util/multierr"
	"tailscale.com/util/set"
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

var ErrUndefinedTagReference = errors.New("references undefined tag")

// SSH validation errors.
var (
	ErrSSHTagSourceToUserDest             = errors.New("tags in SSH source cannot access user-owned devices")
	ErrSSHUserDestRequiresSameUser        = errors.New("user destination requires source to contain only that same user")
	ErrSSHAutogroupSelfRequiresUserSource = errors.New("autogroup:self destination requires source to contain only users or groups, not tags or autogroup:tagged")
	ErrSSHTagSourceToAutogroupMember      = errors.New("tags in SSH source cannot access autogroup:member (user-owned devices)")
	ErrSSHWildcardDestination             = errors.New("wildcard (*) is not supported as SSH destination")
	ErrSSHCheckPeriodAboveMax             = errors.New("is above the max (168h)")
	ErrSSHCheckPeriodNegative             = errors.New("must be a positive duration")
	ErrSSHCheckPeriodOnNonCheck           = errors.New("checkPeriod is only valid with action \"check\"")
	ErrInvalidLocalpart                   = errors.New("invalid localpart format, must be localpart:*@<domain>")
	ErrSSHUsersMustBeSpecified            = errors.New("users must be specified")
	ErrSSHUserInvalid                     = errors.New("is not valid")
	ErrSSHAcceptEnvEmpty                  = errors.New("acceptEnv values cannot be empty")
	ErrSSHActionMustBeSpecified           = errors.New("action must be specified")
	ErrSSHActionInvalid                   = errors.New("is not a valid action")
	ErrSSHDestinationHostAlias            = errors.New("invalid dst")
	ErrTagNameMustStartWithLetter         = errors.New("tag names must start with a letter, after 'tag:'")
	ErrGroupMembersCannotBeRecursive      = errors.New("group members cannot be recursive")
)

// SSH check period constants per Tailscale docs:
// https://tailscale.com/docs/features/tailscale-ssh#checkperiod
// SaaS imposes no minimum (0s is accepted) so headscale matches.
const (
	SSHCheckPeriodDefault = 12 * time.Hour
	SSHCheckPeriodMax     = 7 * 24 * time.Hour
)

// ACL validation errors.
var (
	ErrACLAutogroupSelfInvalidSource = errors.New("autogroup:self can only be used with users, groups, or supported autogroups")
)

// Grant validation errors.
var (
	ErrGrantMissingIPOrApp             = errors.New("ip and app can not both be empty")
	ErrGrantViaNotATag                 = errors.New("via can only be a tag")
	ErrProtocolPortInvalidFormat       = errors.New("expected only one colon in Internet protocol and port type")
	ErrCapNameInvalidForm              = errors.New("capability name must have the form {domain}/{path}")
	ErrCapNameTailscaleDomain          = errors.New("capability name must not be in the tailscale.com domain")
	ErrGrantAutogroupSelfInvalidSource = errors.New("autogroup:self can only be used with users, groups, or supported autogroups")
	ErrGrantAppWithAutogroupInternet   = errors.New("cannot use app grants with autogroup:internet")
	ErrGrantDefaultRouteCIDR           = errors.New("to allow all IP addresses, use \"*\" or \"autogroup:internet\"")
)

// NodeAttrs validation errors.
var (
	ErrNodeAttrsIPPoolReserved      = errors.New("nodeAttrs ipPool must not overlap reserved Tailscale ranges")
	ErrNodeAttrsIPPoolOutOfRange    = errors.New("nodeAttrs ipPool must be within 100.64.0.0/10")
	ErrNodeAttrsAutogroupNotAllowed = errors.New("nodeAttrs target does not support this autogroup")
	ErrNodeAttrUnsupported          = errors.New("nodeAttrs uses a feature headscale does not yet support")
	ErrNodeAttrIPPoolUnsupported    = errors.New("nodeAttrs ipPool requires the IP allocator (https://github.com/juanfont/headscale/issues/2912)")
	ErrNodeAttrTargetUnsupported    = errors.New("nodeAttrs target alias type is not supported")
)

// nodeAttrUnsupportedCaps lists caps that headscale parses but cannot act on
// today. Each entry maps to the tracking issue an operator can follow. The
// caps are accepted by Tailscale SaaS, but delivering them via headscale
// without the matching server-side machinery would be misleading — nodes
// would advertise a feature that does not work. Reject at policy load and
// point operators at the issue.
var nodeAttrUnsupportedCaps = map[tailcfg.NodeCapability]string{
	tailcfg.NodeAttrFunnel: "https://github.com/juanfont/headscale/issues/2527",
}

// Policy validation errors.
var (
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
	ErrInvalidHostIP               = errors.New("hostname contains invalid IP address")
	ErrTagNotDefined               = errors.New("tag not found")
	ErrAutoApproverNotAlias        = errors.New("auto approver is not an alias")
	ErrInvalidACLAction            = errors.New("invalid ACL action")
	ErrInvalidSSHAction            = errors.New("invalid SSH action")
	ErrInvalidProtocolNumber       = errors.New("invalid protocol number")
	ErrProtocolLeadingZero         = errors.New("leading 0 not permitted in protocol number")
	ErrProtocolOutOfRange          = errors.New("protocol number out of range (0-255)")
	ErrAutogroupNotSupported       = errors.New("autogroup not supported in headscale")
	ErrAutogroupInternetSrc        = errors.New("autogroup:internet can only be used in ACL destinations")
	ErrAutogroupSelfSrc            = errors.New("\"autogroup:self\" not valid on the src side of a rule")
	ErrAutogroupNotSupportedACLSrc = errors.New("autogroup not supported for ACL sources")
	ErrAutogroupNotSupportedACLDst = errors.New("autogroup not supported for ACL destinations")
	ErrAutogroupDangerAllDst       = errors.New("cannot use autogroup:danger-all as a dst")
	ErrAutogroupNotSupportedSSHSrc = errors.New("autogroup not supported for SSH sources")
	ErrAutogroupNotSupportedSSHDst = errors.New("autogroup not supported for SSH destinations")
	ErrHostNotDefined              = errors.New("host not defined in policy")
	ErrSSHSourceAliasNotSupported  = errors.New("alias not supported for SSH source")
	ErrSSHDestAliasNotSupported    = errors.New("alias not supported for SSH destination")
	ErrUnknownField                = errors.New("unknown field")
	ErrProtocolNoSpecificPorts     = errors.New("protocol does not support specific ports")
	ErrTestEmptyAssertions         = errors.New("test entry must have at least one of \"accept\" or \"deny\"")
	ErrTestProtocolNotAllowed      = errors.New("test protocol must be tcp, udp, sctp, or empty")
	ErrTestDestinationMultiPort    = errors.New("test destination port must be a single port")
	ErrTestDestinationCIDR         = errors.New("test destination must be a single host, not a CIDR range")
	ErrAutogroupInternetTestDst    = errors.New("autogroup:internet not valid as a test destination")
	ErrSSHTestEmptySrc             = errors.New("SSH tests entry must have a non-empty src")
	ErrSSHTestEmptyDst             = errors.New("SSH tests entry must have at least one dst")
	ErrSSHTestDstUnknownTag        = errors.New("SSH tests dst contains unknown tag")
	ErrSSHTestDstDisallowedElement = errors.New("SSH tests dst contains disallowed element")
)

type resolved struct {
	ips netipx.IPSet
}

func newResolved(ipb *netipx.IPSetBuilder) (resolved, error) {
	ips, err := ipb.IPSet()
	if err != nil {
		return resolved{}, err
	}

	return resolved{ips: *ips}, nil
}

func newResolvedAddresses(ips *netipx.IPSet, err error) (ResolvedAddresses, error) {
	if ips == nil {
		return nil, err
	}

	return resolved{ips: *ips}, err
}

func ipSetToStrings(ips *netipx.IPSet) []string {
	var result []string

	for _, r := range ips.Ranges() {
		if r.From() == r.To() {
			result = append(result, r.From().String())
			continue
		}

		if p, ok := r.Prefix(); ok {
			result = append(result, p.String())
			continue
		}

		result = append(result, r.String())
	}

	return result
}

func (res resolved) Strings() []string {
	return ipSetToStrings(&res.ips)
}

func (res resolved) Prefixes() []netip.Prefix {
	ret := res.ips.Prefixes()

	return ret
}

func (res resolved) Empty() bool {
	return len(res.ips.Prefixes()) == 0
}

func (res resolved) Iter() iter.Seq[netip.Addr] {
	return util.IPSetAddrIter(&res.ips)
}

func (res resolved) Contains(ip netip.Addr) bool {
	return res.ips.Contains(ip)
}

type ResolvedAddresses interface {
	// Strings returns a slice of string representations of IP addresses,
	// it will return the appropriate representation for the underlying Alias.
	// Some should be returned as Prefixes and some as IP ranges.
	Strings() []string

	// Prefixes returns a slice of netip.Prefix representations of IP addresses.
	Prefixes() []netip.Prefix

	// Empty reports if there are no addresses in the ResolvedAddresses.
	Empty() bool

	// Iter returns an iterator over netip.Addr representations of IP addresses.
	Iter() iter.Seq[netip.Addr]

	// Contains reports if the given IP address is contained in the ResolvedAddresses.
	Contains(ip netip.Addr) bool
}

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

	alias := a.String()

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

var asterixResolved = sync.OnceValue(func() *netipx.IPSet {
	var ipb netipx.IPSetBuilder
	ipb.AddPrefix(tsaddr.TailscaleULARange())
	ipb.AddPrefix(tsaddr.CGNATRange())
	ipb.RemovePrefix(tsaddr.ChromeOSVMRange())

	ips, err := ipb.IPSet()
	if err != nil {
		panic(fmt.Sprintf("failed to build IPSet for wildcard: %v", err))
	}

	return ips
})

func (a Asterix) Resolve(p *Policy, u types.Users, n views.Slice[types.NodeView]) (ResolvedAddresses, error) {
	return newResolvedAddresses(a.resolve(p, u, n))
}

func (a Asterix) resolve(_ *Policy, _ types.Users, _ views.Slice[types.NodeView]) (*netipx.IPSet, error) {
	return asterixResolved(), nil
}

// approvedSubnetRoutes collects all approved non-exit subnet routes
// advertised across all nodes. Per Tailscale documentation, wildcard
// (*) SrcIPs include "any approved subnets".
//
// These are collected separately from the Asterix IPSet because
// IPSet merges overlapping ranges (e.g. 10.0.0.0/8 absorbs
// 10.33.0.0/16), but Tailscale preserves individual route entries.
func approvedSubnetRoutes(nodes views.Slice[types.NodeView]) []string {
	seen := make(set.Set[string])

	var routes []string

	for _, node := range nodes.All() {
		for _, route := range node.SubnetRoutes() {
			s := route.String()
			if !seen.Contains(s) {
				seen.Add(s)
				routes = append(routes, s)
			}
		}
	}

	return routes
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

// resolveUser attempts to find a user in the provided [types.Users] slice that matches the [Username].
// It prioritizes matching the [types.User.ProviderIdentifier], and if not found, it falls back to matching
// the [types.User.Email] or [types.User.Name].
// If no matching user is found, it returns an error indicating no user matching.
// If multiple matching users are found, it returns an error indicating multiple users matching.
// It returns the matched [types.User] and a nil error if exactly one match is found.
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

func (u *Username) Resolve(_ *Policy, users types.Users, nodes views.Slice[types.NodeView]) (ResolvedAddresses, error) {
	return newResolvedAddresses(u.resolve(nil, users, nodes))
}

func (u *Username) resolve(_ *Policy, users types.Users, nodes views.Slice[types.NodeView]) (*netipx.IPSet, error) {
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

func (g *Group) Resolve(p *Policy, users types.Users, nodes views.Slice[types.NodeView]) (ResolvedAddresses, error) {
	return newResolvedAddresses(g.resolve(p, users, nodes))
}

func (g *Group) resolve(p *Policy, users types.Users, nodes views.Slice[types.NodeView]) (*netipx.IPSet, error) {
	var (
		ips  netipx.IPSetBuilder
		errs []error
	)

	for _, user := range p.Groups[*g] {
		uips, err := user.resolve(nil, users, nodes)
		if err != nil {
			errs = append(errs, err)
		}

		ips.AddSet(uips)
	}

	return buildIPSetMultiErr(&ips, errs)
}

// Tag is a special string which is always prefixed with `tag:`.
type Tag string

// Validate enforces the `tag:` prefix and the SaaS rule that the
// first character after the prefix is an ASCII letter ([A-Za-z]).
// Subsequent characters may be ASCII letters, digits, hyphens, or
// dots — those are checked by the existing alias parser elsewhere.
func (t *Tag) Validate() error {
	s := string(*t)
	if !isTag(s) {
		return fmt.Errorf("%w, got: %q", ErrInvalidTagFormat, *t)
	}

	rest := strings.TrimPrefix(s, "tag:")
	if rest == "" {
		return ErrTagNameMustStartWithLetter
	}

	first := rest[0]
	if (first < 'a' || first > 'z') && (first < 'A' || first > 'Z') {
		return ErrTagNameMustStartWithLetter
	}

	return nil
}

func (t *Tag) UnmarshalJSON(b []byte) error {
	*t = Tag(strings.Trim(string(b), `"`))

	err := t.Validate()
	if err != nil {
		return err
	}

	return nil
}

func (t *Tag) Resolve(p *Policy, users types.Users, nodes views.Slice[types.NodeView]) (ResolvedAddresses, error) {
	return newResolvedAddresses(t.resolve(p, users, nodes))
}

func (t *Tag) resolve(p *Policy, users types.Users, nodes views.Slice[types.NodeView]) (*netipx.IPSet, error) {
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

func (h *Host) Resolve(p *Policy, _ types.Users, nodes views.Slice[types.NodeView]) (ResolvedAddresses, error) {
	return newResolvedAddresses(h.resolve(p, nil, nodes))
}

func (h *Host) resolve(p *Policy, _ types.Users, _ views.Slice[types.NodeView]) (*netipx.IPSet, error) {
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

	// Address-based aliases (host names) resolve to exactly the
	// literal prefix from the hosts map. They do NOT expand to
	// include the matching node's other IP addresses.
	ips.AddPrefix(netip.Prefix(pref))

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

// Resolve resolves the [Prefix] to an [netipx.IPSet]. The [netipx.IPSet] will
// contain all the IP addresses that the [Prefix] represents within Headscale.
// It is the product of the [Prefix] and the [Policy], [types.Users], and [types.Nodes].
//
// See [Policy], [types.Users], and [types.Nodes] for more details.
func (p *Prefix) Resolve(_ *Policy, _ types.Users, nodes views.Slice[types.NodeView]) (ResolvedAddresses, error) {
	return newResolvedAddresses(p.resolve(nil, nil, nodes))
}

func (p *Prefix) resolve(_ *Policy, _ types.Users, _ views.Slice[types.NodeView]) (*netipx.IPSet, error) {
	var (
		ips  netipx.IPSetBuilder
		errs []error
	)

	// Address-based aliases resolve to exactly the literal prefix.
	// Unlike identity-based aliases (tags, users, groups), they do
	// NOT expand to include the matching node's other IP addresses.
	ips.AddPrefix(netip.Prefix(*p))

	return buildIPSetMultiErr(&ips, errs)
}

// AutoGroup is a special string which is always prefixed with `autogroup:`.
type AutoGroup string

const (
	AutoGroupInternet  AutoGroup = "autogroup:internet"
	AutoGroupMember    AutoGroup = "autogroup:member"
	AutoGroupNonRoot   AutoGroup = "autogroup:nonroot"
	AutoGroupTagged    AutoGroup = "autogroup:tagged"
	AutoGroupSelf      AutoGroup = "autogroup:self"
	AutoGroupDangerAll AutoGroup = "autogroup:danger-all"
)

var autogroups = []AutoGroup{
	AutoGroupInternet,
	AutoGroupMember,
	AutoGroupNonRoot,
	AutoGroupTagged,
	AutoGroupSelf,
	AutoGroupDangerAll,
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

func (ag *AutoGroup) Resolve(p *Policy, users types.Users, nodes views.Slice[types.NodeView]) (ResolvedAddresses, error) {
	return newResolvedAddresses(ag.resolve(p, users, nodes))
}

func (ag *AutoGroup) resolve(p *Policy, users types.Users, nodes views.Slice[types.NodeView]) (*netipx.IPSet, error) {
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

	case AutoGroupDangerAll:
		// autogroup:danger-all matches ALL IP addresses, including
		// non-Tailscale addresses. Resolves to 0.0.0.0/0 + ::/0.
		// Filter compilation converts this to SrcIPs: ["*"].
		build.AddPrefix(netip.MustParsePrefix("0.0.0.0/0"))
		build.AddPrefix(netip.MustParsePrefix("::/0"))

		return build.IPSet()

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

	// String renders the alias back to its policy-file form. Implementations
	// are expected to return a value that round-trips through [parseAlias] for
	// any alias the parser accepted, so callers can use it as a stable
	// identity in rendered errors and logs.
	String() string

	// Resolve resolves the [Alias] to a [netipx.IPSet]. The [netipx.IPSet] will
	// contain all the IP addresses that the [Alias] represents within Headscale.
	// It is the product of the [Alias] and the [Policy], [types.Users] and
	// [types.Nodes]. This is an interface definition and the implementation is
	// independent of the [Alias] type.
	Resolve(pol *Policy, users types.Users, nodes views.Slice[types.NodeView]) (ResolvedAddresses, error)

	resolve(pol *Policy, users types.Users, nodes views.Slice[types.NodeView]) (*netipx.IPSet, error)
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

		originalDst := vs

		if strings.Contains(vs, ":") {
			vs, portsPart, err = splitDestinationAndPort(vs)
			if err != nil {
				return err
			}

			ports, err := parsePortRange(portsPart)
			if err != nil {
				return fmt.Errorf(
					"dst=%q: port range %q: %w",
					originalDst, portsPart, err,
				)
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

// ProtocolPort is a representation of the "network layer capabilities"
// of a Grant.
type ProtocolPort struct {
	Ports    []tailcfg.PortRange
	Protocol Protocol
}

func (ve *ProtocolPort) UnmarshalJSON(b []byte) error {
	var v any

	err := json.Unmarshal(b, &v)
	if err != nil {
		return err
	}

	switch vs := v.(type) {
	case string:
		if vs == "*" {
			ve.Protocol = ProtocolNameWildcard
			ve.Ports = []tailcfg.PortRange{tailcfg.PortRangeAny}

			return nil
		}

		// Only contains a port, no protocol
		if !strings.Contains(vs, ":") {
			ports, err := parsePortRange(vs)
			if err != nil {
				return fmt.Errorf("port range %q: %w", vs, err)
			}

			ve.Protocol = ProtocolNameWildcard
			ve.Ports = ports

			return nil
		}

		parts := strings.Split(vs, ":")
		if len(parts) != 2 {
			return fmt.Errorf("%w, got: %v(%d)", ErrProtocolPortInvalidFormat, parts, len(parts))
		}

		protocol := Protocol(parts[0])

		err := protocol.validate()
		if err != nil {
			return err
		}

		portsPart := parts[1]

		ports, err := parsePortRange(portsPart)
		if err != nil {
			return fmt.Errorf("port range %q: %w", portsPart, err)
		}

		ve.Protocol = protocol
		ve.Ports = ports

	default:
		return fmt.Errorf("%w: %T", ErrTypeNotSupported, vs)
	}

	return nil
}

func (ve ProtocolPort) MarshalJSON() ([]byte, error) {
	// Handle wildcard protocol with all ports
	if ve.Protocol == ProtocolNameWildcard && len(ve.Ports) == 1 &&
		ve.Ports[0].First == 0 && ve.Ports[0].Last == 65535 {
		return json.Marshal("*")
	}

	// Build port string
	var portParts []string

	for _, portRange := range ve.Ports {
		if portRange.First == portRange.Last {
			portParts = append(portParts, strconv.FormatUint(uint64(portRange.First), 10))
		} else {
			portParts = append(portParts, fmt.Sprintf("%d-%d", portRange.First, portRange.Last))
		}
	}

	portStr := strings.Join(portParts, ",")

	// Combine protocol and ports
	result := fmt.Sprintf("%s:%s", ve.Protocol, portStr)

	return json.Marshal(result)
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

// UnmarshalJSON trims surrounding whitespace from each alias string
// before dispatching so that `"tag:server "` or `" odin@example.com"`
// resolves to the same tag or user SaaS would resolve. SaaS trims
// before lookup; a literal-match policy here would drop the affected
// node from every rule referencing it.
func (ve *AliasEnc) UnmarshalJSON(b []byte) error {
	ptr, err := unmarshalPointer(
		b,
		func(s string) (Alias, error) {
			return parseAlias(strings.TrimSpace(s))
		},
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
		aliases[i] = alias.String()
	}

	return json.Marshal(aliases)
}

func (a *Aliases) Resolve(p *Policy, users types.Users, nodes views.Slice[types.NodeView]) (ResolvedAddresses, error) {
	var (
		ips  netipx.IPSetBuilder
		errs []error
	)

	for _, alias := range *a {
		aips, err := alias.resolve(p, users, nodes)
		if err != nil {
			errs = append(errs, err)
		}

		ips.AddSet(aips)
	}

	return newResolvedAddresses(buildIPSetMultiErr(&ips, errs))
}

func buildIPSetMultiErr(ipBuilder *netipx.IPSetBuilder, errs []error) (*netipx.IPSet, error) {
	ips, err := ipBuilder.IPSet()
	return ips, multierr.New(append(errs, err)...)
}

// Helper function to unmarshal a JSON string into either an [AutoApprover] or [Owner] pointer.
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
		approvers[i] = approver.String()
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
		owners[i] = owner.String()
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

// Groups are a map of [Group] to a list of [Username].
type Groups map[Group]Usernames

func (g *Groups) Contains(group *Group) error {
	if group == nil {
		return nil
	}

	if _, ok := (*g)[*group]; ok {
		return nil
	}

	return fmt.Errorf("%w: %q", ErrGroupNotDefined, group)
}

// UnmarshalJSON overrides the default JSON unmarshalling for [Groups] to ensure
// that each group name is validated using the [isGroup] function. This ensures
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

	// Reject group-in-group references. Reverse-sort the keys so the
	// reported (parent, child) pair names the deepest non-leaf parent
	// first.
	keys := make([]string, 0, len(rawGroups))
	for k := range rawGroups {
		keys = append(keys, k)
	}

	slices.Sort(keys)
	slices.Reverse(keys)

	for _, key := range keys {
		for _, u := range rawGroups[key] {
			if isGroup(u) {
				return fmt.Errorf("groups[%q]: %q: %w", key, u, ErrGroupMembersCannotBeRecursive)
			}
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
			ownerStrs[i] = owner.String()
		}

		rawTagOwners[tagStr] = ownerStrs
	}

	return json.Marshal(rawTagOwners)
}

// TagOwners are a map of [Tag] to a list of the UserEntities that own the tag.
type TagOwners map[Tag]Owners

func (to TagOwners) Contains(tagOwner *Tag) error {
	if tagOwner == nil {
		return nil
	}

	if _, ok := to[*tagOwner]; ok {
		return nil
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

// resolveAutoApprovers resolves the [AutoApprovers] to a map of [netip.Prefix] to [netipx.IPSet].
// The resulting map can be used to quickly look up if a node can self-approve a route.
// It is intended for internal use in a [PolicyManager].
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
			ips, _ := aa.resolve(p, users, nodes)
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
			ips, _ := aa.resolve(p, users, nodes)
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

// Action represents the action to take for an [ACL] rule.
type Action string

const (
	ActionAccept Action = "accept"
)

// SSHAction represents the action to take for an [SSH] rule.
type SSHAction string

const (
	SSHActionAccept SSHAction = "accept"
	SSHActionCheck  SSHAction = "check"
)

// String returns the string representation of the [Action].
func (a *Action) String() string {
	return string(*a)
}

// UnmarshalJSON implements JSON unmarshaling for [Action].
func (a *Action) UnmarshalJSON(b []byte) error {
	str := strings.Trim(string(b), `"`)
	switch str {
	case "accept":
		*a = ActionAccept
	default:
		return fmt.Errorf("action=%q is not supported: %w", str, ErrInvalidACLAction)
	}

	return nil
}

// MarshalJSON implements JSON marshaling for [Action].
func (a *Action) MarshalJSON() ([]byte, error) {
	return json.Marshal(string(*a))
}

// String returns the string representation of the [SSHAction].
func (a *SSHAction) String() string {
	return string(*a)
}

// UnmarshalJSON trims surrounding whitespace before matching, lets the
// empty string through (per-rule Validate() surfaces it later), and
// rejects every other unknown value here.
func (a *SSHAction) UnmarshalJSON(b []byte) error {
	str := strings.TrimSpace(strings.Trim(string(b), `"`))
	switch str {
	case "":
		*a = SSHAction("")
	case "accept":
		*a = SSHActionAccept
	case "check":
		*a = SSHActionCheck
	default:
		return fmt.Errorf("%q %w", str, ErrSSHActionInvalid)
	}

	return nil
}

// MarshalJSON implements JSON marshaling for [SSHAction].
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

// String returns the string representation of the [Protocol].
func (p *Protocol) String() string {
	return string(*p)
}

// toIANAProtocolNumbers converts a [Protocol] to its IANA protocol numbers.
// Since validation happens during [Protocol.UnmarshalJSON], this method should not fail for valid [Protocol] values.
func (p *Protocol) toIANAProtocolNumbers() []int {
	switch *p {
	case "":
		// Empty means the same as wildcard-ish, the client will add the default protocols (TCP, UDP, ICMP) if empty.
		return nil
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

// UnmarshalJSON implements JSON unmarshaling for [Protocol].
//
// Tailscale accepts both named ("tcp") and numeric IANA ("6") forms.
// Storing whichever form the user wrote leaves downstream code with
// two equivalents to handle separately, and any consumer that
// branches on the named form would silently mishandle the numeric
// equivalent. Canonicalising to the named form here makes [Protocol]
// hold one value post-parse — every downstream consumer sees the
// same form regardless of what the user wrote.
func (p *Protocol) UnmarshalJSON(b []byte) error {
	str := strings.Trim(string(b), `"`)

	// Normalize to lowercase for case-insensitive matching
	*p = Protocol(strings.ToLower(str))

	num, atoiErr := strconv.Atoi(string(*p))
	if atoiErr == nil && num >= 0 && num <= 255 {
		if name, ok := ProtocolNumberToName[num]; ok {
			*p = name
		}
	}

	err := p.validate()
	if err != nil {
		return err
	}

	return nil
}

// validate checks if the [Protocol] is valid.
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

// MarshalJSON implements JSON marshaling for [Protocol].
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

// ProtocolNumberToName maps IANA protocol numbers to their [Protocol] name strings.
var ProtocolNumberToName = map[int]Protocol{
	ProtocolICMP:     ProtocolNameICMP,
	ProtocolIGMP:     ProtocolNameIGMP,
	ProtocolIPv4:     ProtocolNameIPv4,
	ProtocolTCP:      ProtocolNameTCP,
	ProtocolEGP:      ProtocolNameEGP,
	ProtocolIGP:      ProtocolNameIGP,
	ProtocolUDP:      ProtocolNameUDP,
	ProtocolGRE:      ProtocolNameGRE,
	ProtocolESP:      ProtocolNameESP,
	ProtocolAH:       ProtocolNameAH,
	ProtocolIPv6ICMP: ProtocolNameIPv6ICMP,
	ProtocolSCTP:     ProtocolNameSCTP,
	ProtocolFC:       ProtocolNameFC,
}

type ACL struct {
	Action       Action           `json:"action"`
	Protocol     Protocol         `json:"proto"`
	Sources      Aliases          `json:"src"`
	Destinations []AliasWithPorts `json:"dst"`
}

// UnmarshalJSON implements custom unmarshalling for [ACL] that ignores fields starting with '#'.
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

type Grant struct {
	// TODO(kradalby): Validate grant src/dst according to ts docs
	Sources      Aliases `json:"src"`
	Destinations Aliases `json:"dst"`

	// TODO(kradalby): validate that either of these fields are included
	InternetProtocols []ProtocolPort     `json:"ip,omitempty"`
	App               tailcfg.PeerCapMap `json:"app,omitzero"`

	Via []Tag `json:"via,omitzero"`
}

// NodeAttrGrant attaches Tailscale node capabilities (and/or an IP-pool
// preference) to every node selected by Targets. The Targets aliases are
// resolved exactly like ACL/grant sources, so users, groups, tags, hosts,
// prefixes, autogroup:member, autogroup:tagged, and "*" are all valid.
//
// IPPool is parsed and validated for forward compatibility with the IP
// allocator; the policy compiler does not consume it yet.
type NodeAttrGrant struct {
	Targets Aliases                  `json:"target"`
	Attrs   []tailcfg.NodeCapability `json:"attr,omitempty"`
	IPPool  []netip.Prefix           `json:"ipPool,omitempty"`
}

// aclToGrants converts an [ACL] rule to one or more equivalent [Grant] rules.
func aclToGrants(acl ACL) []Grant {
	ret := make([]Grant, 0, len(acl.Destinations))

	// Check if the ACL has any non-autogroup destinations. If so,
	// reorder to place non-self grants before self grants. This matches
	// Tailscale's behavior where autogroup-only ACLs (self + member)
	// preserve policy order, but ACLs with groups, users, tags, or
	// hosts emit non-self rules first.
	hasNonAutogroup := false

	for _, dst := range acl.Destinations {
		if _, ok := dst.Alias.(*AutoGroup); !ok {
			hasNonAutogroup = true

			break
		}
	}

	if hasNonAutogroup {
		// Non-self destinations first, self destinations second.
		for _, dst := range acl.Destinations {
			if ag, ok := dst.Alias.(*AutoGroup); ok && ag.Is(AutoGroupSelf) {
				continue
			}

			ret = append(ret, Grant{
				Sources:      acl.Sources,
				Destinations: Aliases{dst.Alias},
				InternetProtocols: []ProtocolPort{{
					Protocol: acl.Protocol,
					Ports:    dst.Ports,
				}},
			})
		}

		for _, dst := range acl.Destinations {
			ag, ok := dst.Alias.(*AutoGroup)
			if !ok || !ag.Is(AutoGroupSelf) {
				continue
			}

			ret = append(ret, Grant{
				Sources:      acl.Sources,
				Destinations: Aliases{dst.Alias},
				InternetProtocols: []ProtocolPort{{
					Protocol: acl.Protocol,
					Ports:    dst.Ports,
				}},
			})
		}
	} else {
		// All-autogroup ACL: preserve policy order.
		for _, dst := range acl.Destinations {
			ret = append(ret, Grant{
				Sources:      acl.Sources,
				Destinations: Aliases{dst.Alias},
				InternetProtocols: []ProtocolPort{{
					Protocol: acl.Protocol,
					Ports:    dst.Ports,
				}},
			})
		}
	}

	return ret
}

// Policy represents a Tailscale Network Policy.
// TODO(kradalby):
// Add validation method checking:
// All users exists
// All groups and users are valid tag [TagOwners]
// Everything referred to in [ACL]s exists in other
// entities.
type Policy struct {
	// validated is set if the policy has been validated.
	// It is not safe to use before it is validated, and
	// callers using it should panic if not
	validated bool `json:"-"`

	Groups              Groups             `json:"groups,omitempty"`
	Hosts               Hosts              `json:"hosts,omitempty"`
	TagOwners           TagOwners          `json:"tagOwners,omitempty"`
	ACLs                []ACL              `json:"acls,omitempty"`
	Grants              []Grant            `json:"grants,omitempty"`
	NodeAttrs           []NodeAttrGrant    `json:"nodeAttrs,omitempty"`
	AutoApprovers       AutoApproverPolicy `json:"autoApprovers"`
	SSHs                []SSH              `json:"ssh,omitempty"`
	Tests               []PolicyTest       `json:"tests,omitempty"`
	SSHTests            []SSHPolicyTest    `json:"sshTests,omitempty"`
	RandomizeClientPort bool               `json:"randomizeClientPort,omitempty"`
}

// MarshalJSON is deliberately not implemented for [Policy].
// We use the default JSON marshalling behavior provided by the Go runtime.

var (
	// TODO(kradalby): Add these checks for tagOwners and autoApprovers.
	autogroupForSrc       = []AutoGroup{AutoGroupMember, AutoGroupTagged, AutoGroupDangerAll}
	autogroupForDst       = []AutoGroup{AutoGroupInternet, AutoGroupMember, AutoGroupTagged, AutoGroupSelf}
	autogroupForSSHSrc    = []AutoGroup{AutoGroupMember, AutoGroupTagged}
	autogroupForSSHDst    = []AutoGroup{AutoGroupMember, AutoGroupTagged, AutoGroupSelf}
	autogroupForNodeAttrs = []AutoGroup{AutoGroupMember, AutoGroupTagged}
	autogroupNotSupported = []AutoGroup{}

	errUnknownProtocolWildcard = errors.New("proto name \"*\" not known; use protocol number 0-255 or protocol name (icmp, tcp, udp, etc.)")
)

// reservedTSRanges are CGNAT subranges that Tailscale uses internally and that
// nodeAttrs ipPool entries must not overlap.
//
//   - 100.100.100.0/24 is MagicDNS / TSMP
//   - 100.115.92.0/23 is the Quad100 / IPN service range
//
// (See https://tailscale.com/kb/1304/ip-pool for the operator-facing list.)
var reservedTSRanges = []netip.Prefix{
	netip.MustParsePrefix("100.100.100.0/24"),
	netip.MustParsePrefix("100.115.92.0/23"),
}

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

	if dst.Is(AutoGroupDangerAll) {
		return ErrAutogroupDangerAllDst
	}

	if !slices.Contains(autogroupForDst, *dst) {
		return fmt.Errorf("%w: %q, can be %v", ErrAutogroupNotSupportedACLDst, *dst, autogroupForDst)
	}

	return nil
}

// validateAutogroupForNodeAttrs accepts only the autogroups that make sense
// as a nodeAttrs target: autogroup:member and autogroup:tagged.
// autogroup:self / autogroup:internet / autogroup:danger-all are rejected —
// none of them describes a stable identity set that a node-level attribute
// can attach to. autogroup:admin / autogroup:owner are rejected one layer
// up: [AutoGroup.UnmarshalJSON] returns [ErrInvalidAutogroup] at parse time
// because those values aren't in the allowed set, so the policy never
// reaches this validator.
func validateAutogroupForNodeAttrs(ag *AutoGroup) error {
	if ag == nil {
		return nil
	}

	if !slices.Contains(autogroupForNodeAttrs, *ag) {
		return fmt.Errorf("%w: %q, can be %v", ErrNodeAttrsAutogroupNotAllowed, *ag, autogroupForNodeAttrs)
	}

	return nil
}

// validateNodeAttrIPPool rejects ipPool entries outside the CGNAT range or
// overlapping the Tailscale-reserved subranges (MagicDNS, Quad100/IPN). A
// [netip.Prefix] is considered "within" CGNAT when it is at least as specific as
// 100.64.0.0/10 and its first address lies inside it.
func validateNodeAttrIPPool(prefix netip.Prefix) error {
	cgnat := tsaddr.CGNATRange()
	masked := prefix.Masked()

	if masked.Bits() < cgnat.Bits() || !cgnat.Contains(masked.Addr()) {
		return fmt.Errorf("%w: %q", ErrNodeAttrsIPPoolOutOfRange, prefix)
	}

	for _, reserved := range reservedTSRanges {
		if masked.Overlaps(reserved) {
			return fmt.Errorf("%w: %q overlaps %q", ErrNodeAttrsIPPoolReserved, prefix, reserved)
		}
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

// validateSSHSrcDstCombination validates that SSH source/destination combinations
// follow Tailscale's security model:
//   - Destination can be: tags, autogroup:self (if source is users/groups), or same-user
//   - Tags/autogroup:tagged CANNOT SSH to user destinations
//   - [Username] destinations require the source to be that same single user only.
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

// validateACLSrcDstCombination validates that [ACL] source/destination combinations
// follow Tailscale's security model:
//   - autogroup:self destinations require ALL sources to be users, groups, autogroup:member, or wildcard (*)
//   - Tags, autogroup:tagged, hosts, and raw IPs are NOT valid sources for autogroup:self
//   - Wildcard (*) is allowed because autogroup:self evaluation narrows it per-node to the node's own IPs.
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

// validateCapabilityName validates that a capability name has the form
// {domain}/{path} (no URL scheme) and is not in the tailscale.com domain
// (unless it's on the allowlist of user-grantable capabilities).
// Tailscale SaaS enforces these rules to prevent confusion with built-in
// capabilities and URL-formatted names.
func validateCapabilityName(name string) error {
	// Reject URL schemes (e.g., "https://tailscale.com/cap/ingress")
	if strings.Contains(name, "://") {
		return ErrCapNameInvalidForm
	}

	// Reject caps in the tailscale.com domain unless allowlisted.
	if strings.HasPrefix(name, "tailscale.com/") {
		if !tailscaleCapAllowlist[tailcfg.PeerCapability(name)] {
			return ErrCapNameTailscaleDomain
		}
	}

	return nil
}

// tailscaleCapAllowlist contains the tailscale.com/cap/* capability names
// that users are allowed to specify in grant app fields. Companion caps
// (drive-sharer, relay-target) and internal caps (ingress, funnel) are
// generated by the server and cannot be specified by users.
var tailscaleCapAllowlist = map[tailcfg.PeerCapability]bool{
	tailcfg.PeerCapabilityTaildrive:  true, // tailscale.com/cap/drive
	tailcfg.PeerCapabilityRelay:      true, // tailscale.com/cap/relay
	tailcfg.PeerCapabilityWebUI:      true, // tailscale.com/cap/webui
	tailcfg.PeerCapabilityKubernetes: true, // tailscale.com/cap/kubernetes
	tailcfg.PeerCapabilityTsIDP:      true, // tailscale.com/cap/tsidp

	// tailscale.com/cap/secrets is the capability used by setec
	// (github.com/tailscale/setec); allow it so it can be granted via policy.
	tailcfg.PeerCapability("tailscale.com/cap/secrets"): true,
}

// validateGrantSrcDstCombination validates [Grant]-specific source/destination
// combinations. [Grant]s are stricter than [ACL]s: wildcard (*) sources are NOT
// allowed with autogroup:self destinations because * includes tags, and tags
// cannot use autogroup:self. [ACL]s allow this combination because ACL
// autogroup:self evaluation narrows it per-node, but [Grant]s reject it at
// validation time.
func validateGrantSrcDstCombination(sources Aliases, destinations Aliases) error {
	hasAutogroupSelf := false

	for _, dst := range destinations {
		if ag, ok := dst.(*AutoGroup); ok && ag.Is(AutoGroupSelf) {
			hasAutogroupSelf = true

			break
		}
	}

	if !hasAutogroupSelf {
		return nil
	}

	for _, src := range sources {
		switch v := src.(type) {
		case *Username, *Group:
			continue
		case *AutoGroup:
			if v.Is(AutoGroupMember) {
				continue
			}

			return ErrGrantAutogroupSelfInvalidSource
		case Asterix:
			// Grants reject wildcard with autogroup:self (unlike ACLs)
			return ErrGrantAutogroupSelfInvalidSource
		default:
			return ErrGrantAutogroupSelfInvalidSource
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
					errs = append(errs, fmt.Errorf("src=%w", err))
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
					errs = append(errs, fmt.Errorf("dst=%q: %w", *h, err))
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
		// Empty action and users survive parse; surface them here.
		if ssh.Action == "" {
			errs = append(errs, ErrSSHActionMustBeSpecified)
		}

		if len(ssh.Users) == 0 {
			errs = append(errs, ErrSSHUsersMustBeSpecified)
		}

		// "" and "*" are not valid login users; any other string
		// (including autogroup, group, tag, malformed localpart) is
		// treated as a literal user name.
		for _, user := range ssh.Users {
			switch user {
			case "", "*":
				errs = append(errs, fmt.Errorf("user %q %w", user, ErrSSHUserInvalid))
			}
		}

		// acceptEnv entries cannot be empty; "*" and "**" are valid.
		for _, env := range ssh.AcceptEnv {
			if env == "" {
				errs = append(errs, ErrSSHAcceptEnvEmpty)
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
			case *Host:
				// Hosts-table aliases are valid on ACL dst but
				// rejected here for SSH dst.
				errs = append(errs, fmt.Errorf("%w %q", ErrSSHDestinationHostAlias, string(*dst)))
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

	for _, grant := range p.Grants {
		// Validate that grants have at least ip or app
		hasIP := len(grant.InternetProtocols) > 0
		hasApp := len(grant.App) > 0

		if !hasIP && !hasApp {
			errs = append(errs, ErrGrantMissingIPOrApp)
		}

		// Validate capability name format in app grants.
		// Tailscale requires cap names to be {domain}/{path} (no URL scheme)
		// and rejects caps in the tailscale.com domain.
		for capName := range grant.App {
			err := validateCapabilityName(string(capName))
			if err != nil {
				errs = append(errs, err)
			}
		}

		// Validate that app grants are not used with autogroup:internet.
		if hasApp {
			for _, dst := range grant.Destinations {
				if ag, ok := dst.(*AutoGroup); ok && ag.Is(AutoGroupInternet) {
					errs = append(errs, ErrGrantAppWithAutogroupInternet)

					break
				}
			}
		}

		// Validate destinations do not contain raw default route CIDRs.
		// Tailscale rejects 0.0.0.0/0 and ::/0 as grant dst, requiring
		// "*" or "autogroup:internet" instead.
		for _, dst := range grant.Destinations {
			if p, ok := dst.(*Prefix); ok {
				prefix := netip.Prefix(*p)
				if prefix.Bits() == 0 {
					errs = append(errs, fmt.Errorf(
						"dst %q: %w",
						prefix.String(), ErrGrantDefaultRouteCIDR,
					))

					break
				}
			}
		}

		// Validate sources (empty arrays are allowed — they produce no rules)
		for _, src := range grant.Sources {
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
					errs = append(errs, fmt.Errorf("src=%w", err))
				}
			}
		}

		// Validate destinations (empty arrays are allowed — they produce no rules)
		for _, dst := range grant.Destinations {
			switch h := dst.(type) {
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

		// Validate via tags. Wording matches Tailscale SaaS
		// ("tag %q not found"), which differs from the ACL-src
		// wording ("src=tag not found: %q").
		for _, viaTag := range grant.Via {
			err := p.TagOwners.Contains(&viaTag)
			if err != nil {
				//nolint:err113 // SaaS-aligned dynamic phrasing; no caller does errors.Is.
				errs = append(errs, fmt.Errorf("tag %q not found", viaTag))
			}
		}

		// Validate grant-specific source/destination combinations.
		// Grants are stricter than ACLs: wildcard (*) src with autogroup:self
		// dst is rejected because * includes tags, and tags cannot use
		// autogroup:self.
		err := validateGrantSrcDstCombination(grant.Sources, grant.Destinations)
		if err != nil {
			errs = append(errs, err)
		}
	}

	for _, na := range p.NodeAttrs {
		// SaaS accepts entries with neither attr nor ipPool (they
		// compile to a no-op); headscale follows suit so policies
		// captured against SaaS round-trip cleanly.
		for _, target := range na.Targets {
			switch t := target.(type) {
			case *Host:
				if !p.Hosts.exist(*t) {
					errs = append(errs, fmt.Errorf("%w: %q", ErrHostNotDefined, *t))
				}
			case *AutoGroup:
				err := validateAutogroupSupported(t)
				if err != nil {
					errs = append(errs, err)

					continue
				}

				err = validateAutogroupForNodeAttrs(t)
				if err != nil {
					errs = append(errs, err)
				}
			case *Group:
				err := p.Groups.Contains(t)
				if err != nil {
					errs = append(errs, err)
				}
			case *Tag:
				err := p.TagOwners.Contains(t)
				if err != nil {
					errs = append(errs, err)
				}
			case *Username, *Prefix, Asterix:
				// User / prefix / wildcard targets are accepted at
				// parse time and resolved at compile time (where a
				// typo'd username surfaces as a propagated Resolve
				// error from compileNodeAttrs). Mirrors the grant
				// source-side validation shape.
			default:
				errs = append(errs, fmt.Errorf("%w: %q (%T)", ErrNodeAttrTargetUnsupported, target, target))
			}
		}

		for _, attr := range na.Attrs {
			issue, ok := nodeAttrUnsupportedCaps[attr]
			if ok {
				errs = append(errs, fmt.Errorf("%w: %q tracked in %s", ErrNodeAttrUnsupported, attr, issue))
			}
		}

		if len(na.IPPool) > 0 {
			errs = append(errs, ErrNodeAttrIPPoolUnsupported)
		}

		for _, prefix := range na.IPPool {
			err := validateNodeAttrIPPool(prefix)
			if err != nil {
				errs = append(errs, err)
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

	if err := validateTests(p, p.Tests); err != nil { //nolint:noinlineerr
		errs = append(errs, err)
	}

	if err := validateSSHTests(p, p.SSHTests); err != nil { //nolint:noinlineerr
		errs = append(errs, err)
	}

	if len(errs) > 0 {
		return multierr.New(errs...)
	}

	p.validated = true

	return nil
}

// SSHCheckPeriod represents the check period for SSH "check" mode rules.
// nil means not specified (runtime default of 12h applies).
// [SSHCheckPeriod.Always]=true means "always" (check on every request).
// [SSHCheckPeriod.Duration] is an explicit period (min 1m, max 168h).
type SSHCheckPeriod struct {
	Always   bool
	Duration time.Duration
}

// UnmarshalJSON implements JSON unmarshaling for [SSHCheckPeriod].
func (p *SSHCheckPeriod) UnmarshalJSON(b []byte) error {
	str := strings.Trim(string(b), `"`)
	if str == "always" {
		p.Always = true

		return nil
	}

	d, err := time.ParseDuration(str)
	if err != nil {
		return err
	}

	p.Duration = d

	return nil
}

// MarshalJSON implements JSON marshaling for [SSHCheckPeriod].
func (p SSHCheckPeriod) MarshalJSON() ([]byte, error) {
	if p.Always {
		return []byte(`"always"`), nil
	}

	return fmt.Appendf(nil, "%q", p.Duration.String()), nil
}

// Validate rejects negative durations and anything above the inclusive
// 168h max.
func (p *SSHCheckPeriod) Validate() error {
	if p.Always {
		return nil
	}

	if p.Duration < 0 {
		return fmt.Errorf("checkPeriod %s %w", p.Duration, ErrSSHCheckPeriodNegative)
	}

	if p.Duration > SSHCheckPeriodMax {
		return fmt.Errorf("checkPeriod %s %w", p.Duration, ErrSSHCheckPeriodAboveMax)
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

// SSHSrcAliases is a list of aliases that can be used as sources in an [SSH] rule.
// It can be a list of usernames, groups, tags or autogroups.
type SSHSrcAliases []Alias

// MarshalJSON marshals the [Groups] to JSON.
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

// MarshalJSON marshals the [SSHDstAliases] to JSON.
func (a SSHDstAliases) MarshalJSON() ([]byte, error) {
	if a == nil {
		return []byte("[]"), nil
	}

	aliases := make([]string, len(a))
	for i, alias := range a {
		// A wildcard renders as "*" so it gets rejected during unmarshal
		// with a proper error message explaining alternatives.
		aliases[i] = alias.String()
	}

	return json.Marshal(aliases)
}

// MarshalJSON marshals the [SSHSrcAliases] to JSON.
func (a *SSHSrcAliases) MarshalJSON() ([]byte, error) {
	if a == nil || *a == nil {
		return []byte("[]"), nil
	}

	aliases := make([]string, len(*a))
	for i, alias := range *a {
		aliases[i] = alias.String()
	}

	return json.Marshal(aliases)
}

func (a *SSHSrcAliases) Resolve(p *Policy, users types.Users, nodes views.Slice[types.NodeView]) (ResolvedAddresses, error) {
	var (
		ips  netipx.IPSetBuilder
		errs []error
	)

	for _, alias := range *a {
		aips, err := alias.resolve(p, users, nodes)
		if err != nil {
			errs = append(errs, err)
		}

		ips.AddSet(aips)
	}

	return newResolvedAddresses(buildIPSetMultiErr(&ips, errs))
}

// SSHDstAliases is a list of aliases that can be used as destinations in an [SSH] rule.
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

// ContainsLocalpart returns true if any entry is a canonical
// `localpart:*@<domain>` form. Non-canonical strings starting with
// `localpart:` are treated as literal usernames.
func (u SSHUsers) ContainsLocalpart() bool {
	return slices.ContainsFunc(u, func(user SSHUser) bool {
		return user.IsCanonicalLocalpart()
	})
}

// NormalUsers returns users that land in the compiled literal user map
// (everything except root, autogroup:nonroot, and canonical
// `localpart:*@<domain>`). Malformed `localpart:` strings stay here as
// literals.
func (u SSHUsers) NormalUsers() []SSHUser {
	return slicesx.Filter(nil, u, func(user SSHUser) bool {
		return user != "root" && user != SSHUser(AutoGroupNonRoot) && !user.IsCanonicalLocalpart()
	})
}

// LocalpartEntries returns only canonical `localpart:*@<domain>` entries.
// Non-canonical localpart strings are excluded so they do not trigger
// the resolution path; they are emitted literally by NormalUsers.
func (u SSHUsers) LocalpartEntries() []SSHUser {
	return slicesx.Filter(nil, u, func(user SSHUser) bool {
		return user.IsCanonicalLocalpart()
	})
}

type SSHUser string //nolint:recvcheck // UnmarshalJSON requires pointer receiver; string-newtype methods use value receivers by convention

func (u SSHUser) String() string {
	return string(u)
}

// IsLocalpart returns true if the [SSHUser] has the literal `localpart:`
// prefix. It is a syntactic check only — non-canonical shapes still
// pass.
func (u SSHUser) IsLocalpart() bool {
	return strings.HasPrefix(string(u), SSHUserLocalpartPrefix)
}

// IsCanonicalLocalpart reports whether the [SSHUser] parses as the
// canonical `localpart:*@<domain>` form that resolution acts on.
func (u SSHUser) IsCanonicalLocalpart() bool {
	if !u.IsLocalpart() {
		return false
	}

	_, err := u.ParseLocalpart()

	return err == nil
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

// MarshalJSON marshals the [SSHUser] to JSON.
func (u SSHUser) MarshalJSON() ([]byte, error) {
	return json.Marshal(string(u))
}

// UnmarshalJSON trims surrounding whitespace per element. A whitespace-
// only entry collapses to `""` and surfaces as `user "" is not valid` in
// the per-rule [Policy.validate] pass.
func (u *SSHUser) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil { //nolint:noinlineerr
		return err
	}

	*u = SSHUser(strings.TrimSpace(s))

	return nil
}

// unmarshalPolicy takes a byte slice and unmarshals it into a [Policy] struct.
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
		if serr, ok := errors.AsType[*json.SemanticError](err); ok {
			if errors.Is(serr.Err, json.ErrUnknownName) {
				ptr := serr.JSONPointer
				name := ptr.LastToken()

				return nil, fmt.Errorf("%w: %q", ErrUnknownField, name)
			}

			// Non-tag entries in grant.via surface as type errors on
			// []Tag; rephrase to the wire-compatible body.
			if strings.Contains(string(serr.JSONPointer), "/via/") {
				return nil, ErrGrantViaNotATag
			}

			// Non-ASCII tag-name failures surface from Tag.Validate
			// at unmarshal time. Reshape to `tagOwners["tag:X"]: …`.
			if errors.Is(serr.Err, ErrTagNameMustStartWithLetter) {
				ptr := serr.JSONPointer
				name := ptr.LastToken()

				return nil, fmt.Errorf("tagOwners[%q]: %w", name, ErrTagNameMustStartWithLetter)
			}
		}

		return nil, fmt.Errorf("parsing policy from bytes: %w", err)
	}

	if err := policy.validate(); err != nil { //nolint:noinlineerr
		return nil, err
	}

	return &policy, nil
}

// validateProtocolPortCompatibility checks that only TCP, UDP, and SCTP [Protocol]s
// can have specific ports. All other [Protocol]s should only use wildcard ports.
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

// validateTests enforces the four shape rules a tests-block entry must
// follow: a tests entry describes one connection attempt to one specific
// destination port over a connection-oriented protocol and asserts
// whether that attempt is allowed or denied. The same shapes remain
// valid inside [ACL] or [Grant] destinations where the rule does not apply.
func validateTests(pol *Policy, tests []PolicyTest) error {
	var errs []error

	for i, t := range tests {
		if len(t.Accept) == 0 && len(t.Deny) == 0 {
			errs = append(errs, fmt.Errorf("test %d: %w", i, ErrTestEmptyAssertions))
		}

		if t.Proto != "" &&
			t.Proto != ProtocolNameTCP &&
			t.Proto != ProtocolNameUDP &&
			t.Proto != ProtocolNameSCTP {
			errs = append(errs, fmt.Errorf("test %d: %w: %q", i, ErrTestProtocolNotAllowed, t.Proto))
		}

		for _, dst := range t.Accept {
			err := validateTestDestination(pol, dst)
			if err != nil {
				errs = append(errs, fmt.Errorf("test %d, accept %q: %w", i, dst, err))
			}
		}

		for _, dst := range t.Deny {
			err := validateTestDestination(pol, dst)
			if err != nil {
				errs = append(errs, fmt.Errorf("test %d, deny %q: %w", i, dst, err))
			}
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("%w:\n%w", errPolicyTestsFailed, multierr.New(errs...))
	}

	return nil
}

// validateTestDestination enforces that a tests-block dst describes one
// connection attempt to one specific host on one specific port. SaaS
// rejects three shapes that violate the rule: autogroup:internet (routed
// by exit-node [tailcfg.Node.AllowedIPs], not the packet filter); multi-port
// (range/list/wildcard, no single allow/deny answer); and CIDR ranges
// — both raw `/N` syntax and `hosts:`-table aliases whose RHS is a
// multi-host prefix. Bare IP literals reach this function as *[Prefix]
// /32 or /128 just like explicit `/32` / `/128` does, so the CIDR
// check inspects the raw input string for `/` rather than the parsed
// alias type.
func validateTestDestination(pol *Policy, dst string) error {
	awp, err := parseDestinationAlias(dst)
	if err != nil {
		return err
	}

	if ag, ok := awp.Alias.(*AutoGroup); ok && *ag == AutoGroupInternet {
		return ErrAutogroupInternetTestDst
	}

	if len(awp.Ports) != 1 || awp.Ports[0].First != awp.Ports[0].Last {
		return ErrTestDestinationMultiPort
	}

	if _, isPrefix := awp.Alias.(*Prefix); isPrefix && strings.Contains(dst, "/") {
		return ErrTestDestinationCIDR
	}

	if h, isHost := awp.Alias.(*Host); isHost && pol != nil {
		if pref, ok := pol.Hosts[*h]; ok {
			p := netip.Prefix(pref)
			if p.Bits() < p.Addr().BitLen() {
				return ErrTestDestinationCIDR
			}
		}
	}

	return nil
}

// validateSSHTests enforces parse-time shape on every sshTests entry:
// non-empty src, at least one dst, and each dst describing a single
// SSH-reachable host. Login-user assertions land with the engine so
// failures surface through the same errSSHPolicyTestsFailed wrapper.
func validateSSHTests(pol *Policy, tests []SSHPolicyTest) error {
	var errs []error

	for i, t := range tests {
		if t.Src == nil {
			errs = append(errs, fmt.Errorf("sshTest %d: %w", i, ErrSSHTestEmptySrc))
		}

		if len(t.Dst) == 0 {
			errs = append(errs, fmt.Errorf("sshTest %d: %w", i, ErrSSHTestEmptyDst))
		}

		for _, dst := range t.Dst {
			err := validateSSHTestDestination(pol, dst)
			if err != nil {
				errs = append(errs, fmt.Errorf("sshTest %d: %w", i, err))
			}
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("%w:\n%w", errSSHPolicyTestsFailed, multierr.New(errs...))
	}

	return nil
}

// validateSSHTestDestination rejects sshTests dst shapes that cannot
// name a single SSH-reachable host:
//
//   - `host:port` suffixes (parsed as an unknown tag),
//   - multi-host CIDRs (raw `/N` or a hosts: entry resolving wider),
//   - autogroup:internet (valid as ACL dst only).
//
// A bare IP literal (single-host /BitLen prefix) is accepted. Tag
// entries must exist in tagOwners.
func validateSSHTestDestination(pol *Policy, alias Alias) error {
	dst := alias.String()

	switch a := alias.(type) {
	case *AutoGroup:
		// autogroup:internet is the only autogroup not valid here;
		// member/tagged/self/nonroot pass to engine evaluation.
		if *a == AutoGroupInternet {
			return fmt.Errorf("%w %q", ErrSSHTestDstDisallowedElement, dst)
		}

	case *Prefix:
		// A bare IP parses as `/BitLen` and is a valid single-host dst;
		// any narrower CIDR is a multi-host range and is rejected.
		p := netip.Prefix(*a)
		if p.Bits() < p.Addr().BitLen() {
			return fmt.Errorf("%w %q", ErrSSHTestDstDisallowedElement, dst)
		}

	case *Tag:
		// A tag must be declared in tagOwners. `tag:server:22` lands
		// here too because isTag only checks the prefix, so the lookup
		// misses and the colon-port suffix surfaces as unknown-tag.
		if pol == nil {
			return fmt.Errorf("%w %q", ErrSSHTestDstUnknownTag, string(*a))
		}

		err := pol.TagOwners.Contains(a)
		if err != nil {
			return fmt.Errorf("%w %q", ErrSSHTestDstUnknownTag, string(*a))
		}

	case *Host:
		// A hosts: alias that resolves to multiple addresses is a CIDR
		// in disguise.
		if pol == nil {
			return nil
		}

		pref, ok := pol.Hosts[*a]
		if !ok {
			return nil
		}

		p := netip.Prefix(pref)
		if p.Bits() < p.Addr().BitLen() {
			return fmt.Errorf("%w %q", ErrSSHTestDstDisallowedElement, dst)
		}
	}

	return nil
}
