package policyv2

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
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
		return types.User{}, fmt.Errorf("multiple users with token %q found: %w", u.String(), ErrorNoUserMatching)
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

	// If the IP is a single host, look for a node to ensure we add all the IPs of
	// the node to the IPSet.
	appendIfNodeHasIP(nodes, &ips, pref)
	ips.AddPrefix(netip.Prefix(pref))

	return ips.IPSet()
}

func appendIfNodeHasIP(nodes types.Nodes, ips *netipx.IPSetBuilder, pref Prefix) {
	if netip.Prefix(pref).IsSingleIP() {
		addr := netip.Prefix(pref).Addr()
		for _, node := range nodes {
			if node.HasIP(addr) {
				node.AppendToIPSet(ips)
			}
		}
	}
}

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

func (p Prefix) Resolve(_ *Policy, _ types.Users, nodes types.Nodes) (*netipx.IPSet, error) {
	var ips netipx.IPSetBuilder

	appendIfNodeHasIP(nodes, &ips, p)
	ips.AddPrefix(netip.Prefix(p))

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
			vs, portsPart, err = splitDestination(vs)
			if err != nil {
				return err
			}

			ports, err := parsePorts(portsPart)
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
	Routes   map[string][]string `json:"routes"`
	ExitNode []string            `json:"exitNode"`
}

type ACL struct {
	Action       string           `json:"action"`
	Protocol     string           `json:"proto"`
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
	Action       string        `json:"action"`
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

// TODO(kradalby): copy tests from parseDestination in policy
func splitDestination(dest string) (string, string, error) {
	var tokens []string

	// Check if there is a IPv4/6:Port combination, IPv6 has more than
	// three ":".
	tokens = strings.Split(dest, ":")
	if len(tokens) < expectedTokenItems || len(tokens) > 3 {
		port := tokens[len(tokens)-1]

		maybeIPv6Str := strings.TrimSuffix(dest, ":"+port)

		filteredMaybeIPv6Str := maybeIPv6Str
		if strings.Contains(maybeIPv6Str, "/") {
			networkParts := strings.Split(maybeIPv6Str, "/")
			filteredMaybeIPv6Str = networkParts[0]
		}

		if maybeIPv6, err := netip.ParseAddr(filteredMaybeIPv6Str); err != nil && !maybeIPv6.Is6() {
			return "", "", fmt.Errorf(
				"failed to split destination: %v",
				tokens,
			)
		} else {
			tokens = []string{maybeIPv6Str, port}
		}
	}

	var alias string
	// We can have here stuff like:
	// git-server:*
	// 192.168.1.0/24:22
	// fd7a:115c:a1e0::2:22
	// fd7a:115c:a1e0::2/128:22
	// tag:montreal-webserver:80,443
	// tag:api-server:443
	// example-host-1:*
	if len(tokens) == expectedTokenItems {
		alias = tokens[0]
	} else {
		alias = fmt.Sprintf("%s:%s", tokens[0], tokens[1])
	}

	return alias, tokens[len(tokens)-1], nil
}

// TODO(kradalby): write/copy tests from expandPorts in policy
func parsePorts(portsStr string) ([]tailcfg.PortRange, error) {
	if portsStr == "*" {
		return []tailcfg.PortRange{
			tailcfg.PortRangeAny,
		}, nil
	}

	var ports []tailcfg.PortRange
	for _, portStr := range strings.Split(portsStr, ",") {
		rang := strings.Split(portStr, "-")
		switch len(rang) {
		case 1:
			port, err := strconv.ParseUint(rang[0], util.Base10, util.BitSize16)
			if err != nil {
				return nil, err
			}
			ports = append(ports, tailcfg.PortRange{
				First: uint16(port),
				Last:  uint16(port),
			})

		case expectedTokenItems:
			start, err := strconv.ParseUint(rang[0], util.Base10, util.BitSize16)
			if err != nil {
				return nil, err
			}
			last, err := strconv.ParseUint(rang[1], util.Base10, util.BitSize16)
			if err != nil {
				return nil, err
			}
			ports = append(ports, tailcfg.PortRange{
				First: uint16(start),
				Last:  uint16(last),
			})

		default:
			return nil, errors.New("invalid ports")
		}
	}

	return ports, nil
}

// For some reason golang.org/x/net/internal/iana is an internal package.
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
	ProtocolFC       = 133 // Fibre Channel
)

// parseProtocol reads the proto field of the ACL and generates a list of
// protocols that will be allowed, following the IANA IP protocol number
// https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
//
// If the ACL proto field is empty, it allows ICMPv4, ICMPv6, TCP, and UDP,
// as per Tailscale behaviour (see tailcfg.FilterRule).
//
// Also returns a boolean indicating if the protocol
// requires all the destinations to use wildcard as port number (only TCP,
// UDP and SCTP support specifying ports).
func parseProtocol(protocol string) ([]int, bool, error) {
	switch protocol {
	case "":
		return nil, false, nil
	case "igmp":
		return []int{protocolIGMP}, true, nil
	case "ipv4", "ip-in-ip":
		return []int{protocolIPv4}, true, nil
	case "tcp":
		return []int{protocolTCP}, false, nil
	case "egp":
		return []int{protocolEGP}, true, nil
	case "igp":
		return []int{protocolIGP}, true, nil
	case "udp":
		return []int{protocolUDP}, false, nil
	case "gre":
		return []int{protocolGRE}, true, nil
	case "esp":
		return []int{protocolESP}, true, nil
	case "ah":
		return []int{protocolAH}, true, nil
	case "sctp":
		return []int{protocolSCTP}, false, nil
	case "icmp":
		return []int{protocolICMP, protocolIPv6ICMP}, true, nil

	default:
		protocolNumber, err := strconv.Atoi(protocol)
		if err != nil {
			return nil, false, fmt.Errorf("parsing protocol number: %w", err)
		}

		// TODO(kradalby): What is this?
		needsWildcard := protocolNumber != protocolTCP &&
			protocolNumber != protocolUDP &&
			protocolNumber != protocolSCTP

		return []int{protocolNumber}, needsWildcard, nil
	}
}
