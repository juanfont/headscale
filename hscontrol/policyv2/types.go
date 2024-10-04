package policyv2

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/rs/zerolog/log"
	"tailscale.com/tailcfg"
)

// Username is a string that represents a username, it must contain an @.
type Username string

func (u Username) Valid() bool {
	return strings.Contains(string(u), "@")
}

func (u Username) UnmarshalJSON(b []byte) error {
	u = Username(strings.Trim(string(b), `"`))
	if !u.Valid() {
		return fmt.Errorf("invalid username %q", u)
	}
	return nil
}

// Group is a special string which is always prefixed with `group:`
type Group string

func (g Group) Valid() bool {
	return strings.HasPrefix(string(g), "group:")
}

func (g Group) UnmarshalJSON(b []byte) error {
	g = Group(strings.Trim(string(b), `"`))
	if !g.Valid() {
		return fmt.Errorf("invalid group %q", g)
	}
	return nil
}

// Tag is a special string which is always prefixed with `tag:`
type Tag string

func (t Tag) Valid() bool {
	return strings.HasPrefix(string(t), "tag:")
}

func (t Tag) UnmarshalJSON(b []byte) error {
	t = Tag(strings.Trim(string(b), `"`))
	if !t.Valid() {
		return fmt.Errorf("invalid tag %q", t)
	}
	return nil
}

// Host is a string that represents a hostname.
type Host string

func (h Host) Valid() bool {
	return true
}

func (h Host) UnmarshalJSON(b []byte) error {
	h = Host(strings.Trim(string(b), `"`))
	if !h.Valid() {
		return fmt.Errorf("invalid host %q", h)
	}
	return nil
}

type Addr netip.Addr

func (a Addr) Valid() bool {
	return netip.Addr(a).IsValid()
}

func (a Addr) UnmarshalJSON(b []byte) error {
	a = Addr(netip.Addr{})
	if err := json.Unmarshal(b, (netip.Addr)(a)); err != nil {
		return err
	}
	if !a.Valid() {
		return fmt.Errorf("invalid address %v", a)
	}
	return nil
}

type Prefix netip.Prefix

func (p Prefix) Valid() bool {
	return netip.Prefix(p).IsValid()
}

func (p Prefix) UnmarshalJSON(b []byte) error {
	p = Prefix(netip.Prefix{})
	if err := json.Unmarshal(b, (netip.Prefix)(p)); err != nil {
		return err
	}
	if !p.Valid() {
		return fmt.Errorf("invalid prefix %v", p)
	}
	return nil
}

// AutoGroup is a special string which is always prefixed with `autogroup:`
type AutoGroup string

func (ag AutoGroup) Valid() bool {
	return strings.HasPrefix(string(ag), "autogroup:")
}

func (ag AutoGroup) UnmarshalJSON(b []byte) error {
	ag = AutoGroup(strings.Trim(string(b), `"`))
	if !ag.Valid() {
		return fmt.Errorf("invalid autogroup %q", ag)
	}
	return nil
}

type Alias interface {
	Valid() bool
	UnmarshalJSON([]byte) error
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

	default:
		return fmt.Errorf("type %T not supported", vs)
	}
	return nil
}

func parseAlias(vs string) Alias {
	// case netip.Addr:
	// 	ve.Alias = Addr(val)
	// case netip.Prefix:
	// 	ve.Alias = Prefix(val)
	if addr, err := netip.ParseAddr(vs); err == nil {
		return Addr(addr)
	}

	if prefix, err := netip.ParsePrefix(vs); err == nil {
		return Prefix(prefix)
	}

	switch {
	case strings.Contains(vs, "@"):
		return Username(vs)
	case strings.HasPrefix(vs, "group:"):
		return Group(vs)
	case strings.HasPrefix(vs, "tag:"):
		return Tag(vs)
	case strings.HasPrefix(vs, "autogroup:"):
		return AutoGroup(vs)
	}
	return Host(vs)
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

// UserEntity is an interface that represents something that can
// return a list of users:
// - Username
// - Group
// - AutoGroup
type UserEntity interface {
	Users() []Username
	UnmarshalJSON([]byte) error
}

// Groups are a map of Group to a list of Username.
type Groups map[Group][]Username

// Hosts are alias for IP addresses or subnets.
type Hosts map[Host]netip.Prefix

// TagOwners are a map of Tag to a list of the UserEntities that own the tag.
type TagOwners map[Tag][]UserEntity

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

// ACLPolicy represents a Tailscale ACL Policy.
type ACLPolicy struct {
	Groups Groups `json:"groups"`
	// Hosts         Hosts         `json:"hosts"`
	TagOwners     TagOwners     `json:"tagOwners"`
	ACLs          []ACL         `json:"acls"`
	AutoApprovers AutoApprovers `json:"autoApprovers"`
	// SSHs          []SSH         `json:"ssh"`
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
		log.Trace().Msgf("parsing portstring: %s", portStr)
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
