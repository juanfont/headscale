// Package packetfilter represents immutable compiled packet policy before wire encoding.
package packetfilter

import (
	"iter"
	"maps"
	"net/netip"
	"reflect"
	"slices"

	"github.com/juanfont/headscale/hscontrol/ipset"
	"tailscale.com/tailcfg"
	"tailscale.com/tailcfg/peercap"
	"tailscale.com/types/ipproto"
	"tailscale.com/util/deephash"
)

// Kind distinguishes network access from application capability grants.
type Kind uint8

const (
	KindInvalid Kind = iota
	KindNetwork
	KindCapability
)

// Destination is one independently reducible address group and its exact ports.
type Destination struct {
	Addresses ipset.Set
	Ports     tailcfg.PortRange
}

// CapabilityGrant associates address coverage with a complete capability payload.
type CapabilityGrant struct {
	Addresses ipset.Set
	CapMap    tailcfg.PeerCapMap
}

// Rule owns its mutable inputs. Its zero value permits no traffic.
type Rule struct {
	kind           Kind
	sources        ipset.Set
	destinationSet ipset.Set
	destinations   []Destination
	protocols      []ipproto.Proto
	capGrants      []CapabilityGrant
	hash           deephash.Sum
}

var defaultProtocols = [...]ipproto.Proto{1, 6, 17, 58}

// NewNetworkRule preserves group order and duplicates, and normalizes protocols.
// Omitted protocols mean exactly ICMPv4, TCP, UDP, and ICMPv6.
func NewNetworkRule(
	sources ipset.Set,
	destinations []Destination,
	protocols []ipproto.Proto,
) Rule {
	if len(protocols) == 0 {
		protocols = defaultProtocols[:]
	}

	protocols = slices.Clone(protocols)
	slices.Sort(protocols)
	protocols = slices.Compact(protocols)

	var union ipset.Builder
	for _, destination := range destinations {
		union.AddSet(destination.Addresses)
	}
	// Sets contain only validated prefixes, so this build cannot fail.
	destinationSet, _ := union.Build()
	rule := Rule{
		kind:           KindNetwork,
		sources:        sources,
		destinationSet: destinationSet,
		destinations:   slices.Clone(destinations),
		protocols:      protocols,
	}
	rule.hash = rule.contentHash()

	return rule
}

// NewCapabilityRule takes ownership of copies of every grant's mutable payload.
func NewCapabilityRule(sources ipset.Set, grants []CapabilityGrant) Rule {
	var union ipset.Builder
	for _, grant := range grants {
		union.AddSet(grant.Addresses)
	}
	// Sets contain only validated prefixes, so this build cannot fail.
	destinationSet, _ := union.Build()
	rule := Rule{
		kind:           KindCapability,
		sources:        sources,
		destinationSet: destinationSet,
		capGrants:      cloneCapGrants(grants),
	}
	rule.hash = rule.contentHash()

	return rule
}

func (r Rule) Kind() Kind                { return r.kind }
func (r Rule) Sources() ipset.Set        { return r.sources }
func (r Rule) DestinationSet() ipset.Set { return r.destinationSet }
func (r Rule) Hash() deephash.Sum        { return r.hash }

func (r Rule) Destinations() iter.Seq[Destination] { return slices.Values(r.destinations) }
func (r Rule) Protocols() iter.Seq[ipproto.Proto]  { return slices.Values(r.protocols) }

// CapGrants returns independent maps and value slices. RawMessage is an immutable string.
func (r Rule) CapGrants() []CapabilityGrant { return cloneCapGrants(r.capGrants) }

func cloneCapGrants(grants []CapabilityGrant) []CapabilityGrant {
	cloned := slices.Clone(grants)
	for i := range cloned {
		cloned[i].CapMap = cloneCapMap(cloned[i].CapMap)
	}

	return cloned
}

func cloneCapMap(capMap tailcfg.PeerCapMap) tailcfg.PeerCapMap {
	cloned := maps.Clone(capMap)
	for capability, values := range cloned {
		cloned[capability] = slices.Clone(values)
	}

	return cloned
}

// Equal confirms typed contents, including ordered duplicates and complete payloads.
// A matching cached hash alone never establishes equality.
func (r Rule) Equal(other Rule) bool {
	if r.kind != other.kind || !r.sources.Equal(other.sources) ||
		!slices.Equal(r.protocols, other.protocols) ||
		len(r.destinations) != len(other.destinations) ||
		len(r.capGrants) != len(other.capGrants) {
		return false
	}

	for i, destination := range r.destinations {
		if destination.Ports != other.destinations[i].Ports ||
			!destination.Addresses.Equal(other.destinations[i].Addresses) {
			return false
		}
	}

	for i, grant := range r.capGrants {
		if !grant.Addresses.Equal(other.capGrants[i].Addresses) ||
			!reflect.DeepEqual(grant.CapMap, other.capGrants[i].CapMap) {
			return false
		}
	}

	return true
}

func (r Rule) contentHash() deephash.Sum {
	type destination struct {
		Addresses []netip.Prefix
		Ports     tailcfg.PortRange
	}

	type capability struct {
		Key    peercap.Cap
		Values []tailcfg.RawMessage
	}

	type grant struct {
		Addresses []netip.Prefix
		NilMap    bool
		Payload   []capability
	}

	projection := struct {
		Kind         Kind
		Sources      []netip.Prefix
		Protocols    []ipproto.Proto
		Destinations []destination
		Grants       []grant
	}{
		Kind:         r.kind,
		Sources:      slices.Collect(r.sources.Prefixes()),
		Protocols:    r.protocols,
		Destinations: make([]destination, len(r.destinations)),
		Grants:       make([]grant, len(r.capGrants)),
	}
	for i, dest := range r.destinations {
		projection.Destinations[i] = destination{
			Addresses: slices.Collect(dest.Addresses.Prefixes()),
			Ports:     dest.Ports,
		}
	}

	for i, capGrant := range r.capGrants {
		payload := make([]capability, 0, len(capGrant.CapMap))
		for _, key := range slices.Sorted(maps.Keys(capGrant.CapMap)) {
			payload = append(
				payload,
				capability{Key: key, Values: capGrant.CapMap[key]},
			)
		}

		projection.Grants[i] = grant{
			Addresses: slices.Collect(capGrant.Addresses.Prefixes()),
			NilMap:    capGrant.CapMap == nil,
			Payload:   payload,
		}
	}

	return deephash.Hash(&projection)
}
