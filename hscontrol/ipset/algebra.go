package ipset

import (
	"iter"
	"net/netip"

	"github.com/gaissmai/extnetip"
	"github.com/gaissmai/iprange"
)

// Union returns all addresses belonging to either set.
func (s Set) Union(other Set) Set {
	if s.IsEmpty() {
		return other
	}

	if other.IsEmpty() || s == other {
		return s
	}

	var b Builder
	b.AddSet(s)
	b.AddSet(other)
	result, _ := b.Build() // Published Sets contain only validated prefixes.

	return result
}

// Intersect returns addresses belonging to both sets.
func (s Set) Intersect(other Set) Set {
	if s.IsEmpty() || other.IsEmpty() {
		return Set{}
	}

	if s == other {
		return s
	}

	if other.multi == nil || (s.multi != nil && other.multi.Size() < s.multi.Size()) {
		s, other = other, s
	}

	var b Builder

	for prefix := range s.Prefixes() {
		if other.ContainsPrefix(prefix) {
			b.AddPrefix(prefix)
			continue
		}

		for subnet := range other.subnets(prefix) {
			b.AddPrefix(subnet)
		}
	}

	result, _ := b.Build()

	return result
}

// Subtract returns addresses in s that do not belong to other.
func (s Set) Subtract(other Set) Set {
	if s.IsEmpty() || other.IsEmpty() {
		return s
	}

	if s == other {
		return Set{}
	}

	var (
		b          Builder
		exclusions []iprange.IPRange
	)

	for prefix := range s.Prefixes() {
		if other.ContainsPrefix(prefix) {
			continue
		}

		exclusions = exclusions[:0]
		// Restrict Remove's sorting/merging to this prefix's actual exclusions.
		for subnet := range other.subnets(prefix) {
			r, _ := iprange.FromAddrs(extnetip.Range(subnet))
			exclusions = append(exclusions, r)
		}

		if len(exclusions) == 0 {
			b.AddPrefix(prefix)
			continue
		}

		r, _ := iprange.FromAddrs(extnetip.Range(prefix))
		for _, remaining := range r.Remove(exclusions) {
			b.AddRange(remaining)
		}
	}

	result, _ := b.Build()

	return result
}

// subnets yields stored prefixes contained within prefix, excluding supernets.
func (s Set) subnets(prefix netip.Prefix) iter.Seq[netip.Prefix] {
	return func(yield func(netip.Prefix) bool) {
		if s.multi != nil {
			s.multi.Subnets(prefix)(yield)
		} else if s.single.IsValid() && prefix.Bits() <= s.single.Bits() &&
			prefix.Contains(s.single.Addr()) {
			yield(s.single)
		}
	}
}
