// Package ipset provides immutable unions of IP addresses.
package ipset

import (
	"errors"
	"iter"
	"net/netip"

	"github.com/gaissmai/bart"
	"github.com/gaissmai/extnetip"
	"github.com/gaissmai/iprange"
)

var (
	errInvalidAddress = errors.New("ipset: invalid address")
	errInvalidPrefix  = errors.New("ipset: invalid prefix")
	errInvalidRange   = errors.New("ipset: invalid range")
)

// Set is an immutable address union. Its zero value is empty and copies share
// read-only storage. IPv4 and IPv4-mapped IPv6 addresses remain distinct.
type Set struct {
	single netip.Prefix
	multi  *bart.Lite
}

// Builder accumulates an address union. The zero value is ready to use.
// A Builder must not be copied after first use or used concurrently.
type Builder struct {
	set Set
	err error
}

// AddAddr adds addr, stripping its zone to preserve address-union construction
// semantics. Membership queries, in contrast, reject zoned addresses.
func (b *Builder) AddAddr(addr netip.Addr) {
	if b.err != nil {
		return
	}

	if !addr.IsValid() {
		b.err = errInvalidAddress
		return
	}

	b.AddPrefix(netip.PrefixFrom(addr.WithZone(""), addr.BitLen()))
}

// AddPrefix adds the complete prefix, masking any host bits.
func (b *Builder) AddPrefix(prefix netip.Prefix) {
	if b.err != nil {
		return
	}

	if !prefix.IsValid() {
		b.err = errInvalidPrefix
		return
	}

	prefix = prefix.Masked()
	if b.set.multi != nil {
		b.set.multi.Insert(prefix)
		return
	}

	if !b.set.single.IsValid() {
		b.set.single = prefix
		return
	}

	if b.set.ContainsPrefix(prefix) {
		return
	}

	if prefix.Bits() <= b.set.single.Bits() && prefix.Contains(b.set.single.Addr()) {
		b.set.single = prefix
		return
	}

	table := new(bart.Lite)
	table.Insert(b.set.single)
	table.Insert(prefix)
	b.set = Set{multi: table}
}

// AddRange adds every address in the inclusive range.
func (b *Builder) AddRange(r iprange.IPRange) {
	if b.err != nil {
		return
	}

	if !r.IsValid() {
		b.err = errInvalidRange
		return
	}

	for prefix := range r.Prefixes() {
		b.AddPrefix(prefix)
	}
}

// AddSet adds s without taking mutable ownership of its storage.
func (b *Builder) AddSet(s Set) {
	if b.err != nil || s.IsEmpty() {
		return
	}

	if s.multi == nil {
		b.AddPrefix(s.single)
		return
	}

	if b.set.multi != nil {
		// Mutable Union clones incoming branches; UnionPersist would share them.
		b.set.multi.Union(s.multi)
		return
	}

	table := s.multi.Clone()
	if b.set.single.IsValid() {
		table.Insert(b.set.single)
	}

	b.set = Set{multi: table}
}

// Build publishes a minimal CIDR cover and resets the builder, including after
// an error. Invalid input returns an empty Set and never publishes partial data.
func (b *Builder) Build() (Set, error) {
	s, err := b.set, b.err
	*b = Builder{}

	if err != nil {
		return Set{}, err
	}

	if s.multi != nil {
		// Only constructor-owned tables may be aggregated in place.
		s.multi.Aggregate()

		if s.multi.Size() == 1 {
			for prefix := range s.multi.All() {
				return Set{single: prefix}, nil
			}
		}
	}

	return s, nil
}

var all = func() Set {
	var b Builder
	b.AddPrefix(netip.PrefixFrom(netip.IPv4Unspecified(), 0))
	b.AddPrefix(netip.PrefixFrom(netip.IPv6Unspecified(), 0))
	s, _ := b.Build()

	return s
}()

// All returns the union of all IPv4 and IPv6 addresses.
func All() Set { return all }

// IsEmpty reports whether s contains no addresses.
func (s Set) IsEmpty() bool { return !s.single.IsValid() && s.multi == nil }

// Contains reports whether s contains addr. Invalid or zoned addresses do not match.
func (s Set) Contains(addr netip.Addr) bool {
	if !addr.IsValid() || addr.Zone() != "" {
		return false
	}

	if s.multi != nil {
		return s.multi.Contains(addr)
	}

	return s.single.Contains(addr)
}

// ContainsPrefix reports whether every address in prefix belongs to s.
func (s Set) ContainsPrefix(prefix netip.Prefix) bool {
	if !prefix.IsValid() {
		return false
	}

	if s.multi != nil {
		return s.multi.LookupPrefix(prefix)
	}

	return s.single.IsValid() && s.single.Bits() <= prefix.Bits() &&
		s.single.Contains(prefix.Addr())
}

// ContainsSet reports whether s covers all of other, including an empty other.
func (s Set) ContainsSet(other Set) bool {
	for prefix := range other.Prefixes() {
		if !s.ContainsPrefix(prefix) {
			return false
		}
	}

	return true
}

// OverlapsPrefix reports whether any address in prefix belongs to s.
func (s Set) OverlapsPrefix(prefix netip.Prefix) bool {
	if !prefix.IsValid() {
		return false
	}

	if s.multi != nil {
		return s.multi.OverlapsPrefix(prefix)
	}

	return s.single.Overlaps(prefix)
}

// Overlaps reports whether s and other share any addresses.
func (s Set) Overlaps(other Set) bool {
	if s.IsEmpty() || other.IsEmpty() {
		return false
	}

	if s.multi == nil {
		return other.OverlapsPrefix(s.single)
	}

	if other.multi == nil {
		return s.OverlapsPrefix(other.single)
	}

	return s.multi.Overlaps(other.multi)
}

// Equal reports whether s and other contain the same addresses.
func (s Set) Equal(other Set) bool {
	if s.multi == nil || other.multi == nil {
		return s.multi == other.multi && s.single == other.single
	}

	return s.multi == other.multi || s.multi.Equal(other.multi)
}

// Prefixes yields the minimal CIDR cover in ascending order, IPv4 before IPv6.
func (s Set) Prefixes() iter.Seq[netip.Prefix] {
	return func(yield func(netip.Prefix) bool) {
		if s.multi != nil {
			s.multi.AllSorted()(yield)
		} else if s.single.IsValid() {
			yield(s.single)
		}
	}
}

// Ranges yields coalesced inclusive intervals, IPv4 before IPv6.
func (s Set) Ranges() iter.Seq[iprange.IPRange] {
	return func(yield func(iprange.IPRange) bool) {
		var first, last netip.Addr

		for prefix := range s.Prefixes() {
			start, end := extnetip.Range(prefix)
			if first.IsValid() && last.Next() != start {
				r, _ := iprange.FromAddrs(first, last)
				if !yield(r) {
					return
				}

				first = netip.Addr{}
			}

			if !first.IsValid() {
				first = start
			}

			last = end
		}

		if first.IsValid() {
			r, _ := iprange.FromAddrs(first, last)
			yield(r)
		}
	}
}

// Addrs yields addresses in ascending family order. Enumerating a large prefix
// is expensive; callers can stop iteration without traversing the rest of s.
func (s Set) Addrs() iter.Seq[netip.Addr] {
	return func(yield func(netip.Addr) bool) {
		for r := range s.Ranges() {
			first, last := r.Addrs()
			for addr := first; ; addr = addr.Next() {
				if !yield(addr) {
					return
				}

				if addr == last {
					break
				}
			}
		}
	}
}
