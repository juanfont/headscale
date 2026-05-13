package types

import "net/netip"

// The named slice types below are used for GORM-persisted Node columns
// that serialise as JSON. GORM v2's struct-based Updates skips fields
// it considers zero — for unnamed slice types that is nil — and the
// default reflect.Value.IsZero treats a nil slice as zero. By giving
// each slice an IsZero() that always returns false, the column is
// always included in UPDATE statements regardless of whether the
// caller is clearing the field. JSON marshalling is unchanged: a nil
// value serialises to null and an empty value serialises to [].
//
// The .List() helpers return the underlying unnamed slice for the
// places (mainly testify assertions over reflect.DeepEqual) where the
// distinction between the named and unnamed type matters.

// Strings is a []string with a GORM-friendly IsZero.
type Strings []string

// IsZero implements GORM's zeroer interface to keep the column in the
// UPDATE set even when the slice is nil or empty.
func (Strings) IsZero() bool { return false }

// List returns the underlying []string.
func (s Strings) List() []string { return []string(s) }

// Prefixes is a []netip.Prefix with a GORM-friendly IsZero.
type Prefixes []netip.Prefix

// IsZero implements GORM's zeroer interface to keep the column in the
// UPDATE set even when the slice is nil or empty.
func (Prefixes) IsZero() bool { return false }

// List returns the underlying []netip.Prefix.
func (s Prefixes) List() []netip.Prefix { return []netip.Prefix(s) }

// AddrPorts is a []netip.AddrPort with a GORM-friendly IsZero.
type AddrPorts []netip.AddrPort

// IsZero implements GORM's zeroer interface to keep the column in the
// UPDATE set even when the slice is nil or empty.
func (AddrPorts) IsZero() bool { return false }

// List returns the underlying []netip.AddrPort.
func (s AddrPorts) List() []netip.AddrPort { return []netip.AddrPort(s) }
