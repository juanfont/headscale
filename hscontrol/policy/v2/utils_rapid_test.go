package v2

import (
	"fmt"
	"strings"
	"testing"

	"pgregory.net/rapid"
	"tailscale.com/tailcfg"
)

// ============================================================================
// Generators
// ============================================================================

// genValidDest generates a simple destination hostname-like string
// that contains no colons, so dest:port splitting is unambiguous.
func genValidDest() *rapid.Generator[string] {
	return rapid.StringMatching(`[a-z][a-z0-9.\-]{0,20}`)
}

// genValidPortNum generates a port number in [1, 65535].
func genValidPortNum() *rapid.Generator[uint16] {
	return rapid.Uint16Range(1, 65535)
}

// genValidPortStr generates a string representation of a valid port.
func genValidPortStr() *rapid.Generator[string] {
	return rapid.Custom[string](func(t *rapid.T) string {
		port := genValidPortNum().Draw(t, "port")
		return fmt.Sprintf("%d", port)
	})
}

// genPortRange generates a valid "first-last" port range string where first <= last.
func genPortRange() *rapid.Generator[string] {
	return rapid.Custom[string](func(t *rapid.T) string {
		first := genValidPortNum().Draw(t, "first")
		last := genValidPortNum().Draw(t, "last")
		if first > last {
			first, last = last, first
		}
		return fmt.Sprintf("%d-%d", first, last)
	})
}

// genIPv6Addr generates a valid IPv6 address string from a curated set.
// Using StringMatching(`[0-9a-f:]{2,39}`) would almost never produce
// a valid IPv6 address, so we sample from known-good values instead.
func genIPv6Addr() *rapid.Generator[string] {
	return rapid.SampledFrom([]string{
		"::1",
		"fd7a:115c:a1e0::1",
		"2001:db8::1",
		"fe80::1",
		"::ffff:c0a8:0101",
		"2001:0db8:85a3:0000:0000:8a2e:0370:7334",
		"::",
	})
}

// ============================================================================
// splitDestinationAndPort properties
// ============================================================================

// TestRapid_SplitDestinationAndPort_Roundtrip verifies that for any valid
// (dest, port) pair, split(dest + ":" + port) returns (dest, port).
func TestRapid_SplitDestinationAndPort_Roundtrip(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		dest := genValidDest().Draw(t, "dest")
		port := genValidPortStr().Draw(t, "port")

		input := dest + ":" + port

		gotDest, gotPort, err := splitDestinationAndPort(input)
		if err != nil {
			t.Fatalf("splitDestinationAndPort(%q) unexpected error: %v", input, err)
		}

		if gotDest != dest {
			t.Fatalf("dest mismatch: got %q, want %q (input=%q)", gotDest, dest, input)
		}
		if gotPort != port {
			t.Fatalf("port mismatch: got %q, want %q (input=%q)", gotPort, port, input)
		}
	})
}

// TestRapid_SplitDestinationAndPort_BracketedIPv6 verifies that
// [addr]:port is correctly split into (addr, port).
func TestRapid_SplitDestinationAndPort_BracketedIPv6(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		addr := genIPv6Addr().Draw(t, "addr")
		port := genValidPortStr().Draw(t, "port")

		input := "[" + addr + "]:" + port

		gotDest, gotPort, err := splitDestinationAndPort(input)
		if err != nil {
			t.Fatalf("splitDestinationAndPort(%q) unexpected error: %v", input, err)
		}

		if gotDest != addr {
			t.Fatalf("dest mismatch for bracketed IPv6: got %q, want %q (input=%q)",
				gotDest, addr, input)
		}
		if gotPort != port {
			t.Fatalf("port mismatch for bracketed IPv6: got %q, want %q (input=%q)",
				gotPort, port, input)
		}
	})
}

// TestRapid_SplitDestinationAndPort_MissingColon verifies that inputs
// without a colon always produce an error.
func TestRapid_SplitDestinationAndPort_MissingColon(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		// Generate strings that cannot contain colons.
		input := rapid.StringMatching(`[a-z0-9./]{1,30}`).Draw(t, "input")

		_, _, err := splitDestinationAndPort(input)
		if err == nil {
			t.Fatalf("splitDestinationAndPort(%q) should fail (no colon), but got nil error", input)
		}
	})
}

// TestRapid_SplitDestinationAndPort_EmptyParts verifies that an empty
// destination (starts with colon) or empty port (ends with colon) returns an error.
func TestRapid_SplitDestinationAndPort_EmptyParts(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		filler := rapid.StringMatching(`[a-z0-9]{1,20}`).Draw(t, "filler")
		// Pick which side is empty: 0 = empty dest, 1 = empty port.
		side := rapid.IntRange(0, 1).Draw(t, "side")

		var input string
		if side == 0 {
			input = ":" + filler // empty destination
		} else {
			input = filler + ":" // empty port
		}

		_, _, err := splitDestinationAndPort(input)
		if err == nil {
			t.Fatalf("splitDestinationAndPort(%q) should fail (empty part), but got nil error", input)
		}
	})
}

// ============================================================================
// parsePortRange properties
// ============================================================================

// TestRapid_ParsePortRange_WildcardIsAny verifies that "*" always
// returns exactly one PortRange equal to PortRangeAny {0, 65535}.
func TestRapid_ParsePortRange_WildcardIsAny(t *testing.T) {
	// This is a constant-input property; rapid.Check still exercises
	// the property multiple times to confirm determinism.
	rapid.Check(t, func(t *rapid.T) {
		result, err := parsePortRange("*")
		if err != nil {
			t.Fatalf("parsePortRange(\"*\") unexpected error: %v", err)
		}
		if len(result) != 1 {
			t.Fatalf("parsePortRange(\"*\") returned %d ranges, want 1", len(result))
		}
		if result[0] != tailcfg.PortRangeAny {
			t.Fatalf("parsePortRange(\"*\") = %v, want PortRangeAny(%v)", result[0], tailcfg.PortRangeAny)
		}
	})
}

// TestRapid_ParsePortRange_SinglePortFirstEqLast verifies that parsing
// a single port number produces a PortRange where First == Last.
func TestRapid_ParsePortRange_SinglePortFirstEqLast(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		port := genValidPortNum().Draw(t, "port")
		portStr := fmt.Sprintf("%d", port)

		result, err := parsePortRange(portStr)
		if err != nil {
			t.Fatalf("parsePortRange(%q) unexpected error: %v", portStr, err)
		}
		if len(result) != 1 {
			t.Fatalf("parsePortRange(%q) returned %d ranges, want 1", portStr, len(result))
		}
		if result[0].First != port || result[0].Last != port {
			t.Fatalf("parsePortRange(%q) = {First:%d, Last:%d}, want {First:%d, Last:%d}",
				portStr, result[0].First, result[0].Last, port, port)
		}
	})
}

// TestRapid_ParsePortRange_RangeFirstLELast verifies that for any valid
// port range string, every returned PortRange has First <= Last.
func TestRapid_ParsePortRange_RangeFirstLELast(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		rangeStr := genPortRange().Draw(t, "range")

		result, err := parsePortRange(rangeStr)
		if err != nil {
			t.Fatalf("parsePortRange(%q) unexpected error: %v", rangeStr, err)
		}
		for i, pr := range result {
			if pr.First > pr.Last {
				t.Fatalf("parsePortRange(%q)[%d] inverted range: First=%d > Last=%d",
					rangeStr, i, pr.First, pr.Last)
			}
		}
	})
}

// TestRapid_ParsePortRange_CommaSeparated verifies that N comma-separated
// ports produce exactly N PortRanges, each matching the input port.
func TestRapid_ParsePortRange_CommaSeparated(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		nPorts := rapid.IntRange(1, 5).Draw(t, "nPorts")
		ports := make([]uint16, nPorts)
		portStrs := make([]string, nPorts)
		for i := range nPorts {
			ports[i] = genValidPortNum().Draw(t, fmt.Sprintf("port_%d", i))
			portStrs[i] = fmt.Sprintf("%d", ports[i])
		}
		input := strings.Join(portStrs, ",")

		result, err := parsePortRange(input)
		if err != nil {
			t.Fatalf("parsePortRange(%q) unexpected error: %v", input, err)
		}

		if len(result) != nPorts {
			t.Fatalf("parsePortRange(%q) returned %d ranges, want %d",
				input, len(result), nPorts)
		}

		for i, pr := range result {
			if pr.First != ports[i] || pr.Last != ports[i] {
				t.Fatalf("parsePortRange(%q)[%d] = {First:%d, Last:%d}, want {First:%d, Last:%d}",
					input, i, pr.First, pr.Last, ports[i], ports[i])
			}
		}
	})
}

// TestRapid_ParsePortRange_InvertedRangeError verifies that a port range
// where first > last always produces an error.
func TestRapid_ParsePortRange_InvertedRangeError(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		first := rapid.Uint16Range(2, 65535).Draw(t, "first")
		last := rapid.Uint16Range(1, first-1).Draw(t, "last")
		input := fmt.Sprintf("%d-%d", first, last)

		_, err := parsePortRange(input)
		if err == nil {
			t.Fatalf("parsePortRange(%q) should fail (inverted range %d > %d), but got nil error",
				input, first, last)
		}
	})
}

// ============================================================================
// parsePort properties
// ============================================================================

// TestRapid_ParsePort_ValidRoundtrip verifies that converting a uint16
// to a string and parsing it back yields the original value.
func TestRapid_ParsePort_ValidRoundtrip(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		port := rapid.Uint16().Draw(t, "port")
		portStr := fmt.Sprintf("%d", port)

		result, err := parsePort(portStr)
		if err != nil {
			t.Fatalf("parsePort(%q) unexpected error: %v", portStr, err)
		}
		if result != port {
			t.Fatalf("parsePort(%q) = %d, want %d", portStr, result, port)
		}
	})
}

// TestRapid_ParsePort_RejectsNegative verifies that negative number
// strings are always rejected.
func TestRapid_ParsePort_RejectsNegative(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		neg := rapid.IntRange(-65535, -1).Draw(t, "neg")
		input := fmt.Sprintf("%d", neg)

		_, err := parsePort(input)
		if err == nil {
			t.Fatalf("parsePort(%q) should fail (negative), but got nil error", input)
		}
	})
}

// TestRapid_ParsePort_RejectsOverflow verifies that numbers greater
// than 65535 are always rejected.
func TestRapid_ParsePort_RejectsOverflow(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		over := rapid.IntRange(65536, 100000).Draw(t, "over")
		input := fmt.Sprintf("%d", over)

		_, err := parsePort(input)
		if err == nil {
			t.Fatalf("parsePort(%q) should fail (overflow > 65535), but got nil error", input)
		}
	})
}
