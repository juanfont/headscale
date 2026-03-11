package v2

import (
	"errors"
	"testing"

	"github.com/google/go-cmp/cmp"
	"tailscale.com/tailcfg"
)

// TestParseDestinationAndPort tests the splitDestinationAndPort function using table-driven tests.
func TestParseDestinationAndPort(t *testing.T) {
	testCases := []struct {
		input       string
		wantDst     string
		wantPort    string
		wantErrIs   error
		wantNoError bool
	}{
		// --- Non-bracketed inputs (existing behavior, unchanged) ---

		// Hostnames and tags
		{"git-server:*", "git-server", "*", nil, true},
		{"example-host-1:*", "example-host-1", "*", nil, true},
		{"hostname:80-90", "hostname", "80-90", nil, true},
		{"tag:montreal-webserver:80,443", "tag:montreal-webserver", "80,443", nil, true},
		{"tag:api-server:443", "tag:api-server", "443", nil, true},

		// IPv4 and IPv4 CIDR
		{"192.168.1.0/24:22", "192.168.1.0/24", "22", nil, true},
		{"10.0.0.1:443", "10.0.0.1", "443", nil, true},

		// Bare IPv6 (no brackets) — last colon splits correctly
		{"fd7a:115c:a1e0::2:22", "fd7a:115c:a1e0::2", "22", nil, true},
		{"fd7a:115c:a1e0::2/128:22", "fd7a:115c:a1e0::2/128", "22", nil, true},

		// --- Bracketed IPv6: [addr]:port ---

		// Single port
		{"[fd7a:115c:a1e0::87e1]:22", "fd7a:115c:a1e0::87e1", "22", nil, true},
		{"[::1]:80", "::1", "80", nil, true},
		{"[2001:db8::1]:443", "2001:db8::1", "443", nil, true},
		{"[fe80::1]:22", "fe80::1", "22", nil, true},

		// Multiple ports
		{"[fd7a:115c:a1e0::87e1]:80,443", "fd7a:115c:a1e0::87e1", "80,443", nil, true},
		{"[::1]:22,80,443", "::1", "22,80,443", nil, true},

		// Port range
		{"[fd7a:115c:a1e0::2]:80-90", "fd7a:115c:a1e0::2", "80-90", nil, true},

		// Wildcard port
		{"[fd7a:115c:a1e0::87e1]:*", "fd7a:115c:a1e0::87e1", "*", nil, true},

		// Unspecified address [::]
		{"[::]:80", "::", "80", nil, true},
		{"[::]:*", "::", "*", nil, true},

		// Full-length IPv6
		{"[2001:0db8:85a3:0000:0000:8a2e:0370:7334]:443", "2001:0db8:85a3:0000:0000:8a2e:0370:7334", "443", nil, true},

		// --- Bracketed IPv6 CIDR: [addr]/prefix:port ---

		{"[fd7a:115c:a1e0::2905]/128:80,443", "fd7a:115c:a1e0::2905/128", "80,443", nil, true},
		{"[fd7a:115c:a1e0::1]/128:22", "fd7a:115c:a1e0::1/128", "22", nil, true},
		{"[2001:db8::1]/32:443", "2001:db8::1/32", "443", nil, true},
		{"[::1]/128:*", "::1/128", "*", nil, true},
		{"[fd7a:115c:a1e0::2]/64:80-90", "fd7a:115c:a1e0::2/64", "80-90", nil, true},
		{"[::]/0:*", "::/0", "*", nil, true},

		// --- Errors: brackets around non-IPv6 ---

		// IPv4 in brackets
		{"[192.168.1.1]:80", "", "", ErrBracketsNotIPv6, false},
		{"[10.0.0.1]:443", "", "", ErrBracketsNotIPv6, false},
		{"[192.168.1.1]/32:80", "", "", ErrBracketsNotIPv6, false},

		// IPv4 CIDR inside brackets
		{"[10.0.0.0/8]:80", "", "", ErrBracketsNotIPv6, false},

		// Hostnames in brackets
		{"[my-hostname]:80", "", "", ErrBracketsNotIPv6, false},
		{"[git-server]:*", "", "", ErrBracketsNotIPv6, false},

		// Tags in brackets
		{"[tag:server]:80", "", "", ErrBracketsNotIPv6, false},

		// --- Errors: CIDR inside brackets (must use [addr]/prefix:port) ---

		{"[fd7a:115c:a1e0::2/128]:22", "", "", ErrBracketsNotIPv6, false},
		{"[2001:db8::/32]:443", "", "", ErrBracketsNotIPv6, false},
		{"[::1/128]:80", "", "", ErrBracketsNotIPv6, false},

		// --- Errors: malformed bracket syntax ---

		// No port after brackets
		{"[::1]", "", "", ErrBracketsNotIPv6, false},
		{"[2001:db8::1]", "", "", ErrBracketsNotIPv6, false},

		// Empty brackets
		{"[]:80", "", "", ErrBracketsNotIPv6, false},

		// Missing close bracket
		{"[::1", "", "", ErrBracketsNotIPv6, false},
		{"[2001:db8::1:80", "", "", ErrBracketsNotIPv6, false},

		// Empty port after colon
		{"[fd7a:115c:a1e0::1]:", "", "", ErrInputEndsWithColon, false},
		{"[::1]:", "", "", ErrInputEndsWithColon, false},
		{"[fd7a::1]/128:", "", "", ErrInputEndsWithColon, false},

		// Junk after close bracket (not : or /)
		{"[::1]blah", "", "", ErrBracketsNotIPv6, false},
		{"[::1] :80", "", "", ErrBracketsNotIPv6, false},

		// --- Errors: non-bracketed malformed input (unchanged) ---

		{"invalidinput", "", "", ErrInputMissingColon, false},
		{":invalid", "", "", ErrInputStartsWithColon, false},
		{"invalid:", "", "", ErrInputEndsWithColon, false},
	}

	for _, tc := range testCases {
		t.Run(tc.input, func(t *testing.T) {
			dst, port, err := splitDestinationAndPort(tc.input)

			if tc.wantNoError {
				if err != nil {
					t.Fatalf("splitDestinationAndPort(%q) unexpected error: %v", tc.input, err)
				}

				if dst != tc.wantDst {
					t.Errorf("splitDestinationAndPort(%q) dst = %q, want %q", tc.input, dst, tc.wantDst)
				}

				if port != tc.wantPort {
					t.Errorf("splitDestinationAndPort(%q) port = %q, want %q", tc.input, port, tc.wantPort)
				}

				return
			}

			if err == nil {
				t.Fatalf("splitDestinationAndPort(%q) = (%q, %q, nil), want error wrapping %v", tc.input, dst, port, tc.wantErrIs)
			}

			if !errors.Is(err, tc.wantErrIs) {
				t.Errorf("splitDestinationAndPort(%q) error = %v, want error wrapping %v", tc.input, err, tc.wantErrIs)
			}
		})
	}
}

func TestParsePort(t *testing.T) {
	tests := []struct {
		input    string
		expected uint16
		err      string
	}{
		{"80", 80, ""},
		{"0", 0, ""},
		{"65535", 65535, ""},
		{"-1", 0, "port number out of range"},
		{"65536", 0, "port number out of range"},
		{"abc", 0, "invalid port number"},
		{"", 0, "invalid port number"},
	}

	for _, test := range tests {
		result, err := parsePort(test.input)
		if err != nil && err.Error() != test.err {
			t.Errorf("parsePort(%q) error = %v, expected error = %v", test.input, err, test.err)
		}

		if err == nil && test.err != "" {
			t.Errorf("parsePort(%q) expected error = %v, got nil", test.input, test.err)
		}

		if result != test.expected {
			t.Errorf("parsePort(%q) = %v, expected %v", test.input, result, test.expected)
		}
	}
}

func TestParsePortRange(t *testing.T) {
	tests := []struct {
		input    string
		expected []tailcfg.PortRange
		err      string
	}{
		{"80", []tailcfg.PortRange{{First: 80, Last: 80}}, ""},
		{"80-90", []tailcfg.PortRange{{First: 80, Last: 90}}, ""},
		{"80,90", []tailcfg.PortRange{{First: 80, Last: 80}, {First: 90, Last: 90}}, ""},
		{"80-91,92,93-95", []tailcfg.PortRange{{First: 80, Last: 91}, {First: 92, Last: 92}, {First: 93, Last: 95}}, ""},
		{"*", []tailcfg.PortRange{tailcfg.PortRangeAny}, ""},
		{"80-", nil, "invalid port range format"},
		{"-90", nil, "invalid port range format"},
		{"80-90,", nil, "invalid port number"},
		{"80,90-", nil, "invalid port range format"},
		{"80-90,abc", nil, "invalid port number"},
		{"80-90,65536", nil, "port number out of range"},
		{"80-90,90-80", nil, "invalid port range: first port is greater than last port"},
	}

	for _, test := range tests {
		result, err := parsePortRange(test.input)
		if err != nil && err.Error() != test.err {
			t.Errorf("parsePortRange(%q) error = %v, expected error = %v", test.input, err, test.err)
		}

		if err == nil && test.err != "" {
			t.Errorf("parsePortRange(%q) expected error = %v, got nil", test.input, test.err)
		}

		if diff := cmp.Diff(result, test.expected); diff != "" {
			t.Errorf("parsePortRange(%q) mismatch (-want +got):\n%s", test.input, diff)
		}
	}
}
