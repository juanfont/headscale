package util

import (
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"tailscale.com/tailcfg"
	"tailscale.com/util/cmpver"
)

func TailscaleVersionNewerOrEqual(minimum, toCheck string) bool {
	if cmpver.Compare(minimum, toCheck) <= 0 ||
		toCheck == "unstable" ||
		toCheck == "head" {
		return true
	}

	return false
}

// ParseLoginURLFromCLILogin parses the output of the tailscale up command to extract the login URL.
// It returns an error if not exactly one URL is found.
func ParseLoginURLFromCLILogin(output string) (*url.URL, error) {
	lines := strings.Split(output, "\n")
	var urlStr string

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "http://") || strings.HasPrefix(line, "https://") {
			if urlStr != "" {
				return nil, fmt.Errorf("multiple URLs found: %s and %s", urlStr, line)
			}
			urlStr = line
		}
	}

	if urlStr == "" {
		return nil, errors.New("no URL found")
	}

	loginURL, err := url.Parse(urlStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse URL: %w", err)
	}

	return loginURL, nil
}

type TraceroutePath struct {
	// Hop is the current jump in the total traceroute.
	Hop int

	// Hostname is the resolved hostname or IP address identifying the jump
	Hostname string

	// IP is the IP address of the jump
	IP netip.Addr

	// Latencies is a list of the latencies for this jump
	Latencies []time.Duration
}

type Traceroute struct {
	// Hostname is the resolved hostname or IP address identifying the target
	Hostname string

	// IP is the IP address of the target
	IP netip.Addr

	// Route is the path taken to reach the target if successful. The list is ordered by the path taken.
	Route []TraceroutePath

	// Success indicates if the traceroute was successful.
	Success bool

	// Err contains an error if  the traceroute was not successful.
	Err error
}

// ParseTraceroute parses the output of the traceroute command and returns a Traceroute struct.
func ParseTraceroute(output string) (Traceroute, error) {
	lines := strings.Split(strings.TrimSpace(output), "\n")
	if len(lines) < 1 {
		return Traceroute{}, errors.New("empty traceroute output")
	}

	// Parse the header line - handle both 'traceroute' and 'tracert' (Windows)
	headerRegex := regexp.MustCompile(`(?i)(?:traceroute|tracing route) to ([^ ]+) (?:\[([^\]]+)\]|\(([^)]+)\))`)
	headerMatches := headerRegex.FindStringSubmatch(lines[0])
	if len(headerMatches) < 2 {
		return Traceroute{}, fmt.Errorf("parsing traceroute header: %s", lines[0])
	}

	hostname := headerMatches[1]
	// IP can be in either capture group 2 or 3 depending on format
	ipStr := headerMatches[2]
	if ipStr == "" {
		ipStr = headerMatches[3]
	}
	ip, err := netip.ParseAddr(ipStr)
	if err != nil {
		return Traceroute{}, fmt.Errorf("parsing IP address %s: %w", ipStr, err)
	}

	result := Traceroute{
		Hostname: hostname,
		IP:       ip,
		Route:    []TraceroutePath{},
		Success:  false,
	}

	// More flexible regex that handles various traceroute output formats
	// Main pattern handles: "hostname (IP)", "hostname [IP]", "IP only", "* * *"
	hopRegex := regexp.MustCompile(`^\s*(\d+)\s+(.*)$`)
	// Patterns for parsing the hop details
	hostIPRegex := regexp.MustCompile(`^([^ ]+) \(([^)]+)\)`)
	hostIPBracketRegex := regexp.MustCompile(`^([^ ]+) \[([^\]]+)\]`)
	// Pattern for latencies with flexible spacing and optional '<'
	latencyRegex := regexp.MustCompile(`(<?\d+(?:\.\d+)?)\s*ms\b`)

	for i := 1; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])
		if line == "" {
			continue
		}

		matches := hopRegex.FindStringSubmatch(line)
		if len(matches) == 0 {
			continue
		}

		hop, err := strconv.Atoi(matches[1])
		if err != nil {
			// Skip lines that don't start with a hop number
			continue
		}

		remainder := strings.TrimSpace(matches[2])
		var hopHostname string
		var hopIP netip.Addr
		var latencies []time.Duration

		// Check for Windows tracert format which has latencies before hostname
		// Format: "  1    <1 ms    <1 ms    <1 ms  router.local [192.168.1.1]"
		latencyFirst := false
		if strings.Contains(remainder, " ms ") && !strings.HasPrefix(remainder, "*") {
			// Check if latencies appear before any hostname/IP
			firstSpace := strings.Index(remainder, " ")
			if firstSpace > 0 {
				firstPart := remainder[:firstSpace]
				if _, err := strconv.ParseFloat(strings.TrimPrefix(firstPart, "<"), 64); err == nil {
					latencyFirst = true
				}
			}
		}

		if latencyFirst {
			// Windows format: extract latencies first
			for {
				latMatch := latencyRegex.FindStringSubmatchIndex(remainder)
				if latMatch == nil || latMatch[0] > 0 {
					break
				}
				// Extract and remove the latency from the beginning
				latStr := strings.TrimPrefix(remainder[latMatch[2]:latMatch[3]], "<")
				ms, err := strconv.ParseFloat(latStr, 64)
				if err == nil {
					// Round to nearest microsecond to avoid floating point precision issues
					duration := time.Duration(ms * float64(time.Millisecond))
					latencies = append(latencies, duration.Round(time.Microsecond))
				}
				remainder = strings.TrimSpace(remainder[latMatch[1]:])
			}
		}

		// Now parse hostname/IP from remainder
		if strings.HasPrefix(remainder, "*") {
			// Timeout hop
			hopHostname = "*"
			// Skip any remaining asterisks
			remainder = strings.TrimLeft(remainder, "* ")
		} else if hostMatch := hostIPRegex.FindStringSubmatch(remainder); len(hostMatch) >= 3 {
			// Format: hostname (IP)
			hopHostname = hostMatch[1]
			hopIP, _ = netip.ParseAddr(hostMatch[2])
			remainder = strings.TrimSpace(remainder[len(hostMatch[0]):])
		} else if hostMatch := hostIPBracketRegex.FindStringSubmatch(remainder); len(hostMatch) >= 3 {
			// Format: hostname [IP] (Windows)
			hopHostname = hostMatch[1]
			hopIP, _ = netip.ParseAddr(hostMatch[2])
			remainder = strings.TrimSpace(remainder[len(hostMatch[0]):])
		} else {
			// Try to parse as IP only or hostname only
			parts := strings.Fields(remainder)
			if len(parts) > 0 {
				hopHostname = parts[0]
				if ip, err := netip.ParseAddr(parts[0]); err == nil {
					hopIP = ip
				}
				remainder = strings.TrimSpace(strings.Join(parts[1:], " "))
			}
		}

		// Extract latencies from the remaining part (if not already done)
		if !latencyFirst {
			latencyMatches := latencyRegex.FindAllStringSubmatch(remainder, -1)
			for _, match := range latencyMatches {
				if len(match) > 1 {
					// Remove '<' prefix if present (e.g., "<1 ms")
					latStr := strings.TrimPrefix(match[1], "<")
					ms, err := strconv.ParseFloat(latStr, 64)
					if err == nil {
						// Round to nearest microsecond to avoid floating point precision issues
						duration := time.Duration(ms * float64(time.Millisecond))
						latencies = append(latencies, duration.Round(time.Microsecond))
					}
				}
			}
		}

		path := TraceroutePath{
			Hop:       hop,
			Hostname:  hopHostname,
			IP:        hopIP,
			Latencies: latencies,
		}

		result.Route = append(result.Route, path)

		// Check if we've reached the target
		if hopIP == ip {
			result.Success = true
		}
	}

	// If we didn't reach the target, it's unsuccessful
	if !result.Success {
		result.Err = errors.New("traceroute did not reach target")
	}

	return result, nil
}

func IsCI() bool {
	if _, ok := os.LookupEnv("CI"); ok {
		return true
	}

	if _, ok := os.LookupEnv("GITHUB_RUN_ID"); ok {
		return true
	}

	return false
}

// SafeHostname extracts a hostname from Hostinfo, providing sensible defaults
// if Hostinfo is nil or Hostname is empty. This prevents nil pointer dereferences
// and ensures nodes always have a valid hostname.
// The hostname is truncated to 63 characters to comply with DNS label length limits (RFC 1123).
func SafeHostname(hostinfo *tailcfg.Hostinfo, machineKey, nodeKey string) string {
	if hostinfo == nil || hostinfo.Hostname == "" {
		// Generate a default hostname using machine key prefix
		if machineKey != "" {
			keyPrefix := machineKey
			if len(machineKey) > 8 {
				keyPrefix = machineKey[:8]
			}
			return fmt.Sprintf("node-%s", keyPrefix)
		}
		if nodeKey != "" {
			keyPrefix := nodeKey
			if len(nodeKey) > 8 {
				keyPrefix = nodeKey[:8]
			}
			return fmt.Sprintf("node-%s", keyPrefix)
		}
		return "unknown-node"
	}

	hostname := hostinfo.Hostname

	// Validate hostname length - DNS label limit is 63 characters (RFC 1123)
	// Truncate if necessary to ensure compatibility with given name generation
	if len(hostname) > 63 {
		hostname = hostname[:63]
	}

	return hostname
}

// EnsureValidHostinfo ensures that Hostinfo is non-nil and has a valid hostname.
// If Hostinfo is nil, it creates a minimal valid Hostinfo with a generated hostname.
// Returns the validated/created Hostinfo and the extracted hostname.
func EnsureValidHostinfo(hostinfo *tailcfg.Hostinfo, machineKey, nodeKey string) (*tailcfg.Hostinfo, string) {
	if hostinfo == nil {
		hostname := SafeHostname(nil, machineKey, nodeKey)
		return &tailcfg.Hostinfo{
			Hostname: hostname,
		}, hostname
	}

	hostname := SafeHostname(hostinfo, machineKey, nodeKey)

	// Update the hostname in the hostinfo if it was empty or if it was truncated
	if hostinfo.Hostname == "" || hostinfo.Hostname != hostname {
		hostinfo.Hostname = hostname
	}

	return hostinfo, hostname
}
