// Package duration reads a duration as Headscale's people write one: the
// units of Go and of Prometheus. The CLI's time values and the config file
// share it, so a duration means the same in both.
package duration

import (
	"math"
	"strings"
	"time"

	"github.com/prometheus/common/model"
)

// Parse reads a duration in the units of Go (ns to h) and of Prometheus
// (d, w, y), combined from large to small.
func Parse(s string) (time.Duration, bool) {
	d, ok := parseGoDuration(s)
	if ok {
		return d, true
	}

	md, err := model.ParseDuration(s)

	return time.Duration(md), err == nil
}

// parseGoDuration is time.ParseDuration component by component: its sum
// wraps past 2^64 back into range ("9223372036854775808ns" twice is 0), so
// each addition is checked against the bounds first.
func parseGoDuration(s string) (time.Duration, bool) {
	sign := ""
	if len(s) > 0 && (s[0] == '-' || s[0] == '+') {
		sign, s = s[:1], s[1:]
	}

	if s == "0" {
		return 0, true
	}

	var total time.Duration

	for {
		part := durationPart(s)
		if part == "" {
			return 0, false
		}

		d, err := time.ParseDuration(sign + part)
		if err != nil || d > 0 && total > math.MaxInt64-d ||
			d < 0 && total < math.MinInt64-d {
			return 0, false
		}

		total += d

		s = s[len(part):]
		if s == "" {
			return total, true
		}
	}
}

// durationPart is the first number and unit of s, such as 1.5h of 1.5h30m;
// "" when s does not start with one.
func durationPart(s string) string {
	num := strings.IndexFunc(
		s,
		func(r rune) bool { return (r < '0' || r > '9') && r != '.' },
	)
	if num <= 0 {
		return ""
	}

	unit := strings.IndexFunc(
		s[num:],
		func(r rune) bool { return r >= '0' && r <= '9' || r == '.' },
	)
	if unit < 0 {
		return s
	}

	return s[:num+unit]
}
