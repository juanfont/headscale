package types

import (
	"errors"
	"fmt"
	"strings"
)

// ErrConfig is a sentinel matching any *ConfigError. Callers can do
// errors.Is(err, types.ErrConfig) to detect "this came from config
// validation" without caring which rule triggered.
var ErrConfig = errors.New("headscale: config validation")

// ConfigError is a structured config-validation error. Pointer receivers
// throughout, following the stdlib convention (*net.OpError,
// *os.PathError, *url.Error). Implements error, Unwrap, Is. errors.As
// works automatically via type assertion against the Unwrap chain.
type ConfigError struct {
	Reason        string
	Current       []KV
	ConflictsWith []KV
	Allowed       []string
	Minimum       string
	Maximum       string
	Detail        string
	Hint          string
	See           string

	// Cause is an optional underlying error included in the chain so
	// errors.Is(cfgErr, sentinel) returns true when a rule was wired
	// to a sentinel (e.g. errInvalidPKCEMethod). It is NOT rendered
	// into Error() — the structured fields are the operator-facing
	// representation.
	Cause error
}

// KV is a config key paired with the value the operator supplied.
// Strings render with %q; everything else with %v.
type KV struct {
	Key   string
	Value any
}

// Error renders a structured operator-facing block. See
// TestConfigError_Render for the canonical wire format.
func (e *ConfigError) Error() string {
	var b strings.Builder
	b.WriteString("Fatal config error: ")
	b.WriteString(e.Reason)
	b.WriteString("\n")
	writeConfigErrLine(&b, "current", joinKVs(e.Current))
	writeConfigErrLine(&b, "conflicts with", joinKVs(e.ConflictsWith))
	writeConfigErrLine(&b, "allowed", joinQuoted(e.Allowed))
	writeConfigErrLine(&b, "minimum", e.Minimum)
	writeConfigErrLine(&b, "maximum", e.Maximum)
	writeConfigErrLine(&b, "why", e.Detail)
	writeConfigErrLine(&b, "hint", e.Hint)
	writeConfigErrLine(&b, "see", e.See)

	return b.String()
}

// Unwrap returns Cause so errors.Is walks through it.
func (e *ConfigError) Unwrap() error { return e.Cause }

// Is matches the ErrConfig sentinel. errors.Is recurses through Unwrap
// for everything else, so this is the only custom case needed.
func (e *ConfigError) Is(target error) bool {
	return target == ErrConfig
}

func writeConfigErrLine(b *strings.Builder, label, value string) {
	if value == "" {
		return
	}

	b.WriteString("  ")
	b.WriteString(label)
	b.WriteString(": ")
	b.WriteString(value)
	b.WriteString("\n")
}

func joinKVs(kvs []KV) string {
	if len(kvs) == 0 {
		return ""
	}

	parts := make([]string, len(kvs))
	for i, kv := range kvs {
		parts[i] = fmt.Sprintf("%s: %s", kv.Key, formatKVValue(kv.Value))
	}

	return strings.Join(parts, ", ")
}

func joinQuoted(ss []string) string {
	if len(ss) == 0 {
		return ""
	}

	parts := make([]string, len(ss))
	for i, s := range ss {
		parts[i] = fmt.Sprintf("%q", s)
	}

	return strings.Join(parts, ", ")
}

func formatKVValue(v any) string {
	switch x := v.(type) {
	case nil:
		return `""`
	case string:
		return fmt.Sprintf("%q", x)
	default:
		return fmt.Sprintf("%v", x)
	}
}

// configValidator collects ConfigError values so an operator sees every
// problem at once instead of fixing them one startup attempt at a time.
// Zero value is ready to use.
type configValidator struct {
	errs []error
}

// Add records a structured rule violation.
func (v *configValidator) Add(e *ConfigError) {
	v.errs = append(v.errs, e)
}

// AddErr records any error (e.g. one returned by a sub-builder helper).
// Useful when wrapping fmt.Errorf("..."): %w results that already carry
// their own wrap.
func (v *configValidator) AddErr(err error) {
	if err == nil {
		return
	}

	v.errs = append(v.errs, err)
}

// HasErrors reports whether any rule has triggered.
func (v *configValidator) HasErrors() bool { return len(v.errs) > 0 }

// Err returns nil if no rules triggered, otherwise the joined error.
// errors.Join's wrapper exposes Unwrap() []error, so errors.Is and
// errors.As walk every branch — sentinel matching and type extraction
// work uniformly across single and joined results.
func (v *configValidator) Err() error {
	if len(v.errs) == 0 {
		return nil
	}

	return errors.Join(v.errs...)
}

// ConfigErrors walks an error tree (single Unwrap and multi-Unwrap) and
// returns every *ConfigError found. Used by callers that need to
// inspect every rule violation, not just the first.
//
// Uses a direct type assertion rather than errors.As so a wrapped
// ConfigError isn't counted twice (once at the wrapper, once at the
// inner ConfigError). Each node in the tree is reported by its concrete
// type.
func ConfigErrors(err error) []*ConfigError {
	var out []*ConfigError

	walkErrTree(err, func(e error) {
		// Direct type assertion is intentional: errors.As walks the
		// Unwrap chain, which would double-count a *ConfigError once at
		// the wrapper and again at the wrapped node we recurse into.
		if ce, ok := e.(*ConfigError); ok { //nolint:errorlint // see comment above
			out = append(out, ce)
		}
	})

	return out
}

func walkErrTree(err error, fn func(error)) {
	if err == nil {
		return
	}

	fn(err)

	// Type-switch on err itself, not the chain: we want to know whether
	// THIS error exposes Unwrap() error or Unwrap() []error so we can
	// pick the right traversal. errors.As would jump past the head and
	// confuse the walk (e.g. a join inside a single-Unwrap chain).
	switch x := err.(type) { //nolint:errorlint // see comment above
	case interface{ Unwrap() error }:
		walkErrTree(x.Unwrap(), fn)
	case interface{ Unwrap() []error }:
		for _, b := range x.Unwrap() {
			walkErrTree(b, fn)
		}
	}
}
