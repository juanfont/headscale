package types

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	errTestCustomSentinel = errors.New("custom-sentinel")
	errTestSentinel       = errors.New("sentinel")
)

func TestConfigError_Render(t *testing.T) {
	tests := []struct {
		name string
		in   ConfigError
		want string
	}{
		{
			name: "minimal",
			in:   ConfigError{Reason: "x is required"},
			want: "Fatal config error: x is required\n",
		},
		{
			name: "scalar with hint",
			in: ConfigError{
				Reason:  "server_url is missing a scheme",
				Current: []KV{{"server_url", "headscale.example.com"}},
				Hint:    "prefix the URL with https:// (recommended) or http://",
			},
			want: "Fatal config error: server_url is missing a scheme\n" +
				`  current: server_url: "headscale.example.com"` + "\n" +
				"  hint: prefix the URL with https:// (recommended) or http://\n",
		},
		{
			name: "pair conflict with see",
			in: ConfigError{
				Reason:        "A and B are mutually exclusive",
				Current:       []KV{{"A", "a"}},
				ConflictsWith: []KV{{"B", "b"}, {"C", "c"}},
				Hint:          "pick one",
				See:           "https://example.com/docs",
			},
			want: "Fatal config error: A and B are mutually exclusive\n" +
				`  current: A: "a"` + "\n" +
				`  conflicts with: B: "b", C: "c"` + "\n" +
				"  hint: pick one\n" +
				"  see: https://example.com/docs\n",
		},
		{
			name: "value-set check",
			in: ConfigError{
				Reason:  "tls_letsencrypt_challenge_type has an unsupported value",
				Current: []KV{{"tls_letsencrypt_challenge_type", "dns-01"}},
				Allowed: []string{"HTTP-01", "TLS-ALPN-01"},
				Hint:    "pick one of the allowed values",
			},
			want: "Fatal config error: tls_letsencrypt_challenge_type has an unsupported value\n" +
				`  current: tls_letsencrypt_challenge_type: "dns-01"` + "\n" +
				`  allowed: "HTTP-01", "TLS-ALPN-01"` + "\n" +
				"  hint: pick one of the allowed values\n",
		},
		{
			name: "numeric bound",
			in: ConfigError{
				Reason:  "x is below the minimum",
				Current: []KV{{"x", "1s"}},
				Minimum: "2s",
				Hint:    "raise the value",
			},
			want: "Fatal config error: x is below the minimum\n" +
				`  current: x: "1s"` + "\n" +
				"  minimum: 2s\n" +
				"  hint: raise the value\n",
		},
		{
			name: "non-string values",
			in: ConfigError{
				Reason:  "test",
				Current: []KV{{"a_string", "x"}, {"a_bool", true}, {"a_int", 42}, {"empty", ""}},
			},
			want: "Fatal config error: test\n" +
				`  current: a_string: "x", a_bool: true, a_int: 42, empty: ""` + "\n",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.in.Error())
		})
	}
}

func TestConfigError_IsErrConfig(t *testing.T) {
	e := &ConfigError{Reason: "test"}
	require.ErrorIs(t, e, ErrConfig)
	require.ErrorIs(t, fmt.Errorf("wrapped: %w", e), ErrConfig)
}

func TestConfigError_IsCauseSentinel(t *testing.T) {
	e := &ConfigError{Reason: "test", Cause: errTestCustomSentinel}
	require.ErrorIs(t, e, errTestCustomSentinel)
	require.ErrorIs(t, e, ErrConfig)
}

func TestConfigError_As(t *testing.T) {
	e := &ConfigError{Reason: "test"}
	wrapped := fmt.Errorf("startup: %w", e)

	var got *ConfigError
	require.ErrorAs(t, wrapped, &got)
	assert.Equal(t, "test", got.Reason)
}

func TestConfigValidator_NilWhenEmpty(t *testing.T) {
	v := &configValidator{}
	assert.False(t, v.HasErrors())
	assert.NoError(t, v.Err())
}

func TestConfigValidator_JoinsWithBlankLine(t *testing.T) {
	v := &configValidator{}
	v.Add(&ConfigError{Reason: "first"})
	v.Add(&ConfigError{Reason: "second"})

	want := "Fatal config error: first\n" +
		"\n" +
		"Fatal config error: second\n"
	assert.Equal(t, want, v.Err().Error())
}

func TestConfigValidator_JoinedErrorsIs(t *testing.T) {
	v := &configValidator{}
	v.Add(&ConfigError{Reason: "first"})
	v.Add(&ConfigError{Reason: "second", Cause: errTestSentinel})
	err := v.Err()

	require.ErrorIs(t, err, ErrConfig)
	require.ErrorIs(t, err, errTestSentinel)
}

func TestConfigValidator_JoinedErrorsAs(t *testing.T) {
	v := &configValidator{}
	v.Add(&ConfigError{Reason: "first"})
	v.Add(&ConfigError{Reason: "second"})
	err := v.Err()

	var got *ConfigError
	require.ErrorAs(t, err, &got)
	assert.Equal(t, "first", got.Reason)
}

func TestConfigValidator_AddErrSkipsNil(t *testing.T) {
	v := &configValidator{}
	v.AddErr(nil)
	assert.False(t, v.HasErrors())
	assert.NoError(t, v.Err())
}

func TestConfigErrors_WalkAllBranches(t *testing.T) {
	v := &configValidator{}
	v.Add(&ConfigError{Reason: "first"})
	v.Add(&ConfigError{Reason: "second"})
	v.AddErr(fmt.Errorf("non-config: %w", &ConfigError{Reason: "third"}))

	got := ConfigErrors(v.Err())
	require.Len(t, got, 3)
	assert.Equal(t, "first", got[0].Reason)
	assert.Equal(t, "second", got[1].Reason)
	assert.Equal(t, "third", got[2].Reason)
}
