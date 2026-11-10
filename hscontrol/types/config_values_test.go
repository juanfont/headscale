package types

import (
	"encoding"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConfigValues(t *testing.T) {
	tests := []struct {
		name string
		// dst is a fresh pointer to decode into.
		dst  encoding.TextUnmarshaler
		in   string
		want any
		// wantErr is a substring of the ConfigError's Reason.
		wantErr string
		wantSee string
	}{
		{name: "filemode/0770", dst: new(FileMode), in: "0770", want: FileMode(0o770)},
		{name: "filemode/0o770", dst: new(FileMode), in: "0o770", want: FileMode(0o770)},
		{name: "filemode/above perm bits", dst: new(FileMode), in: "17777", wantErr: "octal file mode"},

		{name: "httpurl/empty", dst: new(HTTPURL), in: "", want: HTTPURL("")},
		{name: "httpurl/https", dst: new(HTTPURL), in: "https://h/x", want: HTTPURL("https://h/x")},
		{name: "httpurl/ftp", dst: new(HTTPURL), in: "ftp://h", wantErr: "is not an http:// or https:// URL"},
		{name: "httpurl/no scheme", dst: new(HTTPURL), in: "h.example.com", wantErr: "is not an http:// or https:// URL"},
		{name: "httpurl/host and port", dst: new(HTTPURL), in: "https://h:8443/x", want: HTTPURL("https://h:8443/x")},
		{name: "httpurl/ipv6", dst: new(HTTPURL), in: "http://[::1]:8080", want: HTTPURL("http://[::1]:8080")},
		{name: "httpurl/no host", dst: new(HTTPURL), in: "https://", wantErr: "is not an http:// or https:// URL"},
		{name: "httpurl/port without host", dst: new(HTTPURL), in: "https://:443/x", wantErr: "is not an http:// or https:// URL"},
		{name: "httpurl/http port without host", dst: new(HTTPURL), in: "http://:80", wantErr: "is not an http:// or https:// URL"},
		{name: "httpurl/unparsable", dst: new(HTTPURL), in: "https://alice:pw?@h", wantErr: "is not an http:// or https:// URL"},

		{name: "listenaddr/empty", dst: new(ListenAddr), in: "", want: ListenAddr("")},
		{name: "listenaddr/port only", dst: new(ListenAddr), in: ":8080", want: ListenAddr(":8080")},
		{name: "listenaddr/named port", dst: new(ListenAddr), in: "0.0.0.0:http", want: ListenAddr("0.0.0.0:http")},
		{name: "listenaddr/no colon", dst: new(ListenAddr), in: "8080", wantErr: "host:port"},
		{name: "listenaddr/bad port", dst: new(ListenAddr), in: "h:abc", wantErr: "host:port"},
		{name: "listenaddr/port above range", dst: new(ListenAddr), in: "h:65536", wantErr: "host:port"},
		{name: "listenaddr/negative port", dst: new(ListenAddr), in: "h:-1", wantErr: "host:port"},
		{name: "listenaddr/highest port", dst: new(ListenAddr), in: "h:65535", want: ListenAddr("h:65535")},

		{name: "loglevel/trace", dst: new(LogLevel), in: "trace", want: LogLevel("trace")},
		{name: "loglevel/debug", dst: new(LogLevel), in: "debug", want: LogLevel("debug")},
		{name: "loglevel/info", dst: new(LogLevel), in: "info", want: LogLevel("info")},
		{name: "loglevel/warn", dst: new(LogLevel), in: "warn", want: LogLevel("warn")},
		{name: "loglevel/error", dst: new(LogLevel), in: "error", want: LogLevel("error")},
		{name: "loglevel/fatal", dst: new(LogLevel), in: "fatal", want: LogLevel("fatal")},
		{name: "loglevel/panic", dst: new(LogLevel), in: "panic", want: LogLevel("panic")},
		{name: "loglevel/disabled", dst: new(LogLevel), in: "disabled", want: LogLevel("disabled")},
		{name: "loglevel/upper case stored lower", dst: new(LogLevel), in: "INFO", want: LogLevel("info")},
		{name: "loglevel/empty", dst: new(LogLevel), in: "", want: LogLevel("")},
		{name: "loglevel/unknown", dst: new(LogLevel), in: "verbose", wantErr: "has an unsupported value"},

		{name: "logformat/text", dst: new(LogFormat), in: "text", want: LogFormat("text")},
		{name: "logformat/json", dst: new(LogFormat), in: "json", want: LogFormat("json")},
		{name: "logformat/empty", dst: new(LogFormat), in: "", want: LogFormat("")},
		{name: "logformat/unknown", dst: new(LogFormat), in: "yaml", wantErr: "has an unsupported value"},

		{name: "database/sqlite", dst: new(DatabaseType), in: "sqlite", want: DatabaseType("sqlite")},
		{name: "database/sqlite3", dst: new(DatabaseType), in: "sqlite3", want: DatabaseType("sqlite3")},
		{name: "database/postgres", dst: new(DatabaseType), in: "postgres", want: DatabaseType("postgres")},
		{name: "database/empty", dst: new(DatabaseType), in: "", want: DatabaseType("")},
		{name: "database/unknown", dst: new(DatabaseType), in: "mysql", wantErr: "has an unsupported value", wantSee: "https://headscale.net/stable/ref/database/"},

		{name: "acme/HTTP-01", dst: new(ACMEChallenge), in: "HTTP-01", want: ACMEChallenge("HTTP-01")},
		{name: "acme/TLS-ALPN-01", dst: new(ACMEChallenge), in: "TLS-ALPN-01", want: ACMEChallenge("TLS-ALPN-01")},
		{name: "acme/DNS-01", dst: new(ACMEChallenge), in: "DNS-01", want: ACMEChallenge("DNS-01")},
		{name: "acme/empty", dst: new(ACMEChallenge), in: "", want: ACMEChallenge("")},
		{name: "acme/case-sensitive", dst: new(ACMEChallenge), in: "http-01", wantErr: "has an unsupported value"},

		{name: "pkce/plain", dst: new(PKCEMethod), in: "plain", want: PKCEMethod("plain")},
		{name: "pkce/S256", dst: new(PKCEMethod), in: "S256", want: PKCEMethod("S256")},
		{name: "pkce/empty", dst: new(PKCEMethod), in: "", want: PKCEMethod("")},
		{name: "pkce/case-sensitive", dst: new(PKCEMethod), in: "s256", wantErr: "has an unsupported value"},

		{name: "policy/file", dst: new(PolicyMode), in: "file", want: PolicyMode("file")},
		{name: "policy/database", dst: new(PolicyMode), in: "database", want: PolicyMode("database")},
		{name: "policy/empty", dst: new(PolicyMode), in: "", want: PolicyMode("")},
		{name: "policy/unknown", dst: new(PolicyMode), in: "db", wantErr: "has an unsupported value", wantSee: "https://headscale.net/stable/ref/policy/"},

		{name: "allocation/sequential", dst: new(IPAllocationStrategy), in: "sequential", want: IPAllocationStrategySequential},
		{name: "allocation/random", dst: new(IPAllocationStrategy), in: "random", want: IPAllocationStrategyRandom},
		{name: "allocation/empty", dst: new(IPAllocationStrategy), in: "", want: IPAllocationStrategy("")},
		{name: "allocation/unknown", dst: new(IPAllocationStrategy), in: "linear", wantErr: "has an unsupported value"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.dst.UnmarshalText([]byte(tt.in))

			enum, isEnum := tt.dst.(interface{ Allowed() []string })
			if isEnum {
				require.NotContains(t, enum.Allowed(), "", "Allowed lists only named values")
			}

			if tt.wantErr == "" {
				require.NoError(t, err)

				got := reflect.ValueOf(tt.dst).Elem().Interface()
				if diff := cmp.Diff(tt.want, got); diff != "" {
					t.Errorf("decoded value mismatch (-want +got):\n%s", diff)
				}

				return
			}

			require.ErrorIs(t, err, ErrConfig)

			var ce *ConfigError
			require.ErrorAs(t, err, &ce)
			require.Contains(t, ce.Reason, tt.wantErr)
			require.Empty(t, ce.Current, "the loader adds the key")
			require.Equal(t, tt.wantSee, ce.See)

			if isEnum {
				require.Equal(t, enum.Allowed(), ce.Allowed)
			}
		})
	}
}

func TestFileModeMarshalText(t *testing.T) {
	tests := []struct {
		mode FileMode
		want string
	}{
		{0, "0000"},
		{0o600, "0600"},
		{0o770, "0770"},
		{0o777, "0777"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			b, err := tt.mode.MarshalText()
			require.NoError(t, err)
			require.Equal(t, tt.want, string(b))

			var got FileMode
			require.NoError(t, got.UnmarshalText(b))
			require.Equal(t, tt.mode, got, "round trip")
		})
	}
}

func TestHTTPURLMarshalJSON(t *testing.T) {
	tests := []struct {
		url  HTTPURL
		want string
	}{
		{"", `""`},
		{"https://derp.example/map", `"https://derp.example/map"`},
		{"https://alice:pw-marker@derp.example/map", `"https://derp.example/map"`},
		{"https://token-marker@derp.example/map?x=1", `"https://derp.example/map?x=1"`},
		{"https://alice:pw-marker@derp.example/%zz", `"\u003credacted\u003e"`},
	}

	for _, tt := range tests {
		t.Run(string(tt.url), func(t *testing.T) {
			b, err := json.Marshal(tt.url)
			require.NoError(t, err)
			assert.Equal(t, tt.want, string(b))
		})
	}
}

// TestHTTPURLErrorHidesValue: a URL may hold credentials, so no error in
// the tree of its parse error, nor its JSON, holds the value.
func TestHTTPURLErrorHidesValue(t *testing.T) {
	for _, in := range []string{
		"https://alice:marker-pass?@h.example.com",
		"https://marker-user:marker-pass@h.example.com/%zz",
		"https://marker-user:marker-pass@h.example.com:port",
		"ftp://marker-user:marker-pass@h.example.com",
	} {
		t.Run(in, func(t *testing.T) {
			var u HTTPURL

			err := u.UnmarshalText([]byte(in))
			require.Error(t, err)
			requireHidden(t, err, "marker")
		})
	}
}

// requireHidden fails when an error in err's tree, its text or its JSON,
// or the JSON of its ConfigErrors holds hidden.
func requireHidden(t *testing.T, err error, hidden string) {
	t.Helper()

	walkErrTree(err, func(e error) {
		assert.NotContains(t, e.Error(), hidden)

		b, jerr := json.Marshal(e)
		require.NoError(t, jerr)
		assert.NotContains(t, string(b), hidden)
	})

	b, jerr := json.Marshal(ConfigErrors(err))
	require.NoError(t, jerr)
	assert.NotContains(t, string(b), hidden)
}

func TestLogLevelZerolog(t *testing.T) {
	tests := []struct {
		level LogLevel
		want  zerolog.Level
	}{
		{"trace", zerolog.TraceLevel},
		{"warn", zerolog.WarnLevel},
		{"disabled", zerolog.Disabled},
		{"", zerolog.InfoLevel},
		{"verbose", zerolog.DebugLevel},
	}

	for _, tt := range tests {
		t.Run(string(tt.level), func(t *testing.T) {
			require.Equal(t, tt.want, tt.level.Zerolog())
		})
	}
}

func TestSecret(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "s"), []byte("  from-file\n"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "empty"), []byte(" \n"), 0o600))
	t.Setenv("D", dir)

	missing := filepath.Join(dir, "missing")
	empty := filepath.Join(dir, "empty")

	tests := []struct {
		name         string
		in           Secret
		want         string
		wantErr      string
		wantFile     bool
		wantRedacted string
	}{
		{name: "empty", in: "", want: "", wantRedacted: ""},
		{name: "literal", in: "literal-value", want: "literal-value", wantRedacted: "<redacted>"},
		{name: "file trimmed", in: Secret("file:" + filepath.Join(dir, "s")), want: "from-file", wantFile: true, wantRedacted: "file:" + filepath.Join(dir, "s")},
		{name: "file path expanded", in: "file:$D/s", want: "from-file", wantFile: true, wantRedacted: "file:$D/s"},
		{name: "missing file names the path", in: Secret("file:" + missing), wantErr: missing, wantFile: true, wantRedacted: "file:" + missing},
		{name: "empty file names the path", in: Secret("file:" + empty), wantErr: empty + ": file is empty", wantFile: true, wantRedacted: "file:" + empty},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.wantFile, tt.in.IsFile())
			require.Equal(t, tt.wantRedacted, tt.in.Redacted())
			require.Equal(t, tt.wantRedacted, fmt.Sprint(tt.in), "String redacts")

			got, err := tt.in.Resolve()
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)

				return
			}

			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}

	_, err := Secret("file:" + missing).Resolve()
	require.ErrorIs(t, err, os.ErrNotExist)
}
