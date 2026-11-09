package config

import (
	"regexp"
	"slices"
	"strings"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var nixOptionLine = regexp.MustCompile(`^( *)(\S+) = (lib\.mkOption )?\{$`)

// nixOptions are the dotted paths of the lib.mkOption calls in src, in
// order, and each one's attributes, dedented to two spaces and between
// newlines. A "name = {" line opens a section.
func nixOptions(src string) ([]string, map[string]string) {
	var (
		paths, stack []string
		indents      []int
		opts         = map[string]string{}
	)

	lines := strings.Split(src, "\n")

	for i, l := range lines {
		m := nixOptionLine.FindStringSubmatch(l)
		if m == nil {
			continue
		}

		for len(indents) > 0 && indents[len(indents)-1] >= len(m[1]) {
			indents, stack = indents[:len(indents)-1], stack[:len(stack)-1]
		}

		indents, stack = append(indents, len(m[1])), append(stack, m[2])

		if m[3] == "" {
			continue
		}

		path := strings.Join(stack, ".")
		end := i + slices.Index(lines[i:], m[1]+"};")

		var body []string
		for _, b := range lines[i+1 : end] {
			body = append(body, strings.TrimPrefix(b, m[1]))
		}

		paths = append(paths, path)
		opts[path] = "\n" + strings.Join(body, "\n") + "\n"
	}

	return paths, opts
}

// nixCode is src without its comments and string literals.
func nixCode(src string) string {
	var code strings.Builder

	for i := 0; i < len(src); i++ {
		switch {
		case src[i] == '#':
			for i < len(src) && src[i] != '\n' {
				i++
			}
		case src[i] == '"':
			for i++; i < len(src) && src[i] != '"'; i++ {
				if src[i] == '\\' {
					i++
				}
			}
		case strings.HasPrefix(src[i:], "''"):
			for i += 2; i < len(src); i++ {
				rest := src[i:]
				if strings.HasPrefix(rest, "'''") || strings.HasPrefix(rest, "''$") {
					i += 2
				} else if strings.HasPrefix(rest, "''\\") {
					i += 3
				} else if strings.HasPrefix(rest, "''") {
					i++

					break
				}
			}
		default:
			code.WriteByte(src[i])
		}
	}

	return code.String()
}

func TestGenerateNixOptionsHeader(t *testing.T) {
	tests := []struct {
		name    string
		release *types.VersionInfo
		want    string
	}{
		{
			name: "development",
			want: "# Generated from hscontrol/types/config.go by `headscale generate nixos-options`; do not edit.\n" +
				"# headscale development tree, not a release\n" +
				"# Options for services.headscale.settings, not a module: import ./options.generated.nix { inherit lib; }\n" +
				"{ lib, ... }:\n" + nixTypes + "{\n",
		},
		{
			name:    "release",
			release: &types.VersionInfo{Version: "v1.2.3", Commit: "abc"},
			want: "# Generated from hscontrol/types/config.go by `headscale generate nixos-options`; do not edit.\n" +
				"# headscale v1.2.3, commit abc\n" +
				"# Options for services.headscale.settings, not a module: import ./options.generated.nix { inherit lib; }\n" +
				"{ lib, ... }:\n" + nixTypes + "{\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out, err := GenerateNixOptions(tt.release)
			require.NoError(t, err)

			got := string(out[:min(len(tt.want), len(out))])
			if diff := gocmp.Diff(tt.want, got); diff != "" {
				t.Errorf("header (-want +got):\n%s", diff)
			}
		})
	}
}

func TestGenerateNixOptions(t *testing.T) {
	out, err := GenerateNixOptions(nil)
	require.NoError(t, err)

	again, err := GenerateNixOptions(nil)
	require.NoError(t, err)
	require.Equal(t, string(out), string(again), "output is not deterministic")

	src := string(out)
	paths, opts := nixOptions(src)

	d := Default()
	// cli.* is read by the CLI from its own configuration, not the server's.
	fields := slices.DeleteFunc(types.ConfigFields(&d), func(f types.ConfigField) bool { return strings.HasPrefix(f.Path, "cli.") })

	t.Run("one option per key, nested, in order", func(t *testing.T) {
		want := make([]string, 0, len(fields))
		for _, f := range fields {
			want = append(want, f.Path)
		}

		got := slices.DeleteFunc(slices.Clone(paths), func(p string) bool { return strings.HasPrefix(p, "dns.extra_records.") })
		if diff := gocmp.Diff(want, got); diff != "" {
			t.Errorf("option paths (-keys +options):\n%s", diff)
		}

		assert.Len(t, paths, len(fields)+len(dnsRecordFields))
		assert.Equal(t, len(fields)+len(dnsRecordFields), strings.Count(src, "lib.mkOption"))
		assert.NotRegexp(t, `(?m)^  cli = \{$`, src)
	})

	t.Run("every option has an example", func(t *testing.T) {
		for _, p := range paths {
			assert.Contains(t, opts[p], "\n  example = ", p)
		}
	})

	t.Run("a function of lib only", func(t *testing.T) {
		// Free variables fail evaluation; these would not. The update
		// operator is no path.
		assert.NotRegexp(t, `import|builtins|[/<>]`, strings.ReplaceAll(nixCode(src), " // ", " "))
	})

	t.Run("types once", func(t *testing.T) {
		assert.Equal(t, 1, strings.Count(src, nixTypes))
	})

	t.Run("layout", func(t *testing.T) {
		assert.True(t, strings.HasSuffix(src, "}\n") && !strings.HasSuffix(src, "\n\n"), "ends in one newline")
		assert.NotRegexp(t, `(?m)[ \t]$`, src, "trailing whitespace")
	})

	tests := []struct {
		path string
		want []string
		hide []string
	}{
		{path: "server_url", want: []string{"\n  example = \"https://", "Required."}, hide: []string{"\n  default = "}},
		{path: "dns.base_domain", want: []string{"\n  default = \"tailnet.internal\";\n"}, hide: []string{"Required"}},
		{
			path: "database.type",
			want: []string{
				"\n  type = lib.types.enum [\n    \"sqlite\"\n", "\n    \"postgres\"\n    \"\"\n  ];\n",
				"\n    - `postgres`: ",
			},
		},
		{path: "tuning.batcher_workers", want: []string{"\n  default = 0;\n  defaultText = lib.literalMD \"three quarters of the CPU cores, at least one\";\n"}},
		{
			path: "oidc.client_secret",
			want: []string{
				"On NixOS, the value must be `\"\"` or `file:<path>`: load the secret as a systemd credential with ",
				"`systemd.services.headscale.serviceConfig.LoadCredential = [ \"oidc_client_secret:/run/secrets/oidc_client_secret\" ];`",
				// Rendered: "file:\${CREDENTIALS_DIRECTORY}/oidc_client_secret", as Nix source takes it.
				"`\"file:\\''${CREDENTIALS_DIRECTORY}/oidc_client_secret\"`",
			},
		},
		{
			path: "dns.challenge.provider",
			want: []string{
				"`systemd.services.headscale.serviceConfig.LoadCredential = [ \"dns_challenge_provider_<setting>:/run/secrets/dns_challenge_provider_<setting>\" ];`",
				"`\"file:\\''${CREDENTIALS_DIRECTORY}/dns_challenge_provider_<setting>\"`", "`name` is not a secret.",
			},
		},
		{path: "dns.nameservers.split", want: []string{"\n  type = lib.types.attrsOf (lib.types.listOf lib.types.str);\n", "\n    \"corp.example.com\" = [\n"}},
		{
			path: "dns.extra_records",
			want: []string{
				// An unknown field reaches headscale's check, not a Nix error.
				"\n  type = lib.types.listOf (\n    lib.types.submodule {\n      freeformType = lib.types.attrsOf lib.types.anything;\n      options = {\n        name = lib.mkOption {\n",
				"\n  default = [ ];\n",
			},
		},
		{path: "dns.extra_records.options.name", want: []string{"\n  type = lib.types.str;\n"}, hide: []string{"\n  default = "}},
		{
			path: "dns.extra_records.options.type",
			want: []string{"\n  type = lib.types.enum [\n    \"\"\n    \"A\"\n    \"AAAA\"\n  ];\n", "\n  default = \"\";\n", "\n  example = \"A\";\n"},
		},
		{path: "dns.extra_records.options.value", want: []string{"\n  type = t.ip;\n"}, hide: []string{"\n  default = "}},
		{path: "log.level", want: []string{"\n  example = \"debug\";\n"}},
		// Files headscale only reads take a Nix path; key and state files
		// must be outside the store, so no key is copied into it.
		{path: "policy.path", want: []string{"\n  type = t.readFile;\n", "On NixOS, paths must be absolute.\n"}},
		{path: "dns.extra_records_path", want: []string{"\n  type = t.readFile;\n"}},
		{path: "tls.cert_path", want: []string{"\n  type = t.readFile;\n"}},
		{path: "derp.paths", want: []string{"\n  type = lib.types.listOf lib.types.path;\n", "On NixOS, paths must be absolute.\n"}},
		{path: "noise.private_key_path", want: []string{"\n  type = t.stateFile;\n", "On NixOS, paths must be absolute and outside the Nix store.\n"}},
		{path: "derp.server.private_key_path", want: []string{"\n  type = t.stateFile;\n"}},
		{path: "database.sqlite.path", want: []string{"\n  type = t.stateFile;\n"}},
		{path: "unix_socket", want: []string{"\n  type = t.stateFile;\n"}},
		{path: "tls.key_path", want: []string{"\n  type = t.stateFile;\n"}},
		{path: "tls.acme.cache_dir", want: []string{"\n  type = t.stateFile;\n"}},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			opt, ok := opts[tt.path]
			require.True(t, ok, "no option %s", tt.path)

			for _, s := range tt.want {
				assert.Contains(t, opt, s)
			}

			for _, s := range tt.hide {
				assert.NotContains(t, opt, s)
			}
		})
	}

	// Built by hand, so the rendering is pinned whatever Default requires.
	t.Run("required when", func(t *testing.T) {
		k := schemaByPath(t)["dns.base_domain"]
		k.Required, k.RequiredWhen = true, "`dns.magic_dns` is true"

		opt, err := nixOption(k, 0)
		require.NoError(t, err)
		assert.Contains(t, opt, "\n  default = \"tailnet.internal\";\n")
		assert.Contains(t, opt, "Required when `dns.magic_dns` is true.")
	})
}

func TestNixLiteral(t *testing.T) {
	tests := []struct {
		name   string
		v      any
		indent int
		want   string
	}{
		{name: "interpolation", v: "file:${CREDENTIALS_DIRECTORY}/x", want: `"file:\${CREDENTIALS_DIRECTORY}/x"`},
		{name: "quote and backslash", v: `a"b\c`, want: `"a\"b\\c"`},
		{name: "newline without a final one", v: "a\nb", want: `"a\nb"`},
		{name: "every line indented", v: "  a\n", want: `"  a\n"`},
		{
			name: "indented string", v: "it''s ${x}\n\n'${y}\nend'\n", indent: 2,
			want: "''\n    it'''s ''${x}\n\n    ''\\'''${y}\n    end'\n  ''",
		},
		{name: "true", v: true, want: "true"},
		{name: "int", v: 8, want: "8"},
		{name: "negative int", v: -1, want: "(-1)"},
		{name: "null", v: nil, want: "null"},
		{name: "empty list", v: []any{}, want: "[ ]"},
		{name: "empty map", v: map[string]any{}, want: "{ }"},
		{name: "one element", v: []any{"a"}, want: "[\n  \"a\"\n]"},
		{
			name: "attr names", v: map[string]any{"corp.example.com": 1, "api_token": "t", "if": true},
			want: "{\n  api_token = \"t\";\n  \"corp.example.com\" = 1;\n  \"if\" = true;\n}",
		},
		// An indented string is no attribute name.
		{name: "attr name with a newline", v: map[string]any{"line\n": 1, "or": 2}, want: "{\n  \"line\\n\" = 1;\n  \"or\" = 2;\n}"},
		{
			name: "nested", v: map[string]any{"a": map[string]any{"b": []any{1, "c"}}}, indent: 4,
			want: "{\n      a = {\n        b = [\n          1\n          \"c\"\n        ];\n      };\n    }",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if diff := gocmp.Diff(tt.want, nixLiteral(tt.v, tt.indent)); diff != "" {
				t.Errorf("(-want +got):\n%s", diff)
			}
		})
	}
}
