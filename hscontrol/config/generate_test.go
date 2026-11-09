package config

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"unicode/utf8"

	gocmp "github.com/google/go-cmp/cmp"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.yaml.in/yaml/v3"
)

// loadGenerated loads out as a config.yaml without environment.
func loadGenerated(t *testing.T, out []byte) *types.Config {
	t.Helper()

	path := filepath.Join(t.TempDir(), "config.yaml")
	require.NoError(t, os.WriteFile(path, out, 0o600))

	l, err := Load(path, true, nil)
	require.NoError(t, err, string(out))

	return l.Config
}

// exampleKeys are the top-level keys of out and the dotted paths of its
// leaves, in order; a section of ConfigTree is walked, any other key is a
// leaf.
func exampleKeys(t *testing.T, out []byte) ([]string, []string) {
	t.Helper()

	var doc yaml.Node
	require.NoError(t, yaml.Unmarshal(out, &doc))

	d := Default()
	sections := map[string]bool{}

	for _, f := range types.ConfigTree(&d) {
		sections[f.Path] = f.Section
	}

	var top, leaves []string

	var walk func(prefix string, n *yaml.Node)
	walk = func(prefix string, n *yaml.Node) {
		for i := 0; i < len(n.Content); i += 2 {
			p := joinConfigPath(prefix, n.Content[i].Value)
			if prefix == "" {
				top = append(top, p)
			}

			if sections[p] {
				walk(p, n.Content[i+1])
			} else {
				leaves = append(leaves, p)
			}
		}
	}
	walk("", doc.Content[0])

	return top, leaves
}

// commentAbove is the text of the comment lines directly above the line
// line, "# " stripped and joined by spaces.
func commentAbove(out, line string) string {
	lines := strings.Split(out, "\n")
	i := slices.Index(lines, line)

	var text []string

	for i--; i >= 0 && strings.HasPrefix(strings.TrimSpace(lines[i]), "#"); i-- {
		text = append([]string{strings.TrimPrefix(strings.TrimSpace(lines[i]), "# ")}, text...)
	}

	return strings.Join(text, " ")
}

// TestGenerateExample: the example of Default() loads back to it, has every
// key in ConfigTree order and is the same on every run; with docs, each
// key's documentation is above it in lines of at most 80 columns.
func TestGenerateExample(t *testing.T) {
	d := Default()

	var wantTop, wantLeaves []string

	for _, f := range types.ConfigTree(&d) {
		if !strings.Contains(f.Path, ".") {
			wantTop = append(wantTop, f.Path)
		}

		if !f.Section {
			wantLeaves = append(wantLeaves, f.Path)
		}
	}

	serverURL := slices.IndexFunc(types.ConfigFields(&d), func(f types.ConfigField) bool { return f.Path == "server_url" })
	require.GreaterOrEqual(t, serverURL, 0)

	for _, docs := range []bool{true, false} {
		t.Run(map[bool]string{true: "docs", false: "no docs"}[docs], func(t *testing.T) {
			cfg := Default()

			out, err := GenerateExample(&cfg, ExampleOptions{Docs: docs})
			require.NoError(t, err)

			again, err := GenerateExample(&cfg, ExampleOptions{Docs: docs})
			require.NoError(t, err)
			assert.True(t, bytes.Equal(out, again), "two runs differ")

			if diff := gocmp.Diff(&d, loadGenerated(t, out), roundTripOpts); diff != "" {
				t.Errorf("loads as (-default +loaded):\n%s", diff)
			}

			top, leaves := exampleKeys(t, out)
			assert.Equal(t, wantTop, top)
			assert.Equal(t, wantLeaves, leaves)

			text := string(out)
			assert.True(t, strings.HasSuffix(text, "\n") && !strings.HasSuffix(text, "\n\n"), "must end in one newline")

			for l := range strings.SplitSeq(strings.TrimSuffix(text, "\n"), "\n") {
				assert.Equal(t, strings.TrimRight(l, " \t"), l, "trailing whitespace")

				if utf8.RuneCountInString(l) > 80 {
					assert.Len(t, strings.Fields(strings.TrimPrefix(strings.TrimSpace(l), "#")), 1, "longer than 80 columns: %q", l)
				}
			}

			if !docs {
				assert.NotContains(t, text, "#")
				assert.NotContains(t, text, "\n\n")

				return
			}

			assert.True(t, strings.HasPrefix(text, "# Every key: https://headscale.net/stable/ref/configuration-options/\n\n"), text)

			above := commentAbove(text, `server_url: ""`)
			assert.Contains(t, above, types.ConfigFields(&d)[serverURL].Doc)
			assert.Contains(t, above, "Required. Example: https://headscale.example.com")
			assert.Contains(t, commentAbove(text, `  level: info`), "One of: `trace`, `debug`, `info`, `warn`, `error`, `fatal`, `panic`, `disabled`.")
			require.Contains(t, text, "\n  base_domain: tailnet.internal\n")
			assert.NotContains(t, commentAbove(text, `  base_domain: tailnet.internal`), "Required when")
			assert.Contains(t, commentAbove(text, `  batcher_workers: 0`), "Default: three quarters of the CPU cores, at least one.")
			assert.Equal(t, len(wantTop), strings.Count(text, "\n\n"), "one blank line before each top-level key")
		})
	}
}

// TestKeyComment: prose paragraphs are wrapped to the width, a list or
// code paragraph keeps its lines, and a bare "#" separates paragraphs.
func TestKeyComment(t *testing.T) {
	tests := []struct {
		name string
		key  keyInfo
		want []string
	}{
		{
			name: "paragraphs and a list",
			key: keyInfo{ConfigField: types.ConfigField{Doc: "The first paragraph is prose, long enough to be wrapped across more than one line.\n\n" +
				"The second.\n\n  - one item, which is long enough to pass the width but is kept as written\n  - two"}},
			want: []string{
				"# The first paragraph is prose, long enough to be",
				"# wrapped across more than one line.",
				"#",
				"# The second.",
				"#",
				"#   - one item, which is long enough to pass the width but is kept as written",
				"#   - two",
			},
		},
		{
			name: "code and the generated lines",
			key: keyInfo{
				ConfigField: types.ConfigField{Doc: "Run:\n\n\tfirst command\n\t  indented more"},
				Type:        typeInfo{Enum: []string{"a", "b"}},
				DefaultText: "chosen at start",
			},
			want: []string{"# Run:", "#", "# \tfirst command", "# \t  indented more", "# One of: `a`, `b`.", "# Default: chosen at start."},
		},
		{
			name: "required",
			key:  keyInfo{ConfigField: types.ConfigField{Doc: "A key."}, Required: true, Example: "https://headscale.example.com"},
			want: []string{"# A key.", "# Required. Example: https://headscale.example.com"},
		},
		{
			name: "required when",
			key:  keyInfo{ConfigField: types.ConfigField{Doc: "A key."}, Required: true, RequiredWhen: "`a` is true"},
			want: []string{"# A key.", "# Required when `a` is true."},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := keyComment(tt.key, 50)
			require.NoError(t, err)

			if diff := gocmp.Diff(tt.want, strings.Split(got, "\n")); diff != "" {
				t.Errorf("keyComment (-want +got):\n%s", diff)
			}
		})
	}
}

// TestGenerateExampleValues: values YAML would read as another type, or
// as syntax, load back as written.
func TestGenerateExampleValues(t *testing.T) {
	for _, s := range []string{"yes", "null", "~", "0x1F", "a: b", "# x", "*x", `""`, ""} {
		t.Run(s, func(t *testing.T) {
			cfg := Default()
			cfg.ServerURL = s
			cfg.Database.Postgres.Host = s
			cfg.DNSConfig.Nameservers.Global = []string{s}
			cfg.OIDC.ExtraParams = map[string]string{"prompt": s}

			for _, docs := range []bool{true, false} {
				out, err := GenerateExample(&cfg, ExampleOptions{Docs: docs})
				require.NoError(t, err)

				if diff := gocmp.Diff(&cfg, loadGenerated(t, out), roundTripOpts); diff != "" {
					t.Errorf("loads as (-written +loaded):\n%s", diff)
				}
			}
		})
	}

	t.Run("typed", func(t *testing.T) {
		cfg := Default()
		cfg.UnixSocketPermission = 0o770
		cfg.TLS.ACME.HTTPListen = ":http"
		cfg.DNSConfig.Nameservers.Split = map[string][]string{
			"corp.example.com": {"192.0.2.53"},
			"a.example.net":    {"198.51.100.53", "2001:db8::53"},
			"z.example.org":    {},
		}

		out, err := GenerateExample(&cfg, ExampleOptions{})
		require.NoError(t, err)

		if diff := gocmp.Diff(&cfg, loadGenerated(t, out), roundTripOpts); diff != "" {
			t.Errorf("loads as (-written +loaded):\n%s", diff)
		}

		assert.Contains(t, string(out), `unix_socket_permission: "0770"`)
		assert.Less(t, strings.Index(string(out), "a.example.net"), strings.Index(string(out), "corp.example.com"))
		assert.Less(t, strings.Index(string(out), "corp.example.com"), strings.Index(string(out), "z.example.org"))
	})
}

// TestGenerateExampleRedacts: redacted, the example holds no credential,
// with docs too, and keeps file: references; unredacted, it holds them.
func TestGenerateExampleRedacts(t *testing.T) {
	for _, tt := range redactTests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := redactConfig(tt.provider)

			out, err := GenerateExample(&cfg, ExampleOptions{Docs: true, Redact: true})
			require.NoError(t, err)

			for _, h := range append(slices.Clone(redactHidden), tt.hidden...) {
				assert.NotContains(t, string(out), h)
			}

			for _, s := range append(slices.Clone(redactShown), tt.shown...) {
				assert.Contains(t, string(out), s)
			}

			raw, err := GenerateExample(&cfg, ExampleOptions{Docs: true})
			require.NoError(t, err)

			for _, s := range append([]string{"marker-oidc-secret", "marker-pg-pass", "marker-server-pass", "marker-issuer-pass"}, tt.hidden...) {
				assert.Contains(t, string(raw), s)
			}
		})
	}

	for _, tt := range serverURLRedactTests {
		t.Run(tt.serverURL, func(t *testing.T) {
			cfg := Default()
			cfg.ServerURL = tt.serverURL

			out, err := GenerateExample(&cfg, ExampleOptions{Docs: true, Redact: true})
			require.NoError(t, err)
			assert.NotContains(t, string(out), "marker")
			assert.Contains(t, string(out), tt.shown)

			raw, err := GenerateExample(&cfg, ExampleOptions{Docs: true})
			require.NoError(t, err)
			assert.Contains(t, string(raw), tt.serverURL)
		})
	}
}

// TestGenerateExampleOmitClientOnly: a server's configuration leaves out
// the cli section and still loads; the example keeps it.
func TestGenerateExampleOmitClientOnly(t *testing.T) {
	for _, tt := range []struct {
		name    string
		omit    bool
		wantCLI bool
	}{
		{name: "example", wantCLI: true},
		{name: "server", omit: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Default()

			out, err := GenerateExample(&cfg, ExampleOptions{Docs: true, OmitClientOnly: tt.omit})
			require.NoError(t, err)

			top, leaves := exampleKeys(t, out)
			assert.Equal(t, tt.wantCLI, slices.Contains(top, "cli"))
			assert.Equal(t, tt.wantCLI, slices.ContainsFunc(leaves, clientOnly))

			if diff := gocmp.Diff(&cfg, loadGenerated(t, out), roundTripOpts); diff != "" {
				t.Errorf("loads as (-want +loaded):\n%s", diff)
			}
		})
	}
}

// TestGenerateExampleSubtree: a subtree holds its own keys under its
// sections, nothing else.
func TestGenerateExampleSubtree(t *testing.T) {
	cfg := Default()

	for _, tt := range []struct {
		root string
		want string
	}{
		{root: "dns.nameservers", want: "dns:\n  nameservers:\n    global: []\n    split: {}\n"},
		{root: "server_url", want: "server_url: \"\"\n"},
		{root: "log", want: "log:\n  level: info\n  format: text\n"},
	} {
		t.Run(tt.root, func(t *testing.T) {
			out, err := exampleYAML(&cfg, ExampleOptions{}, tt.root)
			require.NoError(t, err)
			assert.Equal(t, tt.want, string(out))
		})
	}
}

// TestGenerateExampleMinimal: the minimal example holds only the keys every
// server must set, under their sections; it and the full example, with
// server_url set, load without warnings and validate.
func TestGenerateExampleMinimal(t *testing.T) {
	d := Default()

	tests := []struct {
		name       string
		opts       ExampleOptions
		wantExact  string // all of the output, when set
		wantPrefix string
		wantText   string
		wantKeys   []string // top-level keys and leaves, when set
	}{
		{name: "minimal", opts: ExampleOptions{Minimal: true}, wantExact: "server_url: \"\"\n"},
		{
			name:       "minimal docs",
			opts:       ExampleOptions{Docs: true, Minimal: true},
			wantPrefix: minimalHeader + "\n",
			wantText:   "Required. Example: https://headscale.example.com",
			wantKeys:   []string{"server_url"},
		},
		{name: "full docs", opts: ExampleOptions{Docs: true}, wantPrefix: exampleHeader + "\n"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out, err := GenerateExample(&d, tt.opts)
			require.NoError(t, err)

			text := string(out)

			if tt.wantExact != "" {
				assert.Equal(t, tt.wantExact, text)
			}

			assert.True(t, strings.HasPrefix(text, tt.wantPrefix), text)
			assert.Contains(t, text, tt.wantText)

			if tt.wantKeys != nil {
				top, leaves := exampleKeys(t, out)
				assert.Equal(t, tt.wantKeys, top)
				assert.Equal(t, tt.wantKeys, leaves)
			}

			// The leading newline matches a first line too.
			require.Contains(t, "\n"+text, "\nserver_url: \"\"\n")
			set := strings.Replace("\n"+text, "\nserver_url: \"\"\n", "\nserver_url: https://headscale.example.com\n", 1)
			path := filepath.Join(t.TempDir(), "config.yaml")
			require.NoError(t, os.WriteFile(path, []byte(set), 0o600))

			l, err := Load(path, true, nil)
			require.NoError(t, err, set)
			assert.Empty(t, l.Warnings)
			assert.NoError(t, Validate(l.Config))
		})
	}

	t.Run("nested", func(t *testing.T) {
		keys, err := schema()
		require.NoError(t, err)

		for _, k := range []struct{ path, when string }{
			{path: "noise.private_key_path"},
			{path: "database.sqlite.path", when: "`database.type` is `sqlite`"},
		} {
			i := slices.IndexFunc(keys, func(ki keyInfo) bool { return ki.Path == k.path })
			require.GreaterOrEqual(t, i, 0, k.path)
			keys[i].Required, keys[i].RequiredWhen = true, k.when
		}

		out, err := exampleOf(keys, &d, ExampleOptions{Minimal: true}, "")
		require.NoError(t, err)

		top, leaves := exampleKeys(t, out)
		assert.Equal(t, []string{"server_url", "noise"}, top)
		assert.Equal(t, []string{"server_url", "noise.private_key_path"}, leaves)
	})
}
