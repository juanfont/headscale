package config

import (
	"os"
	"os/exec"
	"regexp"
	"slices"
	"strings"
	"testing"
	"unicode/utf8"

	gocmp "github.com/google/go-cmp/cmp"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	refHeading = regexp.MustCompile("(?m)^(#+) `([^`]+)` \\{ #(\\S+) data-toc-label=\"([^\"]+)\" \\}$")
	refAnchor  = regexp.MustCompile(`\{ #([^ }]+)|<span id="([^"]+)"></span>`)
	refLink    = regexp.MustCompile(`\]\(#([^)]+)\)`)
	refFence   = regexp.MustCompile("(?ms)^ *```.*?^ *```$")
	refCode    = regexp.MustCompile("`[^`]*`")
	refBareTag = regexp.MustCompile(`<[A-Za-z/][^>]*>`)
)

func referencePage(t *testing.T) string {
	t.Helper()

	page, err := GenerateReference()
	require.NoError(t, err)

	return string(page)
}

// keyBlocks are page's blocks by key path, each from its heading to the
// next heading.
func keyBlocks(page string) map[string]string {
	blocks := map[string]string{}

	for _, m := range refHeading.FindAllStringSubmatchIndex(page, -1) {
		block := page[m[1]:]
		if i := strings.Index(block, "\n#"); i >= 0 {
			block = block[:i]
		}

		blocks[page[m[4]:m[5]]] = block
	}

	return blocks
}

func TestReference(t *testing.T) {
	page := referencePage(t)
	d := Default()
	tree := types.ConfigTree(&d)

	t.Run("headings", func(t *testing.T) {
		want := make([]string, 0, len(tree))

		for _, f := range tree {
			leaf := f.Path[strings.LastIndex(f.Path, ".")+1:]
			want = append(want, strings.Repeat("#", 2+strings.Count(f.Path, "."))+" "+f.Path+" #"+f.Path+" "+leaf)
		}

		headings := refHeading.FindAllStringSubmatch(page, -1)
		got := make([]string, 0, len(headings))

		for _, m := range headings {
			got = append(got, m[1]+" "+m[2]+" #"+m[3]+" "+m[4])
		}

		if diff := gocmp.Diff(want, got); diff != "" {
			t.Errorf("headings (-want +got):\n%s", diff)
		}

		require.Contains(t, page, "#### `dns.nameservers.split` { #dns.nameservers.split data-toc-label=\"split\" }\n")
	})

	blocks := keyBlocks(page)

	for _, f := range tree {
		if f.Section {
			continue
		}

		t.Run(f.Path, func(t *testing.T) {
			block := blocks[f.Path]
			require.Contains(t, block, "\n- **Type:** [")
			require.Regexp(t, `\n- \*\*(Default:\*\* |Required\*\*\n)`, block)
			require.Contains(t, block, "\n- **Env:** `"+configEnvName(f.Path)+"`")
		})
	}

	t.Run("removed rows", func(t *testing.T) {
		_, removed, ok := strings.Cut(page, "\n## Removed keys { #removed-keys }\n")
		require.True(t, ok)

		for _, r := range removedKeys {
			require.Contains(t, removed, "| <span id=\""+r.Old+"\"></span>`"+r.Old+"` ")
		}

		require.Contains(t, removed, "| <span id=\"dns.challenge.provider.setting_path\"></span>`dns.challenge.provider.<setting>_path` ")
		require.Equal(t, len(removedKeys)+1, strings.Count(removed, "<span id="))

		// The last cell is the hint the load error gives, keys linked.
		for _, row := range []string{
			"| use [`log.format`](#log.format): `json` ",
			"| use [`prefixes.v4`](#prefixes.v4) and [`prefixes.v6`](#prefixes.v6) ",
			"| remove `oidc.user`; see the CHANGELOG for context ",
			"| use [`dns.challenge.provider.<setting>`](#dns.challenge.provider): `file:<path>` ",
			"| move every `dns_config.*` key to dns (nameservers to [`dns.nameservers.global`](#dns.nameservers.global), ",
		} {
			require.Contains(t, removed, row)
		}
	})

	t.Run("anchors", func(t *testing.T) {
		matches := refAnchor.FindAllStringSubmatch(page, -1)
		ids := make([]string, 0, len(matches))

		for _, m := range matches {
			ids = append(ids, m[1]+m[2])
		}

		for _, id := range []string{"conventions", "types", "env", "secrets", "removed-keys", "type-file-mode", "type-URL", "type-list", "type-map"} {
			require.Contains(t, ids, id)
		}

		seen := map[string]bool{}
		for _, id := range ids {
			require.False(t, seen[id], "duplicate anchor %s", id)
			seen[id] = true
		}

		linked := map[string]bool{}

		for _, m := range refLink.FindAllStringSubmatch(page, -1) {
			assert.True(t, seen[m[1]], "link to missing anchor #%s", m[1])
			linked[m[1]] = true
		}

		for _, id := range ids {
			if strings.HasPrefix(id, "type-") {
				assert.True(t, linked[id], "legend id %s has no link", id)
			}
		}
	})

	t.Run("links", func(t *testing.T) {
		require.NotContains(t, page, "https://headscale.net/stable/ref/")
		require.Contains(t, page, "(dns.md#dns-01-challenge-provider)")
		require.Contains(t, page, "(api.md#remote-control)")
		// A key's doc links other keys, not itself.
		require.Contains(t, blocks["tls.key_path"], "[`tls.cert_path`](#tls.cert_path)")
		require.NotContains(t, blocks["oidc.issuer"], "](#oidc.issuer)")
	})
}

func TestRelativeTopicLinks(t *testing.T) {
	tests := []struct {
		name, doc, want string
	}{
		{"page", "See https://headscale.net/stable/ref/dns/.", "See dns.md."},
		{"fragment", "(https://headscale.net/stable/ref/oidc/#enable-pkce-recommended)", "(oidc.md#enable-pkce-recommended)"},
		{"nested page", "https://headscale.net/stable/ref/integration/reverse-proxy/", "integration/reverse-proxy.md"},
		{"two links", "https://headscale.net/stable/ref/dns/ and https://headscale.net/stable/ref/api/#remote-control", "dns.md and api.md#remote-control"},
		{"empty fragment", "https://headscale.net/stable/ref/dns/#", "dns.md#"},
		{"other host", "https://example.com/stable/ref/dns/", "https://example.com/stable/ref/dns/"},
		{"prefix only", "https://headscale.net/stable/ref/", "https://headscale.net/stable/ref/"},
		{"no link", "plain text", "plain text"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, relativeTopicLinks(tt.doc))
		})
	}
}

// TestReferenceKeys pins the parts of a key's block the schema decides.
func TestReferenceKeys(t *testing.T) {
	blocks := keyBlocks(referencePage(t))

	tests := []struct {
		path       string
		want, hide []string
	}{
		{path: "server_url", want: []string{"\n- **Required**\n", "\n    export HEADSCALE_SERVER_URL=https://headscale.example.com\n"}},
		{path: "database.type", want: []string{
			"- **Type:** [enum](#type-enum): `sqlite`, `sqlite3`, `postgres`\n",
			"- **Default:** `sqlite`\n",
			"| `postgres` | PostgreSQL, at [`database.postgres.host`](#database.postgres.host). ",
		}},
		{path: "dns.base_domain", want: []string{"- **Default:** `tailnet.internal`\n"}, hide: []string{"required"}},
		{path: "tuning.batcher_workers", want: []string{"- **Default:** `0` (three quarters of the CPU cores, at least one)\n"}},
		{path: "unix_socket_permission", want: []string{"- **Type:** [file mode](#type-file-mode)\n", "- **Default:** `\"0770\"`\n"}},
		{path: "dns.nameservers.split", want: []string{
			"- **Type:** [map of `<domain>` → list of strings](#type-map)\n",
			"- **Env:** `HEADSCALE_DNS_NAMESERVERS_SPLIT` ([JSON object](#env))\n",
			"    export HEADSCALE_DNS_NAMESERVERS_SPLIT='{\"corp.example.com\":[\"192.0.2.53\"],",
			"    services.headscale.settings.dns.nameservers.split = {\n      \"corp.example.com\" = [\n",
		}, hide: []string{"Each `<domain>` key"}},
		{path: "database.postgres.pass", want: []string{
			"- **Type:** [secret](#secrets)\n",
			"    services.headscale.settings.database.postgres.pass = \"file:\\${CREDENTIALS_DIRECTORY}/database_postgres_pass\";\n",
			"    systemd.services.headscale.serviceConfig.LoadCredential = [ \"database_postgres_pass:/run/secrets/postgres_password\" ];\n",
			"Replaces `database.postgres.password_file` ([removed](#database.postgres.password_file)).",
		}},
		{path: "dns.challenge.provider", want: []string{
			"| Provider ",
			"| `cloudflare` ",
			"Each text setting can also be set on its own as `HEADSCALE_DNS_CHALLENGE_PROVIDER_<SETTING>`",
			"An object setting, such as the `config` of `acmedns`, goes inside the JSON object of `HEADSCALE_DNS_CHALLENGE_PROVIDER`",
			"(dns.md#environment-variables)",
			"api_token = \"file:\\${CREDENTIALS_DIRECTORY}/dns_challenge_provider_api_token\";",
			"LoadCredential = [ \"dns_challenge_provider_api_token:/run/secrets/cloudflare\" ];",
		}},
		{path: "cli", want: []string{"`services.headscale.settings`"}},
		{path: "cli.api_key", want: []string{"=== \"Environment\"", "export HEADSCALE_CLI_API_KEY=file:/run/secrets/"}, hide: []string{"=== \"NixOS\"", "CREDENTIALS_DIRECTORY"}},
		{path: "dns.extra_records", want: []string{
			"- **Env:** `HEADSCALE_DNS_EXTRA_RECORDS` ([JSON array](#env))\n",
			"| Field ",
			"| `value` | [string](#type-string) | The IP address the name resolves to. ",
		}},
		{path: "dns", want: []string{
			"??? example \"All `dns` keys and defaults\"\n\n    ```yaml\n    dns:\n      magic_dns: true\n",
			"Replaces `dns_config` ([removed](#dns_config)).",
		}},
		{path: "noise.private_key_path", want: []string{
			"Replaces `private_key_path` ([removed](#private_key_path)).\nReplaces `noise_private_key_path` ([removed](#noise_private_key_path)).",
		}},
		{path: "tls.acme.hostname", want: []string{"    tls:\n      acme:\n        hostname: "}},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			for _, w := range tt.want {
				require.Contains(t, blocks[tt.path], w)
			}

			for _, h := range tt.hide {
				require.NotContains(t, blocks[tt.path], h)
			}
		})
	}

	// Built by hand, so the rendering is pinned whatever Default requires.
	t.Run("required when", func(t *testing.T) {
		k := schemaByPath(t)["dns.base_domain"]
		k.Required, k.RequiredWhen = true, "`dns.magic_dns` is true"

		r := &reference{paths: map[string]bool{"dns.magic_dns": true}}
		require.NoError(t, r.facts(k))
		require.Contains(t, r.String(), "- **Default:** `tailnet.internal`; required when [`dns.magic_dns`](#dns.magic_dns) is true\n")
	})
}

// TestOpenMapDocs: the page prints an open map's key case only through its
// doc, so the doc must state the rule the loader applies.
func TestOpenMapDocs(t *testing.T) {
	keys, err := schema()
	require.NoError(t, err)

	for _, k := range keys {
		if !k.Open {
			continue
		}

		t.Run(k.Path, func(t *testing.T) {
			if slices.Contains(caseSensitiveMaps, k.Path) {
				require.Contains(t, k.Doc, "keep their case")

				return
			}

			require.Contains(t, k.Doc, "lowercased on load")
			require.Contains(t, k.Doc, "two that differ only in case are an error")
		})
	}
}

func TestReferenceEscapes(t *testing.T) {
	page := referencePage(t)

	d := Default()
	example, err := GenerateExample(&d, ExampleOptions{Docs: true})
	require.NoError(t, err)

	// The macros plugin renders the page and the included example as Jinja.
	for name, text := range map[string]string{"page": page, "example": string(example)} {
		for _, jinja := range []string{"{{", "{%", "{#"} {
			require.NotContains(t, text, jinja, name)
		}
	}

	prose := refCode.ReplaceAllString(refFence.ReplaceAllString(page, ""), "")
	prose = regexp.MustCompile(`<span id="[^"]+"></span>`).ReplaceAllString(prose, "")
	require.Empty(t, refBareTag.FindAllString(prose, -1))

	tables := 0

	var width []int

	for line := range strings.Lines(page + "\n") {
		if !strings.HasPrefix(line, "|") {
			if len(width) > 0 {
				tables++
				require.Len(t, slices.Compact(width), 1, "rows of table %d differ in width", tables)
			}

			width = nil

			continue
		}

		width = append(width, utf8.RuneCountInString(line))
	}

	require.GreaterOrEqual(t, tables, 3)
}

// exported runs line in a clean shell and returns what a child it starts
// reads from env.
func exported(t *testing.T, line, env string) string {
	t.Helper()

	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no sh")
	}

	cmd := exec.CommandContext(t.Context(), sh, "-c", line+`sh -c 'printf %s "$`+env+`"'`)
	cmd.Env = []string{"PATH=" + os.Getenv("PATH")}

	out, err := cmd.Output()
	require.NoError(t, err, line)

	return string(out)
}

// TestReferenceEnvTabs: an Environment tab pasted into a shell reaches
// the headscale it starts.
func TestReferenceEnvTabs(t *testing.T) {
	blocks := keyBlocks(referencePage(t))
	byPath := schemaByPath(t)

	for _, path := range []string{"dns.nameservers.global", "dns.nameservers.split", "database.postgres.pass", "dns.challenge.provider"} {
		t.Run(path, func(t *testing.T) {
			_, tab, ok := strings.Cut(blocks[path], "=== \"Environment\"\n\n    ```shell\n    ")
			require.True(t, ok)

			line, _, _ := strings.Cut(tab, "\n")
			k := byPath[path]
			require.Equal(t, envValue(k.Example), exported(t, line+"\n", k.Env))
		})
	}

	t.Run("quotes", func(t *testing.T) {
		v := `it's "q" $HOME`
		require.Equal(t, v, exported(t, envLine("HEADSCALE_X", v), "HEADSCALE_X"))
	})
}

func TestShellQuote(t *testing.T) {
	tests := []struct{ in, want string }{
		{in: "abc", want: "abc"},
		{in: "file:/run/secrets/x", want: "file:/run/secrets/x"},
		{in: "a b", want: "'a b'"},
		{in: "file:${X}/y", want: "'file:${X}/y'"},
		{in: "it's", want: `'it'\''s'`},
		{in: "", want: "''"},
		{in: `["a","b"]`, want: `'["a","b"]'`},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			require.Equal(t, tt.want, shellQuote(tt.in))
		})
	}
}
