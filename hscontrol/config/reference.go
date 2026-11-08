package config

import (
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"

	hsdns "github.com/juanfont/headscale/hscontrol/dns"
	"github.com/juanfont/headscale/hscontrol/types"
	"go.yaml.in/yaml/v3"
)

// The page's prose, around what the schema generates.
const (
	referenceHead = "# Configuration options\n\n" +
		"!!! note \"Generated page\"\n\n" +
		"    This page is generated from the doc comments in `hscontrol/types/config.go` by\n" +
		"    `go generate ./hscontrol/types/`. Edit the comments there, not this page.\n\n" +
		"Every key headscale reads, in the order `headscale generate config` prints them, with its type, default,\n" +
		"environment variable and an example for a configuration file, the environment and NixOS. Keys that no longer\n" +
		"work are listed under [Removed keys](#removed-keys). [Configuration](configuration.md) explains where headscale\n" +
		"finds its configuration, how to check it, and shows the full example.\n\n" +
		"## Conventions { #conventions }\n\n" +
		"### Value types { #types }\n\n"

	referenceEnv = "### Environment variables { #env }\n\n" +
		"Every key can also be set with an environment variable: `HEADSCALE_` and the key's path in capitals, with `_` for\n" +
		"`.`, e.g. `HEADSCALE_LOG_LEVEL` for `log.level`. Each key below names its variable. A variable wins over the\n" +
		"configuration file, which wins over the default; an empty variable counts as unset.\n\n" +
		"A list is a JSON array or, unless its values are objects, its values separated by spaces. A map is a JSON object,\n" +
		"which replaces the map in the configuration file instead of merging into it. The examples below write every list\n" +
		"and map as JSON.\n\n" +
		"A `HEADSCALE_` variable that names no key logs a warning, and one for a removed key also says what to do instead.\n" +
		"Other software uses the same prefix, so neither stops headscale.\n\n" +
		"A DNS provider setting that takes text can also be set on its own as `HEADSCALE_DNS_CHALLENGE_PROVIDER_<SETTING>`,\n" +
		"e.g. `HEADSCALE_DNS_CHALLENGE_PROVIDER_API_TOKEN`; see [`dns.challenge.provider`](#dns.challenge.provider).\n\n"

	referenceSecrets = "### Secrets { #secrets }\n\n" +
		"A secret takes the value itself or `file:<path>`, which reads it from that file. Environment variables in the path\n" +
		"are expanded, as in `file:${CREDENTIALS_DIRECTORY}/oidc_client_secret`, and whitespace around the file's contents\n" +
		"is trimmed; an empty file is an error. Headscale reads the file only where the secret is used, and\n" +
		"`headscale check config` and `headscale check all` never read it. `headscale generate config --running` and\n" +
		"`/debug/config` show a literal secret as `<redacted>` and a `file:` reference as written.\n\n"

	referenceNixSecret = "On NixOS, keep a secret out of the Nix store: load it as a systemd credential and point the key at it.\n\n" +
		"```nix\n" +
		"services.headscale.settings.oidc.client_secret = \"file:\\${CREDENTIALS_DIRECTORY}/oidc_client_secret\";\n" +
		"systemd.services.headscale.serviceConfig.LoadCredential = [ \"oidc_client_secret:/run/secrets/oidc_client_secret\" ];\n" +
		"```\n\n"

	referenceRemoved = "## Removed keys { #removed-keys }\n\n" +
		"Keys headscale no longer reads. One in the configuration file stops headscale with an error and a variable for\n" +
		"one logs a warning, each saying what to do instead, as the table does.\n\n"

	secretsDir = "file:/run/secrets/"
)

var (
	backtickedKey = regexp.MustCompile("`[a-z0-9_.]+`")
	dottedName    = regexp.MustCompile(`\b[a-z][a-z0-9_]*(\.([a-z0-9_]+|\*))+`)
	shellWord     = regexp.MustCompile(`^[A-Za-z0-9@%+=:,./_-]+$`)
)

// reference is the page being written.
type reference struct {
	strings.Builder

	keys  []keyInfo
	paths map[string]bool
}

// GenerateReference is the configuration reference page,
// docs/ref/configuration-options.md: the conventions, every node of
// [types.ConfigTree] with its type, default, variable and examples, and
// the removed keys.
func GenerateReference() ([]byte, error) {
	keys, err := schema()
	if err != nil {
		return nil, err
	}

	r := &reference{keys: keys, paths: map[string]bool{}}
	for _, k := range keys {
		r.paths[k.Path] = true
	}

	r.WriteString(referenceHead)
	r.types()
	r.WriteString(referenceEnv)
	r.secrets(keys)

	for _, k := range keys {
		err := r.key(k)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", k.Path, err)
		}
	}

	r.removed()

	return []byte(strings.TrimSuffix(r.String(), "\n")), nil
}

// types writes the value-type legend; a row a Type line links carries
// the anchor.
func (r *reference) types() {
	linked := map[string]bool{}
	for _, k := range r.keys {
		linked[k.Type.Anchor] = true
	}

	rows := make([][]string, 0, len(leafTypes))

	for _, t := range leafTypes {
		label := t.Label
		if id := "type-" + strings.ReplaceAll(t.Label, " ", "-"); linked["#"+id] {
			label = `<span id="` + id + `"></span>` + label
		}

		rows = append(rows, []string{label, t.Format, t.Sample})
	}

	r.table([]string{"Type", "Format", "Example"}, rows)
}

func (r *reference) secrets(keys []keyInfo) {
	var names []string

	for _, k := range keys {
		if k.Field.Type == secretType {
			names = append(names, r.link(k.Path))
		}
	}

	r.WriteString(referenceSecrets)
	fmt.Fprintf(r, "The secrets are %s and every string setting of %s.\n\n", strings.Join(names, ", "), r.link(providerKey))
	r.WriteString(referenceNixSecret)
}

// key writes k's heading and block.
func (r *reference) key(k keyInfo) error {
	name := k.Path[strings.LastIndex(k.Path, ".")+1:]
	fmt.Fprintf(r, "%s `%s` { #%s data-toc-label=\"%s\" }\n\n", strings.Repeat("#", 2+strings.Count(k.Path, ".")), k.Path, k.Path, name)

	if k.Section {
		r.paragraph(r.prose(k.Doc, k.Path))
		r.replaces(k)

		example, err := exampleOf(r.keys, new(Default()), ExampleOptions{}, k.Path)
		if err != nil {
			return err
		}

		fmt.Fprintf(r, "??? example \"All `%s` keys and defaults\"\n\n", k.Path)
		r.code("yaml", string(example))

		return nil
	}

	err := r.facts(k)
	if err != nil {
		return err
	}

	r.paragraph(r.prose(k.Doc, k.Path))
	r.details(k)

	return r.examples(k)
}

// facts writes k's Type, Default and Env lines.
func (r *reference) facts(k keyInfo) error {
	typ := "[" + k.Type.Label + "](" + k.Type.Anchor + ")"
	if len(k.Type.Enum) > 0 {
		typ += ": `" + strings.Join(k.Type.Enum, "`, `") + "`"
	}

	def := "- **Required**"

	if !k.Required || k.RequiredWhen != "" {
		v, err := flowYAML(k.Default)
		if err != nil {
			return err
		}

		def = "- **Default:** `" + v + "`"
		if k.DefaultText != "" {
			def += " (" + k.DefaultText + ")"
		}

		if k.RequiredWhen != "" {
			def += "; required when " + r.prose(k.RequiredWhen, k.Path)
		}
	}

	env := "`" + k.Env + "`"
	if k.Type.Env != "" {
		env += " ([" + k.Type.Env + "](#env))"
	}

	fmt.Fprintf(r, "- **Type:** %s\n%s\n- **Env:** %s\n\n", typ, def, env)

	return nil
}

// details writes what k's type adds to its doc: the meaning of each enum
// value, the fields of a DNS record and the DNS providers. An open map's
// key case is its doc's to state.
func (r *reference) details(k keyInfo) {
	values := make([][]string, 0, len(k.Type.Enum))

	for _, v := range k.Type.Enum {
		values = append(values, []string{"`" + v + "`", r.prose(types.ConfigValueDoc(k.Field.Type, v), k.Path)})
	}

	if slices.ContainsFunc(values, func(row []string) bool { return row[1] != "" }) {
		r.table([]string{"Value", "Meaning"}, values)
	}

	if k.Field.Type == recordsType {
		fields := make([][]string, 0, len(dnsRecordFields))
		for _, f := range dnsRecordFields {
			fields = append(fields, []string{"`" + f.Name + "`", "[string](#type-string)", r.prose(f.Doc, k.Path)})
		}

		r.table([]string{"Field", "Type", "Description"}, fields)
	}

	if k.Path == providerKey {
		names := hsdns.ProviderNames()
		providers := make([][]string, 0, len(names))

		for _, p := range names {
			providers = append(providers, []string{"`" + p + "`", "`" + strings.Join(hsdns.SettingNames(p), "`, `") + "`"})
		}

		r.table([]string{"Provider", "Settings"}, providers)
		// The variable holds text, so an object setting cannot have one.
		r.paragraph("Each text setting can also be set on its own as `HEADSCALE_DNS_CHALLENGE_PROVIDER_<SETTING>`, e.g. " +
			"`HEADSCALE_DNS_CHALLENGE_PROVIDER_API_TOKEN`, which wins over the same setting in `" + k.Env + "` and in the configuration file. " +
			"An object setting, such as the `config` of `acmedns`, goes inside the JSON object of `" + k.Env + "`; " +
			"see [Environment variables](dns.md#environment-variables).")
	}
}

// examples writes k's example as a file, a variable and, for a key the
// server reads, NixOS settings, then the removed keys it replaces.
func (r *reference) examples(k keyInfo) error {
	file, err := yamlText(nest(k.Path, k.Example))
	if err != nil {
		return err
	}

	r.WriteString("=== \"YAML\"\n\n")
	r.code("yaml", file)
	r.WriteString("=== \"Environment\"\n\n")
	r.code("shell", envLine(k.Env, k.Example))

	if !clientOnly(k.Path) {
		var creds []string

		nix := "services.headscale.settings." + k.Path + " = " + nixLiteral(credentials(k.Path, k.Example, &creds), 0) + ";\n"
		if len(creds) > 0 {
			nix += "systemd.services.headscale.serviceConfig.LoadCredential = [ \"" + strings.Join(creds, "\" \"") + "\" ];\n"
		}

		r.WriteString("=== \"NixOS\"\n\n")
		r.code("nix", nix)
	}

	r.replaces(k)

	return nil
}

// credentials is v, the example of the key at path, with each
// file:/run/secrets/ reference, at any map depth, read from the systemd
// credential named for its key instead; it appends each LoadCredential
// entry to creds, in key order.
func credentials(path string, v any, creds *[]string) any {
	switch x := v.(type) {
	case string:
		if !strings.HasPrefix(x, secretsDir) {
			return x
		}

		name := credentialName(path)
		*creds = append(*creds, name+":"+strings.TrimPrefix(x, "file:"))

		return "file:${CREDENTIALS_DIRECTORY}/" + name
	case map[string]any:
		out := make(map[string]any, len(x))
		for _, key := range slices.Sorted(maps.Keys(x)) {
			out[key] = credentials(path+"."+key, x[key], creds)
		}

		return out
	}

	return v
}

func (r *reference) replaces(k keyInfo) {
	lines := make([]string, 0, len(k.Replaces))
	for _, old := range k.Replaces {
		lines = append(lines, "Replaces `"+old.Old+"` ([removed](#"+old.Old+")).")
	}

	r.paragraph(strings.Join(lines, "\n"))
}

// removed writes the removed-keys table: each row's first cell the
// anchor of its key, its last the hint the load error gives.
func (r *reference) removed() {
	type row struct {
		old   string
		cells []string
	}

	rows := make([]row, 0, len(removedKeys)+1)

	// The provider's <setting>_path form is matched by name, not listed.
	provider, _ := removedProviderPath(providerKey + ".<setting>_path")

	for _, k := range append(slices.Clone(removedKeys), provider) {
		k.Hint = r.hint(k.Hint)
		id := strings.NewReplacer("<", "", ">", "").Replace(k.Old)
		rows = append(rows, row{k.Old, []string{`<span id="` + id + `"></span>` + "`" + k.Old + "`", k.Since, k.hintAs(r.keyRef, "%s: `%s`")}})
	}

	slices.SortFunc(rows, func(a, b row) int { return strings.Compare(a.old, b.old) })

	table := make([][]string, 0, len(rows))
	for _, row := range rows {
		table = append(table, row.cells)
	}

	r.WriteString(referenceRemoved)
	r.table([]string{"Key", "Removed in", "What to do"}, table)
}

// topicPrefix starts the docs links in field comments. YAML and Nix need
// them absolute; the page links its own version instead (Decision 17).
const topicPrefix = "https://headscale.net/stable/ref/"

// relativeTopicLinks rewrites each topicPrefix + "<page>/[#frag]" in doc
// to "<page>.md[#frag]".
func relativeTopicLinks(doc string) string {
	var b strings.Builder

	for {
		before, after, found := strings.Cut(doc, topicPrefix)
		b.WriteString(before)

		if !found {
			return b.String()
		}

		path := after[:runEnd(after, isPathRune)]

		slash := strings.LastIndexByte(path, '/')
		if slash <= 0 {
			b.WriteString(topicPrefix)

			doc = after

			continue
		}

		b.WriteString(path[:slash] + ".md")

		doc = after[slash+1:]
		if frag, ok := strings.CutPrefix(doc, "#"); ok {
			if n := runEnd(frag, isFragRune); n > 0 {
				b.WriteString("#" + frag[:n])

				doc = frag[n:]
			}
		}
	}
}

// runEnd is the length of s's leading run of runes that keep returns true for.
func runEnd(s string, keep func(rune) bool) int {
	if n := strings.IndexFunc(s, func(c rune) bool { return !keep(c) }); n >= 0 {
		return n
	}

	return len(s)
}

func isFragRune(c rune) bool {
	return c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_' || c == '-'
}

func isPathRune(c rune) bool {
	return isFragRune(c) || c == '/'
}

// prose is a doc as the page prints it: each backticked key but self
// linked to its heading, each docs link relative.
func (r *reference) prose(doc, self string) string {
	doc = relativeTopicLinks(doc)

	return backtickedKey.ReplaceAllStringFunc(doc, func(span string) string {
		key := strings.Trim(span, "`")
		if !r.paths[key] || key == self {
			return span
		}

		return "[" + span + "](#" + key + ")"
	})
}

// hint is a removed key's free-text hint as Markdown: each key linked,
// each key pattern such as dns_config.* as code.
func (r *reference) hint(text string) string {
	return dottedName.ReplaceAllStringFunc(text, func(name string) string {
		switch {
		case r.paths[name]:
			return r.link(name)
		case strings.HasSuffix(name, ".*"):
			return "`" + name + "`"
		}

		return name
	})
}

func (r *reference) link(key string) string {
	return "[`" + key + "`](#" + key + ")"
}

// keyRef is key as code, linked to its heading or, for a placeholder
// such as dns.challenge.provider.<setting>, to its map's.
func (r *reference) keyRef(key string) string {
	target, _, _ := strings.Cut(key, ".<")
	if !r.paths[target] {
		return "`" + key + "`"
	}

	return "[`" + key + "`](#" + target + ")"
}

func (r *reference) paragraph(text string) {
	if text != "" {
		r.WriteString(text + "\n\n")
	}
}

// code writes body, which ends in a newline, as a fenced block indented
// into the admonition or tab above it.
func (r *reference) code(lang, body string) {
	const indent = "    "

	r.WriteString(indent + "```" + lang + "\n")

	for l := range strings.Lines(body) {
		if l != "\n" {
			r.WriteString(indent)
		}

		r.WriteString(l)
	}

	r.WriteString(indent + "```\n\n")
}

// table writes a table as mdformat does: each cell padded to its
// column's width in runes, | escaped.
func (r *reference) table(header []string, body [][]string) {
	rows := append([][]string{header}, body...)
	widths := make([]int, len(header))
	cells := make([][]string, len(rows))

	for i, row := range rows {
		for j, c := range row {
			c = strings.ReplaceAll(c, "|", `\|`)
			cells[i] = append(cells[i], c)
			widths[j] = max(widths[j], 3, utf8.RuneCountInString(c))
		}
	}

	line := func(cells []string) {
		for j, c := range cells {
			r.WriteString("| " + c + strings.Repeat(" ", widths[j]-utf8.RuneCountInString(c)) + " ")
		}

		r.WriteString("|\n")
	}

	line(cells[0])

	delimiter := make([]string, len(widths))
	for j, w := range widths {
		delimiter[j] = strings.Repeat("-", w)
	}

	line(delimiter)

	for _, row := range cells[1:] {
		line(row)
	}

	r.WriteString("\n")
}

// yamlText is v as a YAML file indented as GenerateExample indents.
func yamlText(v any) (string, error) {
	var b strings.Builder

	enc := yaml.NewEncoder(&b)
	enc.SetIndent(2)

	err := enc.Encode(v)
	if err != nil {
		return "", err
	}

	err = enc.Close()

	return b.String(), err
}

// envLine is the shell line setting the variable env to v, exported so
// the headscale started next reads it.
func envLine(env string, v any) string {
	return "export " + env + "=" + shellQuote(envValue(v)) + "\n"
}

// shellQuote is s as one POSIX shell word: as is when no character is
// special, else single-quoted.
func shellQuote(s string) string {
	if shellWord.MatchString(s) {
		return s
	}

	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
