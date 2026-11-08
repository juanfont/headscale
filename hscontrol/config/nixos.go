package config

import (
	"errors"
	"fmt"
	"maps"
	"reflect"
	"regexp"
	"slices"
	"strings"

	"github.com/juanfont/headscale/hscontrol/types"
	"tailscale.com/tailcfg"
)

const nixHeader = "# Generated from hscontrol/types/config.go by `headscale generate nixos-options`; do not edit.\n"

// nixTypes names the option types nixpkgs lacks, so an IP or a listen
// address of the wrong shape fails evaluation at the option.
const nixTypes = `let
  o4 = "(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])";
  ip4 = "${o4}(\\.${o4}){3}";
  # Two colons at least, so host:port is not taken for one.
  ip6 = "[0-9A-Fa-f.]*:[0-9A-Fa-f.]*:[0-9A-Fa-f:.]*";
  shape = description: pattern: lib.types.strMatching pattern // { inherit description; };
  t = {
    ip = shape "IP address" "(${ip4}|${ip6}(%[^%]+)?)?";
    prefix = shape "IP prefix in CIDR notation" "(${ip4}/([0-9]|[12][0-9]|3[0-2])|${ip6}/([0-9]|[1-9][0-9]|1[01][0-9]|12[0-8]))?";
    listenAddr = shape "host:port address" "((\\[[^]]*]|[^]:[]*):([0-9]+|https?))?";
    httpURL = shape "http:// or https:// URL" "(https?://[^/?#]+([/?#].*)?)?";
    duration = shape "duration such as 1h30m" "[-+]?(0|(([0-9]+(\\.[0-9]*)?|\\.[0-9]+)(ns|us|µs|μs|ms|s|m|h|d|w|y))+)";
    fileMode = shape "quoted octal file mode" "(0[oO])?0*[0-7]{1,3}";
    secretFile = shape "file: reference to a secret" "(file:.+)?";
    readFile = lib.types.either lib.types.path (lib.types.enum [ "" ]);
    stateFile = lib.types.either lib.types.externalPath (lib.types.enum [ "" ]);
  };
in
`

var (
	errNoNixType = errors.New("no NixOS type")

	recordsType = reflect.TypeFor[[]tailcfg.DNSRecord]()
	secretType  = reflect.TypeFor[types.Secret]()
	nixIdent    = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_'-]*$`)
	nixKeywords = []string{"assert", "else", "if", "in", "inherit", "let", "or", "rec", "then", "with"}

	nixQuoted = strings.NewReplacer(`\`, `\\`, `"`, `\"`, "${", `\${`, "\n", `\n`, "\r", `\r`, "\t", `\t`)
	// A ' before an escape starting with '' would join it, so it is
	// escaped itself.
	nixIndented = strings.NewReplacer("'${", `''\'''${`, "''", "'''", "${", "''${")
)

// GenerateNixOptions is the NixOS options of services.headscale.settings:
// a function of lib only, one option per key, nested as the file nests
// keys. release stamps a release's version and commit; nil marks the
// development tree.
func GenerateNixOptions(release *types.VersionInfo) ([]byte, error) {
	keys, err := schema()
	if err != nil {
		return nil, err
	}

	var b strings.Builder

	b.WriteString(nixHeader)

	if release == nil {
		b.WriteString("# headscale development tree, not a release\n")
	} else {
		fmt.Fprintf(&b, "# headscale %s, commit %s\n", release.Version, release.Commit)
	}

	b.WriteString("# Options for services.headscale.settings, not a module: import ./options.generated.nix { inherit lib; }\n{ lib, ... }:\n" + nixTypes + "{\n")

	var open []string // the sections around the key, outermost first

	for _, k := range keys {
		if clientOnly(k.Path) {
			continue
		}

		for len(open) > 0 && !strings.HasPrefix(k.Path, open[len(open)-1]+".") {
			open = open[:len(open)-1]
			fmt.Fprintf(&b, "%s};\n", strings.Repeat("  ", len(open)+1))
		}

		indent := 2 * (len(open) + 1)
		name := nixAttr(k.Path[strings.LastIndex(k.Path, ".")+1:])

		if k.Section {
			fmt.Fprintf(&b, "%s%s = {\n", strings.Repeat(" ", indent), name)

			open = append(open, k.Path)

			continue
		}

		opt, err := nixOption(k, indent)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", k.Path, err)
		}

		fmt.Fprintf(&b, "%s%s = %s;\n", strings.Repeat(" ", indent), name, opt)
	}

	for i := len(open); i > 0; i-- {
		fmt.Fprintf(&b, "%s};\n", strings.Repeat("  ", i))
	}

	b.WriteString("}\n")

	return []byte(b.String()), nil
}

// nixOption is the lib.mkOption call for leaf k, on a line indented by
// indent.
func nixOption(k keyInfo, indent int) (string, error) {
	in := indent + 2

	var typ string

	switch {
	case len(k.Type.Enum) > 0:
		// Every enum decodes "" as its default.
		typ = "lib.types.enum " + nixLiteral(append(toAny(k.Type.Enum), ""), in)
	case k.Type.Nix != "":
		typ = k.Type.Nix
	case k.Field.Type == recordsType:
		// The record fields' examples are the first example record's.
		var first map[string]any
		if records, _ := k.Example.([]any); len(records) > 0 {
			first, _ = records[0].(map[string]any)
		}

		if first == nil {
			return "", fmt.Errorf("%w: the example holds no record", errNoNixType)
		}

		var fields strings.Builder

		pad := strings.Repeat(" ", in+6)

		for _, f := range dnsRecordFields {
			attrs := [][2]string{{"type", f.Nix}}
			if f.Enum != nil {
				attrs[0][1] = "lib.types.enum " + nixLiteral(toAny(f.Enum), in+8)
			}

			if f.Default != nil {
				attrs = append(attrs, [2]string{"default", nixLiteral(f.Default, in+8)})
			}

			attrs = append(attrs,
				[2]string{"description", nixLiteral(f.Doc+"\n", in+8)},
				[2]string{"example", nixLiteral(first[f.Name], in+8)},
			)

			fmt.Fprintf(&fields, "%s%s = %s;\n", pad, f.Name, mkOption(in+6, attrs))
		}

		typ = fmt.Sprintf("lib.types.listOf (\n%[1]s  lib.types.submodule {\n%[1]s    options = {\n%[2]s%[1]s    };\n%[1]s  }\n%[1]s)",
			strings.Repeat(" ", in), fields.String())
	default:
		return "", fmt.Errorf("%w for %s", errNoNixType, k.Field.Type)
	}

	attrs := [][2]string{{"type", typ}}

	if !k.Required || k.RequiredWhen != "" {
		attrs = append(attrs, [2]string{"default", nixLiteral(k.Default, in)})
	}

	if k.DefaultText != "" {
		attrs = append(attrs, [2]string{"defaultText", "lib.literalMD " + nixLiteral(k.DefaultText, in)})
	}

	attrs = append(attrs,
		[2]string{"description", nixLiteral(nixDescription(k)+"\n", in)},
		[2]string{"example", nixLiteral(k.Example, in)},
	)

	return mkOption(indent, attrs), nil
}

// mkOption is a lib.mkOption call on a line indented by indent, of
// attribute names and Nix values.
func mkOption(indent int, attrs [][2]string) string {
	var b strings.Builder

	b.WriteString("lib.mkOption {\n")

	for _, a := range attrs {
		fmt.Fprintf(&b, "%s  %s = %s;\n", strings.Repeat(" ", indent), a[0], a[1])
	}

	return b.String() + strings.Repeat(" ", indent) + "}"
}

// nixDescription is k's documentation in Markdown: its doc, its enum
// values, whether it is required, for a path or a secret what the NixOS
// type accepts and, for a secret, how NixOS passes it as a file.
func nixDescription(k keyInfo) string {
	parts := []string{k.Doc}

	if len(k.Type.Enum) > 0 {
		var values strings.Builder

		values.WriteString("One of:\n")

		for _, v := range k.Type.Enum {
			fmt.Fprintf(&values, "\n- `%s`", v)

			if doc := types.ConfigValueDoc(k.Field.Type, v); doc != "" {
				values.WriteString(": " + doc)
			}
		}

		parts = append(parts, values.String())
	}

	switch {
	case k.Required && k.RequiredWhen == "":
		parts = append(parts, "Required.")
	case k.Required:
		parts = append(parts, "Required when "+k.RequiredWhen+".")
	}

	switch {
	case k.Field.Type == secretType:
		parts = append(parts, nixCredential("the value must be `\"\"` or `file:<path>`", credentialName(k.Path), "the secret", "this option"))
	case k.Path == providerKey:
		parts = append(parts, nixCredential("keep a secret setting out of the Nix store", credentialName(k.Path+".<setting>"), "it", "the setting")+" `name` is not a secret.")
	case k.Field.Tag.Get("nix") == "path":
		parts = append(parts, "On NixOS, paths must be absolute.")
	case k.Field.Tag.Get("nix") == "external":
		parts = append(parts, "On NixOS, paths must be absolute and outside the Nix store.")
	}

	return strings.Join(parts, "\n\n")
}

// nixCredential is rule on NixOS, then how to keep what out of the Nix
// store: as the systemd credential name, which target reads with file:.
func nixCredential(rule, name, what, target string) string {
	return "On NixOS, " + rule + ": load " + what + " as a systemd credential with " +
		"`systemd.services.headscale.serviceConfig.LoadCredential = [ \"" + name + ":/run/secrets/" + name + "\" ];` " +
		"and set " + target + " to `\"file:\\${CREDENTIALS_DIRECTORY}/" + name + "\"`."
}

// credentialName is the systemd credential NixOS loads the secret at path
// as.
func credentialName(path string) string {
	return strings.ReplaceAll(path, ".", "_")
}

// nixLiteral is v, as plainFields prints values, as a Nix expression whose
// first line continues one indented by indent. A non-empty list or
// attribute set has one element per line, an attribute name is quoted
// unless it is an identifier, and a string ending in a newline is an
// indented string, as nixfmt leaves them.
func nixLiteral(v any, indent int) string {
	pad := strings.Repeat(" ", indent+2)

	switch x := v.(type) {
	case nil:
		return "null"
	case string:
		if !indentable(x) {
			return `"` + nixQuoted.Replace(x) + `"`
		}

		var b strings.Builder

		b.WriteString("''\n")

		for l := range strings.Lines(x) {
			if l != "\n" {
				b.WriteString(pad)
			}

			b.WriteString(nixIndented.Replace(l))
		}

		return b.String() + strings.Repeat(" ", indent) + "''"
	case []any:
		if len(x) == 0 {
			return "[ ]"
		}

		var b strings.Builder

		b.WriteString("[\n")

		for _, e := range x {
			b.WriteString(pad + nixLiteral(e, indent+2) + "\n")
		}

		return b.String() + strings.Repeat(" ", indent) + "]"
	case map[string]any:
		if len(x) == 0 {
			return "{ }"
		}

		var b strings.Builder

		b.WriteString("{\n")

		for _, k := range slices.Sorted(maps.Keys(x)) {
			fmt.Fprintf(&b, "%s%s = %s;\n", pad, nixAttr(k), nixLiteral(x[k], indent+2))
		}

		return b.String() + strings.Repeat(" ", indent) + "}"
	}

	// shortcut: other values (bool, int, float64) print as Go does, which
	// Nix reads alike; parenthesised, a negative number stays one list
	// element. A float in exponent form (1e+21) is no Nix literal; format
	// floats with a decimal point once an example holds one.
	s := fmt.Sprint(v)
	if strings.HasPrefix(s, "-") {
		return "(" + s + ")"
	}

	return s
}

// indentable reports whether s reads back as written from an indented
// string: it ends in a newline, which the closing line keeps, and a line
// starts at the indentation Nix strips. Lines with trailing whitespace or
// a carriage return stay quoted.
func indentable(s string) bool {
	lines := strings.Split(strings.TrimSuffix(s, "\n"), "\n")

	return strings.HasSuffix(s, "\n") && !strings.Contains(s, "\r") &&
		!slices.ContainsFunc(lines, func(l string) bool { return strings.TrimRight(l, " \t") != l }) &&
		slices.ContainsFunc(lines, func(l string) bool { return l != "" && l[0] != ' ' })
}

// nixAttr is name as an attribute name, which takes no indented string.
func nixAttr(name string) string {
	if nixIdent.MatchString(name) && !slices.Contains(nixKeywords, name) {
		return name
	}

	return `"` + nixQuoted.Replace(name) + `"`
}

func toAny(s []string) []any {
	out := make([]any, len(s))
	for i, v := range s {
		out[i] = v
	}

	return out
}
