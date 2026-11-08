package config

import (
	"bytes"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/juanfont/headscale/hscontrol/types"
	"go.yaml.in/yaml/v3"
)

// ExampleOptions select what [GenerateExample] prints.
type ExampleOptions struct {
	// Docs puts each key's documentation above it, as comments.
	Docs bool
	// Redact hides secrets as [Marshal] does.
	Redact bool
	// OmitClientOnly leaves out the keys only the CLI reads, which a
	// server's configuration has no use for.
	OmitClientOnly bool
}

const (
	exampleHeader = "# Every key: https://headscale.net/stable/ref/configuration-options/\n"
	commentWidth  = 80
)

// GenerateExample is cfg as a YAML configuration file: every key, nested
// in [types.ConfigTree] order, a nil list as [] and a nil map as {}.
func GenerateExample(cfg *types.Config, opts ExampleOptions) ([]byte, error) {
	return exampleYAML(cfg, opts, "")
}

// exampleYAML is the part of [GenerateExample]'s output at the dotted
// root, under its sections; "" is all of it.
func exampleYAML(cfg *types.Config, opts ExampleOptions, root string) ([]byte, error) {
	keys, err := schema()
	if err != nil {
		return nil, err
	}

	return exampleOf(keys, cfg, opts, root)
}

// exampleOf is [exampleYAML] from keys, the result of schema.
func exampleOf(keys []keyInfo, cfg *types.Config, opts ExampleOptions, root string) ([]byte, error) {
	var err error

	values := plainFields(cfg, opts.Redact)
	top := &yaml.Node{Kind: yaml.MappingNode}
	mappings := map[string]*yaml.Node{"": top}

	for _, k := range keys {
		if root != "" && k.Path != root && !strings.HasPrefix(k.Path, root+".") && !strings.HasPrefix(root, k.Path+".") {
			continue
		}

		if opts.OmitClientOnly && clientOnly(k.Path) {
			continue
		}

		parent, name := "", k.Path
		if i := strings.LastIndex(k.Path, "."); i >= 0 {
			parent, name = k.Path[:i], k.Path[i+1:]
		}

		key := &yaml.Node{Kind: yaml.ScalarNode, Value: name}
		if opts.Docs {
			key.HeadComment, err = keyComment(k, commentWidth-2*strings.Count(k.Path, ".")-len("# "))
			if err != nil {
				return nil, err
			}
		}

		value := &yaml.Node{Kind: yaml.MappingNode}
		if k.Section {
			mappings[k.Path] = value
		} else {
			err = value.Encode(orEmpty(values[k.Path], k.Field.Type))
			if err != nil {
				return nil, err
			}
		}

		mappings[parent].Content = append(mappings[parent].Content, key, value)
	}

	var b bytes.Buffer

	if opts.Docs && root == "" {
		b.WriteString(exampleHeader)
	}

	// One document per top-level key, so blank lines can separate them.
	for i := 0; i < len(top.Content); i += 2 {
		if opts.Docs && b.Len() > 0 {
			b.WriteString("\n")
		}

		enc := yaml.NewEncoder(&b)
		enc.SetIndent(2)

		err = enc.Encode(&yaml.Node{Kind: yaml.MappingNode, Content: top.Content[i : i+2]})
		if err != nil {
			return nil, err
		}

		err = enc.Close()
		if err != nil {
			return nil, err
		}
	}

	return b.Bytes(), nil
}

// clientOnly reports whether path is read only by the headscale CLI, from
// its own configuration, so a server's configuration has no use for it.
func clientOnly(path string) bool {
	return path == "cli" || strings.HasPrefix(path, "cli.")
}

// keyComment is k's documentation as "# " lines: its doc, its enum
// values, whether it is required, and its default in words. Prose is
// wrapped to width runes; a list or code paragraph, which has an indented
// line, keeps its lines. A bare "#" separates paragraphs.
func keyComment(k keyInfo, width int) (string, error) {
	var lines []string

	add := func(text string) {
		for i, p := range strings.Split(text, "\n\n") {
			if i > 0 {
				lines = append(lines, "#")
			}

			para := strings.Split(p, "\n")
			if !slices.ContainsFunc(para, func(l string) bool { return strings.HasPrefix(l, " ") || strings.HasPrefix(l, "\t") }) {
				para = wrap(p, width)
			}

			for _, l := range para {
				lines = append(lines, "# "+l)
			}
		}
	}

	add(k.Doc)

	if len(k.Type.Enum) > 0 {
		add("One of: `" + strings.Join(k.Type.Enum, "`, `") + "`.")
	}

	switch {
	case k.Required && k.RequiredWhen == "":
		example, err := flowYAML(k.Example)
		if err != nil {
			return "", err
		}

		add("Required. Example: " + example)
	case k.Required:
		add("Required when " + k.RequiredWhen + ".")
	}

	if k.DefaultText != "" {
		add("Default: " + k.DefaultText + ".")
	}

	return strings.Join(lines, "\n"), nil
}

// wrap breaks text at spaces into lines of at most width runes; a longer
// word has a line of its own.
func wrap(text string, width int) []string {
	var lines []string

	line := ""

	for _, w := range strings.Fields(text) {
		if line != "" && utf8.RuneCountInString(line)+1+utf8.RuneCountInString(w) > width {
			lines = append(lines, line)
			line = ""
		}

		if line != "" {
			line += " "
		}

		line += w
	}

	if line != "" {
		lines = append(lines, line)
	}

	return lines
}

// flowYAML is v in YAML flow style, on one line.
func flowYAML(v any) (string, error) {
	var n yaml.Node

	err := n.Encode(v)
	if err != nil {
		return "", err
	}

	n.Style = yaml.FlowStyle

	out, err := yaml.Marshal(&n)

	return strings.TrimSpace(string(out)), err
}
