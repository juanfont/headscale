package config

import (
	"bytes"
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/knadh/koanf/providers/confmap"
	"github.com/knadh/koanf/v2"
	"tailscale.com/tailcfg"
)

var (
	errUnknownType    = errors.New("no value type for Go type")
	errBadExample     = errors.New("bad example tag")
	errNoMapKey       = errors.New("open map without a mapkey tag")
	errInvalidDefault = errors.New("a default fails validation")
	errBadNixTag      = errors.New("bad nix tag")
)

// keyInfo is what the generators know about one node of
// [types.ConfigTree].
type keyInfo struct {
	types.ConfigField

	Env  string   // configEnvName(Path); "" for sections
	Type typeInfo // zero for sections
	// Default is the value in Default(), as plainFields prints it; a nil
	// list or map is empty.
	Default any
	// Example is the example tag as plainFields prints it once loaded;
	// !Default for a bool, nil for sections.
	Example  any
	Required bool
	// RequiredWhen is the condition under which Required holds, keys
	// backticked; "" is always.
	RequiredWhen string
	MapKey       string       // the placeholder for an open map's keys
	DefaultText  string       // the default in words, where Default is a stand-in
	Replaces     []removedKey // the removed keys whose New names Path
}

// typeInfo is how a key's value is written.
type typeInfo struct {
	Label  string // "duration", "list of prefixes", "map of `<domain>` → list of strings"
	Anchor string // the legend row explaining Label
	Env    string // the encoding of a variable: "" for text, or "JSON object", ...
	Nix    string // the NixOS option type; "" where a generator builds it
	Enum   []string
}

// leafType is a row of the value-type legend. Rows match a Go type
// exactly, then by implementing an interface Type, then by kind.
type leafType struct {
	Type  reflect.Type
	Kinds []reflect.Kind

	Label, Plural string
	// Format and Sample explain the type in the legend, in Markdown.
	Format, Sample string
	// Nix is the NixOS type, or for a list or map its constructor.
	Nix string
	// Anchor overrides "#type-" + Label.
	Anchor string
}

const nixStr = "lib.types.str"

// nixFiles types a file a key names, by the key's nix tag and Go type.
// "path" is a file headscale only reads and that holds no secret, so a Nix
// path may copy it to the store; "external" is a key or state file, which
// must stay out of the world-readable store.
var nixFiles = map[string]map[reflect.Type]string{
	"path": {
		reflect.TypeFor[string]():   "t.readFile",
		reflect.TypeFor[[]string](): "lib.types.listOf lib.types.path",
	},
	"external": {reflect.TypeFor[string](): "t.stateFile"},
}

var allowedType = reflect.TypeFor[interface{ Allowed() []string }]()

// leafTypes is the one type table: the page's legend, every key's type
// label and its NixOS type.
var leafTypes = []leafType{
	{
		Kinds: []reflect.Kind{reflect.String}, Label: "string", Plural: "strings",
		Format: "Text. Quote it where YAML would read another type, as in `\"0x1F\"` or `\"null\"`.",
		Sample: "`/var/lib/headscale/db.sqlite`", Nix: nixStr,
	},
	{
		Kinds: []reflect.Kind{reflect.Bool}, Label: "boolean", Plural: "booleans",
		Format: "`true` or `false`.", Sample: "`true`", Nix: "lib.types.bool",
	},
	{
		Kinds: []reflect.Kind{reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64}, Label: "integer", Plural: "integers",
		Format: "A whole number.", Sample: "`1024`", Nix: "lib.types.int",
	},
	{
		Type: reflect.TypeFor[time.Duration](), Label: "duration", Plural: "durations",
		Format: "A number with a unit, `ms`, `s`, `m`, `h`, `d`, `w` or `y`, units combined largest first; `0` needs none.",
		Sample: "`1h30m`", Nix: "t.duration",
	},
	{
		Type: reflect.TypeFor[types.FileMode](), Label: "file mode", Plural: "file modes",
		Format: "Octal permission bits, quoted.", Sample: "`\"0770\"`", Nix: "t.fileMode",
	},
	{
		Type: reflect.TypeFor[types.ListenAddr](), Label: "listen address", Plural: "listen addresses",
		Format: "`host:port`. An empty host listens on every address; the port may be `http` or `https`.",
		Sample: "`0.0.0.0:8080`", Nix: "t.listenAddr",
	},
	{
		Type: reflect.TypeFor[types.HTTPURL](), Label: "URL", Plural: "URLs",
		Format: "An absolute `http://` or `https://` URL with a host.", Sample: "`https://headscale.example.com`", Nix: "t.httpURL",
	},
	{
		Type: reflect.TypeFor[netip.Prefix](), Label: "prefix", Plural: "prefixes",
		Format: "An IP range in CIDR notation.", Sample: "`100.64.0.0/10`", Nix: "t.prefix",
	},
	{
		Type: reflect.TypeFor[types.Secret](), Label: "secret", Plural: "secrets", Anchor: "#secrets",
		Format: "Text, or `file:<path>` to read it from a file.", Sample: "`file:/run/secrets/oidc_client_secret`", Nix: "t.secretFile",
	},
	{
		Type: allowedType, Label: "enum", Plural: "enums",
		Format: "One of the values listed with the key.", Sample: "`sqlite`",
	},
	{
		Type: reflect.TypeFor[tailcfg.DNSRecord](), Label: "DNS record", Plural: "DNS records",
		Format: "An object with `name`, `type` and `value`.",
		Sample: "`{name: grafana.example.com, type: A, value: 100.64.0.3}`",
	},
	{
		Kinds: []reflect.Kind{reflect.Interface}, Label: "value", Plural: "values",
		Format: "Whatever the setting takes: text, a number, a boolean, a list or a map.",
		Sample: "`file:/run/secrets/cloudflare`", Nix: "lib.types.anything",
	},
	{
		Kinds: []reflect.Kind{reflect.Slice}, Label: "list",
		Format: "A list. A variable holds it as a JSON array or, unless its values are objects, separated by spaces. An empty item is an error.",
		Sample: "`[9.9.9.9, 2620:fe::fe]`", Nix: "lib.types.listOf",
	},
	{
		Kinds: []reflect.Kind{reflect.Map}, Label: "map",
		Format: "Keys you choose, each with a value. A variable holds a JSON object.",
		Sample: "`{corp.example.com: [192.0.2.53]}`", Nix: "lib.types.attrsOf",
	},
}

// recordField is a field of a dns.extra_records entry.
type recordField struct {
	Name, Doc string
	// Nix is the NixOS type; with Enum, an enum of those values.
	Nix  string
	Enum []string
	// Default is the NixOS default; nil makes the field required.
	Default any
}

// dnsRecordFields document [tailcfg.DNSRecord], whose fields carry no
// docs of ours.
var dnsRecordFields = []recordField{
	{Name: "name", Doc: "The fully qualified domain name, e.g. `grafana.example.com`; the trailing dot is optional.", Nix: nixStr},
	{
		Name: "type", Doc: "The record type, `A` or `AAAA`; empty picks it from `value`. Clients ignore other types.",
		Enum: []string{"", "A", "AAAA"}, Default: "",
	},
	{Name: "value", Doc: "The IP address the name resolves to.", Nix: "t.ip"},
}

// schema describes every node of ConfigTree(Default()), in its order. It
// fails on a leaf of a type leafTypes lacks, or whose example does not
// load as written.
func schema() ([]keyInfo, error) {
	d := Default()
	defaults := plainFields(&d, false)

	required, err := requiredKeys()
	if err != nil {
		return nil, err
	}

	var keys []keyInfo

	for _, f := range types.ConfigTree(&d) {
		k := keyInfo{ConfigField: f}

		for _, r := range removedKeys {
			if slices.Contains(strings.Fields(r.New), f.Path) {
				k.Replaces = append(k.Replaces, r)
			}
		}

		if !f.Section {
			err := k.describeLeaf(defaults[f.Path], required)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", f.Path, err)
			}
		}

		keys = append(keys, k)
	}

	return keys, nil
}

func (k *keyInfo) describeLeaf(def any, required map[string]string) error {
	var err error

	k.Env = configEnvName(k.Path)
	k.MapKey = k.Field.Tag.Get("mapkey")
	k.DefaultText = k.Field.Tag.Get("defaulttext")
	k.RequiredWhen, k.Required = required[k.Path]

	k.Type, err = typeOf(k.Field.Type)
	if err != nil {
		return err
	}

	if tag := k.Field.Tag.Get("nix"); tag != "" {
		nix, ok := nixFiles[tag][k.Field.Type]
		if !ok {
			return fmt.Errorf("%w %q on %s", errBadNixTag, tag, k.Field.Type)
		}

		k.Type.Nix = nix
	}

	if k.Open {
		if k.MapKey == "" {
			return errNoMapKey
		}

		k.Type.Label = strings.Replace(k.Type.Label, "<key>", "<"+k.MapKey+">", 1)
	}

	k.Default = orEmpty(def, k.Field.Type)

	k.Example, err = loadExample(k.ConfigField, k.Default)

	return err
}

// orEmpty is v, or for nil, which plainFields gives a nil list or map, an
// empty one of t's kind.
func orEmpty(v any, t reflect.Type) any {
	switch {
	case v != nil:
		return v
	case t.Kind() == reflect.Slice:
		return []any{}
	default:
		return map[string]any{}
	}
}

// loadExample is f's example tag as plainFields prints it once the
// loader has read it, which must be the tag's own JSON; for a bool, !def.
func loadExample(f types.ConfigField, def any) (any, error) {
	tag, tagged := f.Field.Tag.Lookup("example")
	b, isBool := def.(bool)

	switch {
	case isBool && !tagged:
		return !b, nil
	case isBool || !tagged:
		return nil, fmt.Errorf("%w: a bool takes none, every other leaf one", errBadExample)
	}

	var v any

	err := json.Unmarshal([]byte(tag), &v)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errBadExample, err)
	}

	d := Default()
	s := &configSource{k: koanf.New("."), envVars: map[string]string{}}

	err = s.k.Load(confmap.Provider(plainMap(&d, false), ""), nil)
	if err != nil {
		return nil, err
	}

	err = s.k.Load(confmap.Provider(nest(f.Path, v), ""), nil)
	if err != nil {
		return nil, err
	}

	cfg, err := s.decode()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errBadExample, err)
	}

	loaded := plainFields(cfg, false)[f.Path]

	want, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}

	got, err := json.Marshal(loaded)
	if err != nil || !bytes.Equal(want, got) {
		return nil, fmt.Errorf("%w: loads as %s", errBadExample, got)
	}

	return loaded, nil
}

// typeOf is how a value of Go type t is written.
func typeOf(t reflect.Type) (typeInfo, error) {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}

	row, ok := leafTypeOf(t)
	if !ok {
		return typeInfo{}, fmt.Errorf("%w %s", errUnknownType, t)
	}

	ti := typeInfo{
		Label:  row.Label,
		Anchor: cmp.Or(row.Anchor, "#type-"+strings.ReplaceAll(row.Label, " ", "-")),
		Nix:    row.Nix,
	}

	switch {
	case row.Type == allowedType:
		ti.Enum = reflect.Zero(t).Interface().(interface{ Allowed() []string }).Allowed() //nolint:forcetypeassert // matched by Implements
	case t.Kind() == reflect.Slice:
		elem, ok := leafTypeOf(t.Elem())
		if !ok || elem.Plural == "" {
			return typeInfo{}, fmt.Errorf("%w %s", errUnknownType, t)
		}

		ti.Label = "list of " + elem.Plural
		ti.Nix = nixOf(row.Nix, elem.Nix)

		ti.Env = "space-separated or JSON array"
		if e := t.Elem(); e.Kind() == reflect.Struct && !reflect.PointerTo(e).Implements(textUnmarshalerType) {
			ti.Env = "JSON array"
		}
	case t.Kind() == reflect.Map:
		elem, err := typeOf(t.Elem())
		if err != nil || t.Key().Kind() != reflect.String {
			return typeInfo{}, fmt.Errorf("%w %s", errUnknownType, t)
		}

		// describeLeaf names the key.
		ti.Label = "map of `<key>` → " + elem.Label
		ti.Nix = nixOf(row.Nix, elem.Nix)
		ti.Env = "JSON object"
	}

	return ti, nil
}

func leafTypeOf(t reflect.Type) (leafType, bool) {
	for _, match := range []func(leafType) bool{
		func(l leafType) bool { return l.Type == t },
		func(l leafType) bool {
			return l.Type != nil && l.Type.Kind() == reflect.Interface && t.Implements(l.Type)
		},
		func(l leafType) bool { return slices.Contains(l.Kinds, t.Kind()) },
	} {
		if i := slices.IndexFunc(leafTypes, match); i >= 0 {
			return leafTypes[i], true
		}
	}

	return leafType{}, false
}

// nixOf applies the list or map constructor to elem, "" when elem is a
// type a generator builds.
func nixOf(constructor, elem string) string {
	switch {
	case elem == "":
		return ""
	case strings.Contains(elem, " "):
		return constructor + " (" + elem + ")"
	default:
		return constructor + " " + elem
	}
}

// requiredKeys are the leaves Validate(Default()) names first in a
// reason, with an empty default, each with the condition of "is required
// when <condition>" or "" for always. A reason naming no leaf (the prefix
// rule) is the docs' to explain.
func requiredKeys() (map[string]string, error) {
	d := Default()

	empty := map[string]bool{}

	for _, f := range types.ConfigFields(&d) {
		v := f.Value
		empty[f.Path] = v.IsZero() || ((v.Kind() == reflect.Slice || v.Kind() == reflect.Map) && v.Len() == 0)
	}

	required := map[string]string{}

	for _, e := range types.ConfigErrors(Validate(&d)) {
		key, rest, _ := strings.Cut(e.Reason, " ")

		isEmpty, leaf := empty[key]
		if !leaf {
			continue
		}

		if !isEmpty {
			return nil, fmt.Errorf("%w: %s", errInvalidDefault, e.Reason)
		}

		_, when, _ := strings.Cut(rest, "is required when ")

		words := strings.Fields(when)
		for i, w := range words {
			if _, ok := empty[w]; ok {
				words[i] = "`" + w + "`"
			}
		}

		required[key] = strings.Join(words, " ")
	}

	return required, nil
}

// envValue is v as a variable writes it: a scalar as text, a list or map
// as JSON, keys sorted. Every list is JSON: separated by spaces, an empty
// element is lost and one starting with "[" reads as JSON.
func envValue(v any) string {
	switch reflect.ValueOf(v).Kind() { //nolint:exhaustive // scalars print as text
	case reflect.Slice, reflect.Map:
		var b bytes.Buffer

		enc := json.NewEncoder(&b)
		enc.SetEscapeHTML(false)

		err := enc.Encode(v)
		if err == nil {
			return strings.TrimSuffix(b.String(), "\n")
		}
	}

	return fmt.Sprint(v)
}

// nest is v at the dotted path, in nested maps as a file holds it.
func nest(path string, v any) map[string]any {
	m := map[string]any{}
	setPath(m, path, v)

	return m
}
