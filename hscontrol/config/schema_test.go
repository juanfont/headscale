package config

import (
	"encoding/json"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	gocmp "github.com/google/go-cmp/cmp"
	hsdns "github.com/juanfont/headscale/hscontrol/dns"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
)

func schemaByPath(t *testing.T) map[string]keyInfo {
	t.Helper()

	keys, err := schema()
	require.NoError(t, err)

	byPath := make(map[string]keyInfo, len(keys))
	for _, k := range keys {
		byPath[k.Path] = k
	}

	return byPath
}

func jsonText(t *testing.T, v any) string {
	t.Helper()

	b, err := json.Marshal(v)
	require.NoError(t, err)

	return string(b)
}

func TestSchemaTypes(t *testing.T) {
	keys, err := schema()
	require.NoError(t, err)

	d := Default()

	tree := types.ConfigTree(&d)
	require.Len(t, keys, len(tree))

	for i, k := range keys {
		require.Equal(t, tree[i].Path, k.Path, "ConfigTree order")

		if k.Section {
			require.Empty(t, k.Env, k.Path)
			require.Equal(t, typeInfo{}, k.Type, k.Path)
			require.Nil(t, k.Example, k.Path)

			continue
		}

		require.Equal(t, configEnvName(k.Path), k.Env)
	}

	byPath := schemaByPath(t)

	tests := []struct {
		path    string
		want    typeInfo
		def     any
		mapKey  string
		defText string
	}{
		{path: "node.expiry", want: typeInfo{Label: "duration", Anchor: "#type-duration", Nix: "t.duration"}, def: "0s"},
		{path: "unix_socket_permission", want: typeInfo{Label: "file mode", Anchor: "#type-file-mode", Nix: "t.fileMode"}, def: "0770"},
		{
			path: "trusted_proxies",
			want: typeInfo{Label: "list of prefixes", Anchor: "#type-list", Env: "space-separated or JSON array", Nix: "lib.types.listOf t.prefix"},
			def:  []any{},
		},
		{path: "prefixes.v4", want: typeInfo{Label: "prefix", Anchor: "#type-prefix", Nix: "t.prefix"}, def: ""},
		{
			path:   "dns.nameservers.split",
			want:   typeInfo{Label: "map of `<domain>` → list of strings", Anchor: "#type-map", Env: "JSON object", Nix: "lib.types.attrsOf (lib.types.listOf lib.types.str)"},
			def:    map[string]any{},
			mapKey: "domain",
		},
		{
			path:   "oidc.extra_params",
			want:   typeInfo{Label: "map of `<param>` → string", Anchor: "#type-map", Env: "JSON object", Nix: "lib.types.attrsOf lib.types.str"},
			def:    map[string]any{},
			mapKey: "param",
		},
		{
			path:   "dns.challenge.provider",
			want:   typeInfo{Label: "map of `<setting>` → value", Anchor: "#type-map", Env: "JSON object", Nix: "lib.types.attrsOf lib.types.anything"},
			def:    map[string]any{},
			mapKey: "setting",
		},
		{path: "database.postgres.pass", want: typeInfo{Label: "secret", Anchor: "#secrets", Nix: "t.secretFile"}, def: ""},
		{path: "database.type", want: typeInfo{Label: "enum", Anchor: "#type-enum", Enum: types.DatabaseType("").Allowed()}, def: ""},
		{path: "dns.extra_records", want: typeInfo{Label: "list of DNS records", Anchor: "#type-list", Env: "JSON array"}, def: []any{}},
		{path: "derp.urls", want: typeInfo{Label: "list of URLs", Anchor: "#type-list", Env: "space-separated or JSON array", Nix: "lib.types.listOf t.httpURL"}, def: []any{}},
		{path: "derp.server.region_id", want: typeInfo{Label: "integer", Anchor: "#type-integer", Nix: "lib.types.int"}, def: 0},
		{path: "listen_addr", want: typeInfo{Label: "listen address", Anchor: "#type-listen-address", Nix: "t.listenAddr"}, def: ""},
		{path: "dns.magic_dns", want: typeInfo{Label: "boolean", Anchor: "#type-boolean", Nix: "lib.types.bool"}, def: true},
		{
			path:    "tuning.batcher_workers",
			want:    typeInfo{Label: "integer", Anchor: "#type-integer", Nix: "lib.types.int"},
			def:     0,
			defText: "three quarters of the CPU cores, at least one",
		},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			k, ok := byPath[tt.path]
			require.True(t, ok)

			if diff := gocmp.Diff(tt.want, k.Type); diff != "" {
				t.Errorf("type (-want +got):\n%s", diff)
			}

			require.Equal(t, tt.def, k.Default)
			require.Equal(t, tt.mapKey, k.MapKey)
			require.Equal(t, tt.defText, k.DefaultText)
		})
	}

	for _, typ := range []reflect.Type{
		reflect.TypeFor[chan int](),
		reflect.TypeFor[uint](),
		reflect.TypeFor[map[int]string](),
		reflect.TypeFor[[][]string](),
	} {
		_, err = typeOf(typ)
		require.ErrorIs(t, err, errUnknownType, typ.String())
	}
}

func TestLoadExample(t *testing.T) {
	field := func(path string, typ reflect.Type, tag string) types.ConfigField {
		return types.ConfigField{Path: path, Field: reflect.StructField{Type: typ, Tag: reflect.StructTag(tag)}}
	}
	duration := reflect.TypeFor[time.Duration]()
	boolean := reflect.TypeFor[bool]()

	tests := []struct {
		name    string
		field   types.ConfigField
		def     any
		want    any
		wantErr bool
	}{
		{name: "duration", field: field("node.expiry", duration, `example:"\"5m\""`), def: "0s", want: "5m"},
		{name: "not as printed", field: field("node.expiry", duration, `example:"\"90d\""`), def: "0s", wantErr: true},
		{name: "does not load", field: field("node.expiry", duration, `example:"\"soon\""`), def: "0s", wantErr: true},
		{name: "not JSON", field: field("node.expiry", duration, `example:"5m"`), def: "0s", wantErr: true},
		{name: "untagged", field: field("node.expiry", duration, ""), def: "0s", wantErr: true},
		{name: "bool", field: field("taildrop.enabled", boolean, ""), def: true, want: false},
		{name: "tagged bool", field: field("taildrop.enabled", boolean, `example:"false"`), def: true, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := loadExample(tt.field, tt.def)
			if tt.wantErr {
				require.ErrorIs(t, err, errBadExample)

				return
			}

			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}

// TestDescribeLeafNixTag: nix:"path" lets a file headscale only reads be a
// Nix path, in the store; nix:"external" keeps a key or state file out of
// it. Any other value, or a tag on another type, is an error, so a secret
// never takes a store path.
func TestDescribeLeafNixTag(t *testing.T) {
	str, list := reflect.TypeFor[string](), reflect.TypeFor[[]string]()

	tests := []struct {
		name    string
		path    string
		typ     reflect.Type
		tag     string
		want    string // Type.Nix
		wantErr bool
	}{
		{name: "path", path: "policy.path", typ: str, tag: `example:"\"/p\"" nix:"path"`, want: "t.readFile"},
		{name: "path list", path: "derp.paths", typ: list, tag: `example:"[\"/d\"]" nix:"path"`, want: "lib.types.listOf lib.types.path"},
		{name: "external", path: "noise.private_key_path", typ: str, tag: `example:"\"/k\"" nix:"external"`, want: "t.stateFile"},
		{name: "untagged", path: "policy.path", typ: str, tag: `example:"\"/p\""`, want: nixStr},
		{name: "unknown value", path: "policy.path", typ: str, tag: `nix:"file"`, wantErr: true},
		{name: "path on a secret", path: "oidc.client_secret", typ: reflect.TypeFor[types.Secret](), tag: `nix:"path"`, wantErr: true},
		{name: "path on an int", path: "database.postgres.port", typ: reflect.TypeFor[int](), tag: `nix:"path"`, wantErr: true},
		{name: "external list", path: "derp.paths", typ: list, tag: `nix:"external"`, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k := keyInfo{Path: tt.path, Field: reflect.StructField{Type: tt.typ, Tag: reflect.StructTag(tt.tag)}}

			err := k.describeLeaf(nil, nil)
			if tt.wantErr {
				require.ErrorIs(t, err, errBadNixTag)

				return
			}

			require.NoError(t, err)
			require.Equal(t, tt.want, k.Type.Nix)
		})
	}
}

func TestExamples(t *testing.T) {
	keys, err := schema()
	require.NoError(t, err)

	empty := writeConfig(t, "")

	yamlParser, err := configParser("config.yaml")
	require.NoError(t, err)

	for _, k := range keys {
		if k.Section {
			continue
		}

		t.Run(k.Path, func(t *testing.T) {
			tag, tagged := k.Field.Tag.Lookup("example")
			if k.Field.Type.Kind() == reflect.Bool {
				require.False(t, tagged, "a bool's example is !default")
				require.Equal(t, !k.Default.(bool), k.Example) //nolint:forcetypeassert // a bool's default is a bool

				return
			}

			require.True(t, tagged, "every other leaf has an example tag")
			require.True(t, json.Valid([]byte(tag)), "example is JSON: %s", tag)

			example := jsonText(t, k.Example)
			require.JSONEq(t, tag, example)
			require.NotEqual(t, jsonText(t, k.Default), example, "example equals the default")

			if k.Field.Type == reflect.TypeFor[types.Secret]() {
				require.True(t, strings.HasPrefix(k.Example.(string), "file:/run/secrets/"), k.Example) //nolint:forcetypeassert // a secret is text
			}

			if k.Open {
				require.Len(t, k.Example, 2, "an open map's example has two entries")
			}

			file, err := yamlParser.Marshal(nest(k.Path, k.Example))
			require.NoError(t, err)

			l, err := Load(writeConfig(t, string(file)), true, nil)
			require.NoError(t, err)
			require.Empty(t, l.Warnings)
			require.JSONEq(t, example, jsonText(t, plainFields(l.Config, false)[k.Path]), "file layer:\n%s", file)

			env := k.Env + "=" + envValue(k.Example)

			l, err = Load(empty, true, []string{env})
			require.NoError(t, err)
			require.Empty(t, l.Warnings)
			require.JSONEq(t, example, jsonText(t, plainFields(l.Config, false)[k.Path]), "env layer: %s", env)
		})
	}

	provider, _ := schemaByPath(t)["dns.challenge.provider"].Example.(map[string]any)
	require.Contains(t, hsdns.ProviderNames(), provider["name"])

	for name, v := range provider {
		if s, ok := v.(string); ok && name != "name" {
			require.True(t, strings.HasPrefix(s, "file:/run/secrets/"), "%s: %s", name, s)
		}
	}

	_, err = types.DNSChallengeConfig{ProviderSettings: provider}.NewProvider(func(_, value string) (string, error) {
		return value, hsdns.ErrSecretUnread
	})
	require.NoError(t, err)
}

func TestRequiredKeys(t *testing.T) {
	want := map[string]string{
		"server_url":             "",
		"noise.private_key_path": "",
		"database.type":          "",
		"dns.base_domain":        "`dns.magic_dns` is true",
		"dns.nameservers.global": "`dns.override_local_dns` is true",
	}

	got, err := requiredKeys()
	require.NoError(t, err)

	if diff := gocmp.Diff(want, got); diff != "" {
		t.Errorf("requiredKeys (-want +got):\n%s", diff)
	}

	for path, k := range schemaByPath(t) {
		when, required := want[path]
		require.Equal(t, required, k.Required, path)
		require.Equal(t, when, k.RequiredWhen, path)
	}
}

func TestEnvValue(t *testing.T) {
	lists := []string{"oidc.scope", "dns.challenge.resolvers"}

	tests := []struct {
		name string
		v    any
		want string
		keys []string
	}{
		{name: "list", v: []any{"a", "b"}, want: `["a","b"]`, keys: lists},
		{name: "empty element", v: []any{""}, want: `[""]`, keys: lists},
		{name: "empty and name", v: []any{"", "example.com"}, want: `["","example.com"]`, keys: lists},
		{name: "leading bracket", v: []any{"[prompt]"}, want: `["[prompt]"]`, keys: lists},
		{name: "IPv6 with port", v: []any{"[2001:db8::53]:53"}, want: `["[2001:db8::53]:53"]`, keys: lists},
		{name: "empty list", v: []any{}, want: `[]`, keys: lists},
		{name: "map", v: map[string]any{"b": "y", "a": "x"}, want: `{"a":"x","b":"y"}`, keys: []string{"oidc.extra_params"}},
		{name: "bool", v: true, want: "true", keys: []string{"logtail.enabled"}},
		{name: "int", v: 5, want: "5", keys: []string{"tuning.batcher_workers"}},
	}

	empty := writeConfig(t, "")

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := envValue(tt.v)
			require.Equal(t, tt.want, got)

			for _, key := range tt.keys {
				l, err := Load(empty, true, []string{configEnvName(key) + "=" + got})
				require.NoError(t, err)
				require.Empty(t, l.Warnings)
				require.JSONEq(t, jsonText(t, tt.v), jsonText(t, plainFields(l.Config, false)[key]), key)
			}
		})
	}
}

func TestDNSRecordFields(t *testing.T) {
	var want []string

	for f := range reflect.TypeFor[tailcfg.DNSRecord]().Fields() {
		if f.IsExported() {
			want = append(want, strings.ToLower(f.Name))
		}
	}

	got := make([]string, 0, len(dnsRecordFields))

	for _, f := range dnsRecordFields {
		require.NotEmpty(t, f.Doc, f.Name)
		got = append(got, f.Name)
	}

	require.Equal(t, want, got)
}

func TestReplaces(t *testing.T) {
	byPath := schemaByPath(t)

	tests := []struct {
		path string
		want []string
	}{
		{path: "tls.cert_path", want: []string{"tls_cert_path"}},
		{path: "prefixes.v4", want: []string{"ip_prefixes"}},
		{path: "prefixes.v6", want: []string{"ip_prefixes"}},
		{path: "dns", want: []string{"dns_config"}},
		{path: "log.format", want: []string{"json_logs"}},
		{path: "noise.private_key_path", want: []string{"private_key_path", "noise_private_key_path"}},
		{path: "server_url"},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			var got []string
			for _, r := range byPath[tt.path].Replaces {
				got = append(got, r.Old)
			}

			require.Equal(t, tt.want, got)
		})
	}

	// Every removed key that names a replacement lands on one.
	for _, r := range removedKeys {
		for n := range strings.FieldsSeq(r.New) {
			require.True(t, slices.ContainsFunc(byPath[n].Replaces, func(x removedKey) bool { return x == r }), "%s → %s", r.Old, n)
		}
	}
}
