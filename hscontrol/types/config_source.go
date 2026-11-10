package types

import (
	"bytes"
	stdjson "encoding/json"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/go-viper/mapstructure/v2"
	hsdns "github.com/juanfont/headscale/hscontrol/dns"
	"github.com/knadh/koanf/parsers/json"
	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/confmap"
	"github.com/knadh/koanf/v2"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cast"
	"github.com/tailscale/hujson"
)

const configEnvPrefix = "HEADSCALE_"

// configFileNames is the per-directory search order. TOML and .env are not
// read, but still found, so an old file is rejected by name, not skipped.
var configFileNames = []string{
	"config.json", "config.toml", "config.yaml", "config.yml", "config.hujson", "config.dotenv", "config.env",
}

// reservedEnvPrefixes name variables with the HEADSCALE_ prefix that are not
// configuration, so they never produce an unknown-variable warning.
var reservedEnvPrefixes = []string{
	"HEADSCALE_DEBUG_", "HEADSCALE_INTEGRATION_", "HEADSCALE_TEST_",
	"HEADSCALE_DNS_CHALLENGE_PROVIDER_", "HEADSCALE_SERVICE_", "HEADSCALE_PORT",
}

var reservedEnvNames = []string{
	"HEADSCALE_CONFIG", "HEADSCALE_UPDATE_GOLDEN",
}

// configSource is the layered configuration: defaults, then file, then
// environment. Keys are lowercase; values coerce like viper's.
type configSource struct {
	k         *koanf.Koanf
	file      string
	fileBytes []byte
	warnings  []string
}

func configEnvName(key string) string {
	return configEnvPrefix + strings.ToUpper(strings.ReplaceAll(key, ".", "_"))
}

// configSearchDirs returns the directories searched when no path is given.
// HOME and the XDG variables come from environ, not the process.
func configSearchDirs(environ []string) []string {
	get := func(key string) string {
		for _, kv := range environ {
			if k, v, _ := strings.Cut(kv, "="); k == key {
				return v
			}
		}

		return ""
	}

	dirs := []string{"/etc/headscale"}
	home := get("HOME")

	xdgHome := get("XDG_CONFIG_HOME")
	if xdgHome == "" && home != "" {
		xdgHome = filepath.Join(home, ".config")
	}

	if xdgHome != "" {
		dirs = append(dirs, filepath.Join(xdgHome, "headscale"))
	}

	xdgDirs := get("XDG_CONFIG_DIRS")
	if xdgDirs == "" {
		xdgDirs = "/etc/xdg"
	}

	for d := range strings.SplitSeq(xdgDirs, ":") {
		if d != "" {
			dirs = append(dirs, filepath.Join(d, "headscale"))
		}
	}

	if home != "" {
		dirs = append(dirs, filepath.Join(home, ".headscale"))
	}

	return append(dirs, ".")
}

// findConfigFile returns the first existing config file, or "" if none.
func findConfigFile(path string, isFile bool, environ []string) string {
	if isFile {
		return path
	}

	dirs := []string{path}
	if path == "" {
		dirs = configSearchDirs(environ)
	}

	for _, d := range dirs {
		for _, n := range configFileNames {
			p := filepath.Join(d, n)

			st, err := os.Stat(p)
			if err == nil && !st.IsDir() {
				return p
			}
		}
	}

	return ""
}

func configParser(file string) (koanf.Parser, error) {
	switch strings.ToLower(filepath.Ext(file)) {
	case ".json", ".hujson":
		// loadFile turns HuJSON into JSON.
		return json.Parser(), nil
	case ".yaml", ".yml":
		return yaml.Parser(), nil
	}

	return nil, fmt.Errorf("unsupported config file format %q: use .json, .yaml, .yml or .hujson", filepath.Ext(file)) //nolint:err113
}

// normaliseConfigMap lowercases keys at every depth and drops nulls, as
// viper does, so lookups are case-insensitive and null means unset.
func normaliseConfigMap(m map[string]any) map[string]any {
	out := make(map[string]any, len(m))

	for k, v := range m {
		if v == nil {
			continue
		}

		out[strings.ToLower(k)] = normaliseConfigValue(v)
	}

	return out
}

func normaliseConfigValue(v any) any {
	switch x := v.(type) {
	case map[string]any:
		return normaliseConfigMap(x)
	case map[any]any:
		// YAML maps with a non-string key.
		m := make(map[string]any, len(x))
		for k, e := range x {
			m[fmt.Sprint(k)] = e
		}

		return normaliseConfigMap(m)
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = normaliseConfigValue(e)
		}

		return out
	}

	return v
}

func isOpenMapPath(path string) bool {
	for _, o := range openMapKeys {
		if path == o || strings.HasPrefix(path, o+".") {
			return true
		}
	}

	return false
}

// configPathParts splits path into names as expansion nests them: below an
// open map the rest is one entry name, so "split.a.com" and "split.a.com.au"
// are siblings, not parent and child.
func configPathParts(path string) []string {
	parts := strings.Split(path, ".")
	for i := 1; i < len(parts); i++ {
		if slices.Contains(openMapKeys, strings.Join(parts[:i], ".")) {
			return append(parts[:i], strings.Join(parts[i:], "."))
		}
	}

	return parts
}

// expandDottedKeys nests dotted names ("log.level") outside open maps. The
// strict pass has already rejected files that spell one path two ways.
func expandDottedKeys(m map[string]any, prefix string) map[string]any {
	out := map[string]any{}

	var dotted []string

	for _, k := range slices.Sorted(maps.Keys(m)) {
		if !isOpenMapPath(prefix) && strings.Contains(k, ".") {
			dotted = append(dotted, k)

			continue
		}

		out[k] = expandConfigValue(m[k], joinConfigPath(prefix, k))
	}

	for _, k := range dotted {
		parts := strings.Split(k, ".")
		cur, path := out, prefix

		var final string

		for i := 0; ; i++ {
			// Below an open map the rest of the name is one literal key.
			if i == len(parts)-1 || isOpenMapPath(path) {
				final = strings.Join(parts[i:], ".")

				break
			}

			next, ok := cur[parts[i]].(map[string]any)
			if !ok {
				next = map[string]any{}
				cur[parts[i]] = next
			}

			cur, path = next, joinConfigPath(path, parts[i])
		}

		cur[final] = expandConfigValue(m[k], joinConfigPath(path, final))
	}

	return out
}

func expandConfigValue(v any, path string) any {
	if child, ok := v.(map[string]any); ok {
		return expandDottedKeys(child, path)
	}

	return v
}

func joinConfigPath(prefix, name string) string {
	if prefix == "" {
		return name
	}

	return prefix + "." + name
}

// newConfigSource loads defaults, the config file found via path/isFile and
// environ (os.Environ form), and rejects removed and unknown file keys.
func newConfigSource(path string, isFile bool, environ []string) (*configSource, error) {
	s := &configSource{k: koanf.New(".")}

	err := s.k.Load(confmap.Provider(configDefaults, "."), nil)
	if err != nil {
		return nil, fmt.Errorf("loading defaults: %w", err)
	}

	s.file = findConfigFile(path, isFile, environ)
	if s.file == "" {
		log.Warn().Msg("no config file found, using defaults")
	} else {
		err = s.loadFile()
		if err != nil {
			return nil, err
		}
	}

	err = s.loadEnv(environ)
	if err != nil {
		return nil, err
	}

	return s, nil
}

func (s *configSource) loadFile() error {
	parser, err := configParser(s.file)
	if err != nil {
		return fmt.Errorf("%w (%s)", err, s.file)
	}

	raw, err := os.ReadFile(s.file)
	if err != nil {
		return fmt.Errorf("fatal error reading config file: %w", err)
	}

	if len(bytes.TrimSpace(raw)) == 0 {
		return nil
	}

	if strings.EqualFold(filepath.Ext(s.file), ".hujson") {
		// Comments and trailing commas become spaces, so line numbers, and
		// error positions with them, still point into the file.
		raw, err = hujson.Standardize(raw)
	}

	s.fileBytes = raw

	var m map[string]any
	if err == nil {
		m, err = parser.Unmarshal(raw)
	}

	if err != nil {
		return fmt.Errorf("fatal error reading config file %s: %w", s.file, err)
	}

	m = normaliseConfigMap(m)

	// Checked before expansion, which would otherwise discard shadowed keys.
	v := &configValidator{}
	s.checkKeys(v, m)

	if v.HasErrors() {
		return v.Err()
	}

	m = expandDottedKeys(m, "")

	// No delimiter: open-map keys such as domain names may contain dots.
	err = s.k.Load(confmap.Provider(m, ""), nil)
	if err != nil {
		return fmt.Errorf("loading config file %s: %w", s.file, err)
	}

	return nil
}

// configKeySets derives the lookup sets the strict pass needs.
func configKeySets() (map[string]bool, map[string]bool) {
	leaf, branch := map[string]bool{}, map[string]bool{}

	for _, k := range slices.Concat(configKeys, openMapKeys) {
		leaf[k] = true

		parts := strings.Split(k, ".")
		for i := 1; i < len(parts); i++ {
			branch[strings.Join(parts[:i], ".")] = true
		}
	}

	return leaf, branch
}

func removedConfigKey(path string) (removedKey, bool) {
	for _, r := range removedKeys {
		if r.Old == path || strings.HasPrefix(path, r.Old+".") {
			return r, true
		}
	}

	return removedProviderPath(path)
}

// removedProviderPath matches a DNS provider's <setting>_path, nested ones
// included, the file form "file:<path>" replaced. Provider settings have no
// fixed list, so the form is matched by name, for every provider, selected
// or not.
func removedProviderPath(path string) (removedKey, bool) {
	const prefix = "dns.challenge.provider."

	field, ok := strings.CutPrefix(path, prefix)
	setting := field[strings.LastIndex(field, ".")+1:]

	if !ok || !strings.HasSuffix(setting, "_path") || hsdns.IsProviderSetting(setting) {
		return removedKey{}, false
	}

	return removedKey{
		Old:   path,
		New:   prefix + strings.TrimSuffix(field, "_path"),
		Value: "file:<path>",
		Since: "0.30",
	}, true
}

// walkRemoved calls add for every removed key below path, an open map
// whose contents are otherwise the user's, and deletes it from m, so a
// caller that only warns loads the rest. labels says m's keys are names,
// such as acme-dns's registrations: data, kept as written and not checked.
func walkRemoved(path string, m map[string]any, labels bool, add func(path string, r removedKey)) {
	for _, name := range slices.Sorted(maps.Keys(m)) {
		key := name
		if !labels {
			key = strings.ToLower(name)
		}

		p := path + "." + key
		if r, removed := removedConfigKey(p); removed && !labels {
			add(p, r)
			delete(m, name)

			continue
		}

		if child, ok := m[name].(map[string]any); ok {
			walkRemoved(p, child, !labels && hsdns.IsProviderMapSetting(key), add)
		}
	}
}

// hintAs says what replaces r, spelling each key with name and a key set
// to Value with assign, so one table serves files and the environment.
func (r removedKey) hintAs(name func(string) string, assign string) string {
	switch {
	case r.Hint != "":
		return r.Hint
	case r.Value != "":
		return "use " + fmt.Sprintf(assign, name(r.New), r.Value)
	case r.New != "":
		keys := strings.Fields(r.New)
		for i, k := range keys {
			keys[i] = name(k)
		}

		last := len(keys) - 1
		if last == 0 {
			return "use " + keys[0]
		}

		return "use " + strings.Join(keys[:last], ", ") + " and " + keys[last]
	}

	return fmt.Sprintf("remove %s; see the CHANGELOG for context", name(r.Old))
}

func (r removedKey) hint() string {
	return r.hintAs(func(key string) string { return key }, `%s: %q`)
}

// envHint is hint for a variable. A removed block has no variable of its
// own, so it names the variables replacing its removed keys.
func (r removedKey) envHint() string {
	var leaves []string

	for _, l := range removedKeys {
		if strings.HasPrefix(l.Old, r.Old+".") && l.New != "" {
			leaves = append(leaves, l.New)
		}
	}

	if len(leaves) > 0 {
		r = removedKey{Old: r.Old, New: strings.Join(leaves, " ")}
	}

	return r.hintAs(configEnvName, "%s=%s")
}

func (r removedKey) reason(what, name string) string {
	return fmt.Sprintf("configuration %s %s was removed in %s", what, name, r.Since)
}

// checkKeys adds an error for every removed or unknown key in the file.
func (s *configSource) checkKeys(v *configValidator, m map[string]any) {
	leaf, branch := configKeySets()

	var walk func(prefix string, m map[string]any)

	walk = func(prefix string, m map[string]any) {
		for _, name := range slices.Sorted(maps.Keys(m)) {
			path := name
			if prefix != "" {
				path = prefix + "." + name
			}

			val := m[name]
			child, isMap := val.(map[string]any)

			switch r, removed := removedConfigKey(path); {
			case removed:
				v.Add(&ConfigError{
					Reason: r.reason("key", path) + s.position(path),
					Hint:   r.hint(),
				})
			case isOpenMapPath(path):
				// The contents are the user's, but for a removed form. A dotted
				// key below the open map (provider.config) is walked from the
				// map, so its contents get the role they have when nested.
				root, below := path, child
				if !slices.Contains(openMapKeys, path) {
					parts := configPathParts(path)
					root = strings.Join(parts[:len(parts)-1], ".")
					below = map[string]any{parts[len(parts)-1]: val}
				}

				walkRemoved(root, below, false, func(p string, r removedKey) {
					v.Add(&ConfigError{Reason: r.reason("key", p) + s.position(p), Hint: r.hint()})
				})
			case leaf[path] && !isMap:
			case (leaf[path] || branch[path]) && isMap:
				// Under a plain setting every child is unknown.
				walk(path, child)
			case branch[path]:
				// The value is not shown: a misplaced block may hold secrets.
				v.Add(&ConfigError{
					Reason: fmt.Sprintf("configuration key %s must be a mapping%s", path, s.position(path)),
				})
			default:
				v.Add(&ConfigError{Reason: fmt.Sprintf("unknown configuration key %s%s", path, s.position(path))})
			}
		}
	}

	walk("", m)
	s.checkOverlaps(v, m)
}

// position renders " (file:line:col)" when the key can be located.
func (s *configSource) position(path string) string {
	line, col, ok := keyPosition(s.fileBytes, strings.Split(path, "."))
	if !ok {
		return " (" + s.file + ")"
	}

	return fmt.Sprintf(" (%s:%d:%d)", s.file, line, col)
}

func (s *configSource) loadEnv(environ []string) error {
	env := map[string]string{}

	for _, kv := range environ {
		name, val, _ := strings.Cut(kv, "=")
		// Empty means unset, as with viper.
		if val != "" && strings.HasPrefix(name, configEnvPrefix) {
			env[name] = val
		}
	}

	layer := map[string]any{}
	names := map[string]bool{}

	openLayer := map[string]string{}

	for _, key := range slices.Concat(configKeys, openMapKeys) {
		name := configEnvName(key)
		names[name] = true

		val, ok := env[name]
		switch {
		case !ok:
		case slices.Contains(openMapKeys, key):
			openLayer[key] = val
		default:
			layer[key] = val
		}
	}

	// Other software shares the prefix (a Kubernetes Service named
	// headscale-db sets HEADSCALE_DB_PORT), so variables only ever warn.
	for _, name := range slices.Sorted(maps.Keys(env)) {
		if names[name] {
			continue
		}

		// Before reservedEnv, which spares every provider variable.
		if r, ok := removedEnv(name); ok {
			s.warnings = append(s.warnings, r.reason("variable", name)+"; "+r.envHint())

			continue
		}

		if reservedEnv(name) {
			continue
		}

		s.warnings = append(s.warnings, "unknown environment variable "+name)
	}

	// A variable for an open map replaces the file's map instead of merging
	// into it. The value stays a raw string, which the cast accessors parse as
	// JSON, unless the JSON object held a removed form, dropped here, or a
	// per-field variable (HEADSCALE_DNS_CHALLENGE_PROVIDER_NAME) has to be
	// layered on top: then the parsed object is set.
	for _, key := range slices.Sorted(maps.Keys(openLayer)) {
		val := openLayer[key]
		s.k.Delete(key)

		var parsed map[string]any

		dropped := false

		// A failed decode may still have filled part of parsed: never used.
		decoded := stdjson.Unmarshal([]byte(val), &parsed) == nil && parsed != nil
		if decoded {
			// The hint names keys: inside the JSON they are keys, not variables.
			name := configEnvName(key)
			walkRemoved(key, parsed, false, func(p string, r removedKey) {
				s.warnings = append(s.warnings, r.reason("key", p+" in "+name)+"; "+r.hint())
				dropped = true
			})
		}

		shared := slices.ContainsFunc(slices.Collect(maps.Keys(layer)), func(k string) bool {
			return strings.HasPrefix(k, key+".")
		})

		var v any = val
		if decoded && (dropped || shared) {
			v = parsed
		}

		err := s.k.Set(key, v)
		if err != nil {
			return err
		}
	}

	return s.k.Load(confmap.Provider(layer, "."), nil)
}

func reservedEnv(name string) bool {
	if slices.Contains(reservedEnvNames, name) {
		return true
	}

	for _, p := range reservedEnvPrefixes {
		if strings.HasPrefix(name, p) {
			return true
		}
	}

	return false
}

func removedEnv(name string) (removedKey, bool) {
	for _, r := range removedKeys {
		if configEnvName(r.Old) == name {
			return r, true
		}
	}

	if field, ok := strings.CutPrefix(name, configEnvName("dns.challenge.provider")+"_"); ok {
		return removedProviderPath("dns.challenge.provider." + strings.ToLower(field))
	}

	return removedKey{}, false
}

// File returns the config file in use, or "" when only defaults apply.
func (s *configSource) File() string { return s.file }

// Warnings returns non-fatal findings from loading.
func (s *configSource) Warnings() []string { return s.warnings }

func (s *configSource) Get(key string) any { return s.k.Get(strings.ToLower(key)) }

func (s *configSource) IsSet(key string) bool { return s.k.Exists(strings.ToLower(key)) }

func (s *configSource) String(key string) string { return cast.ToString(s.Get(key)) }

func (s *configSource) Bool(key string) bool { return cast.ToBool(s.Get(key)) }

func (s *configSource) Int(key string) int { return cast.ToInt(s.Get(key)) }

func (s *configSource) Int64(key string) int64 { return cast.ToInt64(s.Get(key)) }

func (s *configSource) Duration(key string) time.Duration { return cast.ToDuration(s.Get(key)) }

func (s *configSource) StringSlice(key string) []string { return cast.ToStringSlice(s.Get(key)) }

func (s *configSource) StringMap(key string) map[string]any { return cast.ToStringMap(s.Get(key)) }

func (s *configSource) StringMapString(key string) map[string]string {
	return cast.ToStringMapString(s.Get(key))
}

func (s *configSource) StringMapStringSlice(key string) map[string][]string {
	return cast.ToStringMapStringSlice(s.Get(key))
}

// UnmarshalKey decodes key into out with viper's decoder settings.
func (s *configSource) UnmarshalKey(key string, out any) error {
	if !s.IsSet(key) {
		return nil
	}

	return s.k.UnmarshalWithConf(strings.ToLower(key), out, koanf.UnmarshalConf{
		DecoderConfig: &mapstructure.DecoderConfig{
			WeaklyTypedInput: true,
			TagName:          "mapstructure",
			DecodeHook: mapstructure.ComposeDecodeHookFunc(
				mapstructure.StringToTimeDurationHookFunc(),
				mapstructure.StringToWeakSliceHookFunc(","),
			),
		},
	})
}

// keyEntry is one key of the file as written, for finding paths that the file
// spells in more than one form.
type keyEntry struct {
	path   string
	parts  []string // path as schema names, see configPathParts
	names  []string // as written, outermost first
	parent int
	dotted bool
	// container marks a plain mapping that only groups its children.
	container bool
}

func (e keyEntry) spelling() string { return strings.Join(e.names, " > ") }

// checkOverlaps rejects a path given both dotted and nested ("log.level" next
// to "log: {level: ...}"): viper resolved such pairs by lookup order, which
// nothing here reproduces.
func (s *configSource) checkOverlaps(v *configValidator, m map[string]any) {
	var entries []keyEntry

	var collect func(prefix string, parent int, names []string, m map[string]any)

	collect = func(prefix string, parent int, names []string, m map[string]any) {
		for _, name := range slices.Sorted(maps.Keys(m)) {
			path := joinConfigPath(prefix, name)
			child, isMap := m[name].(map[string]any)
			own := append(slices.Clone(names), name)

			entries = append(entries, keyEntry{
				path: path, parts: configPathParts(path), names: own, parent: parent,
				dotted:    strings.Contains(name, "."),
				container: isMap && !isOpenMapPath(path) && !strings.Contains(name, "."),
			})

			if isMap && !isOpenMapPath(path) {
				collect(path, len(entries)-1, own, child)
			}
		}
	}

	collect("", -1, nil, m)

	ancestor := func(a, b int) bool {
		for ; b >= 0; b = entries[b].parent {
			if b == a {
				return true
			}
		}

		return false
	}
	reported := map[[2]int]bool{}

	for j := range entries {
		for i := range j {
			a, b := entries[i], entries[j]

			if len(a.parts) > len(b.parts) {
				a, b = b, a
			}

			if !slices.Equal(a.parts, b.parts[:len(a.parts)]) ||
				ancestor(i, j) || ancestor(j, i) ||
				(!a.dotted && !b.dotted) || (a.container && a.path != b.path) {
				continue
			}

			// Its parents already overlap: one report per overlap.
			if reported[[2]int{entries[i].parent, j}] || reported[[2]int{i, entries[j].parent}] ||
				reported[[2]int{entries[i].parent, entries[j].parent}] {
				continue
			}

			reported[[2]int{i, j}] = true

			if len(b.names) < len(a.names) {
				a, b = b, a
			}

			v.Add(&ConfigError{
				Reason: fmt.Sprintf("configuration key %s is set both as %q%s and as %q%s",
					a.path, a.spelling(), s.positionOf(a.names), b.spelling(), s.positionOf(b.names)),
				Hint: "use one form, either the dotted key or nested mappings",
			})
		}
	}
}

// positionOf renders " (file:line:col)" for a key written as names.
func (s *configSource) positionOf(names []string) string {
	line, col, ok := keyPosition(s.fileBytes, names)
	if !ok {
		return ""
	}

	return fmt.Sprintf(" (%s:%d:%d)", s.file, line, col)
}
