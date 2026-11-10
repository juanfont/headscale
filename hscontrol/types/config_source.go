package types

import (
	"bytes"
	"cmp"
	"encoding"
	stdjson "encoding/json"
	"errors"
	"fmt"
	"maps"
	"math"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/go-viper/mapstructure/v2"
	hsdns "github.com/juanfont/headscale/hscontrol/dns"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/knadh/koanf/parsers/json"
	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/confmap"
	"github.com/knadh/koanf/v2"
	"github.com/prometheus/common/model"
	"github.com/rs/zerolog/log"
	"github.com/tailscale/hujson"
)

const (
	configEnvPrefix = "HEADSCALE_"
	providerKey     = "dns.challenge.provider"
)

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
// environment, with lowercase keys. [configSource.decode] turns it into a
// [Config].
type configSource struct {
	k         *koanf.Koanf
	file      string
	fileBytes []byte
	// keys is the file parsed for the positions of its keys, or nil.
	keys     *keyNode
	warnings []string
	// envVars names the variable that set each key, for errors.
	envVars map[string]string
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

// normaliseConfigMap lowercases keys at every depth and drops nulls, so
// lookups are case-insensitive and null means unset.
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

// schemaKey is a key of the configuration; an open map's keys are the
// user's.
type schemaKey struct {
	Path string
	Open bool
}

func schemaKeys() []schemaKey {
	fields := ConfigFields(&Config{})

	keys := make([]schemaKey, len(fields))
	for i, f := range fields {
		keys[i] = schemaKey{Path: f.Path, Open: f.Open}
	}

	return keys
}

func openMapKeys() []string {
	var open []string

	for _, k := range schemaKeys() {
		if k.Open {
			open = append(open, k.Path)
		}
	}

	return open
}

func isOpenMapPath(path string) bool {
	for _, o := range openMapKeys() {
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
		if slices.Contains(openMapKeys(), strings.Join(parts[:i], ".")) {
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
	s := &configSource{k: koanf.New("."), envVars: map[string]string{}}

	d := defaultConfig()

	err := s.k.Load(confmap.Provider(plainMap(&d, false), ""), nil)
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
	s.keys = keyTree(raw)

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

	for _, key := range schemaKeys() {
		k := key.Path
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
				if !slices.Contains(openMapKeys(), path) {
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

// position renders " (file:line:col)" when the key can be located, written
// nested, dotted or mixed, else " (file)".
func (s *configSource) position(path string) string {
	line, col, ok := dottedPosition(s.keys, strings.Split(path, "."))
	if !ok {
		return " (" + s.file + ")"
	}

	return fmt.Sprintf(" (%s:%d:%d)", s.file, line, col)
}

func (s *configSource) loadEnv(environ []string) error {
	env := map[string]string{}

	for _, kv := range environ {
		name, val, _ := strings.Cut(kv, "=")
		// Empty means unset, so a blank variable never overrides the file.
		if val != "" && strings.HasPrefix(name, configEnvPrefix) {
			env[name] = val
		}
	}

	layer := map[string]any{}
	names := map[string]bool{}

	openLayer := map[string]string{}

	for _, key := range schemaKeys() {
		name := configEnvName(key.Path)
		names[name] = true

		val, ok := env[name]
		switch {
		case !ok:
			continue
		case key.Open:
			openLayer[key.Path] = val
		default:
			layer[key.Path] = val
		}

		s.envVars[key.Path] = name
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
	// into it. Its JSON object is set without the removed forms it holds;
	// a value that is not one stays a string, which decode reports.
	for _, key := range slices.Sorted(maps.Keys(openLayer)) {
		val := openLayer[key]
		s.k.Delete(key)

		var (
			v      any = val
			parsed map[string]any
		)

		// A failed decode may still have filled part of parsed: never used.
		if stdjson.Unmarshal([]byte(val), &parsed) == nil && parsed != nil {
			// The hint names keys: inside the JSON they are keys, not variables.
			name := configEnvName(key)
			walkRemoved(key, parsed, false, func(p string, r removedKey) {
				s.warnings = append(s.warnings, r.reason("key", p+" in "+name)+"; "+r.hint())
			})

			v = parsed
		}

		err := s.k.Set(key, v)
		if err != nil {
			return err
		}
	}

	err := s.k.Load(confmap.Provider(layer, "."), nil)
	if err != nil {
		return err
	}

	return s.foldProviderEnv(env)
}

// foldProviderEnv sets HEADSCALE_DNS_CHALLENGE_PROVIDER_NAME, then each
// HEADSCALE_DNS_CHALLENGE_PROVIDER_<SETTING> of the provider named once the
// rest is loaded. Settings depend on the provider, so the schema cannot list
// them; a variable no setting of it has is ignored, as the prefix is
// reserved.
func (s *configSource) foldProviderEnv(env map[string]string) error {
	settings, ok := s.k.Get(providerKey).(map[string]any)
	if !ok {
		if s.k.Exists(providerKey) {
			// Not an object: decode reports it.
			return nil
		}

		settings = map[string]any{}
	}

	folded := false
	fold := func(setting string) {
		key := providerKey + "." + setting
		if v := env[configEnvName(key)]; v != "" {
			settings[setting] = v
			s.envVars[key] = configEnvName(key)
			folded = true
		}
	}

	fold("name")

	for _, setting := range hsdns.SettingNames(DNSChallengeConfig{ProviderSettings: settings}.ProviderName()) {
		fold(setting)
	}

	if !folded {
		return nil
	}

	return s.k.Set(providerKey, settings)
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
// to "log: {level: ...}"): no rule says which of the two should win.
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
	line, col, ok := keyPosition(s.keys, names)
	if !ok {
		return ""
	}

	return fmt.Sprintf(" (%s:%d:%d)", s.file, line, col)
}

// decode decodes the layers into a Config. Every value that does not fit
// its key is reported, in one error.
func (s *configSource) decode() (*Config, error) {
	var cfg Config

	err := s.k.UnmarshalWithConf("", &cfg, koanf.UnmarshalConf{
		Tag: "koanf",
		DecoderConfig: &mapstructure.DecoderConfig{
			ErrorUnused: true,
			DecodeHook: mapstructure.ComposeDecodeHookFunc(
				mapstructure.DecodeHookFuncValue(scalarHook),
				mapstructure.TextUnmarshallerHookFunc(),
			),
		},
	})
	if err != nil {
		return nil, s.decodeErrors(err)
	}

	cfg.ServerURL = strings.TrimRight(cfg.ServerURL, "/")
	for i, p := range cfg.TrustedProxies {
		cfg.TrustedProxies[i] = p.Masked()
	}

	cfg.ConfigDir = s.configDir()

	return &cfg, nil
}

// configDir is where relative paths in the configuration are resolved: the
// config file's directory, or the working directory without a file.
func (s *configSource) configDir() string {
	dir := "."
	if s.file != "" {
		dir = filepath.Dir(s.file)
	}

	abs, err := filepath.Abs(dir)
	if err != nil {
		return dir
	}

	return abs
}

// decodeErrors turns each value mapstructure rejected into a ConfigError
// naming its key and where it was set.
func (s *configSource) decodeErrors(err error) error {
	v := &configValidator{}
	seen := map[string]bool{}

	walkErrTree(err, func(e error) {
		de, ok := e.(*mapstructure.DecodeError) //nolint:errorlint // every node is visited
		if !ok {
			return
		}

		// An element or entry is reported on its key.
		key, _, _ := strings.Cut(de.Name(), "[")

		var leaf *ConfigError
		if !errors.As(de.Unwrap(), &leaf) {
			leaf = &ConfigError{Reason: de.Unwrap().Error(), Cause: de.Unwrap()}

			// The decoder's own error keeps the value (UnconvertibleTypeError's
			// Value); its text does not.
			if hiddenValue(key) {
				leaf.Cause = nil
			}
		}

		ce := *leaf
		ce.Reason = key + " " + leaf.Reason + s.origin(key)

		if !hiddenValue(key) {
			ce.Current = []KV{{key, s.k.Get(key)}}
		}

		if !seen[ce.Reason] {
			seen[ce.Reason] = true
			v.Add(&ce)
		}
	})

	if !v.HasErrors() {
		return err
	}

	return v.Err()
}

// origin renders where key's value came from: its variable, else its
// position in the file.
func (s *configSource) origin(key string) string {
	if name, ok := s.envVars[key]; ok {
		return " (env " + name + ")"
	}

	if s.file == "" {
		return ""
	}

	return s.position(key)
}

// hiddenValue reports whether key's value may be a credential, which errors
// do not show: a secret, a URL (its userinfo) or a DNS provider setting.
func hiddenValue(key string) bool {
	if key == providerKey || strings.HasPrefix(key, providerKey+".") || slices.Contains(URLKeys, key) {
		return true
	}

	for _, f := range ConfigFields(&Config{}) {
		if f.Path != key {
			continue
		}

		return f.Field.Type == reflect.TypeFor[Secret]()
	}

	return false
}

var (
	durationType  = reflect.TypeFor[time.Duration]()
	fileModeType  = reflect.TypeFor[FileMode]()
	prefixType    = reflect.TypeFor[netip.Prefix]()
	prefixPtrType = reflect.TypeFor[*netip.Prefix]()
)

// scalarHook converts a value as written into what its field's type takes,
// before mapstructure and TextUnmarshaler see it. A string is the form
// variables take, so it may stand for a number, bool, list or map.
func scalarHook(from, to reflect.Value) (any, error) {
	data := from.Interface()
	s, isString := data.(string)

	switch t := to.Type(); {
	case t == durationType:
		return toDuration(from)
	case t == fileModeType && !isString:
		// YAML reads an unquoted 0770 as the integer 504, which cannot be
		// told apart from a literal 504.
		return nil, &ConfigError{
			Reason:  "must be quoted",
			Maximum: `"0777"`,
			Hint:    `quote the value, e.g. "0770"; unquoted, YAML reads 0770 as the number 504`,
			Cause:   util.ErrInvalidFileMode,
		}
	case t == prefixPtrType && isString && s == "":
		// Unset. Typed: the next hook reads its type.
		return (*netip.Prefix)(nil), nil
	case t == prefixType && isString:
		_, err := netip.ParsePrefix(s)
		if err != nil {
			return nil, &ConfigError{
				Reason: "is not a valid CIDR",
				Detail: err.Error(),
				Hint:   `use CIDR form, e.g. "100.64.0.0/10"`,
				Cause:  err,
			}
		}
	case t.Kind() == reflect.String:
		if text, ok := scalarText(from); ok {
			return text, nil
		}
	case t.Kind() == reflect.Bool:
		return toBool(from)
	case t.Kind() >= reflect.Int && t.Kind() <= reflect.Int64:
		return toInt(from, t)
	case t.Kind() == reflect.Slice && isString:
		return toList(s, t.Elem())
	case t.Kind() == reflect.Map && isString:
		return toObject(s)
	}

	return data, nil
}

// scalarText is a number or bool as text.
func scalarText(v reflect.Value) (string, bool) {
	switch {
	case v.Kind() == reflect.Bool:
		return strconv.FormatBool(v.Bool()), true
	case v.CanInt():
		return strconv.FormatInt(v.Int(), 10), true
	case v.CanUint():
		return strconv.FormatUint(v.Uint(), 10), true
	case v.CanFloat():
		return strconv.FormatFloat(v.Float(), 'f', -1, 64), true
	}

	return "", false
}

func toDuration(v reflect.Value) (any, error) {
	unit := &ConfigError{Reason: "needs a unit", Hint: `write the unit, e.g. "30s", "5m" or "90d"`}

	if v.Kind() != reflect.String {
		if _, ok := scalarText(v); !ok || v.Kind() == reflect.Bool {
			return v.Interface(), nil
		}

		if v.IsZero() {
			return time.Duration(0), nil
		}

		return nil, unit
	}

	s := v.String()

	d, err := time.ParseDuration(s)
	if err == nil {
		return d, nil
	}

	md, err := model.ParseDuration(s)
	if err == nil {
		return time.Duration(md), nil
	}

	_, err = strconv.ParseFloat(s, 64)
	if err == nil {
		return nil, unit
	}

	return nil, &ConfigError{Reason: "is not a duration", Hint: unit.Hint}
}

func toBool(v reflect.Value) (any, error) {
	text, ok := reflect.TypeAssert[string](v)
	if !ok {
		if text, ok = scalarText(v); !ok || v.Kind() == reflect.Bool {
			return v.Interface(), nil
		}
	}

	b, err := strconv.ParseBool(text)
	if err != nil {
		return nil, &ConfigError{Reason: "is not a boolean", Hint: "use true or false", Cause: err}
	}

	return b, nil
}

// toInt takes a whole number in t's range, written as one or as text.
func toInt(v reflect.Value, t reflect.Type) (any, error) {
	var (
		n     int64
		whole bool
	)

	switch {
	case v.Kind() == reflect.String:
		i, err := strconv.ParseInt(v.String(), 10, 64)
		if errors.Is(err, strconv.ErrRange) {
			return nil, &ConfigError{Reason: "is out of range"}
		}

		n, whole = i, err == nil
	case v.CanInt():
		n, whole = v.Int(), true
	case v.CanUint():
		if v.Uint() > math.MaxInt64 {
			return nil, &ConfigError{Reason: "is out of range"}
		}

		n, whole = int64(v.Uint()), true //nolint:gosec // bounded above
	case v.CanFloat():
		f := v.Float()
		if f < math.MinInt64 || f >= math.MaxInt64 {
			return nil, &ConfigError{Reason: "is out of range"}
		}

		n, whole = int64(f), f == math.Trunc(f)
	default:
		return v.Interface(), nil
	}

	if !whole {
		return nil, &ConfigError{Reason: "is not an integer"}
	}

	if reflect.Zero(t).OverflowInt(n) {
		return nil, &ConfigError{Reason: "is out of range"}
	}

	return n, nil
}

// toList splits a list written as one string: as JSON when it starts with
// "[", as a list of objects must, else on whitespace.
func toList(s string, elem reflect.Type) (any, error) {
	object := elem.Kind() == reflect.Struct && !reflect.PointerTo(elem).Implements(textUnmarshalerType)

	if !object && !strings.HasPrefix(strings.TrimSpace(s), "[") {
		fields := strings.Fields(s)

		list := make([]any, len(fields))
		for i, f := range fields {
			list[i] = f
		}

		return list, nil
	}

	var list []any

	err := stdjson.Unmarshal([]byte(s), &list)
	if err != nil {
		hint := `write the list as JSON, e.g. ["a", "b"]`
		if object {
			hint = `write the list as JSON, e.g. [{"name": "a.example.com", "type": "A", "value": "100.64.0.1"}]`
		}

		return nil, &ConfigError{Reason: "is not a JSON list", Hint: hint, Cause: err}
	}

	return list, nil
}

func toObject(s string) (any, error) {
	var m map[string]any

	err := stdjson.Unmarshal([]byte(s), &m)
	if err != nil || m == nil {
		return nil, &ConfigError{
			Reason: "is not a JSON object",
			Hint:   `write the map as JSON, e.g. {"example.com": ["1.1.1.1"]}`,
			Cause:  err,
		}
	}

	return m, nil
}

// plainMap is cfg as nested maps of plain values, keyed as in a file: what
// the defaults layer loads and a parser marshals. With redact, a secret
// shows only a file: reference, a URL no userinfo, and every DNS provider
// setting but a scalar name and file: references is hidden: any of them, a
// number included, may be a credential.
func plainMap(cfg *Config, redact bool) map[string]any {
	out := map[string]any{}

	if redact {
		// HTTPURL and Secret values redact themselves, plain strings not.
		r := cfg.RedactedURLs()
		cfg = &r
	}

	for _, f := range ConfigFields(cfg) {
		v := plainValue(f.Value, redact)

		switch settings, isMap := v.(map[string]any); {
		case f.Field.Type == prefixPtrType && f.Value.IsNil():
			// An explicit unset, which survives a default.
			v = ""
		case redact && isMap && f.Path == providerKey:
			v = redactProvider(settings)
		}

		if v == nil {
			continue
		}

		parts := strings.Split(f.Path, ".")
		m := out

		for _, p := range parts[:len(parts)-1] {
			child, ok := m[p].(map[string]any)
			if !ok {
				child = map[string]any{}
				m[p] = child
			}

			m = child
		}

		m[parts[len(parts)-1]] = v
	}

	return out
}

// maxExactJSONInt is the largest integer a float64, as JSON parsers read
// numbers, holds exactly.
const maxExactJSONInt = 1 << 53

// plainValue is v as a parser writes it, or nil to leave it out.
func plainValue(v reflect.Value, redact bool) any {
	for v.Kind() == reflect.Pointer || v.Kind() == reflect.Interface {
		if v.IsNil() {
			return nil
		}

		v = v.Elem()
	}

	switch x := v.Interface().(type) {
	case time.Duration:
		return x.String()
	case Secret:
		if redact {
			return x.Redacted()
		}

		return string(x)
	case HTTPURL:
		// As written: its JSON form drops userinfo.
		if redact {
			return x.Redacted()
		}

		return string(x)
	case encoding.TextMarshaler:
		text, err := x.MarshalText()
		if err != nil {
			return nil
		}

		return string(text)
	}

	switch v.Kind() { //nolint:exhaustive // the kinds Config holds; default keeps the rest as is
	case reflect.String:
		return v.String()
	case reflect.Bool:
		return v.Bool()
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		if n := v.Int(); n > maxExactJSONInt || n < -maxExactJSONInt {
			// The integer hook takes it back from text.
			return strconv.FormatInt(n, 10)
		}

		return int(v.Int())
	case reflect.Slice:
		if v.IsNil() {
			return nil
		}

		list := make([]any, v.Len())
		for i := range list {
			list[i] = plainValue(v.Index(i), redact)
		}

		return list
	case reflect.Map:
		if v.IsNil() {
			return nil
		}

		m := make(map[string]any, v.Len())

		for iter := v.MapRange(); iter.Next(); {
			if e := plainValue(iter.Value(), redact); e != nil {
				m[fmt.Sprint(iter.Key().Interface())] = e
			}
		}

		return m
	case reflect.Struct:
		// Without koanf tags (tailcfg.DNSRecord): its field names, lowercased.
		m := map[string]any{}

		for f, fv := range v.Fields() {
			if f.IsExported() {
				m[cmp.Or(f.Tag.Get("koanf"), strings.ToLower(f.Name))] = plainValue(fv, redact)
			}
		}

		return m
	default:
		return v.Interface()
	}
}

func redactProvider(settings map[string]any) map[string]any {
	out := make(map[string]any, len(settings))
	for k, v := range settings {
		out[k] = redactLeaves(v)
	}

	// A name that is a map or list stays hidden: it is no name.
	if _, ok := (DNSChallengeConfig{ProviderSettings: settings}).providerName(); ok {
		if name, set := settings["name"]; set {
			out["name"] = name
		}
	}

	return out
}

func redactLeaves(v any) any {
	switch x := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, e := range x {
			out[k] = redactLeaves(e)
		}

		return out
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = redactLeaves(e)
		}

		return out
	case string:
		if strings.HasPrefix(x, "file:") {
			return x
		}
	}

	return "<redacted>"
}
