package dns

import (
	"errors"
	"fmt"
	"maps"
	"os"
	"reflect"
	"slices"
	"strings"

	"github.com/go-viper/mapstructure/v2"
	gigahost "github.com/kradalby/libdns-gigahost"
	"github.com/libdns/cloudflare"
	"github.com/libdns/hetzner/v2"
	"github.com/libdns/libdns"
	"github.com/libdns/powerdns"
	"github.com/libdns/rfc2136"
)

// Provider writes ACME DNS-01 challenge records into a zone.
//
// It is append and delete only: a wildcard order puts two values on the
// same name, so SetRecords would replace the value the CA is validating.
type Provider interface {
	libdns.RecordAppender
	libdns.RecordDeleter
}

// providers is the compiled-in provider registry. Providers are decoded
// from configuration through their json tags, so adding one is one line
// plus its module; the set is curated because each provider is a
// dependency to keep current and its quirks become ours.
var providers = map[string]func() Provider{
	"cloudflare": func() Provider { return new(cloudflare.Provider) },
	"gigahost":   func() Provider { return new(gigahost.Provider) },
	"hetzner":    func() Provider { return new(hetzner.Provider) },
	"powerdns":   func() Provider { return new(powerdns.Provider) },
	"rfc2136":    func() Provider { return new(rfc2136.Provider) },
}

var (
	ErrUnknownProvider = errors.New("unknown DNS provider")
	ErrProviderConfig  = errors.New("invalid DNS provider configuration")
)

// pathSuffix marks a setting whose value is read from a file, keeping
// secrets out of the configuration file.
const pathSuffix = "_path"

// ProviderNames returns the names of the compiled-in providers.
func ProviderNames() []string {
	return slices.Sorted(maps.Keys(providers))
}

// NewProvider builds the named provider from its settings.
//
// settings holds the provider's keys as written in the configuration
// file. get looks up a single key and is consulted for every field of
// the provider, because environment variables only reach individual
// keys, never a map. Any string field can instead be read from a file
// named by "<field>_path". Unknown keys are an error so a typo does not
// silently leave a credential empty.
func NewProvider(
	name string,
	settings map[string]any,
	get func(key string) (any, bool),
) (Provider, error) {
	newProvider, ok := providers[strings.ToLower(name)]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrUnknownProvider, name)
	}

	provider := newProvider()

	input := make(map[string]any, len(settings))
	for k, v := range settings {
		input[strings.ToLower(k)] = v
	}

	delete(input, "name")

	fields := jsonFields(provider)
	for tag, kind := range fields {
		if v, ok := get(tag); ok {
			input[tag] = v
		}

		pathKey := tag + pathSuffix
		if _, isField := fields[pathKey]; isField || kind != reflect.String {
			continue
		}

		if v, ok := get(pathKey); ok {
			input[pathKey] = v
		}

		path, ok := input[pathKey]
		if !ok {
			continue
		}

		if _, both := input[tag]; both {
			return nil, fmt.Errorf("%w: %s and %s are mutually exclusive", ErrProviderConfig, tag, pathKey)
		}

		value, err := os.ReadFile(os.ExpandEnv(fmt.Sprint(path)))
		if err != nil {
			return nil, fmt.Errorf("%w: reading %s: %w", ErrProviderConfig, pathKey, err)
		}

		input[tag] = strings.TrimSpace(string(value))
		delete(input, pathKey)
	}

	// Every provider needs a credential or a server: a block with only a
	// name is a secret that was not set, and would fail at the first
	// certificate instead of at startup.
	if len(input) == 0 {
		return nil, fmt.Errorf("%w for %s: no settings", ErrProviderConfig, name)
	}

	decoder, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		TagName:          "json",
		WeaklyTypedInput: true,
		ErrorUnused:      true,
		Result:           provider,
	})
	if err != nil {
		return nil, fmt.Errorf("creating decoder: %w", err)
	}

	err = decoder.Decode(input)
	if err != nil {
		return nil, fmt.Errorf("%w for %s: %w", ErrProviderConfig, name, err)
	}

	return provider, nil
}

// jsonFields returns the json key and kind of each configurable field of
// the provider struct.
func jsonFields(provider Provider) map[string]reflect.Kind {
	t := reflect.TypeOf(provider).Elem()
	fields := make(map[string]reflect.Kind, t.NumField())

	for f := range t.Fields() {
		name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
		if !f.IsExported() || name == "" || name == "-" {
			continue
		}

		fields[name] = f.Type.Kind()
	}

	return fields
}
