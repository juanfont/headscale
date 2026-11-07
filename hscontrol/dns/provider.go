package dns

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/url"
	"os"
	"reflect"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/go-viper/mapstructure/v2"
	gigahost "github.com/kradalby/libdns-gigahost"
	"github.com/libdns/acmedns"
	"github.com/libdns/cloudflare"
	"github.com/libdns/hetzner/v2"
	"github.com/libdns/libdns"
	"github.com/libdns/powerdns"
	"github.com/libdns/rfc2136"
)

// Isolator is implemented by a provider that can answer several names'
// challenges from one record, as acme-dns does for names sharing a
// registration. The CA accepts a value found there for any of those
// names, so a node only gets a certificate for a name the provider
// isolates.
type Isolator interface {
	// Isolates reports whether name's challenge is answered apart from
	// every other name's, once CheckIsolation passed.
	Isolates(name string) bool
	// CheckIsolation reports why node certificate names would share a
	// record.
	CheckIsolation() error
}

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
// dependency to keep current and its quirks become ours. required lists
// the settings the provider's own code cannot work without, so a missing
// one fails at startup instead of at the first certificate. env names the
// variable the provider's own code reads a required setting from when the
// setting is unset.
var providers = map[string]struct {
	build    func() Provider
	required []string
	env      map[string]string
}{
	// validate checks the accounts.
	"acmedns": {build: func() Provider { return &acmeDNS{served: make(map[string][2]acmeDNSValue)} }},
	// api_token authenticates writes; zone_token only zone lookups.
	"cloudflare": {build: func() Provider { return new(cloudflare.Provider) }, required: []string{"api_token"}},
	"gigahost":   {build: func() Provider { return new(gigahost.Provider) }, required: []string{"api_key"}},
	"hetzner": {
		build:    func() Provider { return new(hetzner.Provider) },
		required: []string{"api_token"},
		env:      map[string]string{"api_token": "LIBDNS_HETZNER_TOKEN"}, //nolint:gosec // a variable's name, not a credential
	},
	"powerdns": {build: func() Provider { return new(powerdns.Provider) }, required: []string{"server_url", "api_token"}},
	// Every request is TSIG-signed.
	"rfc2136": {build: func() Provider { return new(rfc2136.Provider) }, required: []string{"server", "key_name", "key_alg", "key"}},
}

var (
	ErrUnknownProvider = errors.New("unknown DNS provider")
	ErrProviderConfig  = errors.New("invalid DNS provider configuration")
	errAcmeDNSAccount  = errors.New("acme-dns needs username, password, subdomain and server_url")
	// The CA accepts a value found in a shared record for any of the
	// names, so a node could publish another's under its own name.
	errAcmeDNSOneAccount = errors.New("acme-dns with one account answers every name's challenge from one record; " +
		"node certificates need a registration per name under config")
	errAcmeDNSShared = errors.New("acme-dns registration mapped to more than one name")
	errNotJSON       = errors.New("file is not JSON")
	errFileValue     = errors.New("file holds an invalid value")
	errFileSecret    = errors.New("file names a secret that cannot be read")

	// ErrSecretUnread is returned, with the value as given, by a secret
	// func that leaves a file: secret unread; checks of it are skipped.
	ErrSecretUnread = errors.New("secret left unread")
)

// settingsKey is where the provider settings live in the configuration.
const settingsKey = "dns.challenge.provider"

// ProviderNames returns the names of the compiled-in providers.
func ProviderNames() []string {
	return slices.Sorted(maps.Keys(providers))
}

// SettingNames returns the names of the named provider's settings, or nil
// for an unknown provider.
func SettingNames(provider string) []string {
	entry, ok := providers[strings.ToLower(provider)]
	if !ok {
		return nil
	}

	return slices.Sorted(maps.Keys(jsonFields(entry.build())))
}

// NewProvider builds the named provider from its settings.
//
// settings holds the provider's keys as written, in any case. get looks up
// a single key as the provider spells it and is consulted for every field
// of the provider, so it wins over a differently cased spelling in
// settings. secret resolves every string setting, nested ones
// included, so any of them can be read from a file; a non-string setting
// set to "file:<path>" is the JSON in that file. Unknown keys are an
// error so a typo does not silently leave a credential empty.
func NewProvider(
	name string,
	settings map[string]any,
	get func(key string) (any, bool),
	secret func(key, value string) (string, error),
) (Provider, error) {
	entry, ok := providers[strings.ToLower(name)]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrUnknownProvider, name)
	}

	provider := entry.build()

	input := make(map[string]any, len(settings))
	for k, v := range settings {
		input[strings.ToLower(k)] = v
	}

	delete(input, "name")

	// The values left unread, for validate to skip. Kept by value, as a
	// setting's name may be spelt in any case.
	unread := map[string]bool{}
	read := func(key, value string) (string, error) {
		s, err := secret(key, value)
		if errors.Is(err, ErrSecretUnread) {
			unread[value] = true

			return value, nil
		}

		return s, err
	}

	// The origin, "<setting>: <path>", of each setting read from a file.
	files := map[string]string{}

	fields := jsonFields(provider)
	for tag, kind := range fields {
		if v, ok := get(tag); ok {
			input[tag] = v
		}

		value, ok := input[tag]
		if !ok {
			continue
		}

		var err error

		if s, isString := value.(string); isString && kind != reflect.String && strings.HasPrefix(s, "file:") {
			files[tag] = settingsKey + "." + tag + ": " + os.ExpandEnv(strings.TrimPrefix(s, "file:"))
			value, err = settingFromFile(entry.build(), tag, s, files[tag], secret)
		} else {
			value, err = resolveSecrets(tag, value, read)
		}

		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrProviderConfig, err)
		}

		input[tag] = value
	}

	err := decode(input, provider)
	if err != nil {
		return nil, fmt.Errorf("%w for %s: %w", ErrProviderConfig, name, err)
	}

	if p, ok := provider.(*acmeDNS); ok {
		p.configFile = files["config"]
	}

	// After decoding, so a misspelt setting is reported as that. An unread
	// file: value counts as set.
	var missing []string

	for _, k := range entry.required {
		// os.Getenv("") is "" for a setting without a fallback variable.
		if v := input[k]; (v == nil || v == "") && os.Getenv(entry.env[k]) == "" {
			missing = append(missing, k)
		}
	}

	if len(missing) > 0 {
		return nil, fmt.Errorf("%w for %s: missing %s", ErrProviderConfig, name, strings.Join(missing, ", "))
	}

	if v, ok := provider.(interface {
		validate(unread map[string]bool) error
	}); ok {
		err = v.validate(unread)
		if err != nil {
			return nil, fmt.Errorf("%w for %s: %w", ErrProviderConfig, name, err)
		}
	}

	return provider, nil
}

// decode sets provider's fields from input by their json tags.
func decode(input map[string]any, provider Provider) error {
	decoder, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		TagName:          "json",
		WeaklyTypedInput: true,
		ErrorUnused:      true,
		Squash:           true,
		Result:           provider,
	})
	if err != nil {
		return fmt.Errorf("creating decoder: %w", err)
	}

	return decoder.Decode(input)
}

// settingFromFile reads the non-string setting tag from the JSON in the
// file value names, decoded into provider, a fresh one, before any secret
// in it is read. Past reading the file, errors name only origin: decoder
// paths, keys and nested paths all come from the file. Left unread, it is
// an empty map: set, with nothing to check.
func settingFromFile(
	provider Provider,
	tag, value, origin string,
	secret func(key, value string) (string, error),
) (any, error) {
	s, err := secret(tag, value)
	if errors.Is(err, ErrSecretUnread) {
		// shortcut: fits map settings only, the one non-string kind any
		// provider has (TestProviderSettingKinds); give another kind its
		// own placeholder when a provider adds one.
		return map[string]any{}, nil
	}

	if err != nil {
		return nil, err
	}

	var v any

	// json's errors quote the contents.
	if json.Unmarshal([]byte(s), &v) != nil {
		return nil, fmt.Errorf("%s: %w", origin, errNotJSON)
	}

	if decode(map[string]any{tag: v}, provider) != nil {
		return nil, fmt.Errorf("%s: %w", origin, errFileValue)
	}

	v, err = resolveSecrets(tag, v, secret)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", origin, errFileSecret)
	}

	return v, nil
}

// resolveSecrets resolves every string in value, down through nested
// settings such as acme-dns's per-name registrations; key names the
// setting in errors. Maps are copied, as they may be the caller's.
func resolveSecrets(key string, value any, secret func(key, value string) (string, error)) (any, error) {
	switch value := value.(type) {
	case string:
		return secret(key, value)
	case map[string]any:
		out := make(map[string]any, len(value))

		for k, v := range value {
			r, err := resolveSecrets(key+"."+k, v, secret)
			if err != nil {
				return nil, err
			}

			out[k] = r
		}

		return out, nil
	}

	return value, nil
}

// IsProviderSetting reports whether a compiled-in provider has a setting
// named name, nested ones such as acme-dns's registrations included.
func IsProviderSetting(name string) bool {
	return providerSetting(name, func(reflect.Type) bool { return true })
}

// IsProviderMapSetting reports whether a compiled-in provider has a map
// setting named name, whose keys are names, such as acme-dns's
// registrations, rather than settings.
func IsProviderMapSetting(name string) bool {
	return providerSetting(name, func(t reflect.Type) bool { return t.Kind() == reflect.Map })
}

func providerSetting(name string, match func(reflect.Type) bool) bool {
	for _, entry := range providers {
		if hasSetting(reflect.TypeOf(entry.build()), name, match) {
			return true
		}
	}

	return false
}

// hasSetting matches names case-insensitively, as the decoder does.
func hasSetting(t reflect.Type, name string, match func(reflect.Type) bool) bool {
	for t.Kind() == reflect.Pointer || t.Kind() == reflect.Map || t.Kind() == reflect.Slice {
		t = t.Elem()
	}

	if t.Kind() != reflect.Struct {
		return false
	}

	for _, f := range reflect.VisibleFields(t) {
		tag, _, _ := strings.Cut(f.Tag.Get("json"), ",")
		if !f.IsExported() || tag == "" || tag == "-" {
			continue
		}

		ft := f.Type
		for ft.Kind() == reflect.Pointer {
			ft = ft.Elem()
		}

		if (strings.EqualFold(tag, name) && match(ft)) || hasSetting(f.Type, name, match) {
			return true
		}
	}

	return false
}

// jsonFields returns the json key and kind of each configurable field of
// the provider struct.
func jsonFields(provider Provider) map[string]reflect.Kind {
	t := reflect.TypeOf(provider).Elem()
	fields := make(map[string]reflect.Kind, t.NumField())

	for _, f := range reflect.VisibleFields(t) {
		name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
		if !f.IsExported() || name == "" || name == "-" {
			continue
		}

		fields[name] = f.Type.Kind()
	}

	return fields
}

// acmeDNSSpacing separates updates to a registration. acme-dns stamps an
// update with the second it lands in and overwrites the earlier stamp,
// either one on a tie, so which value is older holds only while updates
// land in distinct seconds. The margin absorbs clock slew.
const acmeDNSSpacing = time.Second + 100*time.Millisecond

// acmeDNS is the acme-dns provider. A registration serves the two values
// written to it last, and deleting is a no-op, so an update overwrites
// whichever is older even if a CA is still validating it. acmeDNS mirrors
// what each registration serves and refuses such an update.
type acmeDNS struct {
	acmedns.Provider

	// configFile is the origin of Configs read from a file, which errors
	// about Configs name instead of anything in it.
	configFile string

	mu sync.Mutex
	// served is what each registration serves, oldest first.
	served map[string][2]acmeDNSValue
}

// acmeDNSValue is a value acme-dns serves. It stays live, and must not
// be overwritten, until it is deleted here.
type acmeDNSValue struct {
	text string
	live bool
	// written is when its update returned; acme-dns stamped it no later.
	written time.Time
}

func (p *acmeDNS) AppendRecords(
	ctx context.Context,
	zone string,
	recs []libdns.Record,
) ([]libdns.Record, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	var appended []libdns.Record

	for _, rec := range recs {
		rr := rec.RR()
		reg := p.registration(zone, rr.Name)
		served := p.served[reg]

		if served[0].live {
			if p.configFile != "" {
				reg = "from " + p.configFile
			}

			return appended, fmt.Errorf(
				"%w: acme-dns registration %s would overwrite a value still in use",
				ErrTooManyChallenges, reg,
			)
		}

		select {
		case <-ctx.Done():
			return appended, ctx.Err()
		case <-time.After(time.Until(served[1].written.Add(acmeDNSSpacing))):
		}

		got, err := p.Provider.AppendRecords(ctx, zone, []libdns.Record{rec})
		appended = append(appended, got...)

		// A failed update may still have reached acme-dns, so the older
		// value counts as overwritten either way.
		p.served[reg] = [2]acmeDNSValue{
			served[1],
			{text: rr.Data, live: err == nil, written: time.Now()},
		}

		if err != nil {
			return appended, p.redact(err)
		}
	}

	return appended, nil
}

// redact hides err's text, which may quote registrations read from a
// file, behind the file's name; errors.Is and errors.As still see err.
func (p *acmeDNS) redact(err error) error {
	if err == nil || p.configFile == "" {
		return err
	}

	return &acmeDNSFileError{origin: p.configFile, err: err}
}

type acmeDNSFileError struct {
	origin string
	err    error
}

func (e *acmeDNSFileError) Error() string { return e.origin + ": acme-dns update failed" }

func (e *acmeDNSFileError) Unwrap() error { return e.err }

func (p *acmeDNS) DeleteRecords(
	ctx context.Context,
	zone string,
	recs []libdns.Record,
) ([]libdns.Record, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	for _, rec := range recs {
		rr := rec.RR()
		reg := p.registration(zone, rr.Name)
		served := p.served[reg]

		// The older copy of a value written twice is the one to free, so
		// the newer keeps serving it.
		for i, v := range served {
			if v.live && v.text == rr.Data {
				served[i].live = false

				break
			}
		}

		p.served[reg] = served
	}

	deleted, err := p.Provider.DeleteRecords(ctx, zone, recs)

	return deleted, p.redact(err)
}

// Isolates reports whether name has a registration of its own;
// CheckIsolation makes sure no other name is mapped to it.
func (p *acmeDNS) Isolates(name string) bool {
	_, ok := p.Configs[name]

	return ok
}

// CheckIsolation requires a registration per name: every name sharing a
// registration has its challenge answered from the same record.
func (p *acmeDNS) CheckIsolation() error {
	if p.Configs == nil {
		return errAcmeDNSOneAccount
	}

	names := make(map[string]string, len(p.Configs))

	for _, name := range slices.Sorted(maps.Keys(p.Configs)) {
		sub := p.Configs[name].Subdomain

		if other, shared := names[sub]; shared {
			if p.configFile != "" {
				return fmt.Errorf("%s: %w", p.configFile, errAcmeDNSShared)
			}

			// The registration is not named: it may have been read from a file.
			return fmt.Errorf("%w: %s and %s share a registration", errAcmeDNSShared, other, name)
		}

		names[sub] = name
	}

	return nil
}

// registration returns the subdomain of the account acmedns writes a
// record with, picked the way acmedns picks it.
func (p *acmeDNS) registration(zone, name string) string {
	if p.Configs == nil {
		return p.Subdomain
	}

	domain := strings.Trim(libdns.AbsoluteName(name, zone), ".")

	return p.Configs[strings.TrimPrefix(domain, "_acme-challenge.")].Subdomain
}

// validate reports at startup what acmedns would only report at the first
// certificate. It builds requests without checking the URL, so a bad
// server_url would panic. An unread server_url is checked once it is read.
func (p *acmeDNS) validate(unread map[string]bool) error {
	accounts := []acmedns.DomainConfig{{
		Username:  p.Username,
		Password:  p.Password,
		Subdomain: p.Subdomain,
		ServerURL: p.ServerURL,
	}}
	if p.Configs != nil {
		accounts = slices.Collect(maps.Values(p.Configs))
	}

	for _, a := range accounts {
		u, err := url.Parse(a.ServerURL)
		missing := a.Username == "" || a.Password == "" || a.Subdomain == ""
		badURL := !unread[a.ServerURL] && (err != nil || u.Host == "")

		if missing || badURL {
			return errAcmeDNSAccount
		}
	}

	return nil
}
