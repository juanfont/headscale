package dns

import (
	"context"
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
// dependency to keep current and its quirks become ours.
var providers = map[string]func() Provider{
	"acmedns":    func() Provider { return &acmeDNS{served: make(map[string][2]acmeDNSValue)} },
	"cloudflare": func() Provider { return new(cloudflare.Provider) },
	"gigahost":   func() Provider { return new(gigahost.Provider) },
	"hetzner":    func() Provider { return new(hetzner.Provider) },
	"powerdns":   func() Provider { return new(powerdns.Provider) },
	"rfc2136":    func() Provider { return new(rfc2136.Provider) },
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
		Squash:           true,
		Result:           provider,
	})
	if err != nil {
		return nil, fmt.Errorf("creating decoder: %w", err)
	}

	err = decoder.Decode(input)
	if err != nil {
		return nil, fmt.Errorf("%w for %s: %w", ErrProviderConfig, name, err)
	}

	if v, ok := provider.(interface{ validate() error }); ok {
		err = v.validate()
		if err != nil {
			return nil, fmt.Errorf("%w for %s: %w", ErrProviderConfig, name, err)
		}
	}

	return provider, nil
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
			return appended, err
		}
	}

	return appended, nil
}

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

	return p.Provider.DeleteRecords(ctx, zone, recs)
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
			return fmt.Errorf("%w: %s and %s share registration %s", errAcmeDNSShared, other, name, sub)
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
// server_url would panic.
func (p *acmeDNS) validate() error {
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

		if missing || err != nil || u.Host == "" {
			return errAcmeDNSAccount
		}
	}

	return nil
}
