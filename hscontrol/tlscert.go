package hscontrol

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/libdns/libdns"
	"tailscale.com/tailcfg"
)

const (
	dnsCertRecordRetention = 10 * time.Minute
	maxTXTValueLength      = 255
)

var (
	errDNSCertProviderExists = errors.New("DNS certificate provider already registered")
	errDNSCertProviderUnset  = errors.New("DNS certificate provider is not registered")
	errDNSCertRecordType     = errors.New("only TXT records are supported")
	errDNSCertRecordName     = errors.New("DNS record name is not allowed")
	errDNSCertRecordValue    = errors.New("invalid TXT record value")
)

// DNSCertificateProviderFactory constructs a libdns RecordSetter from the
// provider_config map in config.yaml.
type DNSCertificateProviderFactory func(map[string]string) (libdns.RecordSetter, error)

var (
	dnsCertProviderMu        sync.RWMutex
	dnsCertProviderFactories = map[string]DNSCertificateProviderFactory{}
)

// RegisterDNSCertificateProvider registers a provider-neutral libdns factory.
// Concrete provider packages should call this from init and return a
// libdns.RecordSetter built from providerConfig.
func RegisterDNSCertificateProvider(
	name string,
	factory DNSCertificateProviderFactory,
) error {
	name = strings.TrimSpace(strings.ToLower(name))
	if name == "" {
		return fmt.Errorf("provider name is empty")
	}
	if factory == nil {
		return fmt.Errorf("provider factory is nil")
	}

	dnsCertProviderMu.Lock()
	defer dnsCertProviderMu.Unlock()

	if _, ok := dnsCertProviderFactories[name]; ok {
		return fmt.Errorf("%w: %s", errDNSCertProviderExists, name)
	}

	dnsCertProviderFactories[name] = factory

	return nil
}

func newDNSCertificateManager(
	cfg types.DNSCertificatesConfig,
) (*dnsCertificateManager, error) {
	providerName := strings.TrimSpace(strings.ToLower(cfg.Provider))

	dnsCertProviderMu.RLock()
	factory := dnsCertProviderFactories[providerName]
	dnsCertProviderMu.RUnlock()

	if factory == nil {
		return nil, fmt.Errorf("%w: %s", errDNSCertProviderUnset, providerName)
	}

	setter, err := factory(cfg.ProviderConfig)
	if err != nil {
		return nil, fmt.Errorf("creating DNS certificate provider %q: %w", providerName, err)
	}
	if setter == nil {
		return nil, fmt.Errorf("creating DNS certificate provider %q: nil provider", providerName)
	}

	return newDNSCertificateManagerForSetter(cfg, setter), nil
}

func newDNSCertificateManagerForSetter(
	cfg types.DNSCertificatesConfig,
	setter libdns.RecordSetter,
) *dnsCertificateManager {
	return &dnsCertificateManager{
		zone:            strings.TrimSuffix(strings.ToLower(cfg.Zone), "."),
		ttl:             cfg.TTL,
		propagationWait: cfg.PropagationWait,
		setter:          setter,
		records:         make(map[string]map[string]time.Time),
	}
}

type dnsCertificateManager struct {
	zone            string
	ttl             time.Duration
	propagationWait time.Duration
	setter          libdns.RecordSetter

	mu      sync.Mutex
	records map[string]map[string]time.Time
}

func (m *dnsCertificateManager) setDNS(
	ctx context.Context,
	node types.NodeView,
	baseDomain string,
	req tailcfg.SetDNSRequest,
) error {
	if m == nil {
		return errDNSCertProviderUnset
	}

	if err := validateSetDNSRequest(node, baseDomain, req); err != nil {
		return err
	}

	name := canonicalDNSName(req.Name)
	value := strings.TrimSpace(req.Value)

	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	m.purgeExpiredLocked(now)

	values := m.records[name]
	if values == nil {
		values = make(map[string]time.Time)
		m.records[name] = values
	}

	retention := dnsCertRecordRetention
	if m.ttl > retention {
		retention = m.ttl
	}
	expires := now.Add(retention)
	values[value] = expires

	records := make([]libdns.Record, 0, len(values))
	for txt := range values {
		records = append(records, libdns.TXT{
			Name: m.relativeRecordName(name),
			TTL:  m.ttl,
			Text: txt,
		})
	}

	if _, err := m.setter.SetRecords(ctx, m.zone, records); err != nil {
		return fmt.Errorf("setting ACME DNS-01 TXT record: %w", err)
	}

	if m.propagationWait > 0 {
		timer := time.NewTimer(m.propagationWait)
		defer timer.Stop()

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
		}
	}

	return nil
}

func (m *dnsCertificateManager) purgeExpiredLocked(now time.Time) {
	for name, values := range m.records {
		for value, expires := range values {
			if !expires.IsZero() && now.After(expires) {
				delete(values, value)
			}
		}

		if len(values) == 0 {
			delete(m.records, name)
		}
	}
}

func (m *dnsCertificateManager) relativeRecordName(name string) string {
	zone := canonicalDNSName(m.zone)
	if name == zone {
		return "@"
	}

	return strings.TrimSuffix(strings.TrimSuffix(name, "."), "."+strings.TrimSuffix(zone, "."))
}

func validateSetDNSRequest(
	node types.NodeView,
	baseDomain string,
	req tailcfg.SetDNSRequest,
) error {
	if !strings.EqualFold(req.Type, "TXT") {
		return errDNSCertRecordType
	}

	value := strings.TrimSpace(req.Value)
	if value == "" || len(value) > maxTXTValueLength {
		return fmt.Errorf("%w: TXT value length must be 1..%d", errDNSCertRecordValue, maxTXTValueLength)
	}

	fqdn, err := node.GetFQDN(baseDomain)
	if err != nil {
		return fmt.Errorf("determining node FQDN: %w", err)
	}

	want := canonicalDNSName("_acme-challenge." + strings.TrimSuffix(fqdn, "."))
	got := canonicalDNSName(req.Name)
	if got != want {
		return fmt.Errorf("%w: got %q, want %q", errDNSCertRecordName, got, want)
	}

	return nil
}

func canonicalDNSName(name string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), ".") + ".")
}
