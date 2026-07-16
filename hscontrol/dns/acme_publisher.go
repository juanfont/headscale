package dns

import (
	"context"
	"fmt"
	"strings"
)

// ACMERecordPublisher publishes short-lived ACME DNS-01 TXT records so
// Let's Encrypt can validate node MagicDNS names for tailscale cert.
type ACMERecordPublisher interface {
	UpsertTXT(ctx context.Context, name, value string) error
}

// RelativeRecordName returns the Azure DNS relative name for fqdn within zone.
func RelativeRecordName(fqdn, zone string) (string, error) {
	fqdn = strings.TrimSuffix(strings.ToLower(fqdn), ".")
	zone = strings.TrimSuffix(strings.ToLower(zone), ".")
	if fqdn == "" || zone == "" {
		return "", fmt.Errorf("fqdn and zone are required")
	}
	if fqdn == zone {
		return "@", nil
	}
	suffix := "." + zone
	if !strings.HasSuffix(fqdn, suffix) {
		return "", fmt.Errorf("name %q is not under zone %q", fqdn, zone)
	}

	return strings.TrimSuffix(fqdn, suffix), nil
}
