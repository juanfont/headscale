package dns

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/dns/armdns"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/rs/zerolog/log"
)

// AzureACMEPublisher upserts ACME TXT records in an Azure DNS zone.
type AzureACMEPublisher struct {
	zoneName      string
	resourceGroup string
	client        *armdns.RecordSetsClient
}

// NewAzureACMEPublisher builds a publisher using DefaultAzureCredential
// (workload identity / env service principal).
func NewAzureACMEPublisher(cfg types.HTTPSCertsAzureConfig) (*AzureACMEPublisher, error) {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return nil, fmt.Errorf("azure credential: %w", err)
	}

	client, err := armdns.NewRecordSetsClient(cfg.SubscriptionID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("azure dns client: %w", err)
	}

	return &AzureACMEPublisher{
		zoneName:      cfg.ZoneName,
		resourceGroup: cfg.ResourceGroup,
		client:        client,
	}, nil
}

func (p *AzureACMEPublisher) UpsertTXT(ctx context.Context, name, value string) error {
	rel, err := RelativeRecordName(name, p.zoneName)
	if err != nil {
		return err
	}

	// Low TTL so failed/stale challenges expire quickly for Let's Encrypt retries.
	ttl := int64(1)
	params := armdns.RecordSet{
		Properties: &armdns.RecordSetProperties{
			TTL: &ttl,
			TxtRecords: []*armdns.TxtRecord{
				{Value: []*string{to.Ptr(value)}},
			},
		},
	}

	_, err = p.client.CreateOrUpdate(
		ctx,
		p.resourceGroup,
		p.zoneName,
		rel,
		armdns.RecordTypeTXT,
		params,
		nil,
	)
	if err != nil {
		return fmt.Errorf("upsert azure dns TXT %q: %w", rel, err)
	}

	log.Info().
		Str("relative", rel).
		Str("zone", p.zoneName).
		Msg("published ACME DNS-01 TXT to Azure DNS; waiting for public visibility")

	// Let's Encrypt validates immediately after set-dns returns. Wait until
	// public resolvers see the new value so we don't race NXDOMAIN / stale TXT.
	if err := waitForPublicTXT(ctx, name, value, 45*time.Second); err != nil {
		log.Warn().Err(err).Str("name", name).Msg("ACME TXT not yet visible on public DNS; continuing")
	}

	return nil
}

func waitForPublicTXT(ctx context.Context, name, want string, timeout time.Duration) error {
	resolver := &net.Resolver{PreferGo: true}
	deadline := time.Now().Add(timeout)
	want = strings.TrimSpace(want)
	fqdn := strings.TrimSuffix(name, ".")

	var lastErr error
	for time.Now().Before(deadline) {
		if err := ctx.Err(); err != nil {
			return err
		}
		txts, err := resolver.LookupTXT(ctx, fqdn)
		if err != nil {
			lastErr = err
		} else {
			for _, t := range txts {
				if strings.TrimSpace(t) == want {
					log.Info().Str("name", name).Msg("ACME TXT visible on public DNS")
					return nil
				}
			}
			lastErr = fmt.Errorf("TXT present but value mismatch (got %v)", txts)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}

	return fmt.Errorf("timed out waiting for public TXT %s: %w", name, lastErr)
}
