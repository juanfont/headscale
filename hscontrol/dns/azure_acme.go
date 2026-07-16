package dns

import (
	"context"
	"fmt"

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

	ttl := int64(60)
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

	log.Debug().
		Str("relative", rel).
		Str("zone", p.zoneName).
		Msg("published ACME DNS-01 TXT to Azure DNS")

	return nil
}
