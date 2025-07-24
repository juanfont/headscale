package hscontrol

import (
	"context"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/libdns/hetzner"
	"github.com/libdns/libdns"
	"tailscale.com/tailcfg"
)

type TlsCertProvider interface {
	GetRecordSetter() libdns.RecordSetter
	GetZoneName() string
	CreateRecord(request tailcfg.SetDNSRequest) libdns.Record
}

func NewHetznerTlsCertProvider(config types.HetznerTlsCertConfig) *TlsCertProviderHetzner {
	return &TlsCertProviderHetzner{
		Provider: hetzner.New(config.ApiToken),
		ZoneId:   config.ZoneId,
		ZoneName: config.ZoneName,
		Ttl:      config.Ttl,
	}
}

type TlsCertProviderHetzner struct {
	Provider libdns.RecordSetter
	ZoneId   string
	ZoneName string
	Ttl      int
}

func (p *TlsCertProviderHetzner) GetRecordSetter() libdns.RecordSetter {
	return p.Provider
}

func (p *TlsCertProviderHetzner) GetZoneName() string {
	return p.ZoneName
}

func (p *TlsCertProviderHetzner) CreateRecord(request tailcfg.SetDNSRequest) libdns.Record {
	return &hetzner.Record{
		ZoneID: p.ZoneId,
		Type:   request.Type,
		Name:   request.Name,
		Value:  request.Value,
		TTL:    p.Ttl,
	}
}

func (h *Headscale) handleSetDns(
	ctx context.Context,
	setDnsReq tailcfg.SetDNSRequest,
) (*tailcfg.SetDNSResponse, error) {
	zoneName := h.tlsCertProvider.GetZoneName()
	recordSetter := h.tlsCertProvider.GetRecordSetter()
	libDnsRecord := h.tlsCertProvider.CreateRecord(setDnsReq)

	_, err := recordSetter.SetRecords(ctx, zoneName, []libdns.Record{libDnsRecord})
	if err != nil {
		return nil, err
	}

	return &tailcfg.SetDNSResponse{}, nil
}
