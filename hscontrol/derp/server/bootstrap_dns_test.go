package server

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"tailscale.com/tailcfg"
)

func TestDERPBootstrapDNSIncludesControlHostQuery(t *testing.T) {
	derpMap := (&tailcfg.DERPMap{
		Regions: map[int]*tailcfg.DERPRegion{
			999: {
				RegionID:   999,
				RegionCode: "headscale",
				RegionName: "Headscale Embedded DERP",
				Nodes: []*tailcfg.DERPNode{{
					Name:     "999a",
					RegionID: 999,
					HostName: "derp.invalid.",
				}},
			},
		},
	}).View()

	req := httptest.NewRequest(http.MethodGet, "/bootstrap-dns?q=localhost", nil)
	rec := httptest.NewRecorder()

	DERPBootstrapDNSHandler(derpMap)(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, rec.Code)
	}

	var entries map[string][]net.IP
	if err := json.NewDecoder(rec.Body).Decode(&entries); err != nil {
		t.Fatalf("decoding bootstrap DNS response: %v", err)
	}

	if len(entries["localhost"]) == 0 {
		t.Fatalf("expected bootstrap DNS response to include the control host query, got %#v", entries)
	}
}
