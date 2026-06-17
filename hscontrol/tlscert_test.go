package hscontrol

import (
	"context"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/libdns/libdns"
	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

type fakeRecordSetter struct {
	zone    string
	records []libdns.Record
}

func (f *fakeRecordSetter) SetRecords(
	_ context.Context,
	zone string,
	records []libdns.Record,
) ([]libdns.Record, error) {
	f.zone = zone
	f.records = append([]libdns.Record(nil), records...)

	return records, nil
}

func testCertNode() types.NodeView {
	nodeKey := key.NewNode()
	machineKey := key.NewMachine()

	return (&types.Node{
		ID:         1,
		Hostname:   "node1",
		GivenName:  "node1",
		NodeKey:    nodeKey.Public(),
		MachineKey: machineKey.Public(),
	}).View()
}

func TestDNSCertificateManagerSetDNS(t *testing.T) {
	t.Parallel()

	setter := &fakeRecordSetter{}
	manager := newDNSCertificateManagerForSetter(types.DNSCertificatesConfig{
		Zone: "example.com",
		TTL:  time.Minute,
	}, setter)

	req := tailcfg.SetDNSRequest{
		NodeKey: testCertNode().NodeKey(),
		Name:    "_acme-challenge.node1.example.com",
		Type:    "TXT",
		Value:   "challenge-token",
	}

	require.NoError(t, manager.setDNS(t.Context(), testCertNode(), "example.com", req))
	require.Equal(t, "example.com", setter.zone)
	require.Len(t, setter.records, 1)

	txt, ok := setter.records[0].(libdns.TXT)
	require.True(t, ok, "record = %T, want libdns.TXT", setter.records[0])
	require.Equal(t, "_acme-challenge.node1", txt.Name)
	require.Equal(t, "challenge-token", txt.Text)
	require.Equal(t, time.Minute, txt.TTL)
}

func TestDNSCertificateManagerKeepsConcurrentTXTValues(t *testing.T) {
	t.Parallel()

	setter := &fakeRecordSetter{}
	manager := newDNSCertificateManagerForSetter(types.DNSCertificatesConfig{
		Zone: "example.com",
		TTL:  time.Minute,
	}, setter)
	node := testCertNode()

	req := tailcfg.SetDNSRequest{
		NodeKey: node.NodeKey(),
		Name:    "_acme-challenge.node1.example.com",
		Type:    "TXT",
		Value:   "token-1",
	}
	require.NoError(t, manager.setDNS(t.Context(), node, "example.com", req))

	req.Value = "token-2"
	require.NoError(t, manager.setDNS(t.Context(), node, "example.com", req))

	require.Len(t, setter.records, 2)
}

func TestValidateSetDNSRequestRejectsWrongRecord(t *testing.T) {
	t.Parallel()

	node := testCertNode()

	tests := []tailcfg.SetDNSRequest{
		{
			NodeKey: node.NodeKey(),
			Name:    "_acme-challenge.node1.example.com",
			Type:    "A",
			Value:   "challenge-token",
		},
		{
			NodeKey: node.NodeKey(),
			Name:    "_acme-challenge.other.example.com",
			Type:    "TXT",
			Value:   "challenge-token",
		},
		{
			NodeKey: node.NodeKey(),
			Name:    "_acme-challenge.node1.example.com",
			Type:    "TXT",
			Value:   "",
		},
	}

	for _, req := range tests {
		require.Error(t, validateSetDNSRequest(node, "example.com", req))
	}
}
