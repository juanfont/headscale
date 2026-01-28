package zlog

import (
	"bytes"
	"encoding/json"
	"net/netip"
	"testing"

	"github.com/juanfont/headscale/hscontrol/util/zlog/zf"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

func TestSafeHostinfo_MarshalZerologObject(t *testing.T) {
	tests := []struct {
		name       string
		hostinfo   *tailcfg.Hostinfo
		wantFields map[string]any
		wantAbsent []string // Fields that should NOT be present
	}{
		{
			name:       "nil hostinfo",
			hostinfo:   nil,
			wantFields: map[string]any{},
		},
		{
			name: "basic hostinfo",
			hostinfo: &tailcfg.Hostinfo{
				Hostname: "myhost",
				OS:       "linux",
			},
			wantFields: map[string]any{
				zf.Hostname: "myhost",
				zf.OS:       "linux",
			},
		},
		{
			name: "hostinfo with routes and tags",
			hostinfo: &tailcfg.Hostinfo{
				Hostname:    "router",
				OS:          "linux",
				RoutableIPs: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")},
				RequestTags: []string{"tag:server"},
			},
			wantFields: map[string]any{
				zf.Hostname:        "router",
				zf.OS:              "linux",
				zf.RoutableIPCount: float64(1),
			},
		},
		{
			name: "hostinfo with netinfo",
			hostinfo: &tailcfg.Hostinfo{
				Hostname: "myhost",
				OS:       "windows",
				NetInfo: &tailcfg.NetInfo{
					PreferredDERP: 1,
				},
			},
			wantFields: map[string]any{
				zf.Hostname: "myhost",
				zf.OS:       "windows",
				zf.DERP:     float64(1),
			},
		},
		{
			name: "sensitive fields are NOT logged",
			hostinfo: &tailcfg.Hostinfo{
				Hostname:    "myhost",
				OS:          "linux",
				OSVersion:   "5.15.0-generic", // Should NOT be logged
				DeviceModel: "ThinkPad X1",    // Should NOT be logged
				IPNVersion:  "1.50.0",         // Should NOT be logged
			},
			wantFields: map[string]any{
				zf.Hostname: "myhost",
				zf.OS:       "linux",
			},
			wantAbsent: []string{"os_version", "device_model", "ipn_version", "OSVersion", "DeviceModel", "IPNVersion"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer

			log := zerolog.New(&buf)

			log.Info().EmbedObject(Hostinfo(tt.hostinfo)).Msg("test")

			var result map[string]any

			err := json.Unmarshal(buf.Bytes(), &result)
			require.NoError(t, err)

			// Check expected fields are present
			for key, wantVal := range tt.wantFields {
				assert.Equal(t, wantVal, result[key], "field %s", key)
			}

			// Check sensitive fields are absent
			for _, key := range tt.wantAbsent {
				_, exists := result[key]
				assert.False(t, exists, "sensitive field %s should not be logged", key)
			}
		})
	}
}

func TestSafeMapRequest_MarshalZerologObject(t *testing.T) {
	nodeKey := key.NewNode().Public()

	tests := []struct {
		name       string
		req        *tailcfg.MapRequest
		wantFields map[string]any
		wantAbsent []string
	}{
		{
			name:       "nil request",
			req:        nil,
			wantFields: map[string]any{},
		},
		{
			name: "basic request",
			req: &tailcfg.MapRequest{
				Stream:    true,
				OmitPeers: false,
				Version:   100,
				NodeKey:   nodeKey,
			},
			wantFields: map[string]any{
				zf.Stream:    true,
				zf.OmitPeers: false,
				zf.Version:   float64(100),
			},
		},
		{
			name: "request with endpoints - only count logged",
			req: &tailcfg.MapRequest{
				Stream:    false,
				OmitPeers: true,
				Version:   100,
				NodeKey:   nodeKey,
				Endpoints: []netip.AddrPort{
					netip.MustParseAddrPort("192.168.1.100:41641"),
					netip.MustParseAddrPort("10.0.0.50:41641"),
				},
			},
			wantFields: map[string]any{
				zf.Stream:         false,
				zf.OmitPeers:      true,
				zf.EndpointsCount: float64(2),
			},
			wantAbsent: []string{"endpoints", "Endpoints"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer

			log := zerolog.New(&buf)

			log.Info().EmbedObject(MapRequest(tt.req)).Msg("test")

			var result map[string]any

			err := json.Unmarshal(buf.Bytes(), &result)
			require.NoError(t, err)

			// Check expected fields are present
			for key, wantVal := range tt.wantFields {
				assert.Equal(t, wantVal, result[key], "field %s", key)
			}

			// Check node.key is a short string (not full key)
			if tt.req != nil {
				nodeKeyStr, ok := result[zf.NodeKey].(string)
				if ok {
					// Short keys are truncated, full keys are 64+ chars
					assert.Less(t, len(nodeKeyStr), 20, "node key should be short form")
				}
			}

			// Check sensitive fields are absent
			for _, key := range tt.wantAbsent {
				_, exists := result[key]
				assert.False(t, exists, "sensitive field %s should not be logged", key)
			}
		})
	}
}

func TestFieldConstants(t *testing.T) {
	// Verify field constants follow the expected naming pattern
	fieldTests := []struct {
		constant string
		expected string
	}{
		{zf.NodeID, "node.id"},
		{zf.NodeName, "node.name"},
		{zf.NodeKey, "node.key"},
		{zf.MachineKey, "machine.key"},
		{zf.NodeTags, "node.tags"},
		{zf.NodeIsTagged, "node.is_tagged"},
		{zf.NodeOnline, "node.online"},
		{zf.NodeExpired, "node.expired"},
		{zf.UserID, "user.id"},
		{zf.UserName, "user.name"},
		{zf.PAKID, "pak.id"},
		{zf.PAKPrefix, "pak.prefix"},
		{zf.APIKeyID, "api_key.id"},
		{zf.APIKeyPrefix, "api_key.prefix"},
		{zf.OmitPeers, "omit_peers"},
		{zf.Stream, "stream"},
	}

	for _, tt := range fieldTests {
		t.Run(tt.expected, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.constant)
		})
	}
}
