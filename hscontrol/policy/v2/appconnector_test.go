package v2

import (
	"net/netip"
	"testing"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"tailscale.com/tailcfg"
	"tailscale.com/types/opt"
)

func TestAppConnectorPolicyParsing(t *testing.T) {
	tests := []struct {
		name          string
		policyJSON    string
		wantConnector []AppConnector
		wantErr       bool
	}{
		{
			name: "basic app connector",
			policyJSON: `{
				"tagOwners": {
					"tag:connector": ["user@example.com"]
				},
				"appConnectors": [
					{
						"name": "Internal Apps",
						"connectors": ["tag:connector"],
						"domains": ["internal.example.com", "*.corp.example.com"]
					}
				]
			}`,
			wantConnector: []AppConnector{
				{
					Name:       "Internal Apps",
					Connectors: []string{"tag:connector"},
					Domains:    []string{"internal.example.com", "*.corp.example.com"},
				},
			},
			wantErr: false,
		},
		{
			name: "app connector with routes",
			policyJSON: `{
				"tagOwners": {
					"tag:connector": ["user@example.com"]
				},
				"appConnectors": [
					{
						"name": "VPN Connector",
						"connectors": ["tag:connector"],
						"domains": ["vpn.example.com"],
						"routes": ["10.0.0.0/8", "192.168.0.0/16"]
					}
				]
			}`,
			wantConnector: []AppConnector{
				{
					Name:       "VPN Connector",
					Connectors: []string{"tag:connector"},
					Domains:    []string{"vpn.example.com"},
					Routes:     []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("192.168.0.0/16")},
				},
			},
			wantErr: false,
		},
		{
			name: "wildcard connector",
			policyJSON: `{
				"appConnectors": [
					{
						"name": "Any Connector",
						"connectors": ["*"],
						"domains": ["app.example.com"]
					}
				]
			}`,
			wantConnector: []AppConnector{
				{
					Name:       "Any Connector",
					Connectors: []string{"*"},
					Domains:    []string{"app.example.com"},
				},
			},
			wantErr: false,
		},
		{
			name: "app connector with undefined tag",
			policyJSON: `{
				"appConnectors": [
					{
						"name": "Bad Connector",
						"connectors": ["tag:undefined"],
						"domains": ["app.example.com"]
					}
				]
			}`,
			wantErr: true,
		},
		{
			name: "app connector without domains",
			policyJSON: `{
				"tagOwners": {
					"tag:connector": ["user@example.com"]
				},
				"appConnectors": [
					{
						"name": "No Domains",
						"connectors": ["tag:connector"],
						"domains": []
					}
				]
			}`,
			wantErr: true,
		},
		{
			name: "app connector without connectors",
			policyJSON: `{
				"appConnectors": [
					{
						"name": "No Connectors",
						"connectors": [],
						"domains": ["app.example.com"]
					}
				]
			}`,
			wantErr: true,
		},
		{
			name: "app connector with invalid domain",
			policyJSON: `{
				"tagOwners": {
					"tag:connector": ["user@example.com"]
				},
				"appConnectors": [
					{
						"name": "Invalid Domain",
						"connectors": ["tag:connector"],
						"domains": [""]
					}
				]
			}`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy, err := unmarshalPolicy([]byte(tt.policyJSON))
			if tt.wantErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, policy)
			assert.Equal(t, tt.wantConnector, policy.AppConnectors)
		})
	}
}

func TestAppConnectorConfigForNode(t *testing.T) {
	policyJSON := `{
		"tagOwners": {
			"tag:connector": ["user@example.com"],
			"tag:other": ["user@example.com"]
		},
		"appConnectors": [
			{
				"name": "Internal Apps",
				"connectors": ["tag:connector"],
				"domains": ["internal.example.com", "*.corp.example.com"]
			},
			{
				"name": "VPN Apps",
				"connectors": ["tag:connector"],
				"domains": ["vpn.example.com"],
				"routes": ["10.0.0.0/8"]
			},
			{
				"name": "Other Apps",
				"connectors": ["tag:other"],
				"domains": ["other.example.com"]
			}
		]
	}`

	users := []types.User{
		{Model: gorm.Model{ID: 1}, Email: "user@example.com"},
	}

	uid := uint(1)
	ipv4 := netip.MustParseAddr("100.64.0.1")

	// Node with tag:connector that IS advertising as app connector
	connectorNode := &types.Node{
		ID:     1,
		UserID: &uid,
		IPv4:   &ipv4,
		Tags:   []string{"tag:connector"},
		Hostinfo: &tailcfg.Hostinfo{
			AppConnector: opt.NewBool(true),
		},
	}

	// Node with tag:connector that is NOT advertising as app connector
	notAdvertisingNode := &types.Node{
		ID:     2,
		UserID: &uid,
		IPv4:   &ipv4,
		Tags:   []string{"tag:connector"},
		Hostinfo: &tailcfg.Hostinfo{
			AppConnector: opt.NewBool(false),
		},
	}

	// Node with different tag that IS advertising
	otherTagNode := &types.Node{
		ID:     3,
		UserID: &uid,
		IPv4:   &ipv4,
		Tags:   []string{"tag:other"},
		Hostinfo: &tailcfg.Hostinfo{
			AppConnector: opt.NewBool(true),
		},
	}

	// Node without any matching tag
	noTagNode := &types.Node{
		ID:     4,
		UserID: &uid,
		IPv4:   &ipv4,
		Tags:   []string{"tag:unrelated"},
		Hostinfo: &tailcfg.Hostinfo{
			AppConnector: opt.NewBool(true),
		},
	}

	nodes := types.Nodes{connectorNode, notAdvertisingNode, otherTagNode, noTagNode}

	pm, err := NewPolicyManager([]byte(policyJSON), users, nodes.ViewSlice())
	require.NoError(t, err)

	tests := []struct {
		name     string
		node     *types.Node
		wantLen  int
		wantName string
	}{
		{
			name:     "connector node gets matching configs",
			node:     connectorNode,
			wantLen:  2, // Internal Apps and VPN Apps
			wantName: "Internal Apps",
		},
		{
			name:    "non-advertising node gets no config",
			node:    notAdvertisingNode,
			wantLen: 0,
		},
		{
			name:     "other tag node gets other config",
			node:     otherTagNode,
			wantLen:  1, // Other Apps
			wantName: "Other Apps",
		},
		{
			name:    "unrelated tag gets no config",
			node:    noTagNode,
			wantLen: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			configs := pm.AppConnectorConfigForNode(tt.node.View())
			assert.Len(t, configs, tt.wantLen)

			if tt.wantLen > 0 && tt.wantName != "" {
				assert.Equal(t, tt.wantName, configs[0].Name)
			}
		})
	}
}

func TestAppConnectorWildcardConnector(t *testing.T) {
	policyJSON := `{
		"appConnectors": [
			{
				"name": "All Connectors",
				"connectors": ["*"],
				"domains": ["*.example.com"]
			}
		]
	}`

	users := []types.User{
		{Model: gorm.Model{ID: 1}, Email: "user@example.com"},
	}

	uid := uint(1)
	ipv4 := netip.MustParseAddr("100.64.0.1")

	// Any node advertising as connector should match wildcard
	node := &types.Node{
		ID:     1,
		UserID: &uid,
		IPv4:   &ipv4,
		Tags:   []string{"tag:anyvalue"},
		Hostinfo: &tailcfg.Hostinfo{
			AppConnector: opt.NewBool(true),
		},
	}

	nodes := types.Nodes{node}

	pm, err := NewPolicyManager([]byte(policyJSON), users, nodes.ViewSlice())
	require.NoError(t, err)

	configs := pm.AppConnectorConfigForNode(node.View())
	require.Len(t, configs, 1)
	assert.Equal(t, "All Connectors", configs[0].Name)
	assert.Equal(t, []string{"*.example.com"}, configs[0].Domains)
}

func TestValidateAppConnectorDomain(t *testing.T) {
	tests := []struct {
		domain  string
		wantErr bool
	}{
		{"example.com", false},
		{"sub.example.com", false},
		{"*.example.com", false},
		{"a.b.c.example.com", false},
		{"", true},
		{".example.com", true},
		{"example.com.", true},
		{"example..com", true},
		{"*.", true},
	}

	for _, tt := range tests {
		t.Run(tt.domain, func(t *testing.T) {
			err := validateAppConnectorDomain(tt.domain)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
