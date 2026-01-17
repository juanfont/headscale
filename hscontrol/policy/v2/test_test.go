package v2

import (
	"testing"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"tailscale.com/types/ptr"
)

// testPolicyAliceToBob22 is a basic test policy allowing alice to access bob on port 22.
const testPolicyAliceToBob22 = `{
	"acls": [
		{
			"action": "accept",
			"src": ["alice@example.com"],
			"dst": ["bob@example.com:22"]
		}
	]
}`

func TestRunTest_BasicAccept(t *testing.T) {
	users := types.Users{
		{Model: gorm.Model{ID: 1}, Name: "alice", Email: "alice@example.com"},
		{Model: gorm.Model{ID: 2}, Name: "bob", Email: "bob@example.com"},
	}

	nodes := types.Nodes{
		{
			ID:       1,
			Hostname: "alice-laptop",
			IPv4:     ap("100.64.0.1"),
			IPv6:     ap("fd7a:115c:a1e0::1"),
			User:     ptr.To(users[0]),
			UserID:   ptr.To(users[0].ID),
		},
		{
			ID:       2,
			Hostname: "bob-server",
			IPv4:     ap("100.64.0.2"),
			IPv6:     ap("fd7a:115c:a1e0::2"),
			User:     ptr.To(users[1]),
			UserID:   ptr.To(users[1].ID),
		},
	}

	pm, err := NewPolicyManager([]byte(testPolicyAliceToBob22), users, nodes.ViewSlice())
	require.NoError(t, err)

	tests := []struct {
		name       string
		test       ACLTest
		wantPassed bool
	}{
		{
			name: "alice_can_access_bob_port_22",
			test: ACLTest{
				Src:    "alice@example.com",
				Accept: []string{"bob@example.com:22"},
			},
			wantPassed: true,
		},
		{
			name: "alice_cannot_access_bob_port_80",
			test: ACLTest{
				Src:  "alice@example.com",
				Deny: []string{"bob@example.com:80"},
			},
			wantPassed: true,
		},
		{
			name: "bob_cannot_access_alice",
			test: ACLTest{
				Src:  "bob@example.com",
				Deny: []string{"alice@example.com:22"},
			},
			wantPassed: true,
		},
		{
			name: "accept_fails_when_access_denied",
			test: ACLTest{
				Src:    "bob@example.com",
				Accept: []string{"alice@example.com:22"},
			},
			wantPassed: false,
		},
		{
			name: "deny_fails_when_access_allowed",
			test: ACLTest{
				Src:  "alice@example.com",
				Deny: []string{"bob@example.com:22"},
			},
			wantPassed: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := pm.RunTest(tt.test)
			assert.Equal(t, tt.wantPassed, result.Passed, "test result mismatch for %s", tt.name)
		})
	}
}

func TestRunTest_WithTags(t *testing.T) {
	users := types.Users{
		{Model: gorm.Model{ID: 1}, Name: "alice", Email: "alice@example.com"},
	}

	nodes := types.Nodes{
		{
			ID:       1,
			Hostname: "alice-laptop",
			IPv4:     ap("100.64.0.1"),
			IPv6:     ap("fd7a:115c:a1e0::1"),
			User:     ptr.To(users[0]),
			UserID:   ptr.To(users[0].ID),
		},
		{
			ID:       2,
			Hostname: "web-server",
			IPv4:     ap("100.64.0.2"),
			IPv6:     ap("fd7a:115c:a1e0::2"),
			Tags:     []string{"tag:webserver"},
		},
		{
			ID:       3,
			Hostname: "db-server",
			IPv4:     ap("100.64.0.3"),
			IPv6:     ap("fd7a:115c:a1e0::3"),
			Tags:     []string{"tag:database"},
		},
	}

	policy := `{
		"tagOwners": {
			"tag:webserver": ["alice@example.com"],
			"tag:database": ["alice@example.com"]
		},
		"acls": [
			{
				"action": "accept",
				"src": ["alice@example.com"],
				"dst": ["tag:webserver:80", "tag:webserver:443"]
			}
		]
	}`

	pm, err := NewPolicyManager([]byte(policy), users, nodes.ViewSlice())
	require.NoError(t, err)

	tests := []struct {
		name       string
		test       ACLTest
		wantPassed bool
	}{
		{
			name: "alice_can_access_webserver",
			test: ACLTest{
				Src:    "alice@example.com",
				Accept: []string{"tag:webserver:80"},
			},
			wantPassed: true,
		},
		{
			name: "alice_cannot_access_database",
			test: ACLTest{
				Src:  "alice@example.com",
				Deny: []string{"tag:database:5432"},
			},
			wantPassed: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := pm.RunTest(tt.test)
			assert.Equal(t, tt.wantPassed, result.Passed, "test result mismatch for %s", tt.name)
		})
	}
}

func TestRunTest_WithGroups(t *testing.T) {
	users := types.Users{
		{Model: gorm.Model{ID: 1}, Name: "alice", Email: "alice@example.com"},
		{Model: gorm.Model{ID: 2}, Name: "bob", Email: "bob@example.com"},
	}

	nodes := types.Nodes{
		{
			ID:       1,
			Hostname: "alice-laptop",
			IPv4:     ap("100.64.0.1"),
			IPv6:     ap("fd7a:115c:a1e0::1"),
			User:     ptr.To(users[0]),
			UserID:   ptr.To(users[0].ID),
		},
		{
			ID:       2,
			Hostname: "bob-laptop",
			IPv4:     ap("100.64.0.2"),
			IPv6:     ap("fd7a:115c:a1e0::2"),
			User:     ptr.To(users[1]),
			UserID:   ptr.To(users[1].ID),
		},
		{
			ID:       3,
			Hostname: "server",
			IPv4:     ap("100.64.0.3"),
			IPv6:     ap("fd7a:115c:a1e0::3"),
			Tags:     []string{"tag:server"},
		},
	}

	policy := `{
		"groups": {
			"group:admins": ["alice@example.com"]
		},
		"tagOwners": {
			"tag:server": ["group:admins"]
		},
		"acls": [
			{
				"action": "accept",
				"src": ["group:admins"],
				"dst": ["tag:server:*"]
			}
		]
	}`

	pm, err := NewPolicyManager([]byte(policy), users, nodes.ViewSlice())
	require.NoError(t, err)

	tests := []struct {
		name       string
		test       ACLTest
		wantPassed bool
	}{
		{
			name: "admin_group_can_access_server",
			test: ACLTest{
				Src:    "group:admins",
				Accept: []string{"tag:server:22"},
			},
			wantPassed: true,
		},
		{
			name: "non_admin_cannot_access_server",
			test: ACLTest{
				Src:  "bob@example.com",
				Deny: []string{"tag:server:22"},
			},
			wantPassed: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := pm.RunTest(tt.test)
			assert.Equal(t, tt.wantPassed, result.Passed, "test result mismatch for %s", tt.name)
		})
	}
}

func TestRunTest_InvalidSource(t *testing.T) {
	users := types.Users{
		{Model: gorm.Model{ID: 1}, Name: "alice", Email: "alice@example.com"},
	}

	nodes := types.Nodes{
		{
			ID:       1,
			Hostname: "alice-laptop",
			IPv4:     ap("100.64.0.1"),
			IPv6:     ap("fd7a:115c:a1e0::1"),
			User:     ptr.To(users[0]),
			UserID:   ptr.To(users[0].ID),
		},
	}

	policy := `{
		"acls": [
			{
				"action": "accept",
				"src": ["alice@example.com"],
				"dst": ["alice@example.com:*"]
			}
		]
	}`

	pm, err := NewPolicyManager([]byte(policy), users, nodes.ViewSlice())
	require.NoError(t, err)

	// Test with non-existent user
	result := pm.RunTest(ACLTest{
		Src:    "nonexistent@example.com",
		Accept: []string{"alice@example.com:22"},
	})

	assert.False(t, result.Passed, "test should fail for non-existent source")
	assert.NotEmpty(t, result.Errors, "should have error messages")
}

func TestRunTests_Multiple(t *testing.T) {
	users := types.Users{
		{Model: gorm.Model{ID: 1}, Name: "alice", Email: "alice@example.com"},
		{Model: gorm.Model{ID: 2}, Name: "bob", Email: "bob@example.com"},
	}

	nodes := types.Nodes{
		{
			ID:       1,
			Hostname: "alice-laptop",
			IPv4:     ap("100.64.0.1"),
			IPv6:     ap("fd7a:115c:a1e0::1"),
			User:     ptr.To(users[0]),
			UserID:   ptr.To(users[0].ID),
		},
		{
			ID:       2,
			Hostname: "bob-server",
			IPv4:     ap("100.64.0.2"),
			IPv6:     ap("fd7a:115c:a1e0::2"),
			User:     ptr.To(users[1]),
			UserID:   ptr.To(users[1].ID),
		},
	}

	pm, err := NewPolicyManager([]byte(testPolicyAliceToBob22), users, nodes.ViewSlice())
	require.NoError(t, err)

	tests := []ACLTest{
		{
			Src:    "alice@example.com",
			Accept: []string{"bob@example.com:22"},
		},
		{
			Src:  "bob@example.com",
			Deny: []string{"alice@example.com:22"},
		},
	}

	results := pm.RunTests(tests)

	assert.True(t, results.AllPassed, "all tests should pass")
	assert.Len(t, results.Results, 2, "should have 2 results")
}

func TestRunTests_SomeFail(t *testing.T) {
	users := types.Users{
		{Model: gorm.Model{ID: 1}, Name: "alice", Email: "alice@example.com"},
		{Model: gorm.Model{ID: 2}, Name: "bob", Email: "bob@example.com"},
	}

	nodes := types.Nodes{
		{
			ID:       1,
			Hostname: "alice-laptop",
			IPv4:     ap("100.64.0.1"),
			IPv6:     ap("fd7a:115c:a1e0::1"),
			User:     ptr.To(users[0]),
			UserID:   ptr.To(users[0].ID),
		},
		{
			ID:       2,
			Hostname: "bob-server",
			IPv4:     ap("100.64.0.2"),
			IPv6:     ap("fd7a:115c:a1e0::2"),
			User:     ptr.To(users[1]),
			UserID:   ptr.To(users[1].ID),
		},
	}

	pm, err := NewPolicyManager([]byte(testPolicyAliceToBob22), users, nodes.ViewSlice())
	require.NoError(t, err)

	tests := []ACLTest{
		{
			Src:    "alice@example.com",
			Accept: []string{"bob@example.com:22"},
		},
		{
			// This test should fail - bob cannot access alice
			Src:    "bob@example.com",
			Accept: []string{"alice@example.com:22"},
		},
	}

	results := pm.RunTests(tests)

	assert.False(t, results.AllPassed, "not all tests should pass")
	assert.Len(t, results.Results, 2, "should have 2 results")
	assert.True(t, results.Results[0].Passed, "first test should pass")
	assert.False(t, results.Results[1].Passed, "second test should fail")
	assert.NotEmpty(t, results.Errors(), "should have error description")
}

func TestPolicyWithEmbeddedTests(t *testing.T) {
	users := types.Users{
		{Model: gorm.Model{ID: 1}, Name: "alice", Email: "alice@example.com"},
		{Model: gorm.Model{ID: 2}, Name: "bob", Email: "bob@example.com"},
	}

	nodes := types.Nodes{
		{
			ID:       1,
			Hostname: "alice-laptop",
			IPv4:     ap("100.64.0.1"),
			IPv6:     ap("fd7a:115c:a1e0::1"),
			User:     ptr.To(users[0]),
			UserID:   ptr.To(users[0].ID),
		},
		{
			ID:       2,
			Hostname: "bob-server",
			IPv4:     ap("100.64.0.2"),
			IPv6:     ap("fd7a:115c:a1e0::2"),
			User:     ptr.To(users[1]),
			UserID:   ptr.To(users[1].ID),
		},
	}

	// Policy with embedded tests
	policy := `{
		"acls": [
			{
				"action": "accept",
				"src": ["alice@example.com"],
				"dst": ["bob@example.com:22"]
			}
		],
		"tests": [
			{
				"src": "alice@example.com",
				"accept": ["bob@example.com:22"]
			},
			{
				"src": "bob@example.com",
				"deny": ["alice@example.com:22"]
			}
		]
	}`

	pm, err := NewPolicyManager([]byte(policy), users, nodes.ViewSlice())
	require.NoError(t, err)

	// Verify the tests were parsed
	require.NotNil(t, pm.pol.Tests)
	require.Len(t, pm.pol.Tests, 2)

	// Run the embedded tests
	results := pm.RunTests(pm.pol.Tests)
	assert.True(t, results.AllPassed, "embedded tests should pass")
}

func TestRunTestsWithPolicy(t *testing.T) {
	users := types.Users{
		{Model: gorm.Model{ID: 1}, Name: "alice", Email: "alice@example.com"},
		{Model: gorm.Model{ID: 2}, Name: "bob", Email: "bob@example.com"},
	}

	nodes := types.Nodes{
		{
			ID:       1,
			Hostname: "alice-laptop",
			IPv4:     ap("100.64.0.1"),
			IPv6:     ap("fd7a:115c:a1e0::1"),
			User:     ptr.To(users[0]),
			UserID:   ptr.To(users[0].ID),
		},
		{
			ID:       2,
			Hostname: "bob-server",
			IPv4:     ap("100.64.0.2"),
			IPv6:     ap("fd7a:115c:a1e0::2"),
			User:     ptr.To(users[1]),
			UserID:   ptr.To(users[1].ID),
		},
	}

	tests := []ACLTest{
		{
			Src:    "alice@example.com",
			Accept: []string{"bob@example.com:22"},
		},
	}

	results, err := RunTestsWithPolicy([]byte(testPolicyAliceToBob22), users, nodes.ViewSlice(), tests)
	require.NoError(t, err)
	assert.True(t, results.AllPassed, "tests should pass")
}

func TestRunTest_ProtocolFiltering(t *testing.T) {
	users := types.Users{
		{Model: gorm.Model{ID: 1}, Name: "alice", Email: "alice@example.com"},
		{Model: gorm.Model{ID: 2}, Name: "bob", Email: "bob@example.com"},
	}

	nodes := types.Nodes{
		{
			ID:       1,
			Hostname: "alice-laptop",
			IPv4:     ap("100.64.0.1"),
			IPv6:     ap("fd7a:115c:a1e0::1"),
			User:     ptr.To(users[0]),
			UserID:   ptr.To(users[0].ID),
		},
		{
			ID:       2,
			Hostname: "bob-server",
			IPv4:     ap("100.64.0.2"),
			IPv6:     ap("fd7a:115c:a1e0::2"),
			User:     ptr.To(users[1]),
			UserID:   ptr.To(users[1].ID),
		},
	}

	// Policy with ICMP-only rule (wildcard IPs) and TCP rule for specific access
	policy := `{
		"acls": [
			{
				"action": "accept",
				"proto": "icmp",
				"src": ["*"],
				"dst": ["*:*"]
			},
			{
				"action": "accept",
				"src": ["alice@example.com"],
				"dst": ["bob@example.com:22"]
			}
		]
	}`

	pm, err := NewPolicyManager([]byte(policy), users, nodes.ViewSlice())
	require.NoError(t, err)

	tests := []struct {
		name       string
		test       ACLTest
		wantPassed bool
	}{
		{
			name: "alice_can_access_bob_tcp_22",
			test: ACLTest{
				Src:    "alice@example.com",
				Proto:  "tcp",
				Accept: []string{"bob@example.com:22"},
			},
			wantPassed: true,
		},
		{
			name: "alice_can_ping_bob_icmp",
			test: ACLTest{
				Src:    "alice@example.com",
				Proto:  "icmp",
				Accept: []string{"bob@example.com:*"},
			},
			wantPassed: true,
		},
		{
			name: "bob_can_ping_alice_icmp",
			test: ACLTest{
				Src:    "bob@example.com",
				Proto:  "icmp",
				Accept: []string{"alice@example.com:*"},
			},
			wantPassed: true,
		},
		{
			name: "bob_cannot_access_alice_tcp_22_only_icmp_allowed",
			test: ACLTest{
				Src:   "bob@example.com",
				Proto: "tcp",
				Deny:  []string{"alice@example.com:22"},
			},
			wantPassed: true,
		},
		{
			name: "bob_cannot_access_alice_default_proto_only_icmp_allowed",
			test: ACLTest{
				Src:  "bob@example.com",
				Deny: []string{"alice@example.com:22"},
			},
			wantPassed: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := pm.RunTest(tt.test)
			assert.Equal(t, tt.wantPassed, result.Passed, "test result mismatch for %s: %v", tt.name, result)
		})
	}
}

func TestRunTest_TCPOnlyRule(t *testing.T) {
	users := types.Users{
		{Model: gorm.Model{ID: 1}, Name: "alice", Email: "alice@example.com"},
		{Model: gorm.Model{ID: 2}, Name: "bob", Email: "bob@example.com"},
	}

	nodes := types.Nodes{
		{
			ID:       1,
			Hostname: "alice-laptop",
			IPv4:     ap("100.64.0.1"),
			IPv6:     ap("fd7a:115c:a1e0::1"),
			User:     ptr.To(users[0]),
			UserID:   ptr.To(users[0].ID),
		},
		{
			ID:       2,
			Hostname: "bob-server",
			IPv4:     ap("100.64.0.2"),
			IPv6:     ap("fd7a:115c:a1e0::2"),
			User:     ptr.To(users[1]),
			UserID:   ptr.To(users[1].ID),
		},
	}

	// Policy with TCP-only rule
	policy := `{
		"acls": [
			{
				"action": "accept",
				"proto": "tcp",
				"src": ["alice@example.com"],
				"dst": ["bob@example.com:22,80,443"]
			}
		]
	}`

	pm, err := NewPolicyManager([]byte(policy), users, nodes.ViewSlice())
	require.NoError(t, err)

	tests := []struct {
		name       string
		test       ACLTest
		wantPassed bool
	}{
		{
			name: "alice_can_ssh_bob_tcp",
			test: ACLTest{
				Src:    "alice@example.com",
				Proto:  "tcp",
				Accept: []string{"bob@example.com:22"},
			},
			wantPassed: true,
		},
		{
			name: "alice_can_http_bob_tcp",
			test: ACLTest{
				Src:    "alice@example.com",
				Proto:  "tcp",
				Accept: []string{"bob@example.com:80"},
			},
			wantPassed: true,
		},
		{
			name: "alice_cannot_access_bob_udp_same_ports",
			test: ACLTest{
				Src:   "alice@example.com",
				Proto: "udp",
				Deny:  []string{"bob@example.com:22"},
			},
			wantPassed: true,
		},
		{
			name: "alice_cannot_access_bob_udp_dns",
			test: ACLTest{
				Src:   "alice@example.com",
				Proto: "udp",
				Deny:  []string{"bob@example.com:53"},
			},
			wantPassed: true,
		},
		{
			name: "alice_cannot_ping_bob_icmp",
			test: ACLTest{
				Src:   "alice@example.com",
				Proto: "icmp",
				Deny:  []string{"bob@example.com:*"},
			},
			wantPassed: true,
		},
		{
			name: "default_proto_matches_tcp_rule",
			test: ACLTest{
				Src:    "alice@example.com",
				Accept: []string{"bob@example.com:22"},
			},
			wantPassed: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := pm.RunTest(tt.test)
			assert.Equal(t, tt.wantPassed, result.Passed, "test result mismatch for %s: %v", tt.name, result)
		})
	}
}

func TestRunTest_UDPOnlyRule(t *testing.T) {
	users := types.Users{
		{Model: gorm.Model{ID: 1}, Name: "alice", Email: "alice@example.com"},
		{Model: gorm.Model{ID: 2}, Name: "bob", Email: "bob@example.com"},
	}

	nodes := types.Nodes{
		{
			ID:       1,
			Hostname: "alice-laptop",
			IPv4:     ap("100.64.0.1"),
			IPv6:     ap("fd7a:115c:a1e0::1"),
			User:     ptr.To(users[0]),
			UserID:   ptr.To(users[0].ID),
		},
		{
			ID:       2,
			Hostname: "dns-server",
			IPv4:     ap("100.64.0.2"),
			IPv6:     ap("fd7a:115c:a1e0::2"),
			User:     ptr.To(users[1]),
			UserID:   ptr.To(users[1].ID),
		},
	}

	// Policy with UDP-only rule for DNS
	policy := `{
		"acls": [
			{
				"action": "accept",
				"proto": "udp",
				"src": ["alice@example.com"],
				"dst": ["bob@example.com:53,123"]
			}
		]
	}`

	pm, err := NewPolicyManager([]byte(policy), users, nodes.ViewSlice())
	require.NoError(t, err)

	tests := []struct {
		name       string
		test       ACLTest
		wantPassed bool
	}{
		{
			name: "alice_can_dns_bob_udp",
			test: ACLTest{
				Src:    "alice@example.com",
				Proto:  "udp",
				Accept: []string{"bob@example.com:53"},
			},
			wantPassed: true,
		},
		{
			name: "alice_can_ntp_bob_udp",
			test: ACLTest{
				Src:    "alice@example.com",
				Proto:  "udp",
				Accept: []string{"bob@example.com:123"},
			},
			wantPassed: true,
		},
		{
			name: "alice_cannot_ssh_bob_tcp",
			test: ACLTest{
				Src:   "alice@example.com",
				Proto: "tcp",
				Deny:  []string{"bob@example.com:22"},
			},
			wantPassed: true,
		},
		{
			name: "alice_cannot_dns_bob_tcp",
			test: ACLTest{
				Src:   "alice@example.com",
				Proto: "tcp",
				Deny:  []string{"bob@example.com:53"},
			},
			wantPassed: true,
		},
		{
			name: "default_proto_matches_udp_rule",
			test: ACLTest{
				Src:    "alice@example.com",
				Accept: []string{"bob@example.com:53"},
			},
			wantPassed: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := pm.RunTest(tt.test)
			assert.Equal(t, tt.wantPassed, result.Passed, "test result mismatch for %s: %v", tt.name, result)
		})
	}
}

func TestRunTest_MixedProtocolRules(t *testing.T) {
	users := types.Users{
		{Model: gorm.Model{ID: 1}, Name: "alice", Email: "alice@example.com"},
		{Model: gorm.Model{ID: 2}, Name: "bob", Email: "bob@example.com"},
	}

	nodes := types.Nodes{
		{
			ID:       1,
			Hostname: "alice-laptop",
			IPv4:     ap("100.64.0.1"),
			IPv6:     ap("fd7a:115c:a1e0::1"),
			User:     ptr.To(users[0]),
			UserID:   ptr.To(users[0].ID),
		},
		{
			ID:       2,
			Hostname: "server",
			IPv4:     ap("100.64.0.2"),
			IPv6:     ap("fd7a:115c:a1e0::2"),
			User:     ptr.To(users[1]),
			UserID:   ptr.To(users[1].ID),
		},
	}

	// Policy with separate TCP, UDP, and ICMP rules
	policy := `{
		"acls": [
			{
				"action": "accept",
				"proto": "tcp",
				"src": ["alice@example.com"],
				"dst": ["bob@example.com:22,80,443"]
			},
			{
				"action": "accept",
				"proto": "udp",
				"src": ["alice@example.com"],
				"dst": ["bob@example.com:53,123"]
			},
			{
				"action": "accept",
				"proto": "icmp",
				"src": ["alice@example.com"],
				"dst": ["bob@example.com:*"]
			}
		]
	}`

	pm, err := NewPolicyManager([]byte(policy), users, nodes.ViewSlice())
	require.NoError(t, err)

	tests := []struct {
		name       string
		test       ACLTest
		wantPassed bool
	}{
		{
			name: "alice_can_ssh_tcp",
			test: ACLTest{
				Src:    "alice@example.com",
				Proto:  "tcp",
				Accept: []string{"bob@example.com:22"},
			},
			wantPassed: true,
		},
		{
			name: "alice_can_dns_udp",
			test: ACLTest{
				Src:    "alice@example.com",
				Proto:  "udp",
				Accept: []string{"bob@example.com:53"},
			},
			wantPassed: true,
		},
		{
			name: "alice_can_ping_icmp",
			test: ACLTest{
				Src:    "alice@example.com",
				Proto:  "icmp",
				Accept: []string{"bob@example.com:*"},
			},
			wantPassed: true,
		},
		{
			name: "alice_cannot_ssh_udp",
			test: ACLTest{
				Src:   "alice@example.com",
				Proto: "udp",
				Deny:  []string{"bob@example.com:22"},
			},
			wantPassed: true,
		},
		{
			name: "alice_cannot_dns_tcp",
			test: ACLTest{
				Src:   "alice@example.com",
				Proto: "tcp",
				Deny:  []string{"bob@example.com:53"},
			},
			wantPassed: true,
		},
		{
			name: "bob_cannot_access_alice_any_proto",
			test: ACLTest{
				Src:  "bob@example.com",
				Deny: []string{"alice@example.com:22"},
			},
			wantPassed: true,
		},
		{
			name: "bob_cannot_ping_alice",
			test: ACLTest{
				Src:   "bob@example.com",
				Proto: "icmp",
				Deny:  []string{"alice@example.com:*"},
			},
			wantPassed: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := pm.RunTest(tt.test)
			assert.Equal(t, tt.wantPassed, result.Passed, "test result mismatch for %s: %v", tt.name, result)
		})
	}
}

func TestRunTest_NoProtoDefaultsTCPUDP(t *testing.T) {
	users := types.Users{
		{Model: gorm.Model{ID: 1}, Name: "alice", Email: "alice@example.com"},
		{Model: gorm.Model{ID: 2}, Name: "bob", Email: "bob@example.com"},
	}

	nodes := types.Nodes{
		{
			ID:       1,
			Hostname: "alice-laptop",
			IPv4:     ap("100.64.0.1"),
			IPv6:     ap("fd7a:115c:a1e0::1"),
			User:     ptr.To(users[0]),
			UserID:   ptr.To(users[0].ID),
		},
		{
			ID:       2,
			Hostname: "server",
			IPv4:     ap("100.64.0.2"),
			IPv6:     ap("fd7a:115c:a1e0::2"),
			User:     ptr.To(users[1]),
			UserID:   ptr.To(users[1].ID),
		},
	}

	// Policy WITHOUT proto field - defaults to TCP+UDP
	policy := `{
		"acls": [
			{
				"action": "accept",
				"src": ["alice@example.com"],
				"dst": ["bob@example.com:22,53,80"]
			}
		]
	}`

	pm, err := NewPolicyManager([]byte(policy), users, nodes.ViewSlice())
	require.NoError(t, err)

	tests := []struct {
		name       string
		test       ACLTest
		wantPassed bool
	}{
		{
			name: "alice_can_ssh_tcp_no_proto_rule",
			test: ACLTest{
				Src:    "alice@example.com",
				Proto:  "tcp",
				Accept: []string{"bob@example.com:22"},
			},
			wantPassed: true,
		},
		{
			name: "alice_can_dns_udp_no_proto_rule",
			test: ACLTest{
				Src:    "alice@example.com",
				Proto:  "udp",
				Accept: []string{"bob@example.com:53"},
			},
			wantPassed: true,
		},
		{
			name: "alice_can_http_tcp_no_proto_rule",
			test: ACLTest{
				Src:    "alice@example.com",
				Proto:  "tcp",
				Accept: []string{"bob@example.com:80"},
			},
			wantPassed: true,
		},
		{
			name: "alice_cannot_ping_icmp_no_proto_rule",
			test: ACLTest{
				Src:   "alice@example.com",
				Proto: "icmp",
				Deny:  []string{"bob@example.com:*"},
			},
			wantPassed: true,
		},
		{
			name: "default_test_proto_matches_no_proto_rule",
			test: ACLTest{
				Src:    "alice@example.com",
				Accept: []string{"bob@example.com:22"},
			},
			wantPassed: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := pm.RunTest(tt.test)
			assert.Equal(t, tt.wantPassed, result.Passed, "test result mismatch for %s: %v", tt.name, result)
		})
	}
}

func TestACLTestResult_Fields(t *testing.T) {
	users := types.Users{
		{Model: gorm.Model{ID: 1}, Name: "alice", Email: "alice@example.com"},
		{Model: gorm.Model{ID: 2}, Name: "bob", Email: "bob@example.com"},
	}

	nodes := types.Nodes{
		{
			ID:       1,
			Hostname: "alice-laptop",
			IPv4:     ap("100.64.0.1"),
			IPv6:     ap("fd7a:115c:a1e0::1"),
			User:     ptr.To(users[0]),
			UserID:   ptr.To(users[0].ID),
		},
		{
			ID:       2,
			Hostname: "bob-server",
			IPv4:     ap("100.64.0.2"),
			IPv6:     ap("fd7a:115c:a1e0::2"),
			User:     ptr.To(users[1]),
			UserID:   ptr.To(users[1].ID),
		},
	}

	pm, err := NewPolicyManager([]byte(testPolicyAliceToBob22), users, nodes.ViewSlice())
	require.NoError(t, err)

	// Test that correctly populates AcceptOK and DenyOK
	result := pm.RunTest(ACLTest{
		Src:    "alice@example.com",
		Accept: []string{"bob@example.com:22"},
		Deny:   []string{"bob@example.com:80"},
	})

	assert.True(t, result.Passed)
	assert.Contains(t, result.AcceptOK, "bob@example.com:22")
	assert.Contains(t, result.DenyOK, "bob@example.com:80")
	assert.Empty(t, result.AcceptFail)
	assert.Empty(t, result.DenyFail)

	// Test that correctly populates AcceptFail and DenyFail
	result = pm.RunTest(ACLTest{
		Src:    "bob@example.com",
		Accept: []string{"alice@example.com:22"}, // Should fail - not allowed
		Deny:   []string{"bob@example.com:22"},   // Should fail - alice can access bob:22, not bob accessing bob:22
	})

	assert.False(t, result.Passed)
	assert.Contains(t, result.AcceptFail, "alice@example.com:22")
}

// TestRunTest_AllSemantics tests that group access uses "ALL" semantics -
// ALL members of a group must have access for the test to pass, not just some.
// This prevents false positives when a user is in multiple groups with different privileges.
func TestRunTest_AllSemantics(t *testing.T) {
	users := types.Users{
		{Model: gorm.Model{ID: 1}, Name: "admin", Email: "admin@example.com"},
		{Model: gorm.Model{ID: 2}, Name: "user1", Email: "user1@example.com"},
		{Model: gorm.Model{ID: 3}, Name: "user2", Email: "user2@example.com"},
	}

	nodes := types.Nodes{
		{
			ID:       1,
			Hostname: "admin-pc",
			IPv4:     ap("100.64.0.1"),
			User:     ptr.To(users[0]),
			UserID:   ptr.To(users[0].ID),
		},
		{
			ID:       2,
			Hostname: "user1-pc",
			IPv4:     ap("100.64.0.2"),
			User:     ptr.To(users[1]),
			UserID:   ptr.To(users[1].ID),
		},
		{
			ID:       3,
			Hostname: "user2-pc",
			IPv4:     ap("100.64.0.3"),
			User:     ptr.To(users[2]),
			UserID:   ptr.To(users[2].ID),
		},
		{
			ID:       4,
			Hostname: "server",
			IPv4:     ap("100.64.0.100"),
			User:     ptr.To(users[0]),
			UserID:   ptr.To(users[0].ID),
		},
	}

	// Policy where:
	// - group:admins (admin@) has full access
	// - group:users (admin@, user1@, user2@) has limited access (only port 80)
	// Admin is in BOTH groups
	const mixedGroupPolicy = `{
		"groups": {
			"group:admins": ["admin@example.com"],
			"group:users": ["admin@example.com", "user1@example.com", "user2@example.com"]
		},
		"acls": [
			{
				"action": "accept",
				"src": ["group:admins"],
				"dst": ["100.64.0.100:*"]
			},
			{
				"action": "accept",
				"src": ["group:users"],
				"dst": ["100.64.0.100:80"]
			}
		]
	}`

	pm, err := NewPolicyManager([]byte(mixedGroupPolicy), users, nodes.ViewSlice())
	require.NoError(t, err)

	t.Run("admin_can_access_server_all_ports", func(t *testing.T) {
		// Admin alone can access all ports
		result := pm.RunTest(ACLTest{
			Src:    "admin@example.com",
			Accept: []string{"100.64.0.100:22", "100.64.0.100:80", "100.64.0.100:443"},
		})
		assert.True(t, result.Passed, "admin should have full access")
	})

	t.Run("group_users_can_only_access_port_80", func(t *testing.T) {
		// group:users can only access port 80
		result := pm.RunTest(ACLTest{
			Src:    "group:users",
			Accept: []string{"100.64.0.100:80"},
		})
		assert.True(t, result.Passed, "group:users should access port 80")
	})

	t.Run("group_users_cannot_access_port_22_ALL_semantics", func(t *testing.T) {
		// With "ALL" semantics: group:users -> :22 should FAIL
		// because user1@ and user2@ don't have access to port 22
		// (even though admin@ does via group:admins)
		result := pm.RunTest(ACLTest{
			Src:    "group:users",
			Accept: []string{"100.64.0.100:22"},
		})
		assert.False(t, result.Passed,
			"group:users should NOT have access to port 22 - user1 and user2 don't have access")
	})

	t.Run("group_admins_can_access_port_22", func(t *testing.T) {
		// group:admins -> :22 should pass (only admin@ is in this group)
		result := pm.RunTest(ACLTest{
			Src:    "group:admins",
			Accept: []string{"100.64.0.100:22"},
		})
		assert.True(t, result.Passed, "group:admins should have access to port 22")
	})

	t.Run("individual_user_without_access_fails", func(t *testing.T) {
		// user2@ alone should fail to access port 22
		result := pm.RunTest(ACLTest{
			Src:    "user2@example.com",
			Accept: []string{"100.64.0.100:22"},
		})
		assert.False(t, result.Passed, "user2 should not have access to port 22")
	})
}
