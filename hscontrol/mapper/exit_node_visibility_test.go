package mapper

import (
	"net/netip"
	"testing"

	"github.com/juanfont/headscale/hscontrol/policy"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/require"
	"tailscale.com/net/tsaddr"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

// TestExitNodeVisibilityWithoutAutogroupInternet tests that exit nodes are not visible
// to nodes that don't have autogroup:internet permission in their ACL.
// This is a regression test for https://github.com/juanfont/headscale/issues/2788
func TestExitNodeVisibilityWithoutAutogroupInternet(t *testing.T) {
	mustNK := func(str string) key.NodePublic {
		var k key.NodePublic
		_ = k.UnmarshalText([]byte(str))
		return k
	}

	mustDK := func(str string) key.DiscoPublic {
		var k key.DiscoPublic
		_ = k.UnmarshalText([]byte(str))
		return k
	}

	mustMK := func(str string) key.MachinePublic {
		var k key.MachinePublic
		_ = k.UnmarshalText([]byte(str))
		return k
	}

	// Create three nodes: mobile, server, exit
	mobile := &types.Node{
		ID: 1,
		MachineKey: mustMK(
			"mkey:f08305b4ee4250b95a70f3b7504d048d75d899993c624a26d422c67af0422507",
		),
		NodeKey: mustNK(
			"nodekey:9b2ffa7e08cc421a3d2cca9012280f6a236fd0de0b4ce005b30a98ad930306fe",
		),
		DiscoKey: mustDK(
			"discokey:cf7b0fd05da556fdc3bab365787b506fd82d64a70745db70e00e86c1b1c03084",
		),
		IPv4:      iap("100.64.0.1"),
		Hostname:  "mobile",
		GivenName: "mobile",
		UserID:    1,
		User: types.User{
			Name: "alice",
		},
	}

	server := &types.Node{
		ID: 2,
		MachineKey: mustMK(
			"mkey:e08305b4ee4250b95a70f3b7504d048d75d899993c624a26d422c67af0422508",
		),
		NodeKey: mustNK(
			"nodekey:8b2ffa7e08cc421a3d2cca9012280f6a236fd0de0b4ce005b30a98ad930306ff",
		),
		DiscoKey: mustDK(
			"discokey:df7b0fd05da556fdc3bab365787b506fd82d64a70745db70e00e86c1b1c03085",
		),
		IPv4:      iap("100.64.0.2"),
		Hostname:  "server",
		GivenName: "server",
		UserID:    1,
		User: types.User{
			Name: "alice",
		},
	}

	exitNode := &types.Node{
		ID: 3,
		MachineKey: mustMK(
			"mkey:d08305b4ee4250b95a70f3b7504d048d75d899993c624a26d422c67af0422509",
		),
		NodeKey: mustNK(
			"nodekey:7b2ffa7e08cc421a3d2cca9012280f6a236fd0de0b4ce005b30a98ad930306fd",
		),
		DiscoKey: mustDK(
			"discokey:ef7b0fd05da556fdc3bab365787b506fd82d64a70745db70e00e86c1b1c03086",
		),
		IPv4:      iap("100.64.0.3"),
		Hostname:  "exit",
		GivenName: "exit",
		UserID:    1,
		User: types.User{
			Name: "alice",
		},
		Hostinfo: &tailcfg.Hostinfo{
			RoutableIPs: []netip.Prefix{
				tsaddr.AllIPv4(),
				tsaddr.AllIPv6(),
			},
		},
		// Exit node has approved exit routes
		ApprovedRoutes: []netip.Prefix{tsaddr.AllIPv4(), tsaddr.AllIPv6()},
	}

	// ACL that only allows mobile -> server:80, no autogroup:internet
	pol := []byte(`{
  "hosts": {
    "mobile": "100.64.0.1/32",
    "server": "100.64.0.2/32",
    "exit": "100.64.0.3/32"
  },
  "acls": [
    {
      "action": "accept",
      "src": ["mobile"],
      "dst": ["server:80"]
    }
  ]
}`)

	polMan, err := policy.NewPolicyManager(pol, []types.User{mobile.User}, types.Nodes{mobile, server, exitNode}.ViewSlice())
	require.NoError(t, err)

	matchers, err := polMan.MatchersForNode(mobile.View())
	require.NoError(t, err)

	cfg := &types.Config{
		BaseDomain:          "",
		RandomizeClientPort: false,
	}

	// Build the exit node as a peer from mobile's perspective
	exitTailNode, err := tailNode(
		exitNode.View(),
		0,
		polMan,
		func(id types.NodeID) []netip.Prefix {
			// No primary routes for this test
			return nil
		},
		func(id types.NodeID) []netip.Prefix {
			// For peer nodes, only include exit routes if the requesting node can use exit nodes
			peerNode := exitNode
			if id != peerNode.ID {
				return nil
			}
			exitRoutes := peerNode.ExitRoutes()
			if len(exitRoutes) == 0 {
				return nil
			}
			// Check if the requesting node has permission to use exit nodes
			if canUseExitRoutes(mobile.View(), matchers) {
				return exitRoutes
			}
			return nil
		},
		cfg,
	)
	require.NoError(t, err)

	// Verify that exit routes are NOT included in AllowedIPs
	// since mobile doesn't have autogroup:internet permission
	hasExitRoutes := false
	for _, prefix := range exitTailNode.AllowedIPs {
		if tsaddr.IsExitRoute(prefix) {
			hasExitRoutes = true
			break
		}
	}

	if hasExitRoutes {
		t.Errorf("Exit node should NOT have exit routes in AllowedIPs when requesting node lacks autogroup:internet permission.\nAllowedIPs: %v", exitTailNode.AllowedIPs)
	}

	// The AllowedIPs should only contain the exit node's own IP, not the exit routes
	// Check the count and that no exit routes are present
	if len(exitTailNode.AllowedIPs) != 1 {
		t.Errorf("Expected exactly 1 IP in AllowedIPs (node's own IP), got %d: %v", len(exitTailNode.AllowedIPs), exitTailNode.AllowedIPs)
	}

	// Verify the one IP is the node's own IP
	expectedIP := netip.MustParsePrefix("100.64.0.3/32")
	found := false
	for _, ip := range exitTailNode.AllowedIPs {
		if ip == expectedIP {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Expected to find node's own IP %s in AllowedIPs, got: %v", expectedIP, exitTailNode.AllowedIPs)
	}
}

// TestExitNodeVisibilityWithAutogroupInternet tests that exit nodes ARE visible
// to nodes that have autogroup:internet permission in their ACL.
func TestExitNodeVisibilityWithAutogroupInternet(t *testing.T) {
	mustNK := func(str string) key.NodePublic {
		var k key.NodePublic
		_ = k.UnmarshalText([]byte(str))
		return k
	}

	mustDK := func(str string) key.DiscoPublic {
		var k key.DiscoPublic
		_ = k.UnmarshalText([]byte(str))
		return k
	}

	mustMK := func(str string) key.MachinePublic {
		var k key.MachinePublic
		_ = k.UnmarshalText([]byte(str))
		return k
	}

	mobile := &types.Node{
		ID: 1,
		MachineKey: mustMK(
			"mkey:f08305b4ee4250b95a70f3b7504d048d75d899993c624a26d422c67af0422507",
		),
		NodeKey: mustNK(
			"nodekey:9b2ffa7e08cc421a3d2cca9012280f6a236fd0de0b4ce005b30a98ad930306fe",
		),
		DiscoKey: mustDK(
			"discokey:cf7b0fd05da556fdc3bab365787b506fd82d64a70745db70e00e86c1b1c03084",
		),
		IPv4:      iap("100.64.0.1"),
		Hostname:  "mobile",
		GivenName: "mobile",
		UserID:    1,
		User: types.User{
			Name: "alice",
		},
	}

	exitNode := &types.Node{
		ID: 3,
		MachineKey: mustMK(
			"mkey:d08305b4ee4250b95a70f3b7504d048d75d899993c624a26d422c67af0422509",
		),
		NodeKey: mustNK(
			"nodekey:7b2ffa7e08cc421a3d2cca9012280f6a236fd0de0b4ce005b30a98ad930306fd",
		),
		DiscoKey: mustDK(
			"discokey:ef7b0fd05da556fdc3bab365787b506fd82d64a70745db70e00e86c1b1c03086",
		),
		IPv4:      iap("100.64.0.3"),
		Hostname:  "exit",
		GivenName: "exit",
		UserID:    1,
		User: types.User{
			Name: "alice",
		},
		Hostinfo: &tailcfg.Hostinfo{
			RoutableIPs: []netip.Prefix{
				tsaddr.AllIPv4(),
				tsaddr.AllIPv6(),
			},
		},
		ApprovedRoutes: []netip.Prefix{tsaddr.AllIPv4(), tsaddr.AllIPv6()},
	}

	// ACL that allows mobile to use autogroup:internet
	pol := []byte(`{
  "hosts": {
    "mobile": "100.64.0.1/32",
    "exit": "100.64.0.3/32"
  },
  "acls": [
    {
      "action": "accept",
      "src": ["mobile"],
      "dst": ["autogroup:internet:*"]
    }
  ]
}`)

	polMan, err := policy.NewPolicyManager(pol, []types.User{mobile.User}, types.Nodes{mobile, exitNode}.ViewSlice())
	require.NoError(t, err)

	matchers, err := polMan.MatchersForNode(mobile.View())
	require.NoError(t, err)

	cfg := &types.Config{
		BaseDomain:          "",
		RandomizeClientPort: false,
	}

	// Build the exit node as a peer from mobile's perspective
	exitTailNode, err := tailNode(
		exitNode.View(),
		0,
		polMan,
		func(id types.NodeID) []netip.Prefix {
			return nil
		},
		func(id types.NodeID) []netip.Prefix {
			peerNode := exitNode
			if id != peerNode.ID {
				return nil
			}
			exitRoutes := peerNode.ExitRoutes()
			if len(exitRoutes) == 0 {
				return nil
			}
			// Check if the requesting node has permission to use exit nodes - mobile has autogroup:internet permission
			if canUseExitRoutes(mobile.View(), matchers) {
				return exitRoutes
			}
			return nil
		},
		cfg,
	)
	require.NoError(t, err)

	// Verify that exit routes ARE included in AllowedIPs
	hasIPv4ExitRoute := false
	hasIPv6ExitRoute := false
	for _, prefix := range exitTailNode.AllowedIPs {
		if prefix == tsaddr.AllIPv4() {
			hasIPv4ExitRoute = true
		}
		if prefix == tsaddr.AllIPv6() {
			hasIPv6ExitRoute = true
		}
	}

	if !hasIPv4ExitRoute {
		t.Errorf("Exit node should have IPv4 exit route (0.0.0.0/0) in AllowedIPs when requesting node has autogroup:internet permission.\nAllowedIPs: %v", exitTailNode.AllowedIPs)
	}

	if !hasIPv6ExitRoute {
		t.Errorf("Exit node should have IPv6 exit route (::/0) in AllowedIPs when requesting node has autogroup:internet permission.\nAllowedIPs: %v", exitTailNode.AllowedIPs)
	}
}
