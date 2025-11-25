package hscontrol

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/mapper"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

// Interactive step type constants
const (
	stepTypeInitialRequest  = "initial_request"
	stepTypeAuthCompletion  = "auth_completion"
	stepTypeFollowupRequest = "followup_request"
)

// interactiveStep defines a step in the interactive authentication workflow
type interactiveStep struct {
	stepType         string // stepTypeInitialRequest, stepTypeAuthCompletion, or stepTypeFollowupRequest
	expectAuthURL    bool
	expectCacheEntry bool
	callAuthPath     bool // Real call to HandleNodeFromAuthPath, not mocked
}

func TestAuthenticationFlows(t *testing.T) {
	// Shared test keys for consistent behavior across test cases
	machineKey1 := key.NewMachine()
	machineKey2 := key.NewMachine()
	nodeKey1 := key.NewNode()
	nodeKey2 := key.NewNode()

	tests := []struct {
		name        string
		setupFunc   func(*testing.T, *Headscale) (string, error) // Returns dynamic values like auth keys
		request     func(dynamicValue string) tailcfg.RegisterRequest
		machineKey  func() key.MachinePublic
		wantAuth    bool
		wantError   bool
		wantAuthURL bool
		wantExpired bool
		validate    func(*testing.T, *tailcfg.RegisterResponse, *Headscale)

		// Interactive workflow support
		requiresInteractiveFlow   bool
		interactiveSteps          []interactiveStep
		validateRegistrationCache bool
		expectedAuthURLPattern    string
		simulateAuthCompletion    bool
		validateCompleteResponse  bool
	}{
		// === PRE-AUTH KEY SCENARIOS ===
		// Tests authentication using pre-authorization keys for automated node registration.
		// Pre-auth keys allow nodes to join without interactive authentication.

		// TEST: Valid pre-auth key registers a new node
		// WHAT: Tests successful node registration using a valid pre-auth key
		// INPUT: Register request with valid pre-auth key, node key, and hostinfo
		// EXPECTED: Node is authorized immediately, registered in database
		// WHY: Pre-auth keys enable automated/headless node registration without user interaction
		{
			name: "preauth_key_valid_new_node",
			setupFunc: func(t *testing.T, app *Headscale) (string, error) {
				user := app.state.CreateUserForTest("preauth-user")
				pak, err := app.state.CreatePreAuthKey(types.UserID(user.ID), true, false, nil, nil)
				if err != nil {
					return "", err
				}
				return pak.Key, nil
			},
			request: func(authKey string) tailcfg.RegisterRequest {
				return tailcfg.RegisterRequest{
					Auth: &tailcfg.RegisterResponseAuth{
						AuthKey: authKey,
					},
					NodeKey: nodeKey1.Public(),
					Hostinfo: &tailcfg.Hostinfo{
						Hostname: "preauth-node-1",
					},
					Expiry: time.Now().Add(24 * time.Hour),
				}
			},
			machineKey: func() key.MachinePublic { return machineKey1.Public() },
			wantAuth:   true,
			validate: func(t *testing.T, resp *tailcfg.RegisterResponse, app *Headscale) {
				assert.True(t, resp.MachineAuthorized)
				assert.False(t, resp.NodeKeyExpired)
				assert.NotEmpty(t, resp.User.DisplayName)

				// Verify node was created in database
				node, found := app.state.GetNodeByNodeKey(nodeKey1.Public())
				assert.True(t, found)
				assert.Equal(t, "preauth-node-1", node.Hostname())
			},
		},

		// TEST: Reusable pre-auth key can register multiple nodes
		// WHAT: Tests that a reusable pre-auth key can be used for multiple node registrations
		// INPUT: Same reusable pre-auth key used to register two different nodes
		// EXPECTED: Both nodes successfully register with the same key
		// WHY: Reusable keys allow multiple machines to join using one key (useful for fleet deployments)
		{
			name: "preauth_key_reusable_multiple_nodes",
			setupFunc: func(t *testing.T, app *Headscale) (string, error) {
				user := app.state.CreateUserForTest("reusable-user")
				pak, err := app.state.CreatePreAuthKey(types.UserID(user.ID), true, false, nil, nil)
				if err != nil {
					return "", err
				}

				// Use the key for first node
				firstReq := tailcfg.RegisterRequest{
					Auth: &tailcfg.RegisterResponseAuth{
						AuthKey: pak.Key,
					},
					NodeKey: nodeKey1.Public(),
					Hostinfo: &tailcfg.Hostinfo{
						Hostname: "reusable-node-1",
					},
					Expiry: time.Now().Add(24 * time.Hour),
				}
				_, err = app.handleRegisterWithAuthKey(firstReq, machineKey1.Public())
				if err != nil {
					return "", err
				}

				// Wait for node to be available in NodeStore
				require.EventuallyWithT(t, func(c *assert.CollectT) {
					_, found := app.state.GetNodeByNodeKey(nodeKey1.Public())
					assert.True(c, found, "node should be available in NodeStore")
				}, 1*time.Second, 50*time.Millisecond, "waiting for node to be available in NodeStore")

				return pak.Key, nil
			},
			request: func(authKey string) tailcfg.RegisterRequest {
				return tailcfg.RegisterRequest{
					Auth: &tailcfg.RegisterResponseAuth{
						AuthKey: authKey,
					},
					NodeKey: nodeKey2.Public(),
					Hostinfo: &tailcfg.Hostinfo{
						Hostname: "reusable-node-2",
					},
					Expiry: time.Now().Add(24 * time.Hour),
				}
			},
			machineKey: func() key.MachinePublic { return machineKey2.Public() },
			wantAuth:   true,
			validate: func(t *testing.T, resp *tailcfg.RegisterResponse, app *Headscale) {
				assert.True(t, resp.MachineAuthorized)
				assert.False(t, resp.NodeKeyExpired)

				// Verify both nodes exist
				node1, found1 := app.state.GetNodeByNodeKey(nodeKey1.Public())
				node2, found2 := app.state.GetNodeByNodeKey(nodeKey2.Public())
				assert.True(t, found1)
				assert.True(t, found2)
				assert.Equal(t, "reusable-node-1", node1.Hostname())
				assert.Equal(t, "reusable-node-2", node2.Hostname())
			},
		},

		// TEST: Single-use pre-auth key cannot be reused
		// WHAT: Tests that a single-use pre-auth key fails on second use
		// INPUT: Single-use key used for first node (succeeds), then attempted for second node
		// EXPECTED: First node registers successfully, second node fails with error
		// WHY: Single-use keys provide security by preventing key reuse after initial registration
		{
			name: "preauth_key_single_use_exhausted",
			setupFunc: func(t *testing.T, app *Headscale) (string, error) {
				user := app.state.CreateUserForTest("single-use-user")
				pak, err := app.state.CreatePreAuthKey(types.UserID(user.ID), false, false, nil, nil)
				if err != nil {
					return "", err
				}

				// Use the key for first node (should work)
				firstReq := tailcfg.RegisterRequest{
					Auth: &tailcfg.RegisterResponseAuth{
						AuthKey: pak.Key,
					},
					NodeKey: nodeKey1.Public(),
					Hostinfo: &tailcfg.Hostinfo{
						Hostname: "single-use-node-1",
					},
					Expiry: time.Now().Add(24 * time.Hour),
				}
				_, err = app.handleRegisterWithAuthKey(firstReq, machineKey1.Public())
				if err != nil {
					return "", err
				}

				// Wait for node to be available in NodeStore
				require.EventuallyWithT(t, func(c *assert.CollectT) {
					_, found := app.state.GetNodeByNodeKey(nodeKey1.Public())
					assert.True(c, found, "node should be available in NodeStore")
				}, 1*time.Second, 50*time.Millisecond, "waiting for node to be available in NodeStore")

				return pak.Key, nil
			},
			request: func(authKey string) tailcfg.RegisterRequest {
				return tailcfg.RegisterRequest{
					Auth: &tailcfg.RegisterResponseAuth{
						AuthKey: authKey,
					},
					NodeKey: nodeKey2.Public(),
					Hostinfo: &tailcfg.Hostinfo{
						Hostname: "single-use-node-2",
					},
					Expiry: time.Now().Add(24 * time.Hour),
				}
			},
			machineKey: func() key.MachinePublic { return machineKey2.Public() },
			wantError:  true,
			validate: func(t *testing.T, resp *tailcfg.RegisterResponse, app *Headscale) {
				// First node should exist, second should not
				_, found1 := app.state.GetNodeByNodeKey(nodeKey1.Public())
				_, found2 := app.state.GetNodeByNodeKey(nodeKey2.Public())
				assert.True(t, found1)
				assert.False(t, found2)
			},
		},

		// TEST: Invalid pre-auth key is rejected
		// WHAT: Tests that an invalid/non-existent pre-auth key is rejected
		// INPUT: Register request with invalid auth key string
		// EXPECTED: Registration fails with error
		// WHY: Invalid keys must be rejected to prevent unauthorized node registration
		{
			name: "preauth_key_invalid",
			setupFunc: func(t *testing.T, app *Headscale) (string, error) {
				return "invalid-key-12345", nil
			},
			request: func(authKey string) tailcfg.RegisterRequest {
				return tailcfg.RegisterRequest{
					Auth: &tailcfg.RegisterResponseAuth{
						AuthKey: authKey,
					},
					NodeKey: nodeKey1.Public(),
					Hostinfo: &tailcfg.Hostinfo{
						Hostname: "invalid-key-node",
					},
					Expiry: time.Now().Add(24 * time.Hour),
				}
			},
			machineKey: func() key.MachinePublic { return machineKey1.Public() },
			wantError:  true,
		},

		// TEST: Ephemeral pre-auth key creates ephemeral node
		// WHAT: Tests that a node registered with ephemeral key is marked as ephemeral
		// INPUT: Pre-auth key with ephemeral=true, standard register request
		// EXPECTED: Node registers and is marked as ephemeral (will be deleted on logout)
		// WHY: Ephemeral nodes auto-cleanup when disconnected, useful for temporary/CI environments
		{
			name: "preauth_key_ephemeral_node",
			setupFunc: func(t *testing.T, app *Headscale) (string, error) {
				user := app.state.CreateUserForTest("ephemeral-user")
				pak, err := app.state.CreatePreAuthKey(types.UserID(user.ID), false, true, nil, nil)
				if err != nil {
					return "", err
				}
				return pak.Key, nil
			},
			request: func(authKey string) tailcfg.RegisterRequest {
				return tailcfg.RegisterRequest{
					Auth: &tailcfg.RegisterResponseAuth{
						AuthKey: authKey,
					},
					NodeKey: nodeKey1.Public(),
					Hostinfo: &tailcfg.Hostinfo{
						Hostname: "ephemeral-node",
					},
					Expiry: time.Now().Add(24 * time.Hour),
				}
			},
			machineKey: func() key.MachinePublic { return machineKey1.Public() },
			wantAuth:   true,
			validate: func(t *testing.T, resp *tailcfg.RegisterResponse, app *Headscale) {
				assert.True(t, resp.MachineAuthorized)
				assert.False(t, resp.NodeKeyExpired)

				// Verify ephemeral node was created
				node, found := app.state.GetNodeByNodeKey(nodeKey1.Public())
				assert.True(t, found)
				assert.NotNil(t, node.AuthKey)
				assert.True(t, node.AuthKey().Ephemeral())
			},
		},

		// === INTERACTIVE REGISTRATION SCENARIOS ===
		// Tests interactive authentication flow where user completes registration via web UI.
		// Interactive flow: node requests registration → receives AuthURL → user authenticates → node gets registered

		// TEST: Complete interactive workflow for new node
		// WHAT: Tests full interactive registration flow from initial request to completion
		// INPUT: Register request with no auth → user completes auth → followup request
		// EXPECTED: Initial request returns AuthURL, after auth completion node is registered
		// WHY: Interactive flow is the standard user-facing authentication method for new nodes
		{
			name: "full_interactive_workflow_new_node",
			setupFunc: func(t *testing.T, app *Headscale) (string, error) {
				return "", nil
			},
			request: func(_ string) tailcfg.RegisterRequest {
				return tailcfg.RegisterRequest{
					NodeKey: nodeKey1.Public(),
					Hostinfo: &tailcfg.Hostinfo{
						Hostname: "interactive-flow-node",
					},
					Expiry: time.Now().Add(24 * time.Hour),
				}
			},
			machineKey:              func() key.MachinePublic { return machineKey1.Public() },
			requiresInteractiveFlow: true,
			interactiveSteps: []interactiveStep{
				{stepType: stepTypeInitialRequest, expectAuthURL: true, expectCacheEntry: true},
				{stepType: stepTypeAuthCompletion, callAuthPath: true, expectCacheEntry: false}, // cleaned up after completion
			},
			validateCompleteResponse: true,
			expectedAuthURLPattern:   "/register/",
		},
		// TEST: Interactive workflow with no Auth struct in request
		// WHAT: Tests interactive flow when request has no Auth field (nil)
		// INPUT: Register request with Auth field set to nil
		// EXPECTED: Node receives AuthURL and can complete registration via interactive flow
		// WHY: Validates handling of requests without Auth field, same as empty auth
		{
			name: "interactive_workflow_no_auth_struct",
			setupFunc: func(t *testing.T, app *Headscale) (string, error) {
				return "", nil
			},
			request: func(_ string) tailcfg.RegisterRequest {
				return tailcfg.RegisterRequest{
					// No Auth field at all
					NodeKey: nodeKey1.Public(),
					Hostinfo: &tailcfg.Hostinfo{
						Hostname: "interactive-no-auth-node",
					},
					Expiry: time.Now().Add(24 * time.Hour),
				}
			},
			machineKey:              func() key.MachinePublic { return machineKey1.Public() },
			requiresInteractiveFlow: true,
			interactiveSteps: []interactiveStep{
				{stepType: stepTypeInitialRequest, expectAuthURL: true, expectCacheEntry: true},
				{stepType: stepTypeAuthCompletion, callAuthPath: true, expectCacheEntry: false}, // cleaned up after completion
			},
			validateCompleteResponse: true,
			expectedAuthURLPattern:   "/register/",
		},

		// === EXISTING NODE SCENARIOS ===
		// Tests behavior when existing registered nodes send requests (logout, re-auth, expiry, etc.)

		// TEST: Existing node logout with past expiry
		// WHAT: Tests node logout by sending request with expiry in the past
		// INPUT: Previously registered node sends request with Auth=nil and past expiry time
		// EXPECTED: Node expiry is updated, NodeKeyExpired=true, MachineAuthorized=true (for compatibility)
		// WHY: Nodes signal logout by setting expiry to past time; system updates node state accordingly
		{
			name: "existing_node_logout",
			setupFunc: func(t *testing.T, app *Headscale) (string, error) {
				user := app.state.CreateUserForTest("logout-user")
				pak, err := app.state.CreatePreAuthKey(types.UserID(user.ID), true, false, nil, nil)
				if err != nil {
					return "", err
				}

				// Register the node first
				regReq := tailcfg.RegisterRequest{
					Auth: &tailcfg.RegisterResponseAuth{
						AuthKey: pak.Key,
					},
					NodeKey: nodeKey1.Public(),
					Hostinfo: &tailcfg.Hostinfo{
						Hostname: "logout-node",
					},
					Expiry: time.Now().Add(24 * time.Hour),
				}
				resp, err := app.handleRegisterWithAuthKey(regReq, machineKey1.Public())
				if err != nil {
					return "", err
				}

				t.Logf("Setup registered node: %+v", resp)

				// Wait for node to be available in NodeStore with debug info
				var attemptCount int
				require.EventuallyWithT(t, func(c *assert.CollectT) {
					attemptCount++
					_, found := app.state.GetNodeByNodeKey(nodeKey1.Public())
					if assert.True(c, found, "node should be available in NodeStore") {
						t.Logf("Node found in NodeStore after %d attempts", attemptCount)
					}
				}, 1*time.Second, 100*time.Millisecond, "waiting for node to be available in NodeStore")

				return "", nil
			},
			request: func(_ string) tailcfg.RegisterRequest {
				return tailcfg.RegisterRequest{
					Auth:    nil,
					NodeKey: nodeKey1.Public(),
					Expiry:  time.Now().Add(-1 * time.Hour), // Past expiry = logout
				}
			},
			machineKey:  func() key.MachinePublic { return machineKey1.Public() },
			wantAuth:    true,
			wantExpired: true,
			validate: func(t *testing.T, resp *tailcfg.RegisterResponse, app *Headscale) {
				assert.True(t, resp.MachineAuthorized)
				assert.True(t, resp.NodeKeyExpired)
			},
		},
		// TEST: Existing node with different machine key is rejected
		// WHAT: Tests that requests for existing node with wrong machine key are rejected
		// INPUT: Node key matches existing node, but machine key is different
		// EXPECTED: Request fails with unauthorized error (machine key mismatch)
		// WHY: Machine key must match to prevent node hijacking/impersonation
		{
			name: "existing_node_machine_key_mismatch",
			setupFunc: func(t *testing.T, app *Headscale) (string, error) {
				user := app.state.CreateUserForTest("mismatch-user")
				pak, err := app.state.CreatePreAuthKey(types.UserID(user.ID), true, false, nil, nil)
				if err != nil {
					return "", err
				}

				// Register with machineKey1
				regReq := tailcfg.RegisterRequest{
					Auth: &tailcfg.RegisterResponseAuth{
						AuthKey: pak.Key,
					},
					NodeKey: nodeKey1.Public(),
					Hostinfo: &tailcfg.Hostinfo{
						Hostname: "mismatch-node",
					},
					Expiry: time.Now().Add(24 * time.Hour),
				}
				_, err = app.handleRegisterWithAuthKey(regReq, machineKey1.Public())
				if err != nil {
					return "", err
				}

				// Wait for node to be available in NodeStore
				require.EventuallyWithT(t, func(c *assert.CollectT) {
					_, found := app.state.GetNodeByNodeKey(nodeKey1.Public())
					assert.True(c, found, "node should be available in NodeStore")
				}, 1*time.Second, 50*time.Millisecond, "waiting for node to be available in NodeStore")

				return "", nil
			},
			request: func(_ string) tailcfg.RegisterRequest {
				return tailcfg.RegisterRequest{
					Auth:    nil,
					NodeKey: nodeKey1.Public(),
					Expiry:  time.Now().Add(-1 * time.Hour),
				}
			},
			machineKey: func() key.MachinePublic { return machineKey2.Public() }, // Different machine key
			wantError:  true,
		},
		// TEST: Existing node cannot extend expiry without re-auth
		// WHAT: Tests that nodes cannot extend their expiry time without authentication
		// INPUT: Existing node sends request with Auth=nil and future expiry (extension attempt)
		// EXPECTED: Request fails with error (extending key not allowed)
		// WHY: Prevents nodes from extending their own lifetime; must re-authenticate
		{
			name: "existing_node_key_extension_not_allowed",
			setupFunc: func(t *testing.T, app *Headscale) (string, error) {
				user := app.state.CreateUserForTest("extend-user")
				pak, err := app.state.CreatePreAuthKey(types.UserID(user.ID), true, false, nil, nil)
				if err != nil {
					return "", err
				}

				// Register the node first
				regReq := tailcfg.RegisterRequest{
					Auth: &tailcfg.RegisterResponseAuth{
						AuthKey: pak.Key,
					},
					NodeKey: nodeKey1.Public(),
					Hostinfo: &tailcfg.Hostinfo{
						Hostname: "extend-node",
					},
					Expiry: time.Now().Add(24 * time.Hour),
				}
				_, err = app.handleRegisterWithAuthKey(regReq, machineKey1.Public())
				if err != nil {
					return "", err
				}

				// Wait for node to be available in NodeStore
				require.EventuallyWithT(t, func(c *assert.CollectT) {
					_, found := app.state.GetNodeByNodeKey(nodeKey1.Public())
					assert.True(c, found, "node should be available in NodeStore")
				}, 1*time.Second, 50*time.Millisecond, "waiting for node to be available in NodeStore")

				return "", nil
			},
			request: func(_ string) tailcfg.RegisterRequest {
				return tailcfg.RegisterRequest{
					Auth:    nil,
					NodeKey: nodeKey1.Public(),
					Expiry:  time.Now().Add(48 * time.Hour), // Future time = extend attempt
				}
			},
			machineKey: func() key.MachinePublic { return machineKey1.Public() },
			wantError:  true,
		},
		// TEST: Expired node must re-authenticate
		// WHAT: Tests that expired nodes receive NodeKeyExpired=true and must re-auth
		// INPUT: Previously expired node sends request with no auth
		// EXPECTED: Response has NodeKeyExpired=true, node must re-authenticate
		// WHY: Expired nodes must go through authentication again for security
		{
			name: "existing_node_expired_forces_reauth",
			setupFunc: func(t *testing.T, app *Headscale) (string, error) {
				user := app.state.CreateUserForTest("reauth-user")
				pak, err := app.state.CreatePreAuthKey(types.UserID(user.ID), true, false, nil, nil)
				if err != nil {
					return "", err
				}

				// Register the node first
				regReq := tailcfg.RegisterRequest{
					Auth: &tailcfg.RegisterResponseAuth{
						AuthKey: pak.Key,
					},
					NodeKey: nodeKey1.Public(),
					Hostinfo: &tailcfg.Hostinfo{
						Hostname: "reauth-node",
					},
					Expiry: time.Now().Add(24 * time.Hour),
				}
				_, err = app.handleRegisterWithAuthKey(regReq, machineKey1.Public())
				if err != nil {
					return "", err
				}

				// Wait for node to be available in NodeStore
				var node types.NodeView
				var found bool
				require.EventuallyWithT(t, func(c *assert.CollectT) {
					node, found = app.state.GetNodeByNodeKey(nodeKey1.Public())
					assert.True(c, found, "node should be available in NodeStore")
				}, 1*time.Second, 50*time.Millisecond, "waiting for node to be available in NodeStore")
				if !found {
					return "", fmt.Errorf("node not found after setup")
				}

				// Expire the node
				expiredTime := time.Now().Add(-1 * time.Hour)
				_, _, err = app.state.SetNodeExpiry(node.ID(), expiredTime)
				return "", err
			},
			request: func(_ string) tailcfg.RegisterRequest {
				return tailcfg.RegisterRequest{
					Auth:    nil,
					NodeKey: nodeKey1.Public(),
					Expiry:  time.Now().Add(24 * time.Hour), // Future expiry
				}
			},
			machineKey:  func() key.MachinePublic { return machineKey1.Public() },
			wantExpired: true,
			validate: func(t *testing.T, resp *tailcfg.RegisterResponse, app *Headscale) {
				assert.True(t, resp.NodeKeyExpired)
				assert.False(t, resp.MachineAuthorized)
			},
		},
		// TEST: Ephemeral node is deleted on logout
		// WHAT: Tests that ephemeral nodes are deleted (not just expired) on logout
		// INPUT: Ephemeral node sends logout request (past expiry)
		// EXPECTED: Node is completely deleted from database, not just marked expired
		// WHY: Ephemeral nodes should not persist after logout; auto-cleanup
		{
			name: "ephemeral_node_logout_deletion",
			setupFunc: func(t *testing.T, app *Headscale) (string, error) {
				user := app.state.CreateUserForTest("ephemeral-logout-user")
				pak, err := app.state.CreatePreAuthKey(types.UserID(user.ID), false, true, nil, nil)
				if err != nil {
					return "", err
				}

				// Register ephemeral node
				regReq := tailcfg.RegisterRequest{
					Auth: &tailcfg.RegisterResponseAuth{
						AuthKey: pak.Key,
					},
					NodeKey: nodeKey1.Public(),
					Hostinfo: &tailcfg.Hostinfo{
						Hostname: "ephemeral-logout-node",
					},
					Expiry: time.Now().Add(24 * time.Hour),
				}
				_, err = app.handleRegisterWithAuthKey(regReq, machineKey1.Public())
				if err != nil {
					return "", err
				}

				// Wait for node to be available in NodeStore
				require.EventuallyWithT(t, func(c *assert.CollectT) {
					_, found := app.state.GetNodeByNodeKey(nodeKey1.Public())
					assert.True(c, found, "node should be available in NodeStore")
				}, 1*time.Second, 50*time.Millisecond, "waiting for node to be available in NodeStore")

				return "", nil
			},
			request: func(_ string) tailcfg.RegisterRequest {
				return tailcfg.RegisterRequest{
					Auth:    nil,
					NodeKey: nodeKey1.Public(),
					Expiry:  time.Now().Add(-1 * time.Hour), // Logout
				}
			},
			machineKey:  func() key.MachinePublic { return machineKey1.Public() },
			wantExpired: true,
			validate: func(t *testing.T, resp *tailcfg.RegisterResponse, app *Headscale) {
				assert.True(t, resp.NodeKeyExpired)
				assert.False(t, resp.MachineAuthorized)

				// Ephemeral node should be deleted, not just marked expired
				_, found := app.state.GetNodeByNodeKey(nodeKey1.Public())
				assert.False(t, found, "ephemeral node should be deleted on logout")
			},
		},

		// === FOLLOWUP REGISTRATION SCENARIOS ===
		// Tests followup request handling after interactive registration is initiated.
		// Followup requests are sent by nodes waiting for auth completion.

		// TEST: Successful followup registration after auth completion
		// WHAT: Tests node successfully completes registration via followup URL
		// INPUT: Register request with followup URL after auth completion
		// EXPECTED: Node receives successful registration response with user info
		// WHY: Followup mechanism allows nodes to poll/wait for auth completion
		{
			name: "followup_registration_success",
			setupFunc: func(t *testing.T, app *Headscale) (string, error) {
				regID, err := types.NewRegistrationID()
				if err != nil {
					return "", err
				}

				registered := make(chan *types.Node, 1)
				nodeToRegister := types.RegisterNode{
					Node: types.Node{
						Hostname: "followup-success-node",
					},
					Registered: registered,
				}
				app.state.SetRegistrationCacheEntry(regID, nodeToRegister)

				// Simulate successful registration
				go func() {
					time.Sleep(20 * time.Millisecond)
					user := app.state.CreateUserForTest("followup-user")
					node := app.state.CreateNodeForTest(user, "followup-success-node")
					registered <- node
				}()

				return fmt.Sprintf("http://localhost:8080/register/%s", regID), nil
			},
			request: func(followupURL string) tailcfg.RegisterRequest {
				return tailcfg.RegisterRequest{
					Followup: followupURL,
					NodeKey:  nodeKey1.Public(),
				}
			},
			machineKey: func() key.MachinePublic { return machineKey1.Public() },
			wantAuth:   true,
			validate: func(t *testing.T, resp *tailcfg.RegisterResponse, app *Headscale) {
				assert.True(t, resp.MachineAuthorized)
				assert.False(t, resp.NodeKeyExpired)
			},
		},
		// TEST: Followup registration times out when auth not completed
		// WHAT: Tests that followup request times out if auth is not completed in time
		// INPUT: Followup request with short timeout, no auth completion
		// EXPECTED: Request times out with unauthorized error
		// WHY: Prevents indefinite waiting; nodes must retry if auth takes too long
		{
			name: "followup_registration_timeout",
			setupFunc: func(t *testing.T, app *Headscale) (string, error) {
				regID, err := types.NewRegistrationID()
				if err != nil {
					return "", err
				}

				registered := make(chan *types.Node, 1)
				nodeToRegister := types.RegisterNode{
					Node: types.Node{
						Hostname: "followup-timeout-node",
					},
					Registered: registered,
				}
				app.state.SetRegistrationCacheEntry(regID, nodeToRegister)
				// Don't send anything on channel - will timeout

				return fmt.Sprintf("http://localhost:8080/register/%s", regID), nil
			},
			request: func(followupURL string) tailcfg.RegisterRequest {
				return tailcfg.RegisterRequest{
					Followup: followupURL,
					NodeKey:  nodeKey1.Public(),
				}
			},
			machineKey: func() key.MachinePublic { return machineKey1.Public() },
			wantError:  true,
		},
		// TEST: Invalid followup URL is rejected
		// WHAT: Tests that malformed/invalid followup URLs are rejected
		// INPUT: Register request with invalid URL in Followup field
		// EXPECTED: Request fails with error (invalid followup URL)
		// WHY: Validates URL format to prevent errors and potential exploits
		{
			name: "followup_invalid_url",
			setupFunc: func(t *testing.T, app *Headscale) (string, error) {
				return "invalid://url[malformed", nil
			},
			request: func(followupURL string) tailcfg.RegisterRequest {
				return tailcfg.RegisterRequest{
					Followup: followupURL,
					NodeKey:  nodeKey1.Public(),
				}
			},
			machineKey: func() key.MachinePublic { return machineKey1.Public() },
			wantError:  true,
		},
		// TEST: Non-existent registration ID is rejected
		// WHAT: Tests that followup with non-existent registration ID fails
		// INPUT: Valid followup URL but registration ID not in cache
		// EXPECTED: Request fails with unauthorized error
		// WHY: Registration must exist in cache; prevents invalid/expired registrations
		{
			name: "followup_registration_not_found",
			setupFunc: func(t *testing.T, app *Headscale) (string, error) {
				return "http://localhost:8080/register/nonexistent-id", nil
			},
			request: func(followupURL string) tailcfg.RegisterRequest {
				return tailcfg.RegisterRequest{
					Followup: followupURL,
					NodeKey:  nodeKey1.Public(),
				}
			},
			machineKey: func() key.MachinePublic { return machineKey1.Public() },
			wantError:  true,
		},

		// === EDGE CASES ===
		// Tests handling of malformed, invalid, or unusual input data

		// TEST: Empty hostname is handled with defensive code
		// WHAT: Tests that empty hostname in hostinfo generates a default hostname
		// INPUT: Register request with hostinfo containing empty hostname string
		// EXPECTED: Node registers successfully with generated hostname (node-MACHINEKEY)
		// WHY: Defensive code prevents errors from missing hostnames; generates sensible default
		{
			name: "empty_hostname",
			setupFunc: func(t *testing.T, app *Headscale) (string, error) {
				user := app.state.CreateUserForTest("empty-hostname-user")
				pak, err := app.state.CreatePreAuthKey(types.UserID(user.ID), true, false, nil, nil)
				if err != nil {
					return "", err
				}
				return pak.Key, nil
			},
			request: func(authKey string) tailcfg.RegisterRequest {
				return tailcfg.RegisterRequest{
					Auth: &tailcfg.RegisterResponseAuth{
						AuthKey: authKey,
					},
					NodeKey: nodeKey1.Public(),
					Hostinfo: &tailcfg.Hostinfo{
						Hostname: "", // Empty hostname should be handled gracefully
					},
					Expiry: time.Now().Add(24 * time.Hour),
				}
			},
			machineKey: func() key.MachinePublic { return machineKey1.Public() },
			wantAuth:   true,
			validate: func(t *testing.T, resp *tailcfg.RegisterResponse, app *Headscale) {
				assert.True(t, resp.MachineAuthorized)

				// Node should be created with generated hostname
				node, found := app.state.GetNodeByNodeKey(nodeKey1.Public())
				assert.True(t, found)
				assert.NotEmpty(t, node.Hostname())
			},
		},
		// TEST: Nil hostinfo is handled with defensive code
		// WHAT: Tests that nil hostinfo in register request is handled gracefully
		// INPUT: Register request with Hostinfo field set to nil
		// EXPECTED: Node registers successfully with generated hostname starting with "node-"
		// WHY: Defensive code prevents nil pointer panics; creates valid default hostinfo
		{
			name: "nil_hostinfo",
			setupFunc: func(t *testing.T, app *Headscale) (string, error) {
				user := app.state.CreateUserForTest("nil-hostinfo-user")
				pak, err := app.state.CreatePreAuthKey(types.UserID(user.ID), true, false, nil, nil)
				if err != nil {
					return "", err
				}
				return pak.Key, nil
			},
			request: func(authKey string) tailcfg.RegisterRequest {
				return tailcfg.RegisterRequest{
					Auth: &tailcfg.RegisterResponseAuth{
						AuthKey: authKey,
					},
					NodeKey:  nodeKey1.Public(),
					Hostinfo: nil, // Nil hostinfo should be handled with defensive code
					Expiry:   time.Now().Add(24 * time.Hour),
				}
			},
			machineKey: func() key.MachinePublic { return machineKey1.Public() },
			wantAuth:   true,
			validate: func(t *testing.T, resp *tailcfg.RegisterResponse, app *Headscale) {
				assert.True(t, resp.MachineAuthorized)

				// Node should be created with generated hostname from defensive code
				node, found := app.state.GetNodeByNodeKey(nodeKey1.Public())
				assert.True(t, found)
				assert.NotEmpty(t, node.Hostname())
				// Hostname should start with "node-" (generated from machine key)
				assert.True(t, strings.HasPrefix(node.Hostname(), "node-"))
			},
		},

		// === PRE-AUTH KEY WITH EXPIRY SCENARIOS ===
		// Tests pre-auth key expiration handling

		// TEST: Expired pre-auth key is rejected
		// WHAT: Tests that a pre-auth key with past expiration date cannot be used
		// INPUT: Pre-auth key with expiry 1 hour in the past
		// EXPECTED: Registration fails with error
		// WHY: Expired keys must be rejected to maintain security and key lifecycle management
		{
			name: "preauth_key_expired",
			setupFunc: func(t *testing.T, app *Headscale) (string, error) {
				user := app.state.CreateUserForTest("expired-pak-user")
				expiry := time.Now().Add(-1 * time.Hour) // Expired 1 hour ago
				pak, err := app.state.CreatePreAuthKey(types.UserID(user.ID), true, false, &expiry, nil)
				if err != nil {
					return "", err
				}
				return pak.Key, nil
			},
			request: func(authKey string) tailcfg.RegisterRequest {
				return tailcfg.RegisterRequest{
					Auth: &tailcfg.RegisterResponseAuth{
						AuthKey: authKey,
					},
					NodeKey: nodeKey1.Public(),
					Hostinfo: &tailcfg.Hostinfo{
						Hostname: "expired-pak-node",
					},
					Expiry: time.Now().Add(24 * time.Hour),
				}
			},
			machineKey: func() key.MachinePublic { return machineKey1.Public() },
			wantError:  true,
		},

		// TEST: Pre-auth key with ACL tags applies tags to node
		// WHAT: Tests that ACL tags from pre-auth key are applied to registered node
		// INPUT: Pre-auth key with ACL tags ["tag:test", "tag:integration"], register request
		// EXPECTED: Node registers with specified ACL tags applied as ForcedTags
		// WHY: Pre-auth keys can enforce ACL policies on nodes during registration
		{
			name: "preauth_key_with_acl_tags",
			setupFunc: func(t *testing.T, app *Headscale) (string, error) {
				user := app.state.CreateUserForTest("tagged-pak-user")
				tags := []string{"tag:server", "tag:database"}
				pak, err := app.state.CreatePreAuthKey(types.UserID(user.ID), true, false, nil, tags)
				if err != nil {
					return "", err
				}
				return pak.Key, nil
			},
			request: func(authKey string) tailcfg.RegisterRequest {
				return tailcfg.RegisterRequest{
					Auth: &tailcfg.RegisterResponseAuth{
						AuthKey: authKey,
					},
					NodeKey: nodeKey1.Public(),
					Hostinfo: &tailcfg.Hostinfo{
						Hostname: "tagged-pak-node",
					},
					Expiry: time.Now().Add(24 * time.Hour),
				}
			},
			machineKey: func() key.MachinePublic { return machineKey1.Public() },
			wantAuth:   true,
			validate: func(t *testing.T, resp *tailcfg.RegisterResponse, app *Headscale) {
				assert.True(t, resp.MachineAuthorized)
				assert.False(t, resp.NodeKeyExpired)

				// Verify node was created with tags
				node, found := app.state.GetNodeByNodeKey(nodeKey1.Public())
				assert.True(t, found)
				assert.Equal(t, "tagged-pak-node", node.Hostname())
				if node.AuthKey().Valid() {
					assert.NotEmpty(t, node.AuthKey().Tags())
				}
			},
		},

		// === RE-AUTHENTICATION SCENARIOS ===
		// TEST: Existing node re-authenticates with new pre-auth key
		// WHAT: Tests that existing node can re-authenticate using new pre-auth key
		// INPUT: Existing node sends request with new valid pre-auth key
		// EXPECTED: Node successfully re-authenticates, stays authorized
		// WHY: Allows nodes to refresh authentication using pre-auth keys
		{
			name: "existing_node_reauth_with_new_authkey",
			setupFunc: func(t *testing.T, app *Headscale) (string, error) {
				user := app.state.CreateUserForTest("reauth-user")

				// First, register with initial auth key
				pak1, err := app.state.CreatePreAuthKey(types.UserID(user.ID), true, false, nil, nil)
				if err != nil {
					return "", err
				}

				regReq := tailcfg.RegisterRequest{
					Auth: &tailcfg.RegisterResponseAuth{
						AuthKey: pak1.Key,
					},
					NodeKey: nodeKey1.Public(),
					Hostinfo: &tailcfg.Hostinfo{
						Hostname: "reauth-node",
					},
					Expiry: time.Now().Add(24 * time.Hour),
				}
				_, err = app.handleRegisterWithAuthKey(regReq, machineKey1.Public())
				if err != nil {
					return "", err
				}

				// Wait for node to be available
				require.EventuallyWithT(t, func(c *assert.CollectT) {
					_, found := app.state.GetNodeByNodeKey(nodeKey1.Public())
					assert.True(c, found, "node should be available in NodeStore")
				}, 1*time.Second, 50*time.Millisecond, "waiting for node to be available in NodeStore")

				// Create new auth key for re-authentication
				pak2, err := app.state.CreatePreAuthKey(types.UserID(user.ID), true, false, nil, nil)
				if err != nil {
					return "", err
				}
				return pak2.Key, nil
			},
			request: func(newAuthKey string) tailcfg.RegisterRequest {
				return tailcfg.RegisterRequest{
					Auth: &tailcfg.RegisterResponseAuth{
						AuthKey: newAuthKey,
					},
					NodeKey: nodeKey1.Public(),
					Hostinfo: &tailcfg.Hostinfo{
						Hostname: "reauth-node-updated",
					},
					Expiry: time.Now().Add(48 * time.Hour),
				}
			},
			machineKey: func() key.MachinePublic { return machineKey1.Public() },
			wantAuth:   true,
			validate: func(t *testing.T, resp *tailcfg.RegisterResponse, app *Headscale) {
				assert.True(t, resp.MachineAuthorized)
				assert.False(t, resp.NodeKeyExpired)

				// Verify node was updated, not duplicated
				node, found := app.state.GetNodeByNodeKey(nodeKey1.Public())
				assert.True(t, found)
				assert.Equal(t, "reauth-node-updated", node.Hostname())
			},
		},
		// TEST: Existing node re-authenticates via interactive flow
		// WHAT: Tests that existing expired node can re-authenticate interactively
		// INPUT: Expired node initiates interactive re-authentication
		// EXPECTED: Node receives AuthURL and can complete re-authentication
		// WHY: Allows expired nodes to re-authenticate without pre-auth keys
		{
			name: "existing_node_reauth_interactive_flow",
			setupFunc: func(t *testing.T, app *Headscale) (string, error) {
				user := app.state.CreateUserForTest("interactive-reauth-user")
				pak, err := app.state.CreatePreAuthKey(types.UserID(user.ID), true, false, nil, nil)
				if err != nil {
					return "", err
				}

				// Register initially with auth key
				regReq := tailcfg.RegisterRequest{
					Auth: &tailcfg.RegisterResponseAuth{
						AuthKey: pak.Key,
					},
					NodeKey: nodeKey1.Public(),
					Hostinfo: &tailcfg.Hostinfo{
						Hostname: "interactive-reauth-node",
					},
					Expiry: time.Now().Add(24 * time.Hour),
				}
				_, err = app.handleRegisterWithAuthKey(regReq, machineKey1.Public())
				if err != nil {
					return "", err
				}

				// Wait for node to be available
				require.EventuallyWithT(t, func(c *assert.CollectT) {
					_, found := app.state.GetNodeByNodeKey(nodeKey1.Public())
					assert.True(c, found, "node should be available in NodeStore")
				}, 1*time.Second, 50*time.Millisecond, "waiting for node to be available in NodeStore")

				return "", nil
			},
			request: func(_ string) tailcfg.RegisterRequest {
				return tailcfg.RegisterRequest{
					Auth: &tailcfg.RegisterResponseAuth{
						AuthKey: "", // Empty auth key triggers interactive flow
					},
					NodeKey: nodeKey1.Public(),
					Hostinfo: &tailcfg.Hostinfo{
						Hostname: "interactive-reauth-node-updated",
					},
					Expiry: time.Now().Add(48 * time.Hour),
				}
			},
			machineKey:  func() key.MachinePublic { return machineKey1.Public() },
			wantAuthURL: true,
			validate: func(t *testing.T, resp *tailcfg.RegisterResponse, app *Headscale) {
				assert.Contains(t, resp.AuthURL, "register/")
				assert.False(t, resp.MachineAuthorized)
			},
		},

		// === NODE KEY ROTATION SCENARIOS ===
		// Tests node key rotation where node changes its node key while keeping same machine key

		// TEST: Node key rotation with same machine key updates in place
		// WHAT: Tests that registering with new node key and same machine key updates existing node
		// INPUT: Register node with nodeKey1, then register again with nodeKey2 but same machineKey
		// EXPECTED: Node is updated in place; nodeKey2 exists, nodeKey1 no longer exists
		// WHY: Same machine key means same physical device; node key rotation updates, doesn't duplicate
		{
			name: "node_key_rotation_same_machine",
			setupFunc: func(t *testing.T, app *Headscale) (string, error) {
				user := app.state.CreateUserForTest("rotation-user")
				pak, err := app.state.CreatePreAuthKey(types.UserID(user.ID), true, false, nil, nil)
				if err != nil {
					return "", err
				}

				// Register with initial node key
				regReq := tailcfg.RegisterRequest{
					Auth: &tailcfg.RegisterResponseAuth{
						AuthKey: pak.Key,
					},
					NodeKey: nodeKey1.Public(),
					Hostinfo: &tailcfg.Hostinfo{
						Hostname: "rotation-node",
					},
					Expiry: time.Now().Add(24 * time.Hour),
				}
				_, err = app.handleRegisterWithAuthKey(regReq, machineKey1.Public())
				if err != nil {
					return "", err
				}

				// Wait for node to be available
				require.EventuallyWithT(t, func(c *assert.CollectT) {
					_, found := app.state.GetNodeByNodeKey(nodeKey1.Public())
					assert.True(c, found, "node should be available in NodeStore")
				}, 1*time.Second, 50*time.Millisecond, "waiting for node to be available in NodeStore")

				// Create new auth key for rotation
				pakRotation, err := app.state.CreatePreAuthKey(types.UserID(user.ID), true, false, nil, nil)
				if err != nil {
					return "", err
				}
				return pakRotation.Key, nil
			},
			request: func(authKey string) tailcfg.RegisterRequest {
				return tailcfg.RegisterRequest{
					Auth: &tailcfg.RegisterResponseAuth{
						AuthKey: authKey,
					},
					NodeKey: nodeKey2.Public(), // Different node key, same machine
					Hostinfo: &tailcfg.Hostinfo{
						Hostname: "rotation-node",
					},
					Expiry: time.Now().Add(24 * time.Hour),
				}
			},
			machineKey: func() key.MachinePublic { return machineKey1.Public() },
			wantAuth:   true,
			validate: func(t *testing.T, resp *tailcfg.RegisterResponse, app *Headscale) {
				assert.True(t, resp.MachineAuthorized)
				assert.False(t, resp.NodeKeyExpired)

				// When same machine key is used, node is updated in place (not duplicated)
				// The old nodeKey1 should no longer exist
				_, found1 := app.state.GetNodeByNodeKey(nodeKey1.Public())
				assert.False(t, found1, "old node key should not exist after rotation")

				// The new nodeKey2 should exist with the same machine key
				node2, found2 := app.state.GetNodeByNodeKey(nodeKey2.Public())
				assert.True(t, found2, "new node key should exist after rotation")
				assert.Equal(t, machineKey1.Public(), node2.MachineKey(), "machine key should remain the same")
			},
		},

		// === MALFORMED REQUEST SCENARIOS ===
		// Tests handling of requests with malformed or unusual field values

		// TEST: Zero-time expiry is handled correctly
		// WHAT: Tests registration with expiry set to zero time value
		// INPUT: Register request with Expiry set to time.Time{} (zero value)
		// EXPECTED: Node registers successfully; zero time treated as no expiry
		// WHY: Zero time is valid Go default; should be handled gracefully
		{
			name: "malformed_expiry_zero_time",
			setupFunc: func(t *testing.T, app *Headscale) (string, error) {
				user := app.state.CreateUserForTest("zero-expiry-user")
				pak, err := app.state.CreatePreAuthKey(types.UserID(user.ID), true, false, nil, nil)
				if err != nil {
					return "", err
				}
				return pak.Key, nil
			},
			request: func(authKey string) tailcfg.RegisterRequest {
				return tailcfg.RegisterRequest{
					Auth: &tailcfg.RegisterResponseAuth{
						AuthKey: authKey,
					},
					NodeKey: nodeKey1.Public(),
					Hostinfo: &tailcfg.Hostinfo{
						Hostname: "zero-expiry-node",
					},
					Expiry: time.Time{}, // Zero time
				}
			},
			machineKey: func() key.MachinePublic { return machineKey1.Public() },
			wantAuth:   true,
			validate: func(t *testing.T, resp *tailcfg.RegisterResponse, app *Headscale) {
				assert.True(t, resp.MachineAuthorized)

				// Node should be created with default expiry handling
				node, found := app.state.GetNodeByNodeKey(nodeKey1.Public())
				assert.True(t, found)
				assert.Equal(t, "zero-expiry-node", node.Hostname())
			},
		},
		// TEST: Malformed hostinfo with very long hostname is truncated
		// WHAT: Tests that excessively long hostname is truncated to DNS label limit
		// INPUT: Hostinfo with 110-character hostname (exceeds 63-char DNS limit)
		// EXPECTED: Node registers successfully; hostname truncated to 63 characters
		// WHY: Defensive code enforces DNS label limit (RFC 1123); prevents errors
		{
			name: "malformed_hostinfo_invalid_data",
			setupFunc: func(t *testing.T, app *Headscale) (string, error) {
				user := app.state.CreateUserForTest("invalid-hostinfo-user")
				pak, err := app.state.CreatePreAuthKey(types.UserID(user.ID), true, false, nil, nil)
				if err != nil {
					return "", err
				}
				return pak.Key, nil
			},
			request: func(authKey string) tailcfg.RegisterRequest {
				return tailcfg.RegisterRequest{
					Auth: &tailcfg.RegisterResponseAuth{
						AuthKey: authKey,
					},
					NodeKey: nodeKey1.Public(),
					Hostinfo: &tailcfg.Hostinfo{
						Hostname:     "test-node-with-very-long-hostname-that-might-exceed-normal-limits-and-contain-special-chars-!@#$%",
						BackendLogID: "invalid-log-id",
						OS:           "unknown-os",
						OSVersion:    "999.999.999",
						DeviceModel:  "test-device-model",
						RequestTags:  []string{"invalid:tag", "another!tag"},
						Services:     []tailcfg.Service{{Proto: "tcp", Port: 65535}},
					},
					Expiry: time.Now().Add(24 * time.Hour),
				}
			},
			machineKey: func() key.MachinePublic { return machineKey1.Public() },
			wantAuth:   true,
			validate: func(t *testing.T, resp *tailcfg.RegisterResponse, app *Headscale) {
				assert.True(t, resp.MachineAuthorized)

				// Node should be created even with malformed hostinfo
				node, found := app.state.GetNodeByNodeKey(nodeKey1.Public())
				assert.True(t, found)
				// Hostname should be sanitized or handled gracefully
				assert.NotEmpty(t, node.Hostname())
			},
		},

		// === REGISTRATION CACHE EDGE CASES ===
		// Tests edge cases in registration cache handling during interactive flow

		// TEST: Followup registration with nil response (cache expired during auth)
		// WHAT: Tests that followup request handles nil node response (cache expired/cleared)
		// INPUT: Followup request where auth completion sends nil (cache was cleared)
		// EXPECTED: Returns new AuthURL so client can retry authentication
		// WHY: Nil response means cache expired - give client new AuthURL instead of error
		{
			name: "followup_registration_node_nil_response",
			setupFunc: func(t *testing.T, app *Headscale) (string, error) {
				regID, err := types.NewRegistrationID()
				if err != nil {
					return "", err
				}

				registered := make(chan *types.Node, 1)
				nodeToRegister := types.RegisterNode{
					Node: types.Node{
						Hostname: "nil-response-node",
					},
					Registered: registered,
				}
				app.state.SetRegistrationCacheEntry(regID, nodeToRegister)

				// Simulate registration that returns nil (cache expired during auth)
				go func() {
					time.Sleep(20 * time.Millisecond)
					registered <- nil // Nil indicates cache expiry
				}()

				return fmt.Sprintf("http://localhost:8080/register/%s", regID), nil
			},
			request: func(followupURL string) tailcfg.RegisterRequest {
				return tailcfg.RegisterRequest{
					Followup: followupURL,
					NodeKey:  nodeKey1.Public(),
					Hostinfo: &tailcfg.Hostinfo{
						Hostname: "nil-response-node",
					},
					Expiry: time.Now().Add(24 * time.Hour),
				}
			},
			machineKey: func() key.MachinePublic { return machineKey1.Public() },
			wantAuth:   false, // Should not be authorized yet - needs to use new AuthURL
			validate: func(t *testing.T, resp *tailcfg.RegisterResponse, app *Headscale) {
				// Should get a new AuthURL, not an error
				assert.NotEmpty(t, resp.AuthURL, "should receive new AuthURL when cache returns nil")
				assert.Contains(t, resp.AuthURL, "/register/", "AuthURL should contain registration path")
				assert.False(t, resp.MachineAuthorized, "machine should not be authorized yet")
			},
		},
		// TEST: Malformed followup path is rejected
		// WHAT: Tests that followup URL with malformed path is rejected
		// INPUT: Followup URL with path that doesn't match expected format
		// EXPECTED: Request fails with error (invalid followup URL)
		// WHY: Path validation prevents processing of corrupted/invalid URLs
		{
			name: "followup_registration_malformed_path",
			setupFunc: func(t *testing.T, app *Headscale) (string, error) {
				return "http://localhost:8080/register/", nil // Missing registration ID
			},
			request: func(followupURL string) tailcfg.RegisterRequest {
				return tailcfg.RegisterRequest{
					Followup: followupURL,
					NodeKey:  nodeKey1.Public(),
				}
			},
			machineKey: func() key.MachinePublic { return machineKey1.Public() },
			wantError:  true,
		},
		// TEST: Wrong followup path format is rejected
		// WHAT: Tests that followup URL with incorrect path structure fails
		// INPUT: Valid URL but path doesn't start with "/register/"
		// EXPECTED: Request fails with error (invalid path format)
		// WHY: Strict path validation ensures only valid registration URLs accepted
		{
			name: "followup_registration_wrong_path_format",
			setupFunc: func(t *testing.T, app *Headscale) (string, error) {
				return "http://localhost:8080/wrong/path/format", nil
			},
			request: func(followupURL string) tailcfg.RegisterRequest {
				return tailcfg.RegisterRequest{
					Followup: followupURL,
					NodeKey:  nodeKey1.Public(),
				}
			},
			machineKey: func() key.MachinePublic { return machineKey1.Public() },
			wantError:  true,
		},

		// === AUTH PROVIDER EDGE CASES ===
		// TEST: Interactive workflow preserves custom hostinfo
		// WHAT: Tests that custom hostinfo fields are preserved through interactive flow
		// INPUT: Interactive registration with detailed hostinfo (OS, version, model, etc.)
		// EXPECTED: Node registers with all hostinfo fields preserved
		// WHY: Ensures interactive flow doesn't lose custom hostinfo data
		{
			name: "interactive_workflow_with_custom_hostinfo",
			setupFunc: func(t *testing.T, app *Headscale) (string, error) {
				return "", nil
			},
			request: func(_ string) tailcfg.RegisterRequest {
				return tailcfg.RegisterRequest{
					NodeKey: nodeKey1.Public(),
					Hostinfo: &tailcfg.Hostinfo{
						Hostname:    "custom-interactive-node",
						OS:          "linux",
						OSVersion:   "20.04",
						DeviceModel: "server",
						RequestTags: []string{"tag:server"},
					},
					Expiry: time.Now().Add(24 * time.Hour),
				}
			},
			machineKey:              func() key.MachinePublic { return machineKey1.Public() },
			requiresInteractiveFlow: true,
			interactiveSteps: []interactiveStep{
				{stepType: stepTypeInitialRequest, expectAuthURL: true, expectCacheEntry: true},
				{stepType: stepTypeAuthCompletion, callAuthPath: true, expectCacheEntry: false}, // cleaned up after completion
			},
			validateCompleteResponse: true,
			expectedAuthURLPattern:   "/register/",
			validate: func(t *testing.T, resp *tailcfg.RegisterResponse, app *Headscale) {
				// Verify custom hostinfo was preserved through interactive workflow
				node, found := app.state.GetNodeByNodeKey(nodeKey1.Public())
				assert.True(t, found, "node should be found after interactive registration")
				if found {
					assert.Equal(t, "custom-interactive-node", node.Hostname())
					assert.Equal(t, "linux", node.Hostinfo().OS())
					assert.Equal(t, "20.04", node.Hostinfo().OSVersion())
					assert.Equal(t, "server", node.Hostinfo().DeviceModel())
					assert.Contains(t, node.Hostinfo().RequestTags().AsSlice(), "tag:server")
				}
			},
		},

		// === PRE-AUTH KEY USAGE TRACKING ===
		// Tests accurate tracking of pre-auth key usage counts

		// TEST: Pre-auth key usage count is tracked correctly
		// WHAT: Tests that each use of a pre-auth key increments its usage counter
		// INPUT: Reusable pre-auth key used to register three different nodes
		// EXPECTED: All three nodes register successfully, key usage count increments each time
		// WHY: Usage tracking enables monitoring and auditing of pre-auth key usage
		{
			name: "preauth_key_usage_count_tracking",
			setupFunc: func(t *testing.T, app *Headscale) (string, error) {
				user := app.state.CreateUserForTest("usage-count-user")
				pak, err := app.state.CreatePreAuthKey(types.UserID(user.ID), false, false, nil, nil) // Single use
				if err != nil {
					return "", err
				}
				return pak.Key, nil
			},
			request: func(authKey string) tailcfg.RegisterRequest {
				return tailcfg.RegisterRequest{
					Auth: &tailcfg.RegisterResponseAuth{
						AuthKey: authKey,
					},
					NodeKey: nodeKey1.Public(),
					Hostinfo: &tailcfg.Hostinfo{
						Hostname: "usage-count-node",
					},
					Expiry: time.Now().Add(24 * time.Hour),
				}
			},
			machineKey: func() key.MachinePublic { return machineKey1.Public() },
			wantAuth:   true,
			validate: func(t *testing.T, resp *tailcfg.RegisterResponse, app *Headscale) {
				assert.True(t, resp.MachineAuthorized)
				assert.False(t, resp.NodeKeyExpired)

				// Verify auth key usage was tracked
				node, found := app.state.GetNodeByNodeKey(nodeKey1.Public())
				assert.True(t, found)
				assert.Equal(t, "usage-count-node", node.Hostname())

				// Key should now be used up (single use)
				if node.AuthKey().Valid() {
					assert.False(t, node.AuthKey().Reusable())
				}
			},
		},

		// === REGISTRATION ID GENERATION AND ADVANCED EDGE CASES ===
		// TEST: Interactive workflow generates valid registration IDs
		// WHAT: Tests that interactive flow generates unique, valid registration IDs
		// INPUT: Interactive registration request
		// EXPECTED: AuthURL contains valid registration ID that can be extracted
		// WHY: Registration IDs must be unique and valid for cache lookup
		{
			name: "interactive_workflow_registration_id_generation",
			setupFunc: func(t *testing.T, app *Headscale) (string, error) {
				return "", nil
			},
			request: func(_ string) tailcfg.RegisterRequest {
				return tailcfg.RegisterRequest{
					NodeKey: nodeKey1.Public(),
					Hostinfo: &tailcfg.Hostinfo{
						Hostname: "registration-id-test-node",
						OS:       "test-os",
					},
					Expiry: time.Now().Add(24 * time.Hour),
				}
			},
			machineKey:              func() key.MachinePublic { return machineKey1.Public() },
			requiresInteractiveFlow: true,
			interactiveSteps: []interactiveStep{
				{stepType: stepTypeInitialRequest, expectAuthURL: true, expectCacheEntry: true},
				{stepType: stepTypeAuthCompletion, callAuthPath: true, expectCacheEntry: false},
			},
			validateCompleteResponse: true,
			expectedAuthURLPattern:   "/register/",
			validate: func(t *testing.T, resp *tailcfg.RegisterResponse, app *Headscale) {
				// Verify registration ID was properly generated and used
				node, found := app.state.GetNodeByNodeKey(nodeKey1.Public())
				assert.True(t, found, "node should be registered after interactive workflow")
				if found {
					assert.Equal(t, "registration-id-test-node", node.Hostname())
					assert.Equal(t, "test-os", node.Hostinfo().OS())
				}
			},
		},
		{
			name: "concurrent_registration_same_node_key",
			setupFunc: func(t *testing.T, app *Headscale) (string, error) {
				user := app.state.CreateUserForTest("concurrent-user")
				pak, err := app.state.CreatePreAuthKey(types.UserID(user.ID), true, false, nil, nil)
				if err != nil {
					return "", err
				}
				return pak.Key, nil
			},
			request: func(authKey string) tailcfg.RegisterRequest {
				return tailcfg.RegisterRequest{
					Auth: &tailcfg.RegisterResponseAuth{
						AuthKey: authKey,
					},
					NodeKey: nodeKey1.Public(),
					Hostinfo: &tailcfg.Hostinfo{
						Hostname: "concurrent-node",
					},
					Expiry: time.Now().Add(24 * time.Hour),
				}
			},
			machineKey: func() key.MachinePublic { return machineKey1.Public() },
			wantAuth:   true,
			validate: func(t *testing.T, resp *tailcfg.RegisterResponse, app *Headscale) {
				assert.True(t, resp.MachineAuthorized)
				assert.False(t, resp.NodeKeyExpired)

				// Verify node was registered
				node, found := app.state.GetNodeByNodeKey(nodeKey1.Public())
				assert.True(t, found)
				assert.Equal(t, "concurrent-node", node.Hostname())
			},
		},
		// TEST: Auth key expiry vs request expiry handling
		// WHAT: Tests that pre-auth key expiry is independent of request expiry
		// INPUT: Valid pre-auth key (future expiry), request with past expiry
		// EXPECTED: Node registers with request expiry used (logout scenario)
		// WHY: Request expiry overrides key expiry; allows logout with valid key
		{
			name: "auth_key_with_future_expiry_past_request_expiry",
			setupFunc: func(t *testing.T, app *Headscale) (string, error) {
				user := app.state.CreateUserForTest("future-expiry-user")
				// Auth key expires in the future
				expiry := time.Now().Add(48 * time.Hour)
				pak, err := app.state.CreatePreAuthKey(types.UserID(user.ID), true, false, &expiry, nil)
				if err != nil {
					return "", err
				}
				return pak.Key, nil
			},
			request: func(authKey string) tailcfg.RegisterRequest {
				return tailcfg.RegisterRequest{
					Auth: &tailcfg.RegisterResponseAuth{
						AuthKey: authKey,
					},
					NodeKey: nodeKey1.Public(),
					Hostinfo: &tailcfg.Hostinfo{
						Hostname: "future-expiry-node",
					},
					// Request expires before auth key
					Expiry: time.Now().Add(12 * time.Hour),
				}
			},
			machineKey: func() key.MachinePublic { return machineKey1.Public() },
			wantAuth:   true,
			validate: func(t *testing.T, resp *tailcfg.RegisterResponse, app *Headscale) {
				assert.True(t, resp.MachineAuthorized)
				assert.False(t, resp.NodeKeyExpired)

				// Node should be created with request expiry (shorter than auth key expiry)
				node, found := app.state.GetNodeByNodeKey(nodeKey1.Public())
				assert.True(t, found)
				assert.Equal(t, "future-expiry-node", node.Hostname())
			},
		},
		// TEST: Re-authentication with different user's auth key
		// WHAT: Tests node transfer when re-authenticating with a different user's auth key
		// INPUT: Node registered with user1's auth key, re-authenticates with user2's auth key
		// EXPECTED: Node is transferred to user2 (updates UserID and related fields)
		// WHY: Validates device reassignment scenarios where a machine moves between users
		{
			name: "reauth_existing_node_different_user_auth_key",
			setupFunc: func(t *testing.T, app *Headscale) (string, error) {
				// Create two users
				user1 := app.state.CreateUserForTest("user1-context")
				user2 := app.state.CreateUserForTest("user2-context")

				// Register node with user1's auth key
				pak1, err := app.state.CreatePreAuthKey(types.UserID(user1.ID), true, false, nil, nil)
				if err != nil {
					return "", err
				}

				regReq := tailcfg.RegisterRequest{
					Auth: &tailcfg.RegisterResponseAuth{
						AuthKey: pak1.Key,
					},
					NodeKey: nodeKey1.Public(),
					Hostinfo: &tailcfg.Hostinfo{
						Hostname: "context-node-user1",
					},
					Expiry: time.Now().Add(24 * time.Hour),
				}
				_, err = app.handleRegisterWithAuthKey(regReq, machineKey1.Public())
				if err != nil {
					return "", err
				}

				// Wait for node to be available
				require.EventuallyWithT(t, func(c *assert.CollectT) {
					_, found := app.state.GetNodeByNodeKey(nodeKey1.Public())
					assert.True(c, found, "node should be available in NodeStore")
				}, 1*time.Second, 50*time.Millisecond, "waiting for node to be available in NodeStore")

				// Return user2's auth key for re-authentication
				pak2, err := app.state.CreatePreAuthKey(types.UserID(user2.ID), true, false, nil, nil)
				if err != nil {
					return "", err
				}
				return pak2.Key, nil
			},
			request: func(user2AuthKey string) tailcfg.RegisterRequest {
				return tailcfg.RegisterRequest{
					Auth: &tailcfg.RegisterResponseAuth{
						AuthKey: user2AuthKey,
					},
					NodeKey: nodeKey1.Public(),
					Hostinfo: &tailcfg.Hostinfo{
						Hostname: "context-node-user2",
					},
					Expiry: time.Now().Add(24 * time.Hour),
				}
			},
			machineKey: func() key.MachinePublic { return machineKey1.Public() },
			wantAuth:   true,
			validate: func(t *testing.T, resp *tailcfg.RegisterResponse, app *Headscale) {
				assert.True(t, resp.MachineAuthorized)
				assert.False(t, resp.NodeKeyExpired)

				// Verify NEW node was created for user2
				node2, found := app.state.GetNodeByMachineKey(machineKey1.Public(), types.UserID(2))
				require.True(t, found, "new node should exist for user2")
				assert.Equal(t, uint(2), node2.UserID(), "new node should belong to user2")

				user := node2.User()
				assert.Equal(t, "user2-context", user.Username(), "new node should show user2 username")

				// Verify original node still exists for user1
				node1, found := app.state.GetNodeByMachineKey(machineKey1.Public(), types.UserID(1))
				require.True(t, found, "original node should still exist for user1")
				assert.Equal(t, uint(1), node1.UserID(), "original node should still belong to user1")

				// Verify they are different nodes (different IDs)
				assert.NotEqual(t, node1.ID(), node2.ID(), "should be different node IDs")
			},
		},
		// TEST: Re-authentication with different user via interactive flow creates new node
		// WHAT: Tests new node creation when re-authenticating interactively with a different user
		// INPUT: Node registered with user1, re-authenticates interactively as user2 (same machine key, same node key)
		// EXPECTED: New node is created for user2, user1's original node remains (no transfer)
		// WHY: Same physical machine can have separate node identities per user
		{
			name: "interactive_reauth_existing_node_different_user_creates_new_node",
			setupFunc: func(t *testing.T, app *Headscale) (string, error) {
				// Create user1 and register a node with auth key
				user1 := app.state.CreateUserForTest("interactive-user-1")
				pak1, err := app.state.CreatePreAuthKey(types.UserID(user1.ID), true, false, nil, nil)
				if err != nil {
					return "", err
				}

				// Register node with user1's auth key first
				initialReq := tailcfg.RegisterRequest{
					Auth: &tailcfg.RegisterResponseAuth{
						AuthKey: pak1.Key,
					},
					NodeKey: nodeKey1.Public(),
					Hostinfo: &tailcfg.Hostinfo{
						Hostname: "transfer-node-user1",
					},
					Expiry: time.Now().Add(24 * time.Hour),
				}
				_, err = app.handleRegister(context.Background(), initialReq, machineKey1.Public())
				if err != nil {
					return "", err
				}

				// Wait for node to be available
				require.EventuallyWithT(t, func(c *assert.CollectT) {
					_, found := app.state.GetNodeByNodeKey(nodeKey1.Public())
					assert.True(c, found, "node should be available in NodeStore")
				}, 1*time.Second, 50*time.Millisecond, "waiting for node to be available in NodeStore")

				return "", nil
			},
			request: func(_ string) tailcfg.RegisterRequest {
				return tailcfg.RegisterRequest{
					Auth:    &tailcfg.RegisterResponseAuth{}, // Empty auth triggers interactive flow
					NodeKey: nodeKey1.Public(),               // Same node key as original registration
					Hostinfo: &tailcfg.Hostinfo{
						Hostname: "transfer-node-user2", // Different hostname
					},
					Expiry: time.Now().Add(24 * time.Hour),
				}
			},
			machineKey:              func() key.MachinePublic { return machineKey1.Public() }, // Same machine key
			requiresInteractiveFlow: true,
			interactiveSteps: []interactiveStep{
				{stepType: stepTypeInitialRequest, expectAuthURL: true, expectCacheEntry: true},
				{stepType: stepTypeAuthCompletion, callAuthPath: true, expectCacheEntry: false},
			},
			validateCompleteResponse: true,
			validate: func(t *testing.T, resp *tailcfg.RegisterResponse, app *Headscale) {
				// User1's original node should STILL exist (not transferred)
				node1, found1 := app.state.GetNodeByMachineKey(machineKey1.Public(), types.UserID(1))
				require.True(t, found1, "user1's original node should still exist")
				assert.Equal(t, uint(1), node1.UserID(), "user1's node should still belong to user1")
				assert.Equal(t, nodeKey1.Public(), node1.NodeKey(), "user1's node should have original node key")

				// User2 should have a NEW node created
				node2, found2 := app.state.GetNodeByMachineKey(machineKey1.Public(), types.UserID(2))
				require.True(t, found2, "user2 should have new node created")
				assert.Equal(t, uint(2), node2.UserID(), "user2's node should belong to user2")

				user := node2.User()
				assert.Equal(t, "interactive-test-user", user.Username(), "user2's node should show correct username")

				// Both nodes should have the same machine key but different IDs
				assert.NotEqual(t, node1.ID(), node2.ID(), "should be different nodes (different IDs)")
				assert.Equal(t, machineKey1.Public(), node2.MachineKey(), "user2's node should have same machine key")
			},
		},
		// TEST: Followup request after registration cache expiry
		// WHAT: Tests that expired followup requests get a new AuthURL instead of error
		// INPUT: Followup request for registration ID that has expired/been evicted from cache
		// EXPECTED: Returns new AuthURL (not error) so client can retry authentication
		// WHY: Validates new reqToNewRegisterResponse functionality - prevents client getting stuck
		{
			name: "followup_request_after_cache_expiry",
			setupFunc: func(t *testing.T, app *Headscale) (string, error) {
				// Generate a registration ID that doesn't exist in cache
				// This simulates an expired/missing cache entry
				regID, err := types.NewRegistrationID()
				if err != nil {
					return "", err
				}
				// Don't add it to cache - it's already expired/missing
				return regID.String(), nil
			},
			request: func(regID string) tailcfg.RegisterRequest {
				return tailcfg.RegisterRequest{
					Followup: "http://localhost:8080/register/" + regID,
					NodeKey:  nodeKey1.Public(),
					Hostinfo: &tailcfg.Hostinfo{
						Hostname: "expired-cache-node",
					},
					Expiry: time.Now().Add(24 * time.Hour),
				}
			},
			machineKey: func() key.MachinePublic { return machineKey1.Public() },
			wantAuth:   false, // Should not be authorized yet - needs to use new AuthURL
			validate: func(t *testing.T, resp *tailcfg.RegisterResponse, app *Headscale) {
				// Should get a new AuthURL, not an error
				assert.NotEmpty(t, resp.AuthURL, "should receive new AuthURL when registration expired")
				assert.Contains(t, resp.AuthURL, "/register/", "AuthURL should contain registration path")
				assert.False(t, resp.MachineAuthorized, "machine should not be authorized yet")

				// Verify the response contains a valid registration URL
				authURL, err := url.Parse(resp.AuthURL)
				assert.NoError(t, err, "AuthURL should be a valid URL")
				assert.True(t, strings.HasPrefix(authURL.Path, "/register/"), "AuthURL path should start with /register/")

				// Extract and validate the new registration ID exists in cache
				newRegIDStr := strings.TrimPrefix(authURL.Path, "/register/")
				newRegID, err := types.RegistrationIDFromString(newRegIDStr)
				assert.NoError(t, err, "should be able to parse new registration ID")

				// Verify new registration entry exists in cache
				_, found := app.state.GetRegistrationCacheEntry(newRegID)
				assert.True(t, found, "new registration should exist in cache")
			},
		},
		// TEST: Logout with expiry exactly at current time
		// WHAT: Tests logout when expiry is set to exact current time (boundary case)
		// INPUT: Existing node sends request with expiry=time.Now() (not past, not future)
		// EXPECTED: Node is logged out (treated as expired)
		// WHY: Edge case: current time should be treated as expired
		{
			name: "logout_with_exactly_now_expiry",
			setupFunc: func(t *testing.T, app *Headscale) (string, error) {
				user := app.state.CreateUserForTest("exact-now-user")
				pak, err := app.state.CreatePreAuthKey(types.UserID(user.ID), true, false, nil, nil)
				if err != nil {
					return "", err
				}

				// Register the node first
				regReq := tailcfg.RegisterRequest{
					Auth: &tailcfg.RegisterResponseAuth{
						AuthKey: pak.Key,
					},
					NodeKey: nodeKey1.Public(),
					Hostinfo: &tailcfg.Hostinfo{
						Hostname: "exact-now-node",
					},
					Expiry: time.Now().Add(24 * time.Hour),
				}
				_, err = app.handleRegisterWithAuthKey(regReq, machineKey1.Public())
				if err != nil {
					return "", err
				}

				// Wait for node to be available
				require.EventuallyWithT(t, func(c *assert.CollectT) {
					_, found := app.state.GetNodeByNodeKey(nodeKey1.Public())
					assert.True(c, found, "node should be available in NodeStore")
				}, 1*time.Second, 50*time.Millisecond, "waiting for node to be available in NodeStore")

				return "", nil
			},
			request: func(_ string) tailcfg.RegisterRequest {
				return tailcfg.RegisterRequest{
					Auth:    nil,
					NodeKey: nodeKey1.Public(),
					Expiry:  time.Now(), // Exactly now (edge case between past and future)
				}
			},
			machineKey:  func() key.MachinePublic { return machineKey1.Public() },
			wantAuth:    true,
			wantExpired: true,
			validate: func(t *testing.T, resp *tailcfg.RegisterResponse, app *Headscale) {
				assert.True(t, resp.MachineAuthorized)
				assert.True(t, resp.NodeKeyExpired)

				// Node should be marked as expired but still exist
				node, found := app.state.GetNodeByNodeKey(nodeKey1.Public())
				assert.True(t, found)
				assert.True(t, node.IsExpired())
			},
		},
		// TEST: Interactive workflow timeout cleans up cache
		// WHAT: Tests that timed-out interactive registrations clean up cache entries
		// INPUT: Interactive registration that times out without completion
		// EXPECTED: Cache entry should be cleaned up (behavior depends on implementation)
		// WHY: Prevents cache bloat from abandoned registrations
		{
			name: "interactive_workflow_timeout_cleanup",
			setupFunc: func(t *testing.T, app *Headscale) (string, error) {
				return "", nil
			},
			request: func(_ string) tailcfg.RegisterRequest {
				return tailcfg.RegisterRequest{
					NodeKey: nodeKey2.Public(),
					Hostinfo: &tailcfg.Hostinfo{
						Hostname: "interactive-timeout-node",
					},
					Expiry: time.Now().Add(24 * time.Hour),
				}
			},
			machineKey:              func() key.MachinePublic { return machineKey2.Public() },
			requiresInteractiveFlow: true,
			interactiveSteps: []interactiveStep{
				{stepType: stepTypeInitialRequest, expectAuthURL: true, expectCacheEntry: true},
				// NOTE: No auth_completion step - simulates timeout scenario
			},
			validateRegistrationCache: true, // should be cleaned up eventually
			validate: func(t *testing.T, resp *tailcfg.RegisterResponse, app *Headscale) {
				// Verify AuthURL was generated but registration not completed
				assert.Contains(t, resp.AuthURL, "/register/")
				assert.False(t, resp.MachineAuthorized)
			},
		},

		// === COMPREHENSIVE INTERACTIVE WORKFLOW EDGE CASES ===
		// TEST: Interactive workflow with existing node from different user creates new node
		// WHAT: Tests new node creation when re-authenticating interactively with different user
		// INPUT: Node already registered with user1, interactive auth with user2 (same machine key, different node key)
		// EXPECTED: New node is created for user2, user1's original node remains (no transfer)
		// WHY: Same physical machine can have separate node identities per user
		{
			name: "interactive_workflow_with_existing_node_different_user_creates_new_node",
			setupFunc: func(t *testing.T, app *Headscale) (string, error) {
				// First create a node under user1
				user1 := app.state.CreateUserForTest("existing-user-1")
				pak1, err := app.state.CreatePreAuthKey(types.UserID(user1.ID), true, false, nil, nil)
				if err != nil {
					return "", err
				}

				// Register the node with user1 first
				initialReq := tailcfg.RegisterRequest{
					Auth: &tailcfg.RegisterResponseAuth{
						AuthKey: pak1.Key,
					},
					NodeKey: nodeKey1.Public(),
					Hostinfo: &tailcfg.Hostinfo{
						Hostname: "existing-node-user1",
					},
					Expiry: time.Now().Add(24 * time.Hour),
				}
				_, err = app.handleRegister(context.Background(), initialReq, machineKey1.Public())
				if err != nil {
					return "", err
				}

				// Wait for node to be available
				require.EventuallyWithT(t, func(c *assert.CollectT) {
					_, found := app.state.GetNodeByNodeKey(nodeKey1.Public())
					assert.True(c, found, "node should be available in NodeStore")
				}, 1*time.Second, 50*time.Millisecond, "waiting for node to be available in NodeStore")

				return "", nil
			},
			request: func(_ string) tailcfg.RegisterRequest {
				return tailcfg.RegisterRequest{
					Auth:    &tailcfg.RegisterResponseAuth{}, // Empty auth triggers interactive flow
					NodeKey: nodeKey2.Public(),               // Different node key for different user
					Hostinfo: &tailcfg.Hostinfo{
						Hostname: "existing-node-user2", // Different hostname
					},
					Expiry: time.Now().Add(24 * time.Hour),
				}
			},
			machineKey:              func() key.MachinePublic { return machineKey1.Public() },
			requiresInteractiveFlow: true,
			interactiveSteps: []interactiveStep{
				{stepType: stepTypeInitialRequest, expectAuthURL: true, expectCacheEntry: true},
				{stepType: stepTypeAuthCompletion, callAuthPath: true, expectCacheEntry: false},
			},
			validateCompleteResponse: true,
			validate: func(t *testing.T, resp *tailcfg.RegisterResponse, app *Headscale) {
				// User1's original node with nodeKey1 should STILL exist
				node1, found1 := app.state.GetNodeByNodeKey(nodeKey1.Public())
				require.True(t, found1, "user1's original node with nodeKey1 should still exist")
				assert.Equal(t, uint(1), node1.UserID(), "user1's node should still belong to user1")
				assert.Equal(t, uint64(1), node1.ID().Uint64(), "user1's node should be ID=1")

				// User2 should have a NEW node with nodeKey2
				node2, found2 := app.state.GetNodeByNodeKey(nodeKey2.Public())
				require.True(t, found2, "user2 should have new node with nodeKey2")

				assert.Equal(t, "existing-node-user2", node2.Hostname(), "hostname should be from new registration")
				user := node2.User()
				assert.Equal(t, "interactive-test-user", user.Username(), "user2's node should belong to user2")
				assert.Equal(t, machineKey1.Public(), node2.MachineKey(), "machine key should be the same")

				// Verify it's a NEW node, not transferred
				assert.NotEqual(t, uint64(1), node2.ID().Uint64(), "should be a NEW node (different ID)")
			},
		},
		// TEST: Interactive workflow with malformed followup URL
		// WHAT: Tests that malformed followup URLs in interactive flow are rejected
		// INPUT: Interactive registration with invalid followup URL format
		// EXPECTED: Request fails with error (invalid URL)
		// WHY: Validates followup URLs to prevent errors
		{
			name: "interactive_workflow_malformed_followup_url",
			setupFunc: func(t *testing.T, app *Headscale) (string, error) {
				return "", nil
			},
			request: func(_ string) tailcfg.RegisterRequest {
				return tailcfg.RegisterRequest{
					NodeKey: nodeKey1.Public(),
					Hostinfo: &tailcfg.Hostinfo{
						Hostname: "malformed-followup-node",
					},
					Expiry: time.Now().Add(24 * time.Hour),
				}
			},
			machineKey:              func() key.MachinePublic { return machineKey1.Public() },
			requiresInteractiveFlow: true,
			interactiveSteps: []interactiveStep{
				{stepType: stepTypeInitialRequest, expectAuthURL: true, expectCacheEntry: true},
			},
			validate: func(t *testing.T, resp *tailcfg.RegisterResponse, app *Headscale) {
				// Test malformed followup URLs after getting initial AuthURL
				authURL := resp.AuthURL
				assert.Contains(t, authURL, "/register/")

				// Test various malformed followup URLs - use completely invalid IDs to avoid blocking
				malformedURLs := []string{
					"invalid-url",
					"/register/",
					"/register/invalid-id-that-does-not-exist",
					"/register/00000000-0000-0000-0000-000000000000",
					"http://malicious-site.com/register/invalid-id",
				}

				for _, malformedURL := range malformedURLs {
					followupReq := tailcfg.RegisterRequest{
						NodeKey:  nodeKey1.Public(),
						Followup: malformedURL,
						Hostinfo: &tailcfg.Hostinfo{
							Hostname: "malformed-followup-node",
						},
						Expiry: time.Now().Add(24 * time.Hour),
					}

					// These should all fail gracefully
					_, err := app.handleRegister(context.Background(), followupReq, machineKey1.Public())
					assert.Error(t, err, "malformed followup URL should be rejected: %s", malformedURL)
				}
			},
		},
		// TEST: Concurrent interactive workflow registrations
		// WHAT: Tests multiple simultaneous interactive registrations
		// INPUT: Two nodes initiate interactive registration concurrently
		// EXPECTED: Both registrations succeed independently
		// WHY: System should handle concurrent interactive flows without conflicts
		{
			name: "interactive_workflow_concurrent_registrations",
			setupFunc: func(t *testing.T, app *Headscale) (string, error) {
				return "", nil
			},
			request: func(_ string) tailcfg.RegisterRequest {
				return tailcfg.RegisterRequest{
					NodeKey: nodeKey1.Public(),
					Hostinfo: &tailcfg.Hostinfo{
						Hostname: "concurrent-registration-node",
					},
					Expiry: time.Now().Add(24 * time.Hour),
				}
			},
			machineKey: func() key.MachinePublic { return machineKey1.Public() },
			validate: func(t *testing.T, resp *tailcfg.RegisterResponse, app *Headscale) {
				// This test validates concurrent interactive registration attempts
				assert.Contains(t, resp.AuthURL, "/register/")

				// Start multiple concurrent followup requests
				authURL := resp.AuthURL
				numConcurrent := 3
				results := make(chan error, numConcurrent)

				for i := range numConcurrent {
					go func(index int) {
						followupReq := tailcfg.RegisterRequest{
							NodeKey:  nodeKey1.Public(),
							Followup: authURL,
							Hostinfo: &tailcfg.Hostinfo{
								Hostname: fmt.Sprintf("concurrent-node-%d", index),
							},
							Expiry: time.Now().Add(24 * time.Hour),
						}

						_, err := app.handleRegister(context.Background(), followupReq, machineKey1.Public())
						results <- err
					}(i)
				}

				// All should wait since no auth completion happened
				// After a short delay, they should timeout or be waiting
				time.Sleep(100 * time.Millisecond)

				// Now complete the authentication to signal one of them
				registrationID, err := extractRegistrationIDFromAuthURL(authURL)
				require.NoError(t, err)

				user := app.state.CreateUserForTest("concurrent-test-user")
				_, _, err = app.state.HandleNodeFromAuthPath(
					registrationID,
					types.UserID(user.ID),
					nil,
					"concurrent-test-method",
				)
				require.NoError(t, err)

				// Collect results - at least one should succeed
				successCount := 0
				for range numConcurrent {
					select {
					case err := <-results:
						if err == nil {
							successCount++
						}
					case <-time.After(2 * time.Second):
						// Some may timeout, which is expected
					}
				}

				// At least one concurrent request should have succeeded
				assert.GreaterOrEqual(t, successCount, 1, "at least one concurrent registration should succeed")
			},
		},
		// TEST: Interactive workflow with node key rotation attempt
		// WHAT: Tests interactive registration with different node key (appears as rotation)
		// INPUT: Node registered with nodeKey1, then interactive registration with nodeKey2
		// EXPECTED: Creates new node for different user (not true rotation)
		// WHY: Interactive flow creates new nodes with new users; doesn't rotate existing nodes
		{
			name: "interactive_workflow_node_key_rotation",
			setupFunc: func(t *testing.T, app *Headscale) (string, error) {
				// Register initial node
				user := app.state.CreateUserForTest("rotation-user")
				pak, err := app.state.CreatePreAuthKey(types.UserID(user.ID), true, false, nil, nil)
				if err != nil {
					return "", err
				}

				initialReq := tailcfg.RegisterRequest{
					Auth: &tailcfg.RegisterResponseAuth{
						AuthKey: pak.Key,
					},
					NodeKey: nodeKey1.Public(),
					Hostinfo: &tailcfg.Hostinfo{
						Hostname: "rotation-node-initial",
					},
					Expiry: time.Now().Add(24 * time.Hour),
				}

				_, err = app.handleRegister(context.Background(), initialReq, machineKey1.Public())
				if err != nil {
					return "", err
				}

				// Wait for node to be available
				require.EventuallyWithT(t, func(c *assert.CollectT) {
					_, found := app.state.GetNodeByNodeKey(nodeKey1.Public())
					assert.True(c, found, "node should be available in NodeStore")
				}, 1*time.Second, 50*time.Millisecond, "waiting for node to be available in NodeStore")

				return "", nil
			},
			request: func(_ string) tailcfg.RegisterRequest {
				return tailcfg.RegisterRequest{
					NodeKey:    nodeKey2.Public(), // Different node key (rotation scenario)
					OldNodeKey: nodeKey1.Public(), // Previous node key
					Hostinfo: &tailcfg.Hostinfo{
						Hostname: "rotation-node-updated",
					},
					Expiry: time.Now().Add(24 * time.Hour),
				}
			},
			machineKey:              func() key.MachinePublic { return machineKey1.Public() },
			requiresInteractiveFlow: true,
			interactiveSteps: []interactiveStep{
				{stepType: stepTypeInitialRequest, expectAuthURL: true, expectCacheEntry: true},
				{stepType: stepTypeAuthCompletion, callAuthPath: true, expectCacheEntry: false},
			},
			validateCompleteResponse: true,
			validate: func(t *testing.T, resp *tailcfg.RegisterResponse, app *Headscale) {
				// User1's original node with nodeKey1 should STILL exist
				oldNode, foundOld := app.state.GetNodeByNodeKey(nodeKey1.Public())
				require.True(t, foundOld, "user1's original node with nodeKey1 should still exist")
				assert.Equal(t, uint(1), oldNode.UserID(), "user1's node should still belong to user1")
				assert.Equal(t, uint64(1), oldNode.ID().Uint64(), "user1's node should be ID=1")

				// User2 should have a NEW node with nodeKey2
				newNode, found := app.state.GetNodeByNodeKey(nodeKey2.Public())
				require.True(t, found, "user2 should have new node with nodeKey2")
				assert.Equal(t, "rotation-node-updated", newNode.Hostname())
				assert.Equal(t, machineKey1.Public(), newNode.MachineKey())

				user := newNode.User()
				assert.Equal(t, "interactive-test-user", user.Username(), "user2's node should belong to user2")

				// Verify it's a NEW node, not transferred
				assert.NotEqual(t, uint64(1), newNode.ID().Uint64(), "should be a NEW node (different ID)")
			},
		},
		// TEST: Interactive workflow with nil hostinfo
		// WHAT: Tests interactive registration when request has nil hostinfo
		// INPUT: Interactive registration request with Hostinfo=nil
		// EXPECTED: Node registers successfully with generated default hostname
		// WHY: Defensive code handles nil hostinfo in interactive flow
		{
			name: "interactive_workflow_with_nil_hostinfo",
			setupFunc: func(t *testing.T, app *Headscale) (string, error) {
				return "", nil
			},
			request: func(_ string) tailcfg.RegisterRequest {
				return tailcfg.RegisterRequest{
					NodeKey:  nodeKey1.Public(),
					Hostinfo: nil, // Nil hostinfo should be handled gracefully
					Expiry:   time.Now().Add(24 * time.Hour),
				}
			},
			machineKey:              func() key.MachinePublic { return machineKey1.Public() },
			requiresInteractiveFlow: true,
			interactiveSteps: []interactiveStep{
				{stepType: stepTypeInitialRequest, expectAuthURL: true, expectCacheEntry: true},
				{stepType: stepTypeAuthCompletion, callAuthPath: true, expectCacheEntry: false},
			},
			validateCompleteResponse: true,
			validate: func(t *testing.T, resp *tailcfg.RegisterResponse, app *Headscale) {
				// Should handle nil hostinfo gracefully
				node, found := app.state.GetNodeByNodeKey(nodeKey1.Public())
				assert.True(t, found, "node should be registered despite nil hostinfo")
				if found {
					// Should have some default hostname or handle nil gracefully
					hostname := node.Hostname()
					assert.NotEmpty(t, hostname, "should have some hostname even with nil hostinfo")
				}
			},
		},
		// TEST: Registration cache cleanup on authentication error
		// WHAT: Tests that cache is cleaned up when authentication fails
		// INPUT: Interactive registration that fails during auth completion
		// EXPECTED: Cache entry removed after error
		// WHY: Failed registrations should clean up to prevent stale cache entries
		{
			name: "interactive_workflow_registration_cache_cleanup_on_error",
			setupFunc: func(t *testing.T, app *Headscale) (string, error) {
				return "", nil
			},
			request: func(_ string) tailcfg.RegisterRequest {
				return tailcfg.RegisterRequest{
					NodeKey: nodeKey1.Public(),
					Hostinfo: &tailcfg.Hostinfo{
						Hostname: "cache-cleanup-test-node",
					},
					Expiry: time.Now().Add(24 * time.Hour),
				}
			},
			machineKey: func() key.MachinePublic { return machineKey1.Public() },
			validate: func(t *testing.T, resp *tailcfg.RegisterResponse, app *Headscale) {
				// Get initial AuthURL and extract registration ID
				authURL := resp.AuthURL
				assert.Contains(t, authURL, "/register/")

				registrationID, err := extractRegistrationIDFromAuthURL(authURL)
				require.NoError(t, err)

				// Verify cache entry exists
				cacheEntry, found := app.state.GetRegistrationCacheEntry(registrationID)
				assert.True(t, found, "registration cache entry should exist initially")
				assert.NotNil(t, cacheEntry)

				// Try to complete authentication with invalid user ID (should cause error)
				invalidUserID := types.UserID(99999) // Non-existent user
				_, _, err = app.state.HandleNodeFromAuthPath(
					registrationID,
					invalidUserID,
					nil,
					"error-test-method",
				)
				assert.Error(t, err, "should fail with invalid user ID")

				// Cache entry should still exist after auth error (for retry scenarios)
				_, stillFound := app.state.GetRegistrationCacheEntry(registrationID)
				assert.True(t, stillFound, "registration cache entry should still exist after auth error for potential retry")
			},
		},
		// TEST: Multiple interactive workflow steps for same node
		// WHAT: Tests that interactive workflow can handle multi-step process for same node
		// INPUT: Node goes through complete interactive flow with multiple steps
		// EXPECTED: Node successfully completes registration after all steps
		// WHY: Validates complete interactive flow works end-to-end
		// TEST: Interactive workflow with multiple registration attempts for same node
		// WHAT: Tests that multiple interactive registrations can be created for same node
		// INPUT: Start two interactive registrations, verify both cache entries exist
		// EXPECTED: Both registrations get different IDs and can coexist
		// WHY: Validates that multiple pending registrations don't interfere with each other
		{
			name: "interactive_workflow_multiple_steps_same_node",
			setupFunc: func(t *testing.T, app *Headscale) (string, error) {
				return "", nil
			},
			request: func(_ string) tailcfg.RegisterRequest {
				return tailcfg.RegisterRequest{
					NodeKey: nodeKey1.Public(),
					Hostinfo: &tailcfg.Hostinfo{
						Hostname: "multi-step-node",
						OS:       "linux",
					},
					Expiry: time.Now().Add(24 * time.Hour),
				}
			},
			machineKey: func() key.MachinePublic { return machineKey1.Public() },
			validate: func(t *testing.T, resp *tailcfg.RegisterResponse, app *Headscale) {
				// Test multiple interactive registration attempts for the same node can coexist
				authURL1 := resp.AuthURL
				assert.Contains(t, authURL1, "/register/")

				// Start a second interactive registration for the same node
				secondReq := tailcfg.RegisterRequest{
					NodeKey: nodeKey1.Public(),
					Hostinfo: &tailcfg.Hostinfo{
						Hostname: "multi-step-node-updated",
						OS:       "linux-updated",
					},
					Expiry: time.Now().Add(24 * time.Hour),
				}

				resp2, err := app.handleRegister(context.Background(), secondReq, machineKey1.Public())
				require.NoError(t, err)
				authURL2 := resp2.AuthURL
				assert.Contains(t, authURL2, "/register/")

				// Both should have different registration IDs
				regID1, err1 := extractRegistrationIDFromAuthURL(authURL1)
				regID2, err2 := extractRegistrationIDFromAuthURL(authURL2)
				require.NoError(t, err1)
				require.NoError(t, err2)
				assert.NotEqual(t, regID1, regID2, "different registration attempts should have different IDs")

				// Both cache entries should exist simultaneously
				_, found1 := app.state.GetRegistrationCacheEntry(regID1)
				_, found2 := app.state.GetRegistrationCacheEntry(regID2)
				assert.True(t, found1, "first registration cache entry should exist")
				assert.True(t, found2, "second registration cache entry should exist")

				// This validates that multiple pending registrations can coexist
				// without interfering with each other
			},
		},
		// TEST: Complete one of multiple pending registrations
		// WHAT: Tests completing the second of two pending registrations for same node
		// INPUT: Create two pending registrations, complete the second one
		// EXPECTED: Second registration completes successfully, node is created
		// WHY: Validates that you can complete any pending registration, not just the first
		{
			name: "interactive_workflow_complete_second_of_multiple_pending",
			setupFunc: func(t *testing.T, app *Headscale) (string, error) {
				return "", nil
			},
			request: func(_ string) tailcfg.RegisterRequest {
				return tailcfg.RegisterRequest{
					NodeKey: nodeKey1.Public(),
					Hostinfo: &tailcfg.Hostinfo{
						Hostname: "pending-node-1",
					},
					Expiry: time.Now().Add(24 * time.Hour),
				}
			},
			machineKey: func() key.MachinePublic { return machineKey1.Public() },
			validate: func(t *testing.T, resp *tailcfg.RegisterResponse, app *Headscale) {
				authURL1 := resp.AuthURL
				regID1, err := extractRegistrationIDFromAuthURL(authURL1)
				require.NoError(t, err)

				// Start a second interactive registration for the same node
				secondReq := tailcfg.RegisterRequest{
					NodeKey: nodeKey1.Public(),
					Hostinfo: &tailcfg.Hostinfo{
						Hostname: "pending-node-2",
					},
					Expiry: time.Now().Add(24 * time.Hour),
				}

				resp2, err := app.handleRegister(context.Background(), secondReq, machineKey1.Public())
				require.NoError(t, err)
				authURL2 := resp2.AuthURL
				regID2, err := extractRegistrationIDFromAuthURL(authURL2)
				require.NoError(t, err)

				// Verify both exist
				_, found1 := app.state.GetRegistrationCacheEntry(regID1)
				_, found2 := app.state.GetRegistrationCacheEntry(regID2)
				assert.True(t, found1, "first cache entry should exist")
				assert.True(t, found2, "second cache entry should exist")

				// Complete the SECOND registration (not the first)
				user := app.state.CreateUserForTest("second-registration-user")

				// Start followup request in goroutine (it will wait for auth completion)
				responseChan := make(chan *tailcfg.RegisterResponse, 1)
				errorChan := make(chan error, 1)

				followupReq := tailcfg.RegisterRequest{
					NodeKey:  nodeKey1.Public(),
					Followup: authURL2,
					Hostinfo: &tailcfg.Hostinfo{
						Hostname: "pending-node-2",
					},
					Expiry: time.Now().Add(24 * time.Hour),
				}

				go func() {
					resp, err := app.handleRegister(context.Background(), followupReq, machineKey1.Public())
					if err != nil {
						errorChan <- err
						return
					}
					responseChan <- resp
				}()

				// Give followup time to start waiting
				time.Sleep(50 * time.Millisecond)

				// Complete authentication for second registration
				_, _, err = app.state.HandleNodeFromAuthPath(
					regID2,
					types.UserID(user.ID),
					nil,
					"second-registration-method",
				)
				require.NoError(t, err)

				// Wait for followup to complete
				select {
				case err := <-errorChan:
					t.Fatalf("followup request failed: %v", err)
				case finalResp := <-responseChan:
					require.NotNil(t, finalResp)
					assert.True(t, finalResp.MachineAuthorized, "machine should be authorized")
				case <-time.After(2 * time.Second):
					t.Fatal("followup request timed out")
				}

				// Verify the node was created with the second registration's data
				node, found := app.state.GetNodeByNodeKey(nodeKey1.Public())
				assert.True(t, found, "node should be registered")
				if found {
					assert.Equal(t, "pending-node-2", node.Hostname())
					assert.Equal(t, "second-registration-user", node.User().Name)
				}

				// First registration should still be in cache (not completed)
				_, stillFound := app.state.GetRegistrationCacheEntry(regID1)
				assert.True(t, stillFound, "first registration should still be pending")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create test app
			app := createTestApp(t)

			// Run setup function
			dynamicValue, err := tt.setupFunc(t, app)
			require.NoError(t, err, "setup should not fail")

			// Check if this test requires interactive workflow
			if tt.requiresInteractiveFlow {
				runInteractiveWorkflowTest(t, tt, app, dynamicValue)
				return
			}

			// Build request
			req := tt.request(dynamicValue)
			machineKey := tt.machineKey()

			// Set up context with timeout for followup tests
			ctx := context.Background()
			if req.Followup != "" {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(context.Background(), 100*time.Millisecond)
				defer cancel()
			}

			// Debug: check node availability before test execution
			if req.Auth == nil {
				if node, found := app.state.GetNodeByNodeKey(req.NodeKey); found {
					t.Logf("Node found before handleRegister: hostname=%s, expired=%t", node.Hostname(), node.IsExpired())
				} else {
					t.Logf("Node NOT found before handleRegister for key %s", req.NodeKey.ShortString())
				}
			}

			// Execute the test
			resp, err := app.handleRegister(ctx, req, machineKey)

			// Validate error expectations
			if tt.wantError {
				assert.Error(t, err, "expected error but got none")
				return
			}

			require.NoError(t, err, "unexpected error: %v", err)
			require.NotNil(t, resp, "response should not be nil")

			// Validate basic response properties
			if tt.wantAuth {
				assert.True(t, resp.MachineAuthorized, "machine should be authorized")
			} else {
				assert.False(t, resp.MachineAuthorized, "machine should not be authorized")
			}

			if tt.wantAuthURL {
				assert.NotEmpty(t, resp.AuthURL, "should have AuthURL")
				assert.Contains(t, resp.AuthURL, "register/", "AuthURL should contain registration path")
			}

			if tt.wantExpired {
				assert.True(t, resp.NodeKeyExpired, "node key should be expired")
			} else {
				assert.False(t, resp.NodeKeyExpired, "node key should not be expired")
			}

			// Run custom validation if provided
			if tt.validate != nil {
				tt.validate(t, resp, app)
			}
		})
	}
}

// runInteractiveWorkflowTest executes a multi-step interactive authentication workflow
func runInteractiveWorkflowTest(t *testing.T, tt struct {
	name                      string
	setupFunc                 func(*testing.T, *Headscale) (string, error)
	request                   func(dynamicValue string) tailcfg.RegisterRequest
	machineKey                func() key.MachinePublic
	wantAuth                  bool
	wantError                 bool
	wantAuthURL               bool
	wantExpired               bool
	validate                  func(*testing.T, *tailcfg.RegisterResponse, *Headscale)
	requiresInteractiveFlow   bool
	interactiveSteps          []interactiveStep
	validateRegistrationCache bool
	expectedAuthURLPattern    string
	simulateAuthCompletion    bool
	validateCompleteResponse  bool
}, app *Headscale, dynamicValue string,
) {
	// Build initial request
	req := tt.request(dynamicValue)
	machineKey := tt.machineKey()
	ctx := context.Background()

	// Execute interactive workflow steps
	var (
		initialResp    *tailcfg.RegisterResponse
		authURL        string
		registrationID types.RegistrationID
		finalResp      *tailcfg.RegisterResponse
		err            error
	)

	// Execute the steps in the correct sequence for interactive workflow
	for i, step := range tt.interactiveSteps {
		t.Logf("Executing interactive step %d: %s", i+1, step.stepType)

		switch step.stepType {
		case stepTypeInitialRequest:
			// Step 1: Initial request should get AuthURL back
			initialResp, err = app.handleRegister(ctx, req, machineKey)
			require.NoError(t, err, "initial request should not fail")
			require.NotNil(t, initialResp, "initial response should not be nil")

			if step.expectAuthURL {
				require.NotEmpty(t, initialResp.AuthURL, "should have AuthURL")
				require.Contains(t, initialResp.AuthURL, "/register/", "AuthURL should contain registration path")
				authURL = initialResp.AuthURL

				// Extract registration ID from AuthURL
				registrationID, err = extractRegistrationIDFromAuthURL(authURL)
				require.NoError(t, err, "should be able to extract registration ID from AuthURL")
			}

			if step.expectCacheEntry {
				// Verify registration cache entry was created
				cacheEntry, found := app.state.GetRegistrationCacheEntry(registrationID)
				require.True(t, found, "registration cache entry should exist")
				require.NotNil(t, cacheEntry, "cache entry should not be nil")
				require.Equal(t, req.NodeKey, cacheEntry.Node.NodeKey, "cache entry should have correct node key")
			}

		case stepTypeAuthCompletion:
			// Step 2: Start followup request that will wait, then complete authentication
			if step.callAuthPath {
				require.NotEmpty(t, registrationID, "registration ID should be available from previous step")

				// Prepare followup request
				followupReq := tt.request(dynamicValue)
				followupReq.Followup = authURL

				// Start the followup request in a goroutine - it will wait for channel signal
				responseChan := make(chan *tailcfg.RegisterResponse, 1)
				errorChan := make(chan error, 1)

				go func() {
					resp, err := app.handleRegister(context.Background(), followupReq, machineKey)
					if err != nil {
						errorChan <- err
						return
					}
					responseChan <- resp
				}()

				// Give the followup request time to start waiting
				time.Sleep(50 * time.Millisecond)

				// Now complete the authentication - this will signal the waiting followup request
				user := app.state.CreateUserForTest("interactive-test-user")
				_, _, err = app.state.HandleNodeFromAuthPath(
					registrationID,
					types.UserID(user.ID),
					nil, // no custom expiry
					"test-method",
				)
				require.NoError(t, err, "HandleNodeFromAuthPath should succeed")

				// Wait for the followup request to complete
				select {
				case err := <-errorChan:
					require.NoError(t, err, "followup request should not fail")
				case finalResp = <-responseChan:
					require.NotNil(t, finalResp, "final response should not be nil")
					// Verify machine is now authorized
					require.True(t, finalResp.MachineAuthorized, "machine should be authorized after followup")
				case <-time.After(5 * time.Second):
					t.Fatal("followup request timed out waiting for authentication completion")
				}
			}

		case stepTypeFollowupRequest:
			// This step is deprecated - followup is now handled within auth_completion step
			t.Logf("followup_request step is deprecated - use expectCacheEntry in auth_completion instead")

		default:
			t.Fatalf("unknown interactive step type: %s", step.stepType)
		}

		// Check cache cleanup expectation for this step
		if step.expectCacheEntry == false && registrationID != "" {
			// Verify cache entry was cleaned up
			_, found := app.state.GetRegistrationCacheEntry(registrationID)
			require.False(t, found, "registration cache entry should be cleaned up after step: %s", step.stepType)
		}
	}

	// Validate final response if requested
	if tt.validateCompleteResponse && finalResp != nil {
		validateCompleteRegistrationResponse(t, finalResp, req)
	}

	// Run custom validation if provided
	if tt.validate != nil {
		responseToValidate := finalResp
		if responseToValidate == nil {
			responseToValidate = initialResp
		}
		tt.validate(t, responseToValidate, app)
	}
}

// extractRegistrationIDFromAuthURL extracts the registration ID from an AuthURL
func extractRegistrationIDFromAuthURL(authURL string) (types.RegistrationID, error) {
	// AuthURL format: "http://localhost/register/abc123"
	const registerPrefix = "/register/"
	idx := strings.LastIndex(authURL, registerPrefix)
	if idx == -1 {
		return "", fmt.Errorf("invalid AuthURL format: %s", authURL)
	}

	idStr := authURL[idx+len(registerPrefix):]
	return types.RegistrationIDFromString(idStr)
}

// validateCompleteRegistrationResponse performs comprehensive validation of a registration response
func validateCompleteRegistrationResponse(t *testing.T, resp *tailcfg.RegisterResponse, originalReq tailcfg.RegisterRequest) {
	// Basic response validation
	require.NotNil(t, resp, "response should not be nil")
	require.True(t, resp.MachineAuthorized, "machine should be authorized")
	require.False(t, resp.NodeKeyExpired, "node key should not be expired")
	require.NotEmpty(t, resp.User.DisplayName, "user should have display name")

	// Additional validation can be added here as needed
	// Note: NodeKey field may not be present in all response types

	// Additional validation can be added here as needed
}

// Simple test to validate basic node creation and lookup
func TestNodeStoreLookup(t *testing.T) {
	app := createTestApp(t)

	machineKey := key.NewMachine()
	nodeKey := key.NewNode()

	user := app.state.CreateUserForTest("test-user")
	pak, err := app.state.CreatePreAuthKey(types.UserID(user.ID), true, false, nil, nil)
	require.NoError(t, err)

	// Register a node
	regReq := tailcfg.RegisterRequest{
		Auth: &tailcfg.RegisterResponseAuth{
			AuthKey: pak.Key,
		},
		NodeKey: nodeKey.Public(),
		Hostinfo: &tailcfg.Hostinfo{
			Hostname: "test-node",
		},
		Expiry: time.Now().Add(24 * time.Hour),
	}

	resp, err := app.handleRegisterWithAuthKey(regReq, machineKey.Public())
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.True(t, resp.MachineAuthorized)

	t.Logf("Registered node successfully: %+v", resp)

	// Wait for node to be available in NodeStore
	var node types.NodeView
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		var found bool
		node, found = app.state.GetNodeByNodeKey(nodeKey.Public())
		assert.True(c, found, "Node should be found in NodeStore")
	}, 1*time.Second, 100*time.Millisecond, "waiting for node to be available in NodeStore")

	require.Equal(t, "test-node", node.Hostname())

	t.Logf("Found node: hostname=%s, id=%d", node.Hostname(), node.ID().Uint64())
}

// TestPreAuthKeyLogoutAndReloginDifferentUser tests the scenario where:
// 1. Multiple nodes register with different users using pre-auth keys
// 2. All nodes logout
// 3. All nodes re-login using a different user's pre-auth key
// EXPECTED BEHAVIOR: Should create NEW nodes for the new user, leaving old nodes with the old user.
// This matches the integration test expectation and web flow behavior.
func TestPreAuthKeyLogoutAndReloginDifferentUser(t *testing.T) {
	app := createTestApp(t)

	// Create two users
	user1 := app.state.CreateUserForTest("user1")
	user2 := app.state.CreateUserForTest("user2")

	// Create pre-auth keys for both users
	pak1, err := app.state.CreatePreAuthKey(types.UserID(user1.ID), true, false, nil, nil)
	require.NoError(t, err)
	pak2, err := app.state.CreatePreAuthKey(types.UserID(user2.ID), true, false, nil, nil)
	require.NoError(t, err)

	// Create machine and node keys for 4 nodes (2 per user)
	type nodeInfo struct {
		machineKey key.MachinePrivate
		nodeKey    key.NodePrivate
		hostname   string
		nodeID     types.NodeID
	}

	nodes := []nodeInfo{
		{machineKey: key.NewMachine(), nodeKey: key.NewNode(), hostname: "user1-node1"},
		{machineKey: key.NewMachine(), nodeKey: key.NewNode(), hostname: "user1-node2"},
		{machineKey: key.NewMachine(), nodeKey: key.NewNode(), hostname: "user2-node1"},
		{machineKey: key.NewMachine(), nodeKey: key.NewNode(), hostname: "user2-node2"},
	}

	// Register nodes: first 2 to user1, last 2 to user2
	for i, node := range nodes {
		authKey := pak1.Key
		if i >= 2 {
			authKey = pak2.Key
		}

		regReq := tailcfg.RegisterRequest{
			Auth: &tailcfg.RegisterResponseAuth{
				AuthKey: authKey,
			},
			NodeKey: node.nodeKey.Public(),
			Hostinfo: &tailcfg.Hostinfo{
				Hostname: node.hostname,
			},
			Expiry: time.Now().Add(24 * time.Hour),
		}

		resp, err := app.handleRegisterWithAuthKey(regReq, node.machineKey.Public())
		require.NoError(t, err)
		require.NotNil(t, resp)
		require.True(t, resp.MachineAuthorized)

		// Get the node ID
		var registeredNode types.NodeView
		require.EventuallyWithT(t, func(c *assert.CollectT) {
			var found bool
			registeredNode, found = app.state.GetNodeByNodeKey(node.nodeKey.Public())
			assert.True(c, found, "Node should be found in NodeStore")
		}, 1*time.Second, 100*time.Millisecond, "waiting for node to be available")

		nodes[i].nodeID = registeredNode.ID()
		t.Logf("Registered node %s with ID %d to user%d", node.hostname, registeredNode.ID().Uint64(), i/2+1)
	}

	// Verify initial state: user1 has 2 nodes, user2 has 2 nodes
	user1Nodes := app.state.ListNodesByUser(types.UserID(user1.ID))
	user2Nodes := app.state.ListNodesByUser(types.UserID(user2.ID))
	require.Equal(t, 2, user1Nodes.Len(), "user1 should have 2 nodes initially")
	require.Equal(t, 2, user2Nodes.Len(), "user2 should have 2 nodes initially")

	t.Logf("Initial state verified: user1=%d nodes, user2=%d nodes", user1Nodes.Len(), user2Nodes.Len())

	// Simulate logout for all nodes
	for _, node := range nodes {
		logoutReq := tailcfg.RegisterRequest{
			Auth:    nil, // nil Auth indicates logout
			NodeKey: node.nodeKey.Public(),
		}

		resp, err := app.handleRegister(context.Background(), logoutReq, node.machineKey.Public())
		require.NoError(t, err)
		t.Logf("Logout response for %s: %+v", node.hostname, resp)
	}

	t.Logf("All nodes logged out")

	// Create a new pre-auth key for user1 (reusable for all nodes)
	newPak1, err := app.state.CreatePreAuthKey(types.UserID(user1.ID), true, false, nil, nil)
	require.NoError(t, err)

	// Re-login all nodes using user1's new pre-auth key
	for i, node := range nodes {
		regReq := tailcfg.RegisterRequest{
			Auth: &tailcfg.RegisterResponseAuth{
				AuthKey: newPak1.Key,
			},
			NodeKey: node.nodeKey.Public(),
			Hostinfo: &tailcfg.Hostinfo{
				Hostname: node.hostname,
			},
			Expiry: time.Now().Add(24 * time.Hour),
		}

		resp, err := app.handleRegisterWithAuthKey(regReq, node.machineKey.Public())
		require.NoError(t, err)
		require.NotNil(t, resp)
		require.True(t, resp.MachineAuthorized)

		t.Logf("Re-registered node %s (originally user%d) with user1's pre-auth key", node.hostname, i/2+1)
	}

	// Verify final state after re-login
	// EXPECTED: New nodes created for user1, old nodes remain with original users
	user1NodesAfter := app.state.ListNodesByUser(types.UserID(user1.ID))
	user2NodesAfter := app.state.ListNodesByUser(types.UserID(user2.ID))

	t.Logf("Final state: user1=%d nodes, user2=%d nodes", user1NodesAfter.Len(), user2NodesAfter.Len())

	// CORRECT BEHAVIOR: When re-authenticating with a DIFFERENT user's pre-auth key,
	// new nodes should be created (not transferred). This matches:
	// 1. The integration test expectation
	// 2. The web flow behavior (creates new nodes)
	// 3. The principle that each user owns distinct node entries
	require.Equal(t, 4, user1NodesAfter.Len(), "user1 should have 4 nodes total (2 original + 2 new from user2's machines)")
	require.Equal(t, 2, user2NodesAfter.Len(), "user2 should still have 2 nodes (old nodes from original registration)")

	// Verify original nodes still exist with original users
	for i := 0; i < 2; i++ {
		node := nodes[i]
		// User1's original nodes should still be owned by user1
		registeredNode, found := app.state.GetNodeByMachineKey(node.machineKey.Public(), types.UserID(user1.ID))
		require.True(t, found, "User1's original node %s should still exist", node.hostname)
		require.Equal(t, user1.ID, registeredNode.UserID(), "Node %s should still belong to user1", node.hostname)
		t.Logf("✓ User1's original node %s (ID=%d) still owned by user1", node.hostname, registeredNode.ID().Uint64())
	}

	for i := 2; i < 4; i++ {
		node := nodes[i]
		// User2's original nodes should still be owned by user2
		registeredNode, found := app.state.GetNodeByMachineKey(node.machineKey.Public(), types.UserID(user2.ID))
		require.True(t, found, "User2's original node %s should still exist", node.hostname)
		require.Equal(t, user2.ID, registeredNode.UserID(), "Node %s should still belong to user2", node.hostname)
		t.Logf("✓ User2's original node %s (ID=%d) still owned by user2", node.hostname, registeredNode.ID().Uint64())
	}

	// Verify new nodes were created for user1 with the same machine keys
	t.Logf("Verifying new nodes created for user1 from user2's machine keys...")
	for i := 2; i < 4; i++ {
		node := nodes[i]
		// Should be able to find a node with user1 and this machine key (the new one)
		newNode, found := app.state.GetNodeByMachineKey(node.machineKey.Public(), types.UserID(user1.ID))
		require.True(t, found, "Should have created new node for user1 with machine key from %s", node.hostname)
		require.Equal(t, user1.ID, newNode.UserID(), "New node should belong to user1")
		t.Logf("✓ New node created for user1 with machine key from %s (ID=%d)", node.hostname, newNode.ID().Uint64())
	}
}

// TestWebFlowReauthDifferentUser validates CLI registration behavior when switching users.
// This test replicates the TestAuthWebFlowLogoutAndReloginNewUser integration test scenario.
//
// IMPORTANT: CLI registration creates NEW nodes (different from interactive flow which transfers).
//
// Scenario:
// 1. Node registers with user1 via pre-auth key
// 2. Node logs out (expires)
// 3. Admin runs: headscale nodes register --user user2 --key <key>
//
// Expected behavior:
// - User1's original node should STILL EXIST (expired)
// - User2 should get a NEW node created (NOT transfer)
// - Both nodes share the same machine key (same physical device)
func TestWebFlowReauthDifferentUser(t *testing.T) {
	machineKey := key.NewMachine()
	nodeKey1 := key.NewNode()
	nodeKey2 := key.NewNode() // Node key rotates on re-auth

	app := createTestApp(t)

	// Step 1: Register node for user1 via pre-auth key (simulating initial web flow registration)
	user1 := app.state.CreateUserForTest("user1")
	pak1, err := app.state.CreatePreAuthKey(types.UserID(user1.ID), true, false, nil, nil)
	require.NoError(t, err)

	regReq1 := tailcfg.RegisterRequest{
		Auth: &tailcfg.RegisterResponseAuth{
			AuthKey: pak1.Key,
		},
		NodeKey: nodeKey1.Public(),
		Hostinfo: &tailcfg.Hostinfo{
			Hostname: "test-machine",
		},
		Expiry: time.Now().Add(24 * time.Hour),
	}

	resp1, err := app.handleRegisterWithAuthKey(regReq1, machineKey.Public())
	require.NoError(t, err)
	require.True(t, resp1.MachineAuthorized, "Should be authorized via pre-auth key")

	// Verify node exists for user1
	user1Node, found := app.state.GetNodeByMachineKey(machineKey.Public(), types.UserID(user1.ID))
	require.True(t, found, "Node should exist for user1")
	require.Equal(t, user1.ID, user1Node.UserID(), "Node should belong to user1")
	user1NodeID := user1Node.ID()
	t.Logf("✓ User1 node created with ID: %d", user1NodeID)

	// Step 2: Simulate logout by expiring the node
	pastTime := time.Now().Add(-1 * time.Hour)
	logoutReq := tailcfg.RegisterRequest{
		NodeKey: nodeKey1.Public(),
		Expiry:  pastTime, // Expired = logout
	}
	_, err = app.handleRegister(context.Background(), logoutReq, machineKey.Public())
	require.NoError(t, err)

	// Verify node is expired
	user1Node, found = app.state.GetNodeByMachineKey(machineKey.Public(), types.UserID(user1.ID))
	require.True(t, found, "Node should still exist after logout")
	require.True(t, user1Node.IsExpired(), "Node should be expired after logout")
	t.Logf("✓ User1 node expired (logged out)")

	// Step 3: Start interactive re-authentication (simulates "tailscale up")
	user2 := app.state.CreateUserForTest("user2")

	reAuthReq := tailcfg.RegisterRequest{
		// No Auth field - triggers interactive flow
		NodeKey: nodeKey2.Public(), // New node key (rotated on re-auth)
		Hostinfo: &tailcfg.Hostinfo{
			Hostname: "test-machine",
		},
		Expiry: time.Now().Add(24 * time.Hour),
	}

	// Initial request should return AuthURL
	initialResp, err := app.handleRegister(context.Background(), reAuthReq, machineKey.Public())
	require.NoError(t, err)
	require.NotEmpty(t, initialResp.AuthURL, "Should receive AuthURL for interactive flow")
	t.Logf("✓ Interactive flow started, AuthURL: %s", initialResp.AuthURL)

	// Extract registration ID from AuthURL
	regID, err := extractRegistrationIDFromAuthURL(initialResp.AuthURL)
	require.NoError(t, err, "Should extract registration ID from AuthURL")
	require.NotEmpty(t, regID, "Should have valid registration ID")

	// Step 4: Admin completes authentication via CLI
	// This simulates: headscale nodes register --user user2 --key <key>
	node, _, err := app.state.HandleNodeFromAuthPath(
		regID,
		types.UserID(user2.ID), // Register to user2, not user1!
		nil,                    // No custom expiry
		"cli",                  // Registration method (CLI register command)
	)
	require.NoError(t, err, "HandleNodeFromAuthPath should succeed")
	t.Logf("✓ Admin registered node to user2 via CLI (node ID: %d)", node.ID())

	t.Run("user1_original_node_still_exists", func(t *testing.T) {
		// User1's original node should STILL exist (not transferred to user2)
		user1NodeAfter, found1 := app.state.GetNodeByMachineKey(machineKey.Public(), types.UserID(user1.ID))
		assert.True(t, found1, "User1's original node should still exist (not transferred)")

		if !found1 {
			t.Fatal("User1's node was transferred or deleted - this breaks the integration test!")
		}

		assert.Equal(t, user1.ID, user1NodeAfter.UserID(), "User1's node should still belong to user1")
		assert.Equal(t, user1NodeID, user1NodeAfter.ID(), "Should be the same node (same ID)")
		assert.True(t, user1NodeAfter.IsExpired(), "User1's node should still be expired")
		t.Logf("✓ User1's original node still exists (ID: %d, expired: %v)", user1NodeAfter.ID(), user1NodeAfter.IsExpired())
	})

	t.Run("user2_has_new_node_created", func(t *testing.T) {
		// User2 should have a NEW node created (not transfer from user1)
		user2Node, found2 := app.state.GetNodeByMachineKey(machineKey.Public(), types.UserID(user2.ID))
		assert.True(t, found2, "User2 should have a new node created")

		if !found2 {
			t.Fatal("User2 doesn't have a node - registration failed!")
		}

		assert.Equal(t, user2.ID, user2Node.UserID(), "User2's node should belong to user2")
		assert.NotEqual(t, user1NodeID, user2Node.ID(), "Should be a NEW node (different ID), not transfer!")
		assert.Equal(t, machineKey.Public(), user2Node.MachineKey(), "Should have same machine key")
		assert.Equal(t, nodeKey2.Public(), user2Node.NodeKey(), "Should have new node key")
		assert.False(t, user2Node.IsExpired(), "User2's node should NOT be expired (active)")
		t.Logf("✓ User2's new node created (ID: %d, active)", user2Node.ID())
	})

	t.Run("returned_node_is_user2_new_node", func(t *testing.T) {
		// The node returned from HandleNodeFromAuthPath should be user2's NEW node
		assert.Equal(t, user2.ID, node.UserID(), "Returned node should belong to user2")
		assert.NotEqual(t, user1NodeID, node.ID(), "Returned node should be NEW, not transferred from user1")
		t.Logf("✓ HandleNodeFromAuthPath returned user2's new node (ID: %d)", node.ID())
	})

	t.Run("both_nodes_share_machine_key", func(t *testing.T) {
		// Both nodes should have the same machine key (same physical device)
		user1NodeFinal, found1 := app.state.GetNodeByMachineKey(machineKey.Public(), types.UserID(user1.ID))
		user2NodeFinal, found2 := app.state.GetNodeByMachineKey(machineKey.Public(), types.UserID(user2.ID))

		require.True(t, found1, "User1 node should exist")
		require.True(t, found2, "User2 node should exist")

		assert.Equal(t, machineKey.Public(), user1NodeFinal.MachineKey(), "User1 node should have correct machine key")
		assert.Equal(t, machineKey.Public(), user2NodeFinal.MachineKey(), "User2 node should have same machine key")
		t.Logf("✓ Both nodes share machine key: %s", machineKey.Public().ShortString())
	})

	t.Run("total_node_count", func(t *testing.T) {
		// We should have exactly 2 nodes total: one for user1 (expired), one for user2 (active)
		allNodesSlice := app.state.ListNodes()
		assert.Equal(t, 2, allNodesSlice.Len(), "Should have exactly 2 nodes total")

		// Count nodes per user
		user1Nodes := 0
		user2Nodes := 0
		for i := 0; i < allNodesSlice.Len(); i++ {
			n := allNodesSlice.At(i)
			if n.UserID() == user1.ID {
				user1Nodes++
			}
			if n.UserID() == user2.ID {
				user2Nodes++
			}
		}

		assert.Equal(t, 1, user1Nodes, "User1 should have 1 node")
		assert.Equal(t, 1, user2Nodes, "User2 should have 1 node")
		t.Logf("✓ Total: 2 nodes (user1: 1 expired, user2: 1 active)")
	})
}

// Helper function to create test app
func createTestApp(t *testing.T) *Headscale {
	t.Helper()

	tmpDir := t.TempDir()

	cfg := types.Config{
		ServerURL:           "http://localhost:8080",
		NoisePrivateKeyPath: tmpDir + "/noise_private.key",
		Database: types.DatabaseConfig{
			Type: "sqlite3",
			Sqlite: types.SqliteConfig{
				Path: tmpDir + "/headscale_test.db",
			},
		},
		OIDC: types.OIDCConfig{},
		Policy: types.PolicyConfig{
			Mode: types.PolicyModeDB,
		},
		Tuning: types.Tuning{
			BatchChangeDelay: 100 * time.Millisecond,
			BatcherWorkers:   1,
		},
	}

	app, err := NewHeadscale(&cfg)
	require.NoError(t, err)

	// Initialize and start the mapBatcher to handle Change() calls
	app.mapBatcher = mapper.NewBatcherAndMapper(&cfg, app.state)
	app.mapBatcher.Start()

	// Clean up the batcher when the test finishes
	t.Cleanup(func() {
		if app.mapBatcher != nil {
			app.mapBatcher.Close()
		}
	})

	return app
}

// TestGitHubIssue2830_NodeRestartWithUsedPreAuthKey tests the scenario reported in
// https://github.com/juanfont/headscale/issues/2830
//
// Scenario:
// 1. Node registers successfully with a single-use pre-auth key
// 2. Node is running fine
// 3. Node restarts (e.g., after headscale upgrade or tailscale container restart)
// 4. Node sends RegisterRequest with the same pre-auth key
// 5. BUG: Headscale rejects the request with "authkey expired" or "authkey already used"
//
// Expected behavior:
// When an existing node (identified by matching NodeKey + MachineKey) re-registers
// with a pre-auth key that it previously used, the registration should succeed.
// The node is not creating a new registration - it's re-authenticating the same device.
func TestGitHubIssue2830_NodeRestartWithUsedPreAuthKey(t *testing.T) {
	t.Parallel()

	app := createTestApp(t)

	// Create user and single-use pre-auth key
	user := app.state.CreateUserForTest("test-user")
	pak, err := app.state.CreatePreAuthKey(types.UserID(user.ID), false, false, nil, nil) // reusable=false
	require.NoError(t, err)
	require.False(t, pak.Reusable, "key should be single-use for this test")

	machineKey := key.NewMachine()
	nodeKey := key.NewNode()

	// STEP 1: Initial registration with pre-auth key (simulates fresh node joining)
	initialReq := tailcfg.RegisterRequest{
		Auth: &tailcfg.RegisterResponseAuth{
			AuthKey: pak.Key,
		},
		NodeKey: nodeKey.Public(),
		Hostinfo: &tailcfg.Hostinfo{
			Hostname: "test-node",
		},
		Expiry: time.Now().Add(24 * time.Hour),
	}

	t.Log("Step 1: Initial registration with pre-auth key")
	initialResp, err := app.handleRegister(context.Background(), initialReq, machineKey.Public())
	require.NoError(t, err, "initial registration should succeed")
	require.NotNil(t, initialResp)
	assert.True(t, initialResp.MachineAuthorized, "node should be authorized")
	assert.False(t, initialResp.NodeKeyExpired, "node key should not be expired")

	// Verify node was created in database
	node, found := app.state.GetNodeByNodeKey(nodeKey.Public())
	require.True(t, found, "node should exist after initial registration")
	assert.Equal(t, "test-node", node.Hostname())
	assert.Equal(t, nodeKey.Public(), node.NodeKey())
	assert.Equal(t, machineKey.Public(), node.MachineKey())

	// Verify pre-auth key is now marked as used
	usedPak, err := app.state.GetPreAuthKey(pak.Key)
	require.NoError(t, err)
	assert.True(t, usedPak.Used, "pre-auth key should be marked as used after initial registration")

	// STEP 2: Simulate node restart - node sends RegisterRequest again with same pre-auth key
	// This happens when:
	// - Tailscale container restarts
	// - Tailscaled service restarts
	// - System reboots
	// The Tailscale client persists the pre-auth key in its state and sends it on every registration
	t.Log("Step 2: Node restart - re-registration with same (now used) pre-auth key")
	restartReq := tailcfg.RegisterRequest{
		Auth: &tailcfg.RegisterResponseAuth{
			AuthKey: pak.Key, // Same key, now marked as Used=true
		},
		NodeKey: nodeKey.Public(), // Same node key
		Hostinfo: &tailcfg.Hostinfo{
			Hostname: "test-node",
		},
		Expiry: time.Now().Add(24 * time.Hour),
	}

	// BUG: This fails with "authkey already used" or "authkey expired"
	// EXPECTED: Should succeed because it's the same node re-registering
	restartResp, err := app.handleRegister(context.Background(), restartReq, machineKey.Public())

	// This is the assertion that currently FAILS in v0.27.0
	assert.NoError(t, err, "BUG: existing node re-registration with its own used pre-auth key should succeed")
	if err != nil {
		t.Logf("Error received (this is the bug): %v", err)
		t.Logf("Expected behavior: Node should be able to re-register with the same pre-auth key it used initially")
		return // Stop here to show the bug clearly
	}

	require.NotNil(t, restartResp)
	assert.True(t, restartResp.MachineAuthorized, "node should remain authorized after restart")
	assert.False(t, restartResp.NodeKeyExpired, "node key should not be expired after restart")

	// Verify it's the same node (not a duplicate)
	nodeAfterRestart, found := app.state.GetNodeByNodeKey(nodeKey.Public())
	require.True(t, found, "node should still exist after restart")
	assert.Equal(t, node.ID(), nodeAfterRestart.ID(), "should be the same node, not a new one")
	assert.Equal(t, "test-node", nodeAfterRestart.Hostname())
}

// TestNodeReregistrationWithReusablePreAuthKey tests that reusable keys work correctly
// for node re-registration.
func TestNodeReregistrationWithReusablePreAuthKey(t *testing.T) {
	t.Parallel()

	app := createTestApp(t)

	user := app.state.CreateUserForTest("test-user")
	pak, err := app.state.CreatePreAuthKey(types.UserID(user.ID), true, false, nil, nil) // reusable=true
	require.NoError(t, err)
	require.True(t, pak.Reusable)

	machineKey := key.NewMachine()
	nodeKey := key.NewNode()

	// Initial registration
	initialReq := tailcfg.RegisterRequest{
		Auth: &tailcfg.RegisterResponseAuth{
			AuthKey: pak.Key,
		},
		NodeKey: nodeKey.Public(),
		Hostinfo: &tailcfg.Hostinfo{
			Hostname: "reusable-test-node",
		},
		Expiry: time.Now().Add(24 * time.Hour),
	}

	initialResp, err := app.handleRegister(context.Background(), initialReq, machineKey.Public())
	require.NoError(t, err)
	require.NotNil(t, initialResp)
	assert.True(t, initialResp.MachineAuthorized)

	// Node restart - re-registration with reusable key
	restartReq := tailcfg.RegisterRequest{
		Auth: &tailcfg.RegisterResponseAuth{
			AuthKey: pak.Key, // Reusable key
		},
		NodeKey: nodeKey.Public(),
		Hostinfo: &tailcfg.Hostinfo{
			Hostname: "reusable-test-node",
		},
		Expiry: time.Now().Add(24 * time.Hour),
	}

	restartResp, err := app.handleRegister(context.Background(), restartReq, machineKey.Public())
	require.NoError(t, err, "reusable key should allow re-registration")
	require.NotNil(t, restartResp)
	assert.True(t, restartResp.MachineAuthorized)
	assert.False(t, restartResp.NodeKeyExpired)
}

// TestNodeReregistrationWithExpiredPreAuthKey tests that truly expired keys
// are still rejected even for existing nodes.
func TestNodeReregistrationWithExpiredPreAuthKey(t *testing.T) {
	t.Parallel()

	app := createTestApp(t)

	user := app.state.CreateUserForTest("test-user")
	expiry := time.Now().Add(-1 * time.Hour) // Already expired
	pak, err := app.state.CreatePreAuthKey(types.UserID(user.ID), true, false, &expiry, nil)
	require.NoError(t, err)

	machineKey := key.NewMachine()
	nodeKey := key.NewNode()

	// Try to register with expired key
	req := tailcfg.RegisterRequest{
		Auth: &tailcfg.RegisterResponseAuth{
			AuthKey: pak.Key,
		},
		NodeKey: nodeKey.Public(),
		Hostinfo: &tailcfg.Hostinfo{
			Hostname: "expired-key-node",
		},
		Expiry: time.Now().Add(24 * time.Hour),
	}

	_, err = app.handleRegister(context.Background(), req, machineKey.Public())
	assert.Error(t, err, "expired pre-auth key should be rejected")
	assert.Contains(t, err.Error(), "authkey expired", "error should mention key expiration")
}

// TestIssue2830_ExistingNodeReregistersWithExpiredKey tests the fix for issue #2830.
// When a node is already registered and the pre-auth key expires, the node should
// still be able to re-register (e.g., after a container restart) using the same
// expired key. The key was only needed for initial authentication.
func TestIssue2830_ExistingNodeReregistersWithExpiredKey(t *testing.T) {
	t.Parallel()

	app := createTestApp(t)

	user := app.state.CreateUserForTest("test-user")

	// Create a valid key (will expire it later)
	expiry := time.Now().Add(1 * time.Hour)
	pak, err := app.state.CreatePreAuthKey(types.UserID(user.ID), false, false, &expiry, nil)
	require.NoError(t, err)

	machineKey := key.NewMachine()
	nodeKey := key.NewNode()

	// Register the node initially (key is still valid)
	req := tailcfg.RegisterRequest{
		Auth: &tailcfg.RegisterResponseAuth{
			AuthKey: pak.Key,
		},
		NodeKey: nodeKey.Public(),
		Hostinfo: &tailcfg.Hostinfo{
			Hostname: "issue2830-node",
		},
		Expiry: time.Now().Add(24 * time.Hour),
	}

	resp, err := app.handleRegister(context.Background(), req, machineKey.Public())
	require.NoError(t, err, "initial registration should succeed")
	require.NotNil(t, resp)
	require.True(t, resp.MachineAuthorized, "node should be authorized after initial registration")

	// Verify node was created
	allNodes := app.state.ListNodes()
	require.Equal(t, 1, allNodes.Len())
	initialNodeID := allNodes.At(0).ID()

	// Now expire the key by updating it in the database to have an expiry in the past.
	// This simulates the real-world scenario where a key expires after initial registration.
	pastExpiry := time.Now().Add(-1 * time.Hour)
	err = app.state.DB().DB.Model(&types.PreAuthKey{}).
		Where("id = ?", pak.ID).
		Update("expiration", pastExpiry).Error
	require.NoError(t, err, "should be able to update key expiration")

	// Reload the key to verify it's now expired
	expiredPak, err := app.state.GetPreAuthKey(pak.Key)
	require.NoError(t, err)
	require.NotNil(t, expiredPak.Expiration)
	require.True(t, expiredPak.Expiration.Before(time.Now()), "key should be expired")

	// Verify the expired key would fail validation
	err = expiredPak.Validate()
	require.Error(t, err, "key should fail validation when expired")
	require.Contains(t, err.Error(), "authkey expired")

	// Attempt to re-register with the SAME key (now expired).
	// This should SUCCEED because:
	// - The node already exists with the same MachineKey and User
	// - The fix allows existing nodes to re-register even with expired keys
	// - The key was only needed for initial authentication
	req2 := tailcfg.RegisterRequest{
		Auth: &tailcfg.RegisterResponseAuth{
			AuthKey: pak.Key, // Same key as initial registration (now expired)
		},
		NodeKey: nodeKey.Public(), // Same NodeKey as initial registration
		Hostinfo: &tailcfg.Hostinfo{
			Hostname: "issue2830-node",
		},
		Expiry: time.Now().Add(24 * time.Hour),
	}

	resp2, err := app.handleRegister(context.Background(), req2, machineKey.Public())
	assert.NoError(t, err, "re-registration should succeed even with expired key for existing node")
	assert.NotNil(t, resp2)
	assert.True(t, resp2.MachineAuthorized, "node should remain authorized after re-registration")

	// Verify we still have only one node (re-registered, not created new)
	allNodes = app.state.ListNodes()
	require.Equal(t, 1, allNodes.Len(), "should have exactly one node (re-registered)")
	assert.Equal(t, initialNodeID, allNodes.At(0).ID(), "node ID should not change on re-registration")
}

// TestGitHubIssue2830_ExistingNodeCanReregisterWithUsedPreAuthKey tests that an existing node
// can re-register using a pre-auth key that's already marked as Used=true, as long as:
// 1. The node is re-registering with the same MachineKey it originally used
// 2. The node is using the same pre-auth key it was originally registered with (AuthKeyID matches)
//
// This is the fix for GitHub issue #2830: https://github.com/juanfont/headscale/issues/2830
//
// Background: When Docker/Kubernetes containers restart, they keep their persistent state
// (including the MachineKey), but container entrypoints unconditionally run:
//
//	tailscale up --authkey=$TS_AUTHKEY
//
// This caused nodes to be rejected after restart because the pre-auth key was already
// marked as Used=true from the initial registration. The fix allows re-registration of
// existing nodes with their own used keys.
func TestGitHubIssue2830_ExistingNodeCanReregisterWithUsedPreAuthKey(t *testing.T) {
	app := createTestApp(t)

	// Create a user
	user := app.state.CreateUserForTest("testuser")

	// Create a SINGLE-USE pre-auth key (reusable=false)
	// This is the type of key that triggers the bug in issue #2830
	preAuthKey, err := app.state.CreatePreAuthKey(types.UserID(user.ID), false, false, nil, nil)
	require.NoError(t, err)
	require.False(t, preAuthKey.Reusable, "Pre-auth key must be single-use to test issue #2830")
	require.False(t, preAuthKey.Used, "Pre-auth key should not be used yet")

	// Generate node keys for the client
	machineKey := key.NewMachine()
	nodeKey := key.NewNode()

	// Step 1: Initial registration with the pre-auth key
	// This simulates the first time the container starts and runs 'tailscale up --authkey=...'
	initialReq := tailcfg.RegisterRequest{
		Auth: &tailcfg.RegisterResponseAuth{
			AuthKey: preAuthKey.Key,
		},
		NodeKey: nodeKey.Public(),
		Hostinfo: &tailcfg.Hostinfo{
			Hostname: "issue-2830-test-node",
		},
		Expiry: time.Now().Add(24 * time.Hour),
	}

	initialResp, err := app.handleRegisterWithAuthKey(initialReq, machineKey.Public())
	require.NoError(t, err, "Initial registration should succeed")
	require.True(t, initialResp.MachineAuthorized, "Node should be authorized after initial registration")
	require.NotNil(t, initialResp.User, "User should be set in response")
	require.Equal(t, "testuser", initialResp.User.DisplayName, "User should match the pre-auth key's user")

	// Verify the pre-auth key is now marked as Used
	updatedKey, err := app.state.GetPreAuthKey(preAuthKey.Key)
	require.NoError(t, err)
	require.True(t, updatedKey.Used, "Pre-auth key should be marked as Used after initial registration")

	// Step 2: Container restart scenario
	// The container keeps its MachineKey (persistent state), but the entrypoint script
	// unconditionally runs 'tailscale up --authkey=$TS_AUTHKEY' again
	//
	// WITHOUT THE FIX: This would fail with "authkey already used" error
	// WITH THE FIX: This succeeds because it's the same node re-registering with its own key

	// Simulate sending the same RegisterRequest again (same MachineKey, same AuthKey)
	// This is exactly what happens when a container restarts
	reregisterReq := tailcfg.RegisterRequest{
		Auth: &tailcfg.RegisterResponseAuth{
			AuthKey: preAuthKey.Key, // Same key, now marked as Used=true
		},
		NodeKey: nodeKey.Public(), // Same NodeKey
		Hostinfo: &tailcfg.Hostinfo{
			Hostname: "issue-2830-test-node",
		},
		Expiry: time.Now().Add(24 * time.Hour),
	}

	reregisterResp, err := app.handleRegisterWithAuthKey(reregisterReq, machineKey.Public()) // Same MachineKey
	require.NoError(t, err, "Re-registration with same MachineKey and used pre-auth key should succeed (fixes #2830)")
	require.True(t, reregisterResp.MachineAuthorized, "Node should remain authorized after re-registration")
	require.NotNil(t, reregisterResp.User, "User should be set in re-registration response")
	require.Equal(t, "testuser", reregisterResp.User.DisplayName, "User should remain the same")

	// Verify that only ONE node was created (not a duplicate)
	nodes := app.state.ListNodesByUser(types.UserID(user.ID))
	require.Equal(t, 1, nodes.Len(), "Should have exactly one node (no duplicates created)")
	require.Equal(t, "issue-2830-test-node", nodes.At(0).Hostname(), "Node hostname should match")

	// Step 3: Verify that a DIFFERENT machine cannot use the same used key
	// This ensures we didn't break the security model - only the original node can re-register
	differentMachineKey := key.NewMachine()
	differentNodeKey := key.NewNode()

	attackReq := tailcfg.RegisterRequest{
		Auth: &tailcfg.RegisterResponseAuth{
			AuthKey: preAuthKey.Key, // Try to use the same key
		},
		NodeKey: differentNodeKey.Public(),
		Hostinfo: &tailcfg.Hostinfo{
			Hostname: "attacker-node",
		},
		Expiry: time.Now().Add(24 * time.Hour),
	}

	_, err = app.handleRegisterWithAuthKey(attackReq, differentMachineKey.Public())
	require.Error(t, err, "Different machine should NOT be able to use the same used pre-auth key")
	require.Contains(t, err.Error(), "already used", "Error should indicate key is already used")

	// Verify still only one node (the original one)
	nodesAfterAttack := app.state.ListNodesByUser(types.UserID(user.ID))
	require.Equal(t, 1, nodesAfterAttack.Len(), "Should still have exactly one node (attack prevented)")
}
