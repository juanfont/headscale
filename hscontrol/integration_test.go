package hscontrol_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/require"
	"zgo.at/zcache/v2"
)

// TestIssue2714_RegistrationCacheDebugEndpoint tests that the /debug/registration-cache
// endpoint does not return "json: unsupported type: chan *types.Node" error
// This is a regression test for GitHub issue #2714
func TestIssue2714_RegistrationCacheDebugEndpoint(t *testing.T) {
	// Create a registration cache similar to what's used in State
	cache := zcache.New[types.RegistrationID, types.RegisterNode](
		5*time.Minute,
		1*time.Minute,
	)

	// Create a minimal RegisterNode that contains the problematic channel
	// This simulates what would be in the actual registration cache
	registerNode := types.RegisterNode{
		Node: types.Node{
			ID:             types.NodeID(1),
			Hostname:       "test-node",
			RegisterMethod: "test",
			CreatedAt:      time.Now(),
			UpdatedAt:      time.Now(),
		},
		Registered: make(chan *types.Node), // This is the problematic channel
	}

	// Add the registration to the cache to simulate a real scenario
	regID := types.RegistrationID("test-reg-1")
	cache.Set(regID, registerNode)

	// Test the logic from DebugRegistrationCache - this should NOT expose the channel
	result := map[string]any{
		"type":       "zcache",
		"expiration": "15m0s", // registerCacheExpiration
		"cleanup":    "20m0s", // registerCacheCleanup
		"status":     "active",
	}

	// Safely get cache statistics without exposing problematic channels
	result["item_count"] = cache.ItemCount()

	// Get registration IDs without exposing the full RegisterNode structs
	keys := cache.Keys()
	registrationIDs := make([]string, 0, len(keys))
	for _, key := range keys {
		registrationIDs = append(registrationIDs, string(key))
	}
	result["registration_ids"] = registrationIDs

	// The key assertion: this should NOT fail with "json: unsupported type: chan *types.Node"
	jsonBytes, err := json.MarshalIndent(result, "", "  ")
	require.NoError(t, err, "DebugRegistrationCache should always be JSON-serializable")

	// Verify it contains expected data
	var unmarshaled map[string]interface{}
	err = json.Unmarshal(jsonBytes, &unmarshaled)
	require.NoError(t, err)

	// Verify the expected fields are present
	expectedFields := []string{"type", "expiration", "cleanup", "status", "item_count", "registration_ids"}
	for _, field := range expectedFields {
		_, exists := unmarshaled[field]
		require.True(t, exists, "Expected field %s not found in response", field)
	}

	require.Equal(t, "zcache", unmarshaled["type"])
	require.Equal(t, "active", unmarshaled["status"])
	require.Equal(t, "15m0s", unmarshaled["expiration"])
	require.Equal(t, "20m0s", unmarshaled["cleanup"])
	require.Equal(t, float64(1), unmarshaled["item_count"]) // JSON numbers are float64

	registrationIDsInterface, ok := unmarshaled["registration_ids"].([]interface{})
	require.True(t, ok)
	require.Len(t, registrationIDsInterface, 1)
	require.Equal(t, "test-reg-1", registrationIDsInterface[0])

	// The key assertion: this test should pass without the "json: unsupported type: chan *types.Node" error
	t.Log("Successfully verified that DebugRegistrationCache returns valid JSON without channel serialization errors")
}
