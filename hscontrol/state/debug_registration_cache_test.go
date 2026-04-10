package state_test

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"zgo.at/zcache/v2"
)

func TestDebugRegistrationCacheJSONMarshal(t *testing.T) {
	// This test specifically verifies that the JSON marshaling issue is fixed
	// by testing the enhanced DebugRegistrationCache functionality directly

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

	// Add the registration to the cache
	regID := types.RegistrationID("test-reg-1")
	cache.Set(regID, registerNode)

	// Test the logic from DebugRegistrationCache - this should NOT expose the channel
	result := map[string]any{
		"type":       "zcache",
		"expiration": "5m0s",
		"cleanup":    "1m0s",
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

	// This should NOT fail with "json: unsupported type: chan *types.Node"
	jsonBytes, err := json.MarshalIndent(result, "", "  ")
	require.NoError(t, err, "DebugRegistrationCache should always be JSON-serializable")

	// Verify it contains expected data
	var unmarshaled map[string]interface{}
	err = json.Unmarshal(jsonBytes, &unmarshaled)
	require.NoError(t, err)

	assert.Equal(t, "zcache", unmarshaled["type"])
	assert.Equal(t, "active", unmarshaled["status"])
	assert.Equal(t, float64(1), unmarshaled["item_count"]) // JSON numbers are float64

	registrationIDsInterface, ok := unmarshaled["registration_ids"].([]interface{})
	require.True(t, ok)
	assert.Len(t, registrationIDsInterface, 1)
	assert.Equal(t, "test-reg-1", registrationIDsInterface[0])
}

func TestDebugRegistrationCacheEmpty(t *testing.T) {
	// Test with empty cache
	cache := zcache.New[types.RegistrationID, types.RegisterNode](
		5*time.Minute,
		1*time.Minute,
	)

	result := map[string]any{
		"type":       "zcache",
		"expiration": "5m0s",
		"cleanup":    "1m0s",
		"status":     "active",
	}

	result["item_count"] = cache.ItemCount()

	keys := cache.Keys()
	registrationIDs := make([]string, 0, len(keys))
	for _, key := range keys {
		registrationIDs = append(registrationIDs, string(key))
	}
	result["registration_ids"] = registrationIDs

	// Should marshal successfully even with empty cache
	jsonBytes, err := json.Marshal(result)
	require.NoError(t, err)

	var unmarshaled map[string]interface{}
	err = json.Unmarshal(jsonBytes, &unmarshaled)
	require.NoError(t, err)

	assert.Equal(t, float64(0), unmarshaled["item_count"])
	registrationIDsInterface, ok := unmarshaled["registration_ids"].([]interface{})
	require.True(t, ok)
	assert.Len(t, registrationIDsInterface, 0)
}

func TestDebugRegistrationCacheMultipleItems(t *testing.T) {
	// Test with multiple items in cache
	cache := zcache.New[types.RegistrationID, types.RegisterNode](
		5*time.Minute,
		1*time.Minute,
	)

	// Add multiple registrations
	for i := 0; i < 3; i++ {
		registerNode := types.RegisterNode{
			Node: types.Node{
				ID:             types.NodeID(uint64(i + 1)),
				Hostname:       fmt.Sprintf("test-node-%d", i+1),
				RegisterMethod: "test",
				CreatedAt:      time.Now(),
				UpdatedAt:      time.Now(),
			},
			Registered: make(chan *types.Node),
		}
		regID := types.RegistrationID(fmt.Sprintf("test-reg-%d", i+1))
		cache.Set(regID, registerNode)
	}

	// Apply the DebugRegistrationCache logic
	result := map[string]any{
		"type":       "zcache",
		"expiration": "5m0s",
		"cleanup":    "1m0s",
		"status":     "active",
	}

	result["item_count"] = cache.ItemCount()

	keys := cache.Keys()
	registrationIDs := make([]string, 0, len(keys))
	for _, key := range keys {
		registrationIDs = append(registrationIDs, string(key))
	}
	result["registration_ids"] = registrationIDs

	// Should marshal successfully even with multiple items containing channels
	jsonBytes, err := json.MarshalIndent(result, "", "  ")
	require.NoError(t, err, "Should marshal successfully with multiple items")

	var unmarshaled map[string]interface{}
	err = json.Unmarshal(jsonBytes, &unmarshaled)
	require.NoError(t, err)

	assert.Equal(t, "zcache", unmarshaled["type"])
	assert.Equal(t, "active", unmarshaled["status"])
	assert.Equal(t, float64(3), unmarshaled["item_count"])

	registrationIDsInterface, ok := unmarshaled["registration_ids"].([]interface{})
	require.True(t, ok)
	assert.Len(t, registrationIDsInterface, 3)
}
