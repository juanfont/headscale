package hscontrol

import (
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
)

// TestNewPingManager verifies proper initialization of PingManager
func TestNewPingManager(t *testing.T) {
	t.Parallel()

	baseURL := "https://headscale.example.com"
	pm := NewPingManager(baseURL)

	assert.NotNil(t, pm)
	assert.NotNil(t, pm.requests)
	assert.Equal(t, baseURL, pm.baseURL)
	assert.Equal(t, 0, len(pm.requests))
}

// TestCreatePingRequest verifies that ping requests are created correctly
func TestCreatePingRequest(t *testing.T) {
	t.Parallel()

	pm := NewPingManager("https://example.com")
	nodeID := types.NodeID(42)
	pingType := "disco,TSMP"
	targetIP := "100.64.0.1"
	payload := []byte("test payload")

	req, err := pm.CreatePingRequest(nodeID, pingType, targetIP, payload)

	require.NoError(t, err)
	assert.NotNil(t, req)
	assert.NotEmpty(t, req.ID, "Request ID should not be empty")
	assert.Equal(t, nodeID, req.NodeID)
	assert.Equal(t, pingType, req.Types)
	assert.Equal(t, targetIP, req.IP)
	assert.Equal(t, payload, req.Payload)
	assert.NotNil(t, req.ResponseChan)
	assert.NotNil(t, req.ctx)
	assert.NotNil(t, req.cancel)
	assert.Contains(t, req.URL, "https://example.com/machine/ping-response/")
	assert.Contains(t, req.URL, req.ID)
	assert.WithinDuration(t, time.Now(), req.CreatedAt, 1*time.Second)
}

// TestCreatePingRequestUniqueIDs ensures each request gets a unique ID
func TestCreatePingRequestUniqueIDs(t *testing.T) {
	t.Parallel()

	pm := NewPingManager("https://example.com")
	nodeID := types.NodeID(1)
	ids := make(map[string]bool)

	// Create 100 requests
	for i := 0; i < 100; i++ {
		req, err := pm.CreatePingRequest(nodeID, "disco", "100.64.0.1", nil)
		require.NoError(t, err)

		// Check that ID is unique
		assert.False(t, ids[req.ID], "Generated duplicate ID: %s", req.ID)
		ids[req.ID] = true

		// Clean up
		req.cancel()
	}

	assert.Equal(t, 100, len(ids))
}

// TestGetRequest verifies retrieving requests by ID
func TestGetRequest(t *testing.T) {
	t.Parallel()

	pm := NewPingManager("https://example.com")
	nodeID := types.NodeID(1)

	// Create a request
	req, err := pm.CreatePingRequest(nodeID, "disco", "100.64.0.1", nil)
	require.NoError(t, err)
	defer req.cancel()

	// Retrieve it
	retrieved, ok := pm.GetRequest(req.ID)
	assert.True(t, ok)
	assert.Equal(t, req.ID, retrieved.ID)
	assert.Equal(t, req.NodeID, retrieved.NodeID)
	assert.Equal(t, req.URL, retrieved.URL)
}

// TestGetRequestNotFound verifies handling of missing requests
func TestGetRequestNotFound(t *testing.T) {
	t.Parallel()

	pm := NewPingManager("https://example.com")

	retrieved, ok := pm.GetRequest("nonexistent-id")
	assert.False(t, ok)
	assert.Nil(t, retrieved)
}

// TestHandleResponse verifies response handling
func TestHandleResponse(t *testing.T) {
	t.Parallel()

	pm := NewPingManager("https://example.com")
	nodeID := types.NodeID(1)

	req, err := pm.CreatePingRequest(nodeID, "disco", "100.64.0.1", nil)
	require.NoError(t, err)
	defer req.cancel()

	// Create a response
	response := &tailcfg.PingResponse{
		Type:   tailcfg.PingDisco,
		NodeIP: "100.64.0.1",
	}

	// Handle the response
	err = pm.HandleResponse(req.ID, response)
	require.NoError(t, err)

	// Receive the response
	select {
	case received := <-req.ResponseChan:
		assert.Equal(t, response.Type, received.Type)
		assert.Equal(t, response.NodeIP, received.NodeIP)
	case <-time.After(1 * time.Second):
		t.Fatal("Timeout waiting for response")
	}
}

// TestHandleResponseNotFound verifies error handling for unknown request IDs
func TestHandleResponseNotFound(t *testing.T) {
	t.Parallel()

	pm := NewPingManager("https://example.com")

	response := &tailcfg.PingResponse{
		Type: tailcfg.PingDisco,
	}

	err := pm.HandleResponse("nonexistent-id", response)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unknown request ID")
}

// TestPingRequestTimeout verifies that requests time out and are cleaned up
func TestPingRequestTimeout(t *testing.T) {
	t.Parallel()

	pm := NewPingManager("https://example.com")
	nodeID := types.NodeID(1)

	// Create request with very short timeout
	req, err := pm.CreatePingRequest(nodeID, "disco", "100.64.0.1", nil)
	require.NoError(t, err)

	// Cancel immediately to simulate timeout
	req.cancel()

	// Wait for cleanup goroutine
	time.Sleep(100 * time.Millisecond)

	// Request should be removed from map
	_, ok := pm.GetRequest(req.ID)
	assert.False(t, ok, "Request should be removed after timeout")

	// Channel should be closed
	select {
	case _, ok := <-req.ResponseChan:
		assert.False(t, ok, "Response channel should be closed")
	case <-time.After(1 * time.Second):
		t.Fatal("Timeout waiting for channel to close")
	}
}

// TestHandleResponseAfterTimeout verifies we can't respond to timed-out requests
func TestHandleResponseAfterTimeout(t *testing.T) {
	t.Parallel()

	pm := NewPingManager("https://example.com")
	nodeID := types.NodeID(1)

	req, err := pm.CreatePingRequest(nodeID, "disco", "100.64.0.1", nil)
	require.NoError(t, err)

	// Cancel and wait for cleanup
	req.cancel()
	time.Sleep(100 * time.Millisecond)

	// Try to handle response
	response := &tailcfg.PingResponse{Type: tailcfg.PingDisco}
	err = pm.HandleResponse(req.ID, response)
	assert.Error(t, err)
}

// TestConcurrentPingRequests verifies thread-safe request creation
func TestConcurrentPingRequests(t *testing.T) {
	t.Parallel()

	pm := NewPingManager("https://example.com")
	numGoroutines := 50
	nodeID := types.NodeID(1)

	var wg sync.WaitGroup
	requestsChan := make(chan *PingRequest, numGoroutines)
	errorsChan := make(chan error, numGoroutines)

	// Create requests concurrently
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req, err := pm.CreatePingRequest(nodeID, "disco", "100.64.0.1", nil)
			if err != nil {
				errorsChan <- err
				return
			}
			requestsChan <- req
		}()
	}

	wg.Wait()
	close(requestsChan)
	close(errorsChan)

	// Check for errors
	for err := range errorsChan {
		t.Errorf("Error creating request: %v", err)
	}

	// Verify all requests were created with unique IDs
	ids := make(map[string]bool)
	requestCount := 0
	for req := range requestsChan {
		requestCount++
		assert.False(t, ids[req.ID], "Duplicate ID found: %s", req.ID)
		ids[req.ID] = true
		req.cancel() // Clean up
	}

	assert.Equal(t, numGoroutines, requestCount)
	assert.Equal(t, numGoroutines, len(ids))
}

// TestConcurrentGetAndAdd verifies concurrent read/write operations
func TestConcurrentGetAndAdd(t *testing.T) {
	t.Parallel()

	pm := NewPingManager("https://example.com")
	nodeID := types.NodeID(1)
	numOperations := 100

	var wg sync.WaitGroup

	// Create requests in one goroutine
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < numOperations; i++ {
			req, err := pm.CreatePingRequest(nodeID, "disco", "100.64.0.1", nil)
			if err != nil {
				t.Errorf("Error creating request: %v", err)
				continue
			}
			// Clean up after a short delay
			go func(r *PingRequest) {
				time.Sleep(10 * time.Millisecond)
				r.cancel()
			}(req)
		}
	}()

	// Read requests in another goroutine
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < numOperations; i++ {
			// Try to get a request (may or may not exist)
			pm.GetRequest("any-id")
			time.Sleep(1 * time.Millisecond)
		}
	}()

	wg.Wait()
}

// TestHighVolumePingRequests stress tests with many requests
func TestHighVolumePingRequests(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping high-volume test in short mode")
	}
	t.Parallel()

	pm := NewPingManager("https://example.com")
	numRequests := 1000
	nodeID := types.NodeID(1)

	requests := make([]*PingRequest, 0, numRequests)

	// Create many requests
	for i := 0; i < numRequests; i++ {
		req, err := pm.CreatePingRequest(nodeID, "disco", "100.64.0.1", nil)
		require.NoError(t, err)
		requests = append(requests, req)
	}

	// Verify we can retrieve all of them
	for _, req := range requests {
		retrieved, ok := pm.GetRequest(req.ID)
		assert.True(t, ok)
		assert.Equal(t, req.ID, retrieved.ID)
	}

	// Clean up
	for _, req := range requests {
		req.cancel()
	}

	// Wait for cleanup
	time.Sleep(200 * time.Millisecond)

	// Verify all are cleaned up
	pm.mu.RLock()
	remaining := len(pm.requests)
	pm.mu.RUnlock()

	assert.Equal(t, 0, remaining, "All requests should be cleaned up")
}

// TestCreateKeepAlivePing verifies keep-alive ping creation
func TestCreateKeepAlivePing(t *testing.T) {
	t.Parallel()

	pm := NewPingManager("https://example.com")
	nodeID := types.NodeID(42)

	pingReq, err := pm.CreateKeepAlivePing(nodeID)
	require.NoError(t, err)
	assert.NotNil(t, pingReq)
	assert.Contains(t, pingReq.URL, "https://example.com/machine/ping-response/")
	assert.True(t, pingReq.URLIsNoise)
	assert.False(t, pingReq.Log)
}

// TestCreateHealthCheckPing verifies health check ping creation
func TestCreateHealthCheckPing(t *testing.T) {
	t.Parallel()

	pm := NewPingManager("https://example.com")
	nodeID := types.NodeID(42)
	targetIP := "100.64.0.1"

	pingReq, trackedReq, err := pm.CreateHealthCheckPing(nodeID, targetIP)
	require.NoError(t, err)
	defer trackedReq.cancel()

	assert.NotNil(t, pingReq)
	assert.NotNil(t, trackedReq)
	assert.Contains(t, pingReq.URL, "https://example.com/machine/ping-response/")
	assert.True(t, pingReq.URLIsNoise)
	assert.True(t, pingReq.Log)
	assert.Equal(t, "disco,TSMP", pingReq.Types)
	assert.Equal(t, targetIP, pingReq.IP.String())
}

// TestCreateHealthCheckPingInvalidIP verifies error handling for invalid IPs
func TestCreateHealthCheckPingInvalidIP(t *testing.T) {
	t.Parallel()

	pm := NewPingManager("https://example.com")
	nodeID := types.NodeID(42)

	_, _, err := pm.CreateHealthCheckPing(nodeID, "invalid-ip")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid IP address")
}

// TestCreateC2NPing verifies c2n ping creation
func TestCreateC2NPing(t *testing.T) {
	t.Parallel()

	pm := NewPingManager("https://example.com")
	nodeID := types.NodeID(42)
	httpRequest := []byte("GET /status HTTP/1.1\r\n\r\n")

	pingReq, trackedReq, err := pm.CreateC2NPing(nodeID, httpRequest)
	require.NoError(t, err)
	defer trackedReq.cancel()

	assert.NotNil(t, pingReq)
	assert.NotNil(t, trackedReq)
	assert.Contains(t, pingReq.URL, "https://example.com/machine/ping-response/")
	assert.True(t, pingReq.URLIsNoise)
	assert.True(t, pingReq.Log)
	assert.Equal(t, "c2n", pingReq.Types)
	assert.Equal(t, httpRequest, pingReq.Payload)
}

// TestPingRequestContextCancellation verifies proper context handling
func TestPingRequestContextCancellation(t *testing.T) {
	t.Parallel()

	pm := NewPingManager("https://example.com")
	nodeID := types.NodeID(1)

	req, err := pm.CreatePingRequest(nodeID, "disco", "100.64.0.1", nil)
	require.NoError(t, err)

	// Verify context is not cancelled initially
	select {
	case <-req.ctx.Done():
		t.Fatal("Context should not be cancelled initially")
	default:
		// Expected
	}

	// Cancel the context
	req.cancel()

	// Verify context is now cancelled
	select {
	case <-req.ctx.Done():
		// Expected
		assert.Error(t, req.ctx.Err())
	case <-time.After(1 * time.Second):
		t.Fatal("Context should be cancelled")
	}
}

// TestMultipleResponsesToSameRequest verifies only first response is delivered
func TestMultipleResponsesToSameRequest(t *testing.T) {
	t.Parallel()

	pm := NewPingManager("https://example.com")
	nodeID := types.NodeID(1)

	req, err := pm.CreatePingRequest(nodeID, "disco", "100.64.0.1", nil)
	require.NoError(t, err)
	defer req.cancel()

	// Send first response
	response1 := &tailcfg.PingResponse{
		Type:   tailcfg.PingDisco,
		NodeIP: "100.64.0.1",
	}
	err = pm.HandleResponse(req.ID, response1)
	require.NoError(t, err)

	// Receive first response
	select {
	case received := <-req.ResponseChan:
		assert.Equal(t, response1.NodeIP, received.NodeIP)
	case <-time.After(1 * time.Second):
		t.Fatal("Timeout waiting for first response")
	}

	// Try to send second response (should block or timeout)
	response2 := &tailcfg.PingResponse{
		Type:   tailcfg.PingDisco,
		NodeIP: "100.64.0.2",
	}

	// This should either timeout or block since channel is unbuffered and already consumed
	done := make(chan error, 1)
	go func() {
		done <- pm.HandleResponse(req.ID, response2)
	}()

	// Give it a moment, but it should not complete quickly since channel has no receiver
	select {
	case err := <-done:
		// If it does complete, it should be because context was cancelled or similar
		if err == nil {
			t.Error("Second response should not succeed without a receiver")
		}
	case <-time.After(100 * time.Millisecond):
		// Expected - the goroutine should be blocked
	}
}

// TestPingRequestMemoryCleanup verifies requests are cleaned up from memory
func TestPingRequestMemoryCleanup(t *testing.T) {
	t.Parallel()

	pm := NewPingManager("https://example.com")
	nodeID := types.NodeID(1)

	// Create multiple requests
	for i := 0; i < 10; i++ {
		req, err := pm.CreatePingRequest(nodeID, "disco", "100.64.0.1", nil)
		require.NoError(t, err)
		req.cancel() // Cancel immediately
	}

	// Wait for cleanup
	time.Sleep(200 * time.Millisecond)

	// Verify map is empty
	pm.mu.RLock()
	count := len(pm.requests)
	pm.mu.RUnlock()

	assert.Equal(t, 0, count, "All requests should be cleaned up from memory")
}

// TestPingResponseSerialization verifies JSON marshaling/unmarshaling
func TestPingResponseSerialization(t *testing.T) {
	t.Parallel()

	response := &tailcfg.PingResponse{
		Type:   tailcfg.PingDisco,
		NodeIP: "100.64.0.1",
		Err:    "test error",
	}

	// Marshal
	data, err := json.Marshal(response)
	require.NoError(t, err)

	// Unmarshal
	var decoded tailcfg.PingResponse
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, response.Type, decoded.Type)
	assert.Equal(t, response.NodeIP, decoded.NodeIP)
	assert.Equal(t, response.Err, decoded.Err)
}

// TestPingManagerNilHandling verifies graceful handling of nil values
func TestPingManagerNilHandling(t *testing.T) {
	t.Parallel()

	pm := NewPingManager("https://example.com")
	nodeID := types.NodeID(1)

	// Create request with nil payload (should be fine)
	req, err := pm.CreatePingRequest(nodeID, "disco", "100.64.0.1", nil)
	require.NoError(t, err)
	assert.Nil(t, req.Payload)
	req.cancel()

	// Create request with empty string types (should be fine)
	req2, err := pm.CreatePingRequest(nodeID, "", "", nil)
	require.NoError(t, err)
	assert.Empty(t, req2.Types)
	req2.cancel()
}

// TestConcurrentResponseHandling verifies thread-safe response handling
func TestConcurrentResponseHandling(t *testing.T) {
	t.Parallel()

	pm := NewPingManager("https://example.com")
	numRequests := 50

	// Create multiple requests
	requests := make([]*PingRequest, 0, numRequests)
	for i := 0; i < numRequests; i++ {
		req, err := pm.CreatePingRequest(types.NodeID(uint64(i)), "disco", "100.64.0.1", nil)
		require.NoError(t, err)
		requests = append(requests, req)
	}

	// Handle responses concurrently
	var wg sync.WaitGroup
	for i, req := range requests {
		wg.Add(1)
		go func(r *PingRequest, idx int) {
			defer wg.Done()
			response := &tailcfg.PingResponse{
				Type:   tailcfg.PingDisco,
				NodeIP: "100.64.0.1",
			}
			err := pm.HandleResponse(r.ID, response)
			assert.NoError(t, err)
		}(req, i)
	}

	// Receive all responses
	for _, req := range requests {
		wg.Add(1)
		go func(r *PingRequest) {
			defer wg.Done()
			select {
			case <-r.ResponseChan:
				// Success
			case <-time.After(2 * time.Second):
				t.Error("Timeout waiting for response")
			}
		}(req)
	}

	wg.Wait()

	// Clean up
	for _, req := range requests {
		req.cancel()
	}
}

// TestURLFormat verifies correct URL formatting
func TestURLFormat(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name    string
		baseURL string
	}{
		{
			name:    "HTTPS URL",
			baseURL: "https://example.com",
		},
		{
			name:    "HTTP URL",
			baseURL: "http://localhost:8080",
		},
		{
			name:    "URL with path",
			baseURL: "https://example.com/headscale",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			pm := NewPingManager(tc.baseURL)
			nodeID := types.NodeID(1)

			req, err := pm.CreatePingRequest(nodeID, "disco", "100.64.0.1", nil)
			require.NoError(t, err)
			defer req.cancel()

			assert.Contains(t, req.URL, tc.baseURL)
			assert.Contains(t, req.URL, "/machine/ping-response/")
			assert.Contains(t, req.URL, req.ID)
		})
	}
}
