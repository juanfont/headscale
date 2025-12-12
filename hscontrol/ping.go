package hscontrol

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"sync"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/rs/zerolog/log"
	"tailscale.com/tailcfg"
)

// PingRequest tracks a pending ping request to a client
type PingRequest struct {
	ID           string
	NodeID       types.NodeID
	URL          string
	Types        string
	IP           string
	Payload      []byte
	CreatedAt    time.Time
	ResponseChan chan *tailcfg.PingResponse
	ctx          context.Context
	cancel       context.CancelFunc
}

// PingManager manages ping requests to clients
type PingManager struct {
	mu       sync.RWMutex
	requests map[string]*PingRequest
	baseURL  string
}

// NewPingManager creates a new ping manager
func NewPingManager(baseURL string) *PingManager {
	return &PingManager{
		requests: make(map[string]*PingRequest),
		baseURL:  baseURL,
	}
}

// CreatePingRequest creates a new ping request with a unique URL
func (pm *PingManager) CreatePingRequest(nodeID types.NodeID, pingType string, targetIP string, payload []byte) (*PingRequest, error) {
	// Generate unique request ID
	idBytes := make([]byte, 16)
	if _, err := rand.Read(idBytes); err != nil {
		return nil, fmt.Errorf("generating request ID: %w", err)
	}
	requestID := hex.EncodeToString(idBytes)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)

	req := &PingRequest{
		ID:           requestID,
		NodeID:       nodeID,
		URL:          fmt.Sprintf("%s/machine/ping-response/%s", pm.baseURL, requestID),
		Types:        pingType,
		IP:           targetIP,
		Payload:      payload,
		CreatedAt:    time.Now(),
		ResponseChan: make(chan *tailcfg.PingResponse, 1),
		ctx:          ctx,
		cancel:       cancel,
	}

	pm.mu.Lock()
	pm.requests[requestID] = req
	pm.mu.Unlock()

	// Clean up after timeout
	go func() {
		<-ctx.Done()
		pm.mu.Lock()
		delete(pm.requests, requestID)
		pm.mu.Unlock()
		close(req.ResponseChan)
	}()

	return req, nil
}

// GetRequest retrieves a ping request by ID
func (pm *PingManager) GetRequest(requestID string) (*PingRequest, bool) {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	req, ok := pm.requests[requestID]
	return req, ok
}

// HandleResponse handles an incoming ping response
func (pm *PingManager) HandleResponse(requestID string, response *tailcfg.PingResponse) error {
	pm.mu.RLock()
	req, ok := pm.requests[requestID]
	pm.mu.RUnlock()

	if !ok {
		return fmt.Errorf("unknown request ID: %s", requestID)
	}

	select {
	case req.ResponseChan <- response:
		return nil
	case <-req.ctx.Done():
		return fmt.Errorf("request timeout")
	}
}

// CreateKeepAlivePing creates a simple keep-alive ping request
func (pm *PingManager) CreateKeepAlivePing(nodeID types.NodeID) (*tailcfg.PingRequest, error) {
	req, err := pm.CreatePingRequest(nodeID, "", "", nil)
	if err != nil {
		return nil, err
	}

	return &tailcfg.PingRequest{
		URL:        req.URL,
		URLIsNoise: true,
		Log:        false,
	}, nil
}

// CreateHealthCheckPing creates a ping to check if a node is responsive
func (pm *PingManager) CreateHealthCheckPing(nodeID types.NodeID, targetIP string) (*tailcfg.PingRequest, *PingRequest, error) {
	req, err := pm.CreatePingRequest(nodeID, "disco,TSMP", targetIP, nil)
	if err != nil {
		return nil, nil, err
	}

	// Parse the IP address - targetIP should be a valid IP string
	addr, err := netip.ParseAddr(targetIP)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid IP address: %w", err)
	}

	return &tailcfg.PingRequest{
		URL:        req.URL,
		URLIsNoise: true,
		Log:        true,
		Types:      req.Types,
		IP:         addr,
	}, req, nil
}

// CreateC2NPing creates a c2n (client-to-node) HTTP request
func (pm *PingManager) CreateC2NPing(nodeID types.NodeID, httpRequest []byte) (*tailcfg.PingRequest, *PingRequest, error) {
	req, err := pm.CreatePingRequest(nodeID, "c2n", "", httpRequest)
	if err != nil {
		return nil, nil, err
	}

	return &tailcfg.PingRequest{
		URL:        req.URL,
		URLIsNoise: true,
		Log:        true,
		Types:      "c2n",
		Payload:    httpRequest,
	}, req, nil
}

// PingResponseHandler handles incoming ping responses from clients
//
// POST /machine/ping-response/:request_id
func (h *Headscale) PingResponseHandler(
	writer http.ResponseWriter,
	req *http.Request,
) {
	if req.Method != http.MethodPost {
		httpError(writer, errMethodNotAllowed)
		return
	}

	// Extract request ID from URL path
	// Format: /machine/ping-response/{request_id}
	path := req.URL.Path
	prefix := "/machine/ping-response/"
	if len(path) <= len(prefix) {
		httpError(writer, NewHTTPError(http.StatusBadRequest, "missing request ID", nil))
		return
	}
	requestID := path[len(prefix):]

	log.Debug().
		Str("request_id", requestID).
		Str("remote_addr", req.RemoteAddr).
		Msg("Received ping response")

	// Read response body
	body, err := io.ReadAll(req.Body)
	if err != nil {
		httpError(writer, NewHTTPError(http.StatusBadRequest, "cannot read request body", err))
		return
	}

	var pingResponse tailcfg.PingResponse
	if err := json.Unmarshal(body, &pingResponse); err != nil {
		httpError(writer, NewHTTPError(http.StatusBadRequest, "invalid JSON", err))
		return
	}

	// Handle the response
	if err := h.pingManager.HandleResponse(requestID, &pingResponse); err != nil {
		log.Warn().
			Err(err).
			Str("request_id", requestID).
			Msg("Failed to handle ping response")
		httpError(writer, NewHTTPError(http.StatusNotFound, "request not found or expired", err))
		return
	}

	log.Info().
		Str("request_id", requestID).
		Str("type", string(pingResponse.Type)).
		Str("node_ip", pingResponse.NodeIP).
		Msg("Successfully processed ping response")

	// Return success
	writer.WriteHeader(http.StatusOK)
	json.NewEncoder(writer).Encode(map[string]interface{}{
		"success": true,
	})
}

// SendPingToNode sends a PingRequest to a specific node via the MapBatcher.
// This bypasses the normal change broadcast system and delivers the ping directly.
func (pm *PingManager) SendPingToNode(
	h *Headscale,
	nodeID types.NodeID,
	pingReq *tailcfg.PingRequest,
) error {
	if pingReq == nil {
		return fmt.Errorf("pingReq cannot be nil")
	}

	resp := &tailcfg.MapResponse{
		PingRequest: pingReq,
		KeepAlive:   false, // This is a real update, not just a keepalive
	}

	return h.mapBatcher.SendDirectUpdate(nodeID, resp)
}

// CheckNodeOnline checks if a node is online by sending a health check ping.
// It creates a ping request, sends it via the MapBatcher, and waits for a response.
func (h *Headscale) CheckNodeOnline(nodeID types.NodeID, targetIP string) (*tailcfg.PingResponse, error) {
	// Create health check ping request
	pingReq, trackedReq, err := h.pingManager.CreateHealthCheckPing(nodeID, targetIP)
	if err != nil {
		return nil, fmt.Errorf("creating ping request: %w", err)
	}

	// Send the ping request to the node
	err = h.pingManager.SendPingToNode(h, nodeID, pingReq)
	if err != nil {
		return nil, fmt.Errorf("sending ping request: %w", err)
	}

	log.Debug().
		Uint64("node.id", nodeID.Uint64()).
		Str("target_ip", targetIP).
		Str("request_id", trackedReq.ID).
		Msg("Sent health check ping to node")

	// Wait for response or timeout
	select {
	case response := <-trackedReq.ResponseChan:
		if response == nil {
			return nil, fmt.Errorf("received nil response")
		}
		return response, nil
	case <-trackedReq.ctx.Done():
		return nil, fmt.Errorf("ping request timeout")
	}
}
