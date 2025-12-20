package hscontrol

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/arl/statsviz"
	"github.com/juanfont/headscale/hscontrol/mapper"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"tailscale.com/tsweb"
)

func (h *Headscale) debugHTTPServer() *http.Server {
	debugMux := http.NewServeMux()
	debug := tsweb.Debugger(debugMux)

	// State overview endpoint
	debug.Handle("overview", "State overview", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check Accept header to determine response format
		acceptHeader := r.Header.Get("Accept")
		wantsJSON := strings.Contains(acceptHeader, "application/json")

		if wantsJSON {
			overview := h.state.DebugOverviewJSON()
			overviewJSON, err := json.MarshalIndent(overview, "", "  ")
			if err != nil {
				httpError(w, err)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write(overviewJSON)
		} else {
			// Default to text/plain for backward compatibility
			overview := h.state.DebugOverview()
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(overview))
		}
	}))

	// Configuration endpoint
	debug.Handle("config", "Current configuration", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		config := h.state.DebugConfig()
		configJSON, err := json.MarshalIndent(config, "", "  ")
		if err != nil {
			httpError(w, err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write(configJSON)
	}))

	// Policy endpoint
	debug.Handle("policy", "Current policy", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		policy, err := h.state.DebugPolicy()
		if err != nil {
			httpError(w, err)
			return
		}
		// Policy data is HuJSON, which is a superset of JSON
		// Set content type based on Accept header preference
		acceptHeader := r.Header.Get("Accept")
		if strings.Contains(acceptHeader, "application/json") {
			w.Header().Set("Content-Type", "application/json")
		} else {
			w.Header().Set("Content-Type", "text/plain")
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(policy))
	}))

	// Filter rules endpoint
	debug.Handle("filter", "Current filter rules", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		filter, err := h.state.DebugFilter()
		if err != nil {
			httpError(w, err)
			return
		}
		filterJSON, err := json.MarshalIndent(filter, "", "  ")
		if err != nil {
			httpError(w, err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write(filterJSON)
	}))

	// SSH policies endpoint
	debug.Handle("ssh", "SSH policies per node", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sshPolicies := h.state.DebugSSHPolicies()
		sshJSON, err := json.MarshalIndent(sshPolicies, "", "  ")
		if err != nil {
			httpError(w, err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write(sshJSON)
	}))

	// DERP map endpoint
	debug.Handle("derp", "DERP map configuration", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check Accept header to determine response format
		acceptHeader := r.Header.Get("Accept")
		wantsJSON := strings.Contains(acceptHeader, "application/json")

		if wantsJSON {
			derpInfo := h.state.DebugDERPJSON()
			derpJSON, err := json.MarshalIndent(derpInfo, "", "  ")
			if err != nil {
				httpError(w, err)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write(derpJSON)
		} else {
			// Default to text/plain for backward compatibility
			derpInfo := h.state.DebugDERPMap()
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(derpInfo))
		}
	}))

	// NodeStore endpoint
	debug.Handle("nodestore", "NodeStore information", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check Accept header to determine response format
		acceptHeader := r.Header.Get("Accept")
		wantsJSON := strings.Contains(acceptHeader, "application/json")

		if wantsJSON {
			nodeStoreNodes := h.state.DebugNodeStoreJSON()
			nodeStoreJSON, err := json.MarshalIndent(nodeStoreNodes, "", "  ")
			if err != nil {
				httpError(w, err)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write(nodeStoreJSON)
		} else {
			// Default to text/plain for backward compatibility
			nodeStoreInfo := h.state.DebugNodeStore()
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(nodeStoreInfo))
		}
	}))

	// Registration cache endpoint
	debug.Handle("registration-cache", "Registration cache information", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cacheInfo := h.state.DebugRegistrationCache()
		cacheJSON, err := json.MarshalIndent(cacheInfo, "", "  ")
		if err != nil {
			httpError(w, err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write(cacheJSON)
	}))

	// Routes endpoint
	debug.Handle("routes", "Primary routes", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check Accept header to determine response format
		acceptHeader := r.Header.Get("Accept")
		wantsJSON := strings.Contains(acceptHeader, "application/json")

		if wantsJSON {
			routes := h.state.DebugRoutes()
			routesJSON, err := json.MarshalIndent(routes, "", "  ")
			if err != nil {
				httpError(w, err)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write(routesJSON)
		} else {
			// Default to text/plain for backward compatibility
			routes := h.state.DebugRoutesString()
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(routes))
		}
	}))

	// Policy manager endpoint
	debug.Handle("policy-manager", "Policy manager state", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check Accept header to determine response format
		acceptHeader := r.Header.Get("Accept")
		wantsJSON := strings.Contains(acceptHeader, "application/json")

		if wantsJSON {
			policyManagerInfo := h.state.DebugPolicyManagerJSON()
			policyManagerJSON, err := json.MarshalIndent(policyManagerInfo, "", "  ")
			if err != nil {
				httpError(w, err)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write(policyManagerJSON)
		} else {
			// Default to text/plain for backward compatibility
			policyManagerInfo := h.state.DebugPolicyManager()
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(policyManagerInfo))
		}
	}))

	debug.Handle("mapresponses", "Map responses for all nodes", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		res, err := h.mapBatcher.DebugMapResponses()
		if err != nil {
			httpError(w, err)
			return
		}

		if res == nil {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("HEADSCALE_DEBUG_DUMP_MAPRESPONSE_PATH not set"))
			return
		}

		resJSON, err := json.MarshalIndent(res, "", "  ")
		if err != nil {
			httpError(w, err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write(resJSON)
	}))

	// Batcher endpoint
	debug.Handle("batcher", "Batcher connected nodes", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check Accept header to determine response format
		acceptHeader := r.Header.Get("Accept")
		wantsJSON := strings.Contains(acceptHeader, "application/json")

		if wantsJSON {
			batcherInfo := h.debugBatcherJSON()

			batcherJSON, err := json.MarshalIndent(batcherInfo, "", "  ")
			if err != nil {
				httpError(w, err)
				return
			}

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write(batcherJSON)
		} else {
			// Default to text/plain for backward compatibility
			batcherInfo := h.debugBatcher()

			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(batcherInfo))
		}
	}))

	err := statsviz.Register(debugMux)
	if err == nil {
		debug.URL("/debug/statsviz", "Statsviz (visualise go metrics)")
	}

	debug.URL("/metrics", "Prometheus metrics")
	debugMux.Handle("/metrics", promhttp.Handler())

	debugHTTPServer := &http.Server{
		Addr:         h.cfg.MetricsAddr,
		Handler:      debugMux,
		ReadTimeout:  types.HTTPTimeout,
		WriteTimeout: 0,
	}

	return debugHTTPServer
}

// debugBatcher returns debug information about the batcher's connected nodes.
func (h *Headscale) debugBatcher() string {
	var sb strings.Builder
	sb.WriteString("=== Batcher Connected Nodes ===\n\n")

	totalNodes := 0
	connectedCount := 0

	// Collect nodes and sort them by ID
	type nodeStatus struct {
		id                types.NodeID
		connected         bool
		activeConnections int
	}

	var nodes []nodeStatus

	// Try to get detailed debug info if we have a LockFreeBatcher
	if batcher, ok := h.mapBatcher.(*mapper.LockFreeBatcher); ok {
		debugInfo := batcher.Debug()
		for nodeID, info := range debugInfo {
			nodes = append(nodes, nodeStatus{
				id:                nodeID,
				connected:         info.Connected,
				activeConnections: info.ActiveConnections,
			})
			totalNodes++
			if info.Connected {
				connectedCount++
			}
		}
	} else {
		// Fallback to basic connection info
		connectedMap := h.mapBatcher.ConnectedMap()
		connectedMap.Range(func(nodeID types.NodeID, connected bool) bool {
			nodes = append(nodes, nodeStatus{
				id:                nodeID,
				connected:         connected,
				activeConnections: 0,
			})
			totalNodes++
			if connected {
				connectedCount++
			}
			return true
		})
	}

	// Sort by node ID
	for i := 0; i < len(nodes); i++ {
		for j := i + 1; j < len(nodes); j++ {
			if nodes[i].id > nodes[j].id {
				nodes[i], nodes[j] = nodes[j], nodes[i]
			}
		}
	}

	// Output sorted nodes
	for _, node := range nodes {
		status := "disconnected"
		if node.connected {
			status = "connected"
		}

		if node.activeConnections > 0 {
			sb.WriteString(fmt.Sprintf("Node %d:\t%s (%d connections)\n", node.id, status, node.activeConnections))
		} else {
			sb.WriteString(fmt.Sprintf("Node %d:\t%s\n", node.id, status))
		}
	}

	sb.WriteString(fmt.Sprintf("\nSummary: %d connected, %d total\n", connectedCount, totalNodes))

	return sb.String()
}

// DebugBatcherInfo represents batcher connection information in a structured format.
type DebugBatcherInfo struct {
	ConnectedNodes map[string]DebugBatcherNodeInfo `json:"connected_nodes"` // NodeID -> node connection info
	TotalNodes     int                             `json:"total_nodes"`
}

// DebugBatcherNodeInfo represents connection information for a single node.
type DebugBatcherNodeInfo struct {
	Connected         bool `json:"connected"`
	ActiveConnections int  `json:"active_connections"`
}

// debugBatcherJSON returns structured debug information about the batcher's connected nodes.
func (h *Headscale) debugBatcherJSON() DebugBatcherInfo {
	info := DebugBatcherInfo{
		ConnectedNodes: make(map[string]DebugBatcherNodeInfo),
		TotalNodes:     0,
	}

	// Try to get detailed debug info if we have a LockFreeBatcher
	if batcher, ok := h.mapBatcher.(*mapper.LockFreeBatcher); ok {
		debugInfo := batcher.Debug()
		for nodeID, debugData := range debugInfo {
			info.ConnectedNodes[fmt.Sprintf("%d", nodeID)] = DebugBatcherNodeInfo{
				Connected:         debugData.Connected,
				ActiveConnections: debugData.ActiveConnections,
			}
			info.TotalNodes++
		}
	} else {
		// Fallback to basic connection info
		connectedMap := h.mapBatcher.ConnectedMap()
		connectedMap.Range(func(nodeID types.NodeID, connected bool) bool {
			info.ConnectedNodes[fmt.Sprintf("%d", nodeID)] = DebugBatcherNodeInfo{
				Connected:         connected,
				ActiveConnections: 0,
			}
			info.TotalNodes++
			return true
		})
	}

	return info
}
