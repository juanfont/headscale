package hscontrol

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/arl/statsviz"
	"github.com/juanfont/headscale/hscontrol/templates"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/types/change"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"tailscale.com/tailcfg"
	"tailscale.com/tsweb"
)

// protectedDebugHandler wraps an [http.Handler] with an access check that
// allows requests from loopback, Tailscale CGNAT IPs, and private
// (RFC 1918 / RFC 4193) addresses. This extends [tsweb.Protected] which
// only allows loopback and Tailscale IPs.
func protectedDebugHandler(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if tsweb.AllowDebugAccess(r) {
			h.ServeHTTP(w, r)

			return
		}

		// [tsweb.AllowDebugAccess] rejects X-Forwarded-For and non-TS IPs.
		// Additionally allow private/LAN addresses so operators can reach
		// debug endpoints from their local network without tailscaled.
		ipStr, _, err := net.SplitHostPort(r.RemoteAddr)
		if err == nil {
			ip, parseErr := netip.ParseAddr(ipStr)
			if parseErr == nil && ip.IsPrivate() {
				h.ServeHTTP(w, r)

				return
			}
		}

		http.Error(w, "debug access denied", http.StatusForbidden)
	})
}

// writeJSON marshals v with indentation and writes it as a 200 JSON response.
func writeJSON(w http.ResponseWriter, v any) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		httpError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(b)
}

// writeDebug renders a debug endpoint as JSON or text/plain depending on the
// request's Accept header. JSON is produced only when explicitly requested;
// text/plain is the default for backward compatibility.
func writeDebug(w http.ResponseWriter, r *http.Request, jsonVal func() any, textVal func() string) {
	if strings.Contains(r.Header.Get("Accept"), "application/json") {
		writeJSON(w, jsonVal())
		return
	}

	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(textVal()))
}

func (h *Headscale) debugHTTPServer() *http.Server {
	debugMux := http.NewServeMux()
	debug := tsweb.Debugger(debugMux)

	// State overview endpoint
	debug.Handle("overview", "State overview", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeDebug(w, r, func() any { return h.state.DebugOverviewJSON() }, h.state.DebugOverview)
	}))

	// Configuration endpoint
	debug.Handle("config", "Current configuration", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, h.state.DebugConfig())
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
		_, _ = w.Write([]byte(policy))
	}))

	// Filter rules endpoint
	debug.Handle("filter", "Current filter rules", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		filter, err := h.state.DebugFilter()
		if err != nil {
			httpError(w, err)
			return
		}

		writeJSON(w, filter)
	}))

	// SSH policies endpoint
	debug.Handle("ssh", "SSH policies per node", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, h.state.DebugSSHPolicies())
	}))

	// DERP map endpoint
	debug.Handle("derp", "DERP map configuration", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeDebug(w, r, func() any { return h.state.DebugDERPJSON() }, h.state.DebugDERPMap)
	}))

	// [state.NodeStore] endpoint
	debug.Handle("nodestore", "NodeStore information", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeDebug(w, r, func() any { return h.state.DebugNodeStoreJSON() }, h.state.DebugNodeStore)
	}))

	// Registration cache endpoint
	debug.Handle("registration-cache", "Registration cache information", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, h.state.DebugRegistrationCache())
	}))

	// Routes endpoint
	debug.Handle("routes", "Primary routes", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeDebug(w, r, func() any { return h.state.DebugRoutes() }, h.state.DebugRoutesString)
	}))

	// Policy manager endpoint
	debug.Handle("policy-manager", "Policy manager state", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeDebug(w, r, func() any { return h.state.DebugPolicyManagerJSON() }, h.state.DebugPolicyManager)
	}))

	debug.Handle("mapresponses", "Map responses for all nodes", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		res, err := h.mapBatcher.DebugMapResponses()
		if err != nil {
			httpError(w, err)
			return
		}

		if res == nil {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("HEADSCALE_DEBUG_DUMP_MAPRESPONSE_PATH not set"))

			return
		}

		writeJSON(w, res)
	}))

	// [mapper.Batcher] endpoint
	debug.Handle("batcher", "Batcher connected nodes", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeDebug(w, r, func() any { return h.debugBatcherJSON() }, h.debugBatcher)
	}))

	// Ping endpoint: sends a [tailcfg.PingRequest] to a node and waits for it to respond.
	// Supports POST (form submit) and GET with ?node= (clickable quick-ping links).
	debug.Handle("ping", "Ping a node to check connectivity", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var (
			query  string
			result *templates.PingResult
		)

		switch r.Method {
		case http.MethodPost:
			r.Body = http.MaxBytesReader(w, r.Body, 4096) //nolint:mnd

			err := r.ParseForm()
			if err != nil {
				http.Error(w, "bad form data", http.StatusBadRequest)
				return
			}

			query = r.FormValue("node")
			result = h.doPing(r.Context(), query)
		case http.MethodGet:
			// Support ?node= for auto-ping links from other debug pages.
			if q := r.URL.Query().Get("node"); q != "" {
				query = q
				result = h.doPing(r.Context(), query)
			}
		}

		nodes := h.connectedNodesList()

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(templates.PingPage(query, result, nodes).Render())) //nolint:gosec // G705: templ component auto-escapes
	}))

	// [statsviz.Register] would mount handlers directly on the raw mux,
	// bypassing the access gate. Build the server by hand and wrap
	// each handler with [protectedDebugHandler].
	statsvizSrv, err := statsviz.NewServer()
	if err == nil {
		debugMux.Handle("/debug/statsviz/", protectedDebugHandler(statsvizSrv.Index()))
		debugMux.Handle("/debug/statsviz/ws", protectedDebugHandler(statsvizSrv.Ws()))
		debug.URL("/debug/statsviz", "Statsviz (visualise go metrics)")
	}

	debug.URL("/metrics", "Prometheus metrics")
	debugMux.Handle("/metrics", promhttp.Handler())

	debugHTTPServer := &http.Server{
		Addr:         h.cfg.MetricsAddr,
		Handler:      securityHeaders(debugMux),
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

	debugInfo := h.mapBatcher.Debug()
	nodes := make([]nodeStatus, 0, len(debugInfo))

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

	// Sort by node ID
	slices.SortFunc(nodes, func(a, b nodeStatus) int {
		return cmp.Compare(a.id, b.id)
	})

	// Output sorted nodes
	for _, node := range nodes {
		status := "disconnected"
		if node.connected {
			status = "connected"
		}

		if node.activeConnections > 0 {
			fmt.Fprintf(&sb, "Node %d:\t%s (%d connections)\n", node.id, status, node.activeConnections)
		} else {
			fmt.Fprintf(&sb, "Node %d:\t%s\n", node.id, status)
		}
	}

	fmt.Fprintf(&sb, "\nSummary: %d connected, %d total\n", connectedCount, totalNodes)

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

	debugInfo := h.mapBatcher.Debug()
	for nodeID, debugData := range debugInfo {
		info.ConnectedNodes[fmt.Sprintf("%d", nodeID)] = DebugBatcherNodeInfo{
			Connected:         debugData.Connected,
			ActiveConnections: debugData.ActiveConnections,
		}
		info.TotalNodes++
	}

	return info
}

// connectedNodesList returns a list of connected nodes for the ping page.
func (h *Headscale) connectedNodesList() []templates.ConnectedNode {
	debugInfo := h.mapBatcher.Debug()

	var nodes []templates.ConnectedNode

	for nodeID, info := range debugInfo {
		if !info.Connected {
			continue
		}

		nv, ok := h.state.GetNodeByID(nodeID)
		if !ok {
			continue
		}

		cn := templates.ConnectedNode{
			ID:       nodeID,
			Hostname: nv.Hostname(),
		}

		for _, ip := range nv.IPs() {
			cn.IPs = append(cn.IPs, ip.String())
		}

		nodes = append(nodes, cn)
	}

	return nodes
}

const pingTimeout = 30 * time.Second

// doPing sends a [tailcfg.PingRequest] to the node identified by query and waits for a response.
func (h *Headscale) doPing(ctx context.Context, query string) *templates.PingResult {
	if query == "" {
		return &templates.PingResult{
			Status:  "error",
			Message: "No node specified.",
		}
	}

	node, ok := h.state.ResolveNode(query)
	if !ok {
		return &templates.PingResult{
			Status:  "error",
			Message: fmt.Sprintf("Node %q not found.", query),
		}
	}

	nodeID := node.ID()

	if !h.mapBatcher.IsConnected(nodeID) {
		return &templates.PingResult{
			Status:  "error",
			NodeID:  nodeID,
			Message: fmt.Sprintf("Node %d is not connected.", nodeID),
		}
	}

	pingID, responseCh := h.state.RegisterPing(nodeID)
	defer h.state.CancelPing(pingID)

	// The callback hits /machine/ping-response on the main TLS router,
	// not the noise chain, so URLIsNoise stays false. Operators running
	// server_url over plain HTTP are on their own — don't do that.
	callbackURL := h.cfg.ServerURL + "/machine/ping-response?id=" + pingID
	h.Change(change.PingNode(nodeID, &tailcfg.PingRequest{
		URL: callbackURL,
		Log: true,
	}))

	select {
	case latency := <-responseCh:
		return &templates.PingResult{
			Status:  "ok",
			Latency: latency,
			NodeID:  nodeID,
		}
	case <-time.After(pingTimeout):
		return &templates.PingResult{
			Status:  "timeout",
			NodeID:  nodeID,
			Message: fmt.Sprintf("No response after %s.", pingTimeout),
		}
	case <-ctx.Done():
		return &templates.PingResult{
			Status:  "error",
			NodeID:  nodeID,
			Message: "Request cancelled.",
		}
	}
}
