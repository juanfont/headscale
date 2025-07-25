package hscontrol

import (
	"encoding/json"
	"net/http"

	"github.com/arl/statsviz"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"tailscale.com/tsweb"
)

func (h *Headscale) debugHTTPServer() *http.Server {
	debugMux := http.NewServeMux()
	debug := tsweb.Debugger(debugMux)

	// State overview endpoint
	debug.Handle("overview", "State overview", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		overview := h.state.DebugOverview()
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(overview))
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
		w.Header().Set("Content-Type", "application/json")
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
		derpInfo := h.state.DebugDERPMap()
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(derpInfo))
	}))

	// NodeStore endpoint
	debug.Handle("nodestore", "NodeStore information", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nodeStoreInfo := h.state.DebugNodeStore()
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(nodeStoreInfo))
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
		routes := h.state.DebugRoutes()
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(routes))
	}))

	// Policy manager endpoint
	debug.Handle("policy-manager", "Policy manager state", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		policyManagerInfo := h.state.DebugPolicyManager()
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(policyManagerInfo))
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
