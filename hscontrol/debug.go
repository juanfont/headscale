package hscontrol

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

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
