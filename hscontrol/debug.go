package hscontrol

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/arl/statsviz"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"tailscale.com/tailcfg"
	"tailscale.com/tsweb"
)

func (h *Headscale) debugHTTPServer() *http.Server {
	debugMux := http.NewServeMux()
	debug := tsweb.Debugger(debugMux)
	debug.Handle("notifier", "Connected nodes in notifier", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(h.nodeNotifier.String()))
	}))
	debug.Handle("config", "Current configuration", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		config, err := json.MarshalIndent(h.cfg, "", "  ")
		if err != nil {
			httpError(w, err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write(config)
	}))
	debug.Handle("policy", "Current policy", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pol, err := h.policyBytes()
		if err != nil {
			httpError(w, err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write(pol)
	}))
	debug.Handle("filter", "Current filter", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		filter := h.polMan.Filter()

		filterJSON, err := json.MarshalIndent(filter, "", "  ")
		if err != nil {
			httpError(w, err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write(filterJSON)
	}))
	debug.Handle("ssh", "SSH Policy per node", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nodes, err := h.db.ListNodes()
		if err != nil {
			httpError(w, err)
			return
		}

		sshPol := make(map[string]*tailcfg.SSHPolicy)
		for _, node := range nodes {
			pol, err := h.polMan.SSHPolicy(node)
			if err != nil {
				httpError(w, err)
				return
			}

			sshPol[fmt.Sprintf("id:%d  hostname:%s givenname:%s", node.ID, node.Hostname, node.GivenName)] = pol
		}

		sshJSON, err := json.MarshalIndent(sshPol, "", "  ")
		if err != nil {
			httpError(w, err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write(sshJSON)
	}))
	debug.Handle("derpmap", "Current DERPMap", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		dm := h.DERPMap

		dmJSON, err := json.MarshalIndent(dm, "", "  ")
		if err != nil {
			httpError(w, err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write(dmJSON)
	}))
	debug.Handle("registration-cache", "Pending registrations", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		registrationsJSON, err := json.MarshalIndent(h.registrationCache.Items(), "", "  ")
		if err != nil {
			httpError(w, err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write(registrationsJSON)
	}))
	debug.Handle("routes", "Routes", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(h.primaryRoutes.String()))
	}))
	debug.Handle("policy-manager", "Policy Manager", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(h.polMan.DebugString()))
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
