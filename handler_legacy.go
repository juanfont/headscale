//go:build ts2019

package headscale

import (
	"net/http"

	"github.com/gorilla/mux"
)

func (h *Headscale) addLegacyHandlers(router *mux.Router) {
	router.HandleFunc("/machine/{mkey}/map", h.PollNetMapHandler).
		Methods(http.MethodPost)
	router.HandleFunc("/machine/{mkey}", h.RegistrationHandler).Methods(http.MethodPost)
}
