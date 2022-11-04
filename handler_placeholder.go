//go:build !ts2019

package headscale

import "github.com/gorilla/mux"

func (h *Headscale) addLegacyHandlers(router *mux.Router) {
}
