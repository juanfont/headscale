//go:build !ts2019

package hscontrol

import "github.com/gorilla/mux"

func (h *Headscale) addLegacyHandlers(router *mux.Router) {
}
