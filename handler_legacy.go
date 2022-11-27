//go:build ts2019

package headscale

import (
	"net/http"
	httpu "github.com/juanfont/headscale/http_utils"
	re "regexp"
	
	"github.com/gorilla/mux"
)

func (h *Headscale) addLegacyHandlers(router *mux.Router) {
	machRouter:= router.PathPrefix("/machine/").Subrouter()
	machRouter.Use(httpu.CharWhitelistMiddlewareGenerator(re.MustCompile("[a-fA-F0-9]+"), "mkey", "invalid characters in machine key"))
	//equivalent to "/machine/{mkey}/map"
	machRouter.HandleFunc("{mkey}/map", h.PollNetMapHandler).Methods(http.MethodPost)
	//equivalent to "/machine/{mkey}"
	machRouter.HandleFunc("{mkey}", h.RegistrationHandler).Methods(http.MethodPost)

}
