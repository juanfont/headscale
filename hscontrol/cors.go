package hscontrol

import (
	"net/http"
	"slices"
	"strings"
)

const (
	corsAllowMethods  = "GET, POST, PUT, PATCH, DELETE"
	corsAllowHeaders  = "Authorization, Content-Type, If-Match"
	corsExposeHeaders = "ETag, Location, Headscale-Version, Headscale-Commit, Deprecation, Sunset, Link"
)

// cors lets pages on origins call the API from a browser. It answers a
// preflight itself and puts the headers on every other answer, errors
// included, or the browser hides the problem behind a network error. No
// origins: next as is. No credentials mode: the API uses no cookies.
func cors(origins []string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		if len(origins) == 0 {
			return next
		}

		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Add("Vary", "Origin")

			origin := r.Header.Get("Origin")
			if !slices.ContainsFunc(origins, func(o string) bool { return strings.EqualFold(o, origin) }) {
				next.ServeHTTP(w, r)

				return
			}

			w.Header().Set("Access-Control-Allow-Origin", origin)

			if r.Method == http.MethodOptions && r.Header.Get("Access-Control-Request-Method") != "" {
				w.Header().Set("Access-Control-Allow-Methods", corsAllowMethods)
				w.Header().Set("Access-Control-Allow-Headers", corsAllowHeaders)
				w.WriteHeader(http.StatusNoContent)

				return
			}

			w.Header().Set("Access-Control-Expose-Headers", corsExposeHeaders)
			next.ServeHTTP(w, r)
		})
	}
}
