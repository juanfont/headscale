package hscontrol

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/gorilla/mux"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/rs/zerolog/log"
)

// RegisterWebApps registers the web apps configured in the config.
func RegisterWebApps(router *mux.Router, cfg types.WebConfig) {
	if !cfg.Enabled {
		return
	}

	for name, app := range cfg.Apps {
		if app.URLPath == "" || app.Root == "" {
			log.Warn().
				Str("name", name).
				Msg("skipping web app with incomplete configuration")
			continue
		}

		log.Info().
			Str("name", name).
			Str("root", app.Root).
			Str("url_path", app.URLPath).
			Str("spa", fmt.Sprintf("%v", app.SPA)).
			Msg("registering web app")

		handler := fileHandler(app.URLPath, app.Root, app.SPA)

		router.
			PathPrefix(app.URLPath).
			Handler(handler)
	}
}

func fileHandler(urlPath, root string, spa bool) http.Handler {
	root = filepath.Clean(root)
	fs := http.FileServer(http.Dir(root))
	rootIndex := filepath.Join(root, "index.html")

	return http.StripPrefix(urlPath, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.NotFound(w, r)
			return
		}

		reqPath := filepath.Clean(r.URL.Path)
		fullPath := filepath.Join(root, reqPath)

		if !strings.HasPrefix(fullPath, root) {
			http.NotFound(w, r)
			return
		}

		info, err := os.Stat(fullPath)
		if err == nil {
			if info.IsDir() {
				// Directory: serve index.html if exists
				indexFile := filepath.Join(fullPath, "index.html")
				if _, err := os.Stat(indexFile); err == nil {
					http.ServeFile(w, r, indexFile)
					return
				}
			} else {
				// Regular file
				fs.ServeHTTP(w, r)
				return
			}
		}

		// SPA fallback
		if spa {
			if _, err := os.Stat(rootIndex); err == nil {
				http.ServeFile(w, r, rootIndex)
				return
			}
		}

		// Not found
		http.NotFound(w, r)
	}))
}
