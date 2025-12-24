package hscontrol

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	"github.com/juanfont/headscale/hscontrol/types"
)

func TestRegisterWebApps(t *testing.T) {
	tmpDir := t.TempDir()

	// index.hyml
	// index.js
	os.WriteFile(filepath.Join(tmpDir, "index.html"), []byte("root index"), 0644)
	os.WriteFile(filepath.Join(tmpDir, "index.js"), []byte("root js"), 0644)

	// /dir1/index.html
	// /dir1/1.js
	dir1 := filepath.Join(tmpDir, "dir1")
	os.MkdirAll(dir1, 0755)
	os.WriteFile(filepath.Join(dir1, "index.html"), []byte("dir1 index"), 0644)
	os.WriteFile(filepath.Join(dir1, "1.js"), []byte("dir1 js"), 0644)

	// /dir2/2.js
	dir2 := filepath.Join(tmpDir, "dir2")
	os.MkdirAll(dir2, 0755)
	os.WriteFile(filepath.Join(dir2, "2.js"), []byte("dir2 js"), 0644)

	prefix := "/app" // simulate URLPath prefix

	tests := []struct {
		path     string
		expected string
		status   int
		spa      bool
	}{
		// SPA mode
		{prefix + "/", "root index", http.StatusOK, true},
		{prefix + "/index.js", "root js", http.StatusOK, true},
		{prefix + "/dir1/", "dir1 index", http.StatusOK, true},
		{prefix + "/dir1/1.js", "dir1 js", http.StatusOK, true},
		{prefix + "/dir2/", "root index", http.StatusOK, true}, // fallback to root index.html
		{prefix + "/dir2/2.js", "dir2 js", http.StatusOK, true},
		{prefix + "/dir3/", "root index", http.StatusOK, true}, // non-existent directory fallback
		{prefix + "/dir3/file", "root index", http.StatusOK, true},

		// Non-SPA mode
		{prefix + "/", "root index", http.StatusOK, false},
		{prefix + "/index.js", "root js", http.StatusOK, false},
		{prefix + "/dir1/", "dir1 index", http.StatusOK, false},
		{prefix + "/dir1/1.js", "dir1 js", http.StatusOK, false},
		{prefix + "/dir2/", "", http.StatusNotFound, false}, // no index.html
		{prefix + "/dir2/2.js", "dir2 js", http.StatusOK, false},
		{prefix + "/dir3/", "", http.StatusNotFound, false},
		{prefix + "/dir3/file", "", http.StatusNotFound, false},
	}

	// Note: Accessing any "/*/index.html" file via FileServer or ServeFile
	// will automatically trigger a 301 redirect to the directory path with trailing '/',
	// e.g., "/dir1/index.html" -> "/dir1/".
	// This is default behavior of Go's http.FileServer for directories.
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			router := mux.NewRouter()
			cfg := types.WebConfig{
				Enabled: true,
				Apps: map[string]types.WebAppConfig{
					"app": {
						URLPath: prefix,
						Root:    tmpDir,
						SPA:     tt.spa,
					},
				},
			}
			RegisterWebApps(router, cfg)

			req := httptest.NewRequest(http.MethodGet, tt.path, nil)
			rr := httptest.NewRecorder()
			router.ServeHTTP(rr, req)

			// Check HTTP status
			if rr.Code != tt.status {
				t.Fatalf("path %q: expected status %d, got %d head %s", tt.path, tt.status, rr.Code, rr.Header())
			}
			// Check response content if expected
			if tt.expected != "" && !strings.Contains(rr.Body.String(), tt.expected) {
				t.Fatalf("path %q: expected body to contain %q, got %q", tt.path, tt.expected, rr.Body.String())
			}
		})
	}
}
