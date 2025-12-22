package hscontrol

import (
	_ "io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func createTestFiles(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for path, content := range files {
		fullPath := filepath.Join(root, path)
		dir := filepath.Dir(fullPath)
		if err := os.MkdirAll(dir, 0755); err != nil {
			t.Fatalf("failed to create dir: %v", err)
		}
		if err := os.WriteFile(fullPath, []byte(content), 0644); err != nil {
			t.Fatalf("failed to write file: %v", err)
		}
	}
}

func TestFileHandler(t *testing.T) {
	root := t.TempDir()

	files := map[string]string{
		"file.txt":       "hello file",
		"dir/index.html": "<html>dir index</html>",
		"index.html":     "<html>root index</html>",
	}

	createTestFiles(t, root, files)

	tests := []struct {
		name       string
		urlPath    string
		uri        string
		spa        bool
		wantStatus int
		wantBody   string
	}{
		{
			name:       "existing file",
			urlPath:    "/",
			uri:        "/file.txt",
			spa:        false,
			wantStatus: 200,
			wantBody:   "hello file",
		},
		{
			name:       "directory with index.html",
			urlPath:    "/",
			uri:        "/dir/",
			spa:        false,
			wantStatus: 200,
			wantBody:   "<html>dir index</html>",
		},
		{
			name:       "nonexistent file with SPA",
			urlPath:    "/",
			uri:        "/notfound",
			spa:        true,
			wantStatus: 200,
			wantBody:   "<html>root index</html>",
		},
		{
			name:       "nonexistent file without SPA",
			urlPath:    "/",
			uri:        "/notfound",
			spa:        false,
			wantStatus: 404,
			wantBody:   "",
		},
		{
			name:       "non GET/HEAD method",
			urlPath:    "/",
			uri:        "/file.txt",
			spa:        false,
			wantStatus: 404,
			wantBody:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := fileHandler(tt.urlPath, root, tt.spa)
			method := http.MethodGet
			if strings.Contains(tt.name, "non GET/HEAD") {
				method = http.MethodPost
			}
			req := httptest.NewRequest(method, tt.uri, nil)
			rr := httptest.NewRecorder()

			handler.ServeHTTP(rr, req)

			if rr.Code != tt.wantStatus {
				t.Errorf("expected status %d, got %d", tt.wantStatus, rr.Code)
			}

			if tt.wantBody != "" && !strings.Contains(rr.Body.String(), tt.wantBody) {
				t.Errorf("expected body %q, got %q", tt.wantBody, rr.Body.String())
			}
		})
	}
}
