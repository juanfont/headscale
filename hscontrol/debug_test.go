package hscontrol

import (
	"net/http"
	"strings"
	"testing"

	"github.com/gorilla/mux"
)

func TestDebugHTTPRoutes(t *testing.T) {
	// Create a test router with some sample routes
	router := mux.NewRouter()
	router.HandleFunc("/test1", testHandler1).Methods(http.MethodGet).Name("test1-route")
	router.HandleFunc("/test2", testHandler2).Methods(http.MethodPost, http.MethodPut)
	router.HandleFunc("/test3/{id}", testHandler3)

	// Create a test Headscale instance
	h := &Headscale{}

	// Test text format
	textOutput := h.debugHTTPRoutes(router)
	if !strings.Contains(textOutput, "/test1") {
		t.Errorf("Expected output to contain /test1, got: %s", textOutput)
	}

	if !strings.Contains(textOutput, "Total routes:") {
		t.Errorf("Expected output to contain total routes count, got: %s", textOutput)
	}

	// Test JSON format
	jsonOutput := h.debugHTTPRoutesJSON(router)
	if jsonOutput.TotalCount != 3 {
		t.Errorf("Expected 3 routes, got: %d", jsonOutput.TotalCount)
	}

	// Verify first route has the name we set
	foundNamedRoute := false

	for _, route := range jsonOutput.Routes {
		if route.Name == "test1-route" {
			foundNamedRoute = true
			break
		}
	}

	if !foundNamedRoute {
		t.Error("Expected to find route with name 'test1-route'")
	}
}

func testHandler1(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
}

func testHandler2(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
}

func testHandler3(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
}
