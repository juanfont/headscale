//go:build newcli

package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestReleases: the lookup reads the tag names, and its request ends with
// its context rather than at the exit of the process.
func TestReleases(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("no lookup on this system")
	}

	arrived, ended := make(chan struct{}), make(chan struct{})
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Has("hang") {
			close(arrived)
			<-r.Context().Done()
			close(ended)

			return
		}

		_, _ = w.Write([]byte(`[{"name": "v0.30.1"}, {"name": "v0.31.0-beta.1"}]`))
	}))

	t.Cleanup(func() { s.CloseClientConnections(); s.Close() })

	tags, err := releases(s.URL)(t.Context())
	require.NoError(t, err)
	require.Equal(t, []string{"v0.30.1", "v0.31.0-beta.1"}, tags)

	ctx, cancel := context.WithCancel(t.Context())

	go func() { <-arrived; cancel() }()

	_, err = releases(s.URL + "?hang")(ctx)
	require.ErrorIs(t, err, context.Canceled)

	select {
	case <-ended:
	case <-time.After(10 * time.Second):
		t.Fatal("the request to GitHub outlived its context")
	}
}
