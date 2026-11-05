package main

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/cenkalti/backoff/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFetch(t *testing.T) {
	fetchBackOff = func() backoff.BackOff { return &backoff.ZeroBackOff{} }

	tests := []struct {
		name      string
		statuses  []int // served in order; the last one repeats
		wantBody  string
		wantErr   error
		wantCalls int32
	}{
		{
			name:      "not-found-is-not-retried",
			statuses:  []int{http.StatusNotFound},
			wantErr:   errNotFound,
			wantCalls: 1,
		},
		{
			name:      "unavailable-then-ok",
			statuses:  []int{http.StatusServiceUnavailable, http.StatusOK},
			wantBody:  "body",
			wantCalls: 2,
		},
		{
			name:      "always-unavailable-fails",
			statuses:  []int{http.StatusServiceUnavailable},
			wantErr:   errUnexpectedStatusCode,
			wantCalls: fetchTries,
		},
		{
			name:      "forbidden-is-not-retried",
			statuses:  []int{http.StatusForbidden},
			wantErr:   errUnexpectedStatusCode,
			wantCalls: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var calls atomic.Int32

			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				n := int(calls.Add(1)) - 1
				w.WriteHeader(tt.statuses[min(n, len(tt.statuses)-1)])
				_, _ = w.Write([]byte("body"))
			}))
			defer srv.Close()

			body, err := fetch(t.Context(), srv.URL, "")
			if tt.wantErr != nil {
				require.ErrorIs(t, err, tt.wantErr)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.wantBody, string(body))
			}

			assert.Equal(t, tt.wantCalls, calls.Load())
		})
	}
}
