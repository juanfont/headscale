package client

import (
	"context"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	clientv0 "github.com/juanfont/headscale/gen/client/headscale/v0"
	"github.com/stretchr/testify/require"
)

type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(
	req *http.Request,
) (*http.Response, error) {
	return f(req)
}

// TestProbeFailedStaysFirst: a probe that fails, because its answer is no
// answer of GET /version or no success, leaves the next write the first:
// it asks GET /version again, and no write goes out.
func TestProbeFailedStaysFirst(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name   string
		status int
	}{
		{"a 200 that is not the version", http.StatusOK},
		{"a success the operation does not answer", http.StatusCreated},
		{"unavailable", http.StatusServiceUnavailable},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var methods []string

			tr := roundTrip(func(r *http.Request) (*http.Response, error) {
				methods = append(methods, r.Method)

				code := http.StatusNoContent
				if r.Method == http.MethodGet {
					code = tt.status
				}

				resp := &http.Response{
					Request:    r,
					StatusCode: code,
					Header:     http.Header{},
					Body:       io.NopCloser(strings.NewReader("{}")),
				}
				resp.Header.Set("Content-Type", "application/json")
				resp.Header.Set("Headscale-Version", "0.30.0")

				return resp, nil
			})

			c, err := New(Options{
				Address:   "http://hs.test",
				APIKey:    "key",
				Version:   "0.30.0",
				Transport: tr,
			})
			require.NoError(t, err)

			for range 2 {
				err := clientv0.Done(c.DeleteNodeWithResponse(t.Context(), "1", nil))
				require.Error(t, err)
			}

			require.Equal(t, []string{"GET", "GET"}, methods)
		})
	}
}

// TestDialEnds: the dial of a socket that is not there tries again until
// the timeout, then says why the last try failed, whatever the context
// of the transport, which never ends.
func TestDialEnds(t *testing.T) {
	t.Parallel()

	s := &socket{
		path:    filepath.Join(t.TempDir(), "none.sock"),
		timeout: 60 * time.Millisecond,
	}
	done := make(chan error, 1)

	go func() {
		//nolint:usetesting // the transport's dial context never ends
		_, err := s.dial(context.Background())
		done <- err
	}()

	select {
	case err := <-done:
		require.ErrorIs(t, err, syscall.ENOENT)
	case <-time.After(10 * time.Second):
		t.Fatal("the dial still retries after the timeout")
	}
}

// TestBodyless: an answer of the caller's transport with no Body, as a 204
// may come, is read as an empty one, a success and a refusal alike.
func TestBodyless(t *testing.T) {
	t.Parallel()

	const version = `{"version":"0.30.0","commit":"","buildTime":"","dirty":false,"go":{"version":"","os":"","arch":""}}`

	for _, tt := range []struct {
		name    string
		header  http.Header
		wantErr bool
	}{
		{"a success", http.Header{"Headscale-Version": {"0.30.0"}}, false},
		{"refused: no Headscale-Version", http.Header{}, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			c, err := New(Options{
				Address: "http://hs.test",
				APIKey:  "key",
				Version: "0.30.0",
				Timeout: time.Minute,
				Transport: roundTrip(func(r *http.Request) (*http.Response, error) {
					if r.Method == http.MethodGet {
						return &http.Response{
							Request:    r,
							StatusCode: http.StatusOK,
							Header: http.Header{
								"Headscale-Version": {"0.30.0"},
								"Content-Type":      {"application/json"},
							},
							Body: io.NopCloser(strings.NewReader(version)),
						}, nil
					}

					return &http.Response{
						Request:    r,
						StatusCode: http.StatusNoContent,
						Header:     tt.header,
					}, nil
				}),
			})
			require.NoError(t, err)

			require.NotPanics(t, func() {
				err = clientv0.Done(c.DeleteNodeWithResponse(t.Context(), "1", nil))
			})

			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
