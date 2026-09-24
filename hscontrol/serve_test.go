package hscontrol

import (
	"context"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testDERPMap = `regions:
  900:
    regionid: 900
    regioncode: test
    regionname: test
    nodes:
      - name: 900a
        regionid: 900
        hostname: localhost
        ipv4: 127.0.0.1
        derpport: 443
`

func freeAddr(t *testing.T) string {
	t.Helper()

	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	defer l.Close()

	return l.Addr().String()
}

func newServeTestApp(t *testing.T, dir, addr string) *Headscale {
	t.Helper()

	derpPath := filepath.Join(dir, "derp.yaml")
	require.NoError(t, os.WriteFile(derpPath, []byte(testDERPMap), 0o600))

	app, err := NewHeadscale(&types.Config{
		ServerURL:           "http://" + addr,
		Addr:                addr,
		UnixSocket:          filepath.Join(dir, "headscale.sock"),
		NoisePrivateKeyPath: filepath.Join(dir, "noise_private.key"),
		DERP:                types.DERPConfig{Paths: []string{derpPath}},
		Database: types.DatabaseConfig{
			Type:   "sqlite3",
			Sqlite: types.SqliteConfig{Path: filepath.Join(dir, "db.sqlite")},
		},
		Policy: types.PolicyConfig{Mode: types.PolicyModeDB},
		Tuning: types.Tuning{
			BatchChangeDelay: 100 * time.Millisecond,
			BatcherWorkers:   1,
		},
	})
	require.NoError(t, err)

	return app
}

// startServe runs app.Serve in the background and returns its cancel
// function and result channel.
func startServe(app *Headscale) (context.CancelFunc, <-chan error) {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)

	go func() { done <- app.Serve(ctx) }()

	return cancel, done
}

func waitHealthy(t *testing.T, addr string) {
	t.Helper()

	require.Eventually(t, func() bool {
		resp, err := http.Get("http://" + addr + "/health") //nolint:noctx
		if err != nil {
			return false
		}

		resp.Body.Close()

		return resp.StatusCode == http.StatusOK
	}, 10*time.Second, 50*time.Millisecond)
}

func waitServeReturn(t *testing.T, done <-chan error) error {
	t.Helper()

	select {
	case err := <-done:
		return err
	case <-time.After(15 * time.Second):
		require.FailNow(t, "Serve did not return")

		return nil
	}
}

func TestServeStopsOnContextCancel(t *testing.T) {
	addr := freeAddr(t)
	app := newServeTestApp(t, t.TempDir(), addr)

	cancel, done := startServe(app)
	waitHealthy(t, addr)

	cancel()
	require.NoError(t, waitServeReturn(t, done))

	_, err := http.Get("http://" + addr + "/health") //nolint:noctx
	assert.Error(t, err, "listener should be closed after Serve returns")
}

func TestServeBindFailure(t *testing.T) {
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	defer busy.Close()

	app := newServeTestApp(t, t.TempDir(), busy.Addr().String())

	_, done := startServe(app)

	var bindErr *types.ListenerBindError

	err = waitServeReturn(t, done)
	require.True(t, errors.As(err, &bindErr), "got %v", err)
	assert.Equal(t, "main HTTP", bindErr.Listener)
}

func TestServeInstancesAreIndependent(t *testing.T) {
	dirA, dirB := t.TempDir(), t.TempDir()
	addrA, addrB := freeAddr(t), freeAddr(t)

	cancelA, doneA := startServe(newServeTestApp(t, dirA, addrA))
	cancelB, doneB := startServe(newServeTestApp(t, dirB, addrB))

	defer cancelB()

	waitHealthy(t, addrA)
	waitHealthy(t, addrB)

	cancelA()
	require.NoError(t, waitServeReturn(t, doneA))

	// B keeps serving.
	waitHealthy(t, addrB)

	// A restarts from the same data dir and address.
	cancelA2, doneA2 := startServe(newServeTestApp(t, dirA, addrA))
	waitHealthy(t, addrA)
	cancelA2()
	require.NoError(t, waitServeReturn(t, doneA2))

	cancelB()
	require.NoError(t, waitServeReturn(t, doneB))
}
