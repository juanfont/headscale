package integration

import (
	"bytes"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/juanfont/headscale/integration/dockertestutil"
	"github.com/juanfont/headscale/integration/hsic"
	"github.com/juanfont/headscale/integration/tsic"
	"github.com/stretchr/testify/require"
)

// This file is intended to "test the test framework", by proxy it will also test
// some Headscale/Tailscale stuff, but mostly in very simple ways.

func IntegrationSkip(t *testing.T) {
	t.Helper()

	if !dockertestutil.IsRunningInContainer() {
		t.Skip("not running in docker, skipping")
	}

	if testing.Short() {
		t.Skip("skipping integration tests due to short flag")
	}
}

// If subtests are parallel, then they will start before setup is run.
// This might mean we approach setup slightly wrong, but for now, ignore
// the linter
// nolint:tparallel
func TestHeadscale(t *testing.T) {
	IntegrationSkip(t)

	var err error

	user := "test-space"

	scenario, err := NewScenario(ScenarioSpec{})

	require.NoError(t, err)
	defer scenario.ShutdownAssertNoPanics(t)

	t.Run("start-headscale", func(t *testing.T) {
		headscale, err := scenario.Headscale(hsic.WithTestName("scenariohs"))
		if err != nil {
			t.Fatalf("failed to create start headcale: %s", err)
		}

		err = headscale.WaitForRunning()
		if err != nil {
			t.Fatalf("headscale failed to become ready: %s", err)
		}
	})

	t.Run("create-user", func(t *testing.T) {
		_, err := scenario.CreateUser(user)
		if err != nil {
			t.Fatalf("failed to create user: %s", err)
		}

		if _, ok := scenario.users[user]; !ok {
			t.Fatalf("user is not in scenario")
		}
	})

	t.Run("create-auth-key", func(t *testing.T) {
		_, err := scenario.CreatePreAuthKey(1, true, false)
		if err != nil {
			t.Fatalf("failed to create preauthkey: %s", err)
		}
	})
}

// If subtests are parallel, then they will start before setup is run.
// This might mean we approach setup slightly wrong, but for now, ignore
// the linter
// nolint:tparallel
func TestTailscaleNodesJoiningHeadcale(t *testing.T) {
	IntegrationSkip(t)

	var err error

	user := "join-node-test"

	count := 1

	scenario, err := NewScenario(ScenarioSpec{})

	require.NoError(t, err)
	defer scenario.ShutdownAssertNoPanics(t)

	t.Run("start-headscale", func(t *testing.T) {
		headscale, err := scenario.Headscale(hsic.WithTestName("scenariojoin"))
		if err != nil {
			t.Fatalf("failed to create start headcale: %s", err)
		}

		err = headscale.WaitForRunning()
		if err != nil {
			t.Fatalf("headscale failed to become ready: %s", err)
		}
	})

	t.Run("create-user", func(t *testing.T) {
		_, err := scenario.CreateUser(user)
		if err != nil {
			t.Fatalf("failed to create user: %s", err)
		}

		if _, ok := scenario.users[user]; !ok {
			t.Fatalf("user is not in scenario")
		}
	})

	t.Run("create-tailscale", func(t *testing.T) {
		err := scenario.CreateTailscaleNodesInUser(user, "unstable", count, tsic.WithNetwork(scenario.networks[scenario.testDefaultNetwork]))
		if err != nil {
			t.Fatalf("failed to add tailscale nodes: %s", err)
		}

		if clients := len(scenario.users[user].Clients); clients != count {
			t.Fatalf("wrong number of tailscale clients: %d != %d", clients, count)
		}
	})

	t.Run("join-headscale", func(t *testing.T) {
		key, err := scenario.CreatePreAuthKey(1, true, false)
		if err != nil {
			t.Fatalf("failed to create preauthkey: %s", err)
		}

		headscale, err := scenario.Headscale()
		if err != nil {
			t.Fatalf("failed to create start headcale: %s", err)
		}

		err = scenario.RunTailscaleUp(
			user,
			headscale.GetEndpoint(),
			key.Key,
		)
		if err != nil {
			t.Fatalf("failed to login: %s", err)
		}
	})

	t.Run("get-ips", func(t *testing.T) {
		ips, err := scenario.GetIPs(user)
		if err != nil {
			t.Fatalf("failed to get tailscale ips: %s", err)
		}

		if len(ips) != count*2 {
			t.Fatalf("got the wrong amount of tailscale ips, %d != %d", len(ips), count*2)
		}
	})
}

// TestLoginDiagnosticsHideAuthID: what the login helpers log and the errors
// they return hide the auth ID, on success and on each failure (a 5xx, a
// refused connection, a 5xx from the confirmation form), while the page
// they return keeps it: the caller needs it to answer the request.
func TestLoginDiagnosticsHideAuthID(t *testing.T) {
	IntegrationSkip(t)

	const id = "hskey-authreq-0123456789abcdef01234567"

	page := "<html>" + id + "</html>"
	form := `<form action="/confirm/` + id + `"><input name="` + registerConfirmCSRFField + `" value="x"></form>`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/fail/"), strings.HasPrefix(r.URL.Path, "/confirm/"):
			w.WriteHeader(http.StatusServiceUnavailable)
		case strings.HasPrefix(r.URL.Path, "/form/"):
			_, _ = io.WriteString(w, form)

			return
		}

		_, _ = io.WriteString(w, page)
	}))
	defer srv.Close()

	closed := httptest.NewServer(http.NotFoundHandler())
	closed.Close()

	var logged bytes.Buffer

	log.SetOutput(&logged)
	defer log.SetOutput(os.Stderr)

	for _, tt := range []struct {
		name, url string
		fails     bool
	}{
		{"an answered page", srv.URL + "/register/" + id, false},
		{"a 503", srv.URL + "/fail/" + id, true},
		{"a refused connection", closed.URL + "/register/" + id, true},
		{"a 503 from the confirmation form", srv.URL + "/form/" + id, true},
	} {
		logged.Reset()

		u, err := url.Parse(tt.url)
		require.NoError(t, err)

		body, _, err := doLoginURLWithClient("host", u, &http.Client{}, true)
		require.Equal(t, tt.fails, err != nil, tt.name)
		require.NotContains(t, logged.String(), id, tt.name)

		if err != nil {
			require.NotContains(t, err.Error(), id, tt.name)
		}

		if tt.name == "an answered page" {
			require.Contains(t, body, id, "the page keeps the ID")
		}
	}
}
