// Package android runs the official Tailscale Android app against headscale.
//
// It lives in its own package so the arm64 integration matrix generator,
// which only scans integration/*_test.go, never schedules it: the emulator
// needs an x86_64 host with KVM.
package android

import (
	"os"
	"regexp"
	"strconv"
	"testing"
	"time"

	clientv1 "github.com/juanfont/headscale/gen/client/v1"
	"github.com/juanfont/headscale/integration"
	"github.com/juanfont/headscale/integration/androidic"
	"github.com/juanfont/headscale/integration/dockertestutil"
	"github.com/juanfont/headscale/integration/hsic"
	"github.com/juanfont/headscale/integration/tsic"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const user = "user1"

var authIDRe = regexp.MustCompile(`starting node registration using auth id: (\S+)`)

// androidSkip skips unless running under hi with an APK to test, which
// also means the host was set up with KVM for it.
func androidSkip(t *testing.T) string {
	t.Helper()

	if !dockertestutil.IsRunningInContainer() || testing.Short() {
		t.Skip("not running in docker, skipping")
	}

	apk := os.Getenv("HEADSCALE_INTEGRATION_ANDROID_APK")
	if apk == "" {
		t.Skip("HEADSCALE_INTEGRATION_ANDROID_APK not set, skipping")
	}

	return apk
}

type env struct {
	scenario  *integration.Scenario
	headscale integration.ControlServer
	peer      integration.TailscaleClient
	android   *androidic.AndroidInContainer
}

func setup(t *testing.T, apk string) *env {
	t.Helper()

	scenario, err := integration.NewScenario(integration.ScenarioSpec{
		NodesPerUser: 1,
		Users:        []string{user},
		Versions:     []string{"unstable"},
	})
	require.NoError(t, err)
	t.Cleanup(func() { scenario.ShutdownAssertNoPanics(t) })

	err = scenario.CreateHeadscaleEnv(
		[]tsic.Option{},
		hsic.WithTestName("android"),
		// ponytail: plain HTTP control and public DERP until the TLS phase
		// installs the headscale CA on the device; the app always dials
		// DERP over TLS and cannot be told to skip verification.
		hsic.WithoutTLS(),
		hsic.WithPublicDERP(),
	)
	require.NoError(t, err)

	headscale, err := scenario.Headscale()
	require.NoError(t, err)

	peers, err := scenario.ListTailscaleClients()
	require.NoError(t, err)
	require.Len(t, peers, 1)

	android, err := androidic.New(
		scenario.Pool(),
		androidic.WithNetwork(scenario.Networks()[0]),
		androidic.WithAPK(apk),
	)
	if android != nil {
		// Registered after the scenario so it runs first: the container
		// must leave the network before the scenario removes it.
		t.Cleanup(func() {
			_, _, err := android.Shutdown()
			if err != nil {
				t.Logf("shutting down android container: %s", err)
			}
		})
	}

	require.NoError(t, err)

	require.NoError(t, android.Install())

	version, err := android.Version()
	require.NoError(t, err)
	t.Logf("Tailscale Android version: %s", version)

	require.NoError(t, android.Launch())

	return &env{
		scenario:  scenario,
		headscale: headscale,
		peer:      peers[0],
		android:   android,
	}
}

// openAccountMenu navigates from a fresh install to the Accounts screen's
// overflow menu, where the alternate server and auth key entries live.
func (e *env) openAccountMenu(t *testing.T) {
	t.Helper()

	// Onboarding only exists on some versions.
	if ok, _ := e.android.HasText("Get Started"); ok {
		require.NoError(t, e.android.Tap("Get Started"))
	}

	require.NoError(t, e.android.Tap("Open settings"))
	require.NoError(t, e.android.Tap("Accounts"))
	require.NoError(t, e.android.Tap("menu"))
}

// setControlURL drives the "Use an alternate server" dialog, the path users
// report as silently failing (tailscale/tailscale#15660).
func (e *env) setControlURL(t *testing.T) {
	t.Helper()

	e.openAccountMenu(t)
	require.NoError(t, e.android.Tap("Use an alternate server"))
	require.NoError(t, e.android.EnterText(e.headscale.GetIPEndpoint()))
	require.NoError(t, e.android.Tap("Add account"))
}

// androidNode waits for the Android node to be registered and online.
func (e *env) androidNode(t *testing.T) *clientv1.Node {
	t.Helper()

	var node *clientv1.Node

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		nodes, err := e.headscale.ListNodes()
		assert.NoError(c, err)

		node = nil

		for _, n := range nodes {
			if n.Name != e.peer.Hostname() {
				node = n
			}
		}

		if assert.NotNil(c, node, "android node not registered") {
			assert.True(c, node.Online, "android node not online")
		}
	}, 2*time.Minute, 2*time.Second)

	require.NotNil(t, node)
	require.NotEmpty(t, node.IpAddresses)

	return node
}

// assertReachable checks the data plane end to end: the Linux peer pings
// the Android node through the tailnet.
func (e *env) assertReachable(t *testing.T, node *clientv1.Node) {
	t.Helper()

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		// Some versions leave the VPN off after login.
		if ok, _ := e.android.HasText("Connect"); ok {
			_ = e.android.Tap("Connect")
		}

		assert.NoError(c, e.peer.Ping(node.IpAddresses[0], tsic.WithPingTimeout(5*time.Second)))
	}, 2*time.Minute, 5*time.Second, "peer cannot reach android node")
}

func TestAndroidLoginCustomControlURL(t *testing.T) {
	apk := androidSkip(t)
	e := setup(t, apk)

	e.setControlURL(t)

	// The app hands the register URL to a browser; stand in for the user
	// opening it and running the command it shows.
	var authID string

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		stdout, stderr, err := e.headscale.ReadLog()
		assert.NoError(c, err)

		m := authIDRe.FindStringSubmatch(stdout + stderr)
		if assert.NotNil(c, m, "headscale never received an interactive registration") {
			authID = m[1]
		}
	}, 2*time.Minute, 2*time.Second)

	_, err := e.headscale.Execute([]string{
		"headscale", "auth", "register", "--user", user, "--auth-id", authID,
	})
	require.NoError(t, err)

	node := e.androidNode(t)
	e.assertReachable(t, node)
}

func TestAndroidLoginAuthKey(t *testing.T) {
	apk := androidSkip(t)
	e := setup(t, apk)

	// The auth key screen logs in to the current control server, so point
	// the app at headscale first and abandon the interactive login.
	e.setControlURL(t)
	require.NoError(t, e.android.Back())

	users, err := e.headscale.ListUsers()
	require.NoError(t, err)
	require.Len(t, users, 1)

	userID, err := strconv.ParseUint(users[0].Id, 10, 64)
	require.NoError(t, err)

	key, err := e.headscale.CreateAuthKey(userID, false, false)
	require.NoError(t, err)

	e.openAccountMenu(t)
	require.NoError(t, e.android.Tap("Use an auth key"))
	require.NoError(t, e.android.EnterText(key.Key))
	require.NoError(t, e.android.Tap("Add account"))

	e.assertReachable(t, e.androidNode(t))
}
