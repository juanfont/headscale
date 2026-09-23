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
	"strings"
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

	// controlURL is what a user would type into the app.
	controlURL string
}

// setup starts headscale, one Linux peer and the emulator with the app
// installed. With tls, headscale serves HTTPS from a private CA that is
// installed on the device the way a user would, in the user CA store.
func setup(t *testing.T, apk string, tls bool) *env {
	t.Helper()

	hsOpts := []hsic.Option{
		hsic.WithTestName("android"),
		// The app always dials DERP over TLS; public relays keep the
		// data plane independent of which CA the device trusts.
		hsic.WithPublicDERP(),
	}
	if !tls {
		hsOpts = append(hsOpts, hsic.WithoutTLS())
	}

	scenario, err := integration.NewScenario(integration.ScenarioSpec{
		NodesPerUser: 1,
		Users:        []string{user},
		Versions:     []string{"unstable"},
	})
	require.NoError(t, err)
	t.Cleanup(func() { scenario.ShutdownAssertNoPanics(t) })

	err = scenario.CreateHeadscaleEnv([]tsic.Option{}, hsOpts...)
	require.NoError(t, err)

	headscale, err := scenario.Headscale()
	require.NoError(t, err)

	peers, err := scenario.ListTailscaleClients()
	require.NoError(t, err)
	require.Len(t, peers, 1)

	android, err := androidic.New(
		scenario.Pool(),
		androidic.WithNetwork(scenario.Networks()[0]),
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

	// Runs before the shutdown above: any app crash fails the test.
	t.Cleanup(func() {
		crashes, err := android.Crashes()
		assert.NoError(t, err)
		assert.Empty(t, crashes, "Tailscale Android app crashed")
	})

	require.NoError(t, android.Install(apk))

	version, err := android.Version()
	require.NoError(t, err)
	t.Logf("Tailscale Android version: %s", version)

	e := &env{
		scenario:  scenario,
		headscale: headscale,
		peer:      peers[0],
		android:   android,
		// The TLS certificate only names the hostname; plain HTTP uses the
		// IP so it does not depend on the guest resolving container names.
		controlURL: headscale.GetIPEndpoint(),
	}

	if tls {
		require.NoError(t, android.InstallUserCA(headscale.GetCert()))

		e.controlURL = headscale.GetEndpoint()
	}

	return e
}

// openAccountMenu navigates from a fresh install to the Accounts screen's
// overflow menu, where the alternate server and auth key entries live.
func (e *env) openAccountMenu(t *testing.T) {
	t.Helper()

	// Onboarding only exists on some versions, and only on first launch.
	e.skipOnboarding(t, "Open settings")

	require.NoError(t, e.android.Tap("Open settings"))
	require.NoError(t, e.android.Tap("Accounts"))
	require.NoError(t, e.android.Tap("menu"))
}

// skipOnboarding waits for the app to render and taps through the intro
// screen if it shows instead of next.
func (e *env) skipOnboarding(t *testing.T, next string) {
	t.Helper()

	// A tap during the intro's entry animation can be dropped, so keep
	// tapping until the next screen shows.
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		got, err := e.android.WaitForAny("Get Started", next)
		if !assert.NoError(c, err) {
			return
		}

		if got == "Get Started" {
			assert.NoError(c, e.android.Tap("Get Started"))
		}

		assert.Equal(c, next, got)
	}, 2*time.Minute, time.Second, "app never left the intro screen")
}

// setControlURL drives the "Use an alternate server" dialog, the path users
// report as silently failing (tailscale/tailscale#15660).
func (e *env) setControlURL(t *testing.T) {
	t.Helper()

	e.openAccountMenu(t)
	require.NoError(t, e.android.Tap("Use an alternate server"))
	require.NoError(t, e.android.EnterText(e.controlURL))
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
			// Linux peers are tsic containers, named ts-*.
			if !strings.HasPrefix(n.Name, "ts-") {
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

func (e *env) authKey(t *testing.T) string {
	t.Helper()

	users, err := e.headscale.ListUsers()
	require.NoError(t, err)
	require.Len(t, users, 1)

	userID, err := strconv.ParseUint(users[0].Id, 10, 64)
	require.NoError(t, err)

	key, err := e.headscale.CreateAuthKey(userID, false, false)
	require.NoError(t, err)

	return key.Key
}

func TestAndroidLoginCustomControlURL(t *testing.T) {
	apk := androidSkip(t)
	e := setup(t, apk, false)

	e.loginInteractive(t)
}

// loginInteractive logs in through the alternate server dialog and the
// interactive registration it starts, returning the registered node.
func (e *env) loginInteractive(t *testing.T) *clientv1.Node {
	t.Helper()

	require.NoError(t, e.android.Launch())
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

	return node
}

// TestAndroidPeerChanges pushes incremental netmap changes at a logged-in
// app and checks it renders them and survives: peer changes are where
// client-side parsing bugs have crashed the app before. Removing a peer
// while others remain and removing the last one take different paths in
// the client, so both are covered.
func TestAndroidPeerChanges(t *testing.T) {
	apk := androidSkip(t)
	e := setup(t, apk, false)

	android := e.loginInteractive(t)

	require.NoError(t, e.scenario.CreateTailscaleNodesInUser(user, "unstable", 1))

	clients, err := e.scenario.ListTailscaleClients(user)
	require.NoError(t, err)
	require.Len(t, clients, 2)

	for _, c := range clients {
		if c.Hostname() != e.peer.Hostname() {
			require.NoError(t, c.Login(e.headscale.GetEndpoint(), e.authKey(t)))
			require.NoError(t, c.WaitForRunning(time.Minute))
		}
	}

	nodes, err := e.headscale.ListNodes()
	require.NoError(t, err)

	var peers []*clientv1.Node

	for _, n := range nodes {
		if strings.HasPrefix(n.Name, "ts-") {
			peers = append(peers, n)
		}
	}

	require.Len(t, peers, 2)

	names := []string{"renamed-peer-a", "renamed-peer-b"}

	for i, p := range peers {
		_, err := e.headscale.Execute([]string{
			"headscale", "nodes", "rename", "--identifier", p.Id, names[i],
		})
		require.NoError(t, err)
	}

	require.NoError(t, e.android.Launch())

	for _, name := range names {
		_, err = e.android.WaitForAny(name)
		require.NoError(t, err, "app does not show renamed peer %s", name)
	}

	for i, p := range peers {
		id, err := strconv.ParseUint(p.Id, 10, 64)
		require.NoError(t, err)
		require.NoError(t, e.headscale.DeleteNode(id))

		assert.EventuallyWithT(t, func(c *assert.CollectT) {
			ok, err := e.android.HasText(names[i])
			assert.NoError(c, err)
			assert.False(c, ok)
		}, time.Minute, 2*time.Second,
			"app still shows deleted peer %s (%d peers left)", names[i], len(peers)-i-1)
	}

	assert.Equal(t, android.Id, e.androidNode(t).Id)
}

func TestAndroidLoginAuthKey(t *testing.T) {
	apk := androidSkip(t)
	e := setup(t, apk, false)
	require.NoError(t, e.android.Launch())

	// The auth key screen logs in to the current control server, so point
	// the app at headscale first and back out of the browser the
	// interactive login opens, as a user would.
	e.setControlURL(t)
	require.NoError(t, e.android.WaitForBrowser())
	require.NoError(t, e.android.Back())

	key := e.authKey(t)

	e.openAccountMenu(t)
	require.NoError(t, e.android.Tap("Use an auth key"))
	require.NoError(t, e.android.EnterText(key))
	require.NoError(t, e.android.Tap("Add account"))

	e.assertReachable(t, e.androidNode(t))
}

func TestAndroidLoginMDM(t *testing.T) {
	apk := androidSkip(t)
	e := setup(t, apk, false)

	e.loginMDM(t)
}

// loginMDM logs in with a managed LoginURL and AuthKey, the way fleets
// enrol devices, returning the registered node.
func (e *env) loginMDM(t *testing.T) *clientv1.Node {
	t.Helper()

	key := e.authKey(t)

	require.NoError(t, e.android.SetManagedConfig(map[string]string{
		"LoginURL":       e.controlURL,
		"AuthKey":        key,
		"OnboardingFlow": "hide",
	}))
	require.NoError(t, e.android.Launch())

	// OnboardingFlow=hide predates some supported versions, and a managed
	// auth key still waits for the user to start the login.
	e.skipOnboarding(t, "Log in")
	require.NoError(t, e.android.Tap("Log in"))

	node := e.androidNode(t)
	e.assertReachable(t, node)

	return node
}

// TestAndroidRestart kills a logged-in app and checks it comes back
// connected as the same node when reopened.
func TestAndroidRestart(t *testing.T) {
	apk := androidSkip(t)
	e := setup(t, apk, false)

	before := e.loginMDM(t)

	_, err := e.android.Shell("am", "force-stop", androidic.Package)
	require.NoError(t, err)
	require.NoError(t, e.android.Launch())

	after := e.androidNode(t)
	assert.Equal(t, before.Id, after.Id, "restart re-registered the node")
	e.assertReachable(t, after)
}

// TestAndroidUpgrade upgrades a logged-in app in place from an older
// release and checks it stays the same connected node.
func TestAndroidUpgrade(t *testing.T) {
	apk := androidSkip(t)

	from := os.Getenv("HEADSCALE_INTEGRATION_ANDROID_UPGRADE_FROM")
	if from == "" {
		t.Skip("HEADSCALE_INTEGRATION_ANDROID_UPGRADE_FROM not set, skipping")
	}

	e := setup(t, from, false)

	before := e.loginMDM(t)

	require.NoError(t, e.android.Install(apk))

	version, err := e.android.Version()
	require.NoError(t, err)
	t.Logf("Upgraded to Tailscale Android version: %s", version)

	require.NoError(t, e.android.Launch())

	after := e.androidNode(t)
	assert.Equal(t, before.Id, after.Id, "upgrade re-registered the node")
	e.assertReachable(t, after)
}

func TestAndroidLoginHook(t *testing.T) {
	apk := androidSkip(t)
	e := setup(t, apk, false)

	debug, err := e.android.Debuggable()
	require.NoError(t, err)

	if !debug {
		t.Skip("release build has no integration login hook")
	}

	require.NoError(t, e.android.LoginHook(e.controlURL, e.authKey(t)))

	e.assertReachable(t, e.androidNode(t))
}

// TestAndroidLoginTLS logs in to headscale behind a private CA the user
// installed on the device, the usual self-hosted setup.
func TestAndroidLoginTLS(t *testing.T) {
	apk := androidSkip(t)
	e := setup(t, apk, true)

	// The app only trusts user-installed CAs from 1.98.
	ok, err := e.android.VersionAtLeast(1, 98)
	require.NoError(t, err)

	if !ok {
		t.Skip("app predates user CA support")
	}

	e.loginInteractive(t)
}
