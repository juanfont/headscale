// Package android runs the official Tailscale Android app against headscale.
//
// It lives in its own package so the arm64 integration matrix generator,
// which only scans integration/*_test.go, never schedules it: the emulator
// needs an x86_64 host with KVM.
package android

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"regexp"
	"slices"
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
	"tailscale.com/tailcfg"
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

// caStore is where the headscale CA is installed on the device; noTLS
// serves plain HTTP instead.
type caStore int

const (
	noTLS caStore = iota
	userCA
	systemCA
)

// setup starts headscale, one Linux peer serving HTTP on port 80 and the
// emulator with the app installed. Unless ca is noTLS, headscale serves
// HTTPS from a private CA installed in the given device store.
func setup(t *testing.T, apk string, ca caStore, extra ...hsic.Option) *env {
	t.Helper()

	hsOpts := append([]hsic.Option{
		hsic.WithTestName("android"),
		// The app always dials DERP over TLS; public relays keep the
		// data plane independent of which CA the device trusts.
		hsic.WithPublicDERP(),
	}, extra...)
	if ca == noTLS {
		hsOpts = append(hsOpts, hsic.WithoutTLS())
	}

	scenario, err := integration.NewScenario(integration.ScenarioSpec{
		NodesPerUser: 1,
		Users:        []string{user},
		Versions:     []string{"unstable"},
	})
	require.NoError(t, err)
	t.Cleanup(func() { scenario.ShutdownAssertNoPanics(t) })

	err = scenario.CreateHeadscaleEnv([]tsic.Option{tsic.WithWebserver(80)}, hsOpts...)
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

	// The TLS certificate only names the hostname.
	if ca != noTLS {
		require.NoError(t, android.AddHost(headscale.GetHostname(), headscale.GetIPInNetwork(scenario.Networks()[0])))
	}

	switch ca {
	case noTLS:
	case userCA:
		require.NoError(t, android.InstallUserCA(headscale.GetCert()))

		e.controlURL = headscale.GetEndpoint()
	case systemCA:
		require.NoError(t, android.InstallSystemCA(headscale.GetCert()))

		e.controlURL = headscale.GetEndpoint()
	}

	return e
}

// openAccountMenu navigates from a fresh install to the Accounts screen's
// overflow menu, where the alternate server and auth key entries live.
func (e *env) openAccountMenu(t *testing.T) {
	t.Helper()

	e.tapPast(t, "Open settings", "Accounts")
	require.NoError(t, e.android.Tap("Accounts"))
	require.NoError(t, e.android.Tap("menu"))
}

// dismissIntro taps through the intro screen, if shown, until next is.
func (e *env) dismissIntro(t *testing.T, next string) {
	t.Helper()

	e.tapPast(t, "Get Started", next)
}

// tapPast taps label until one of next is on screen, dismissing the intro
// whenever it shows. The intro can appear over the main screen after its
// first frame, and taps during its entry animation can be dropped.
func (e *env) tapPast(t *testing.T, label string, next ...string) {
	t.Helper()

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		// "Wait" answers the system's not-responding dialog, which slow
		// emulators show over whatever is on screen.
		got, err := e.android.WaitForAny(append([]string{"Get Started", "Wait", label}, next...)...)
		if !assert.NoError(c, err) {
			// Overloaded emulators can drop the app to the launcher.
			_ = e.android.Launch()

			return
		}

		if !slices.Contains(next, got) {
			assert.NoError(c, e.android.Tap(got))
		}

		assert.Contains(c, next, got)
	}, 2*time.Minute, time.Second, "never got past %q to %v", label, next)
}

// leaveBrowser closes the login Custom Tab as a user would, until the app
// is back in front. Back does not close it on every Android release and a
// tap can land before the tab is ready, so it retries.
func (e *env) leaveBrowser(t *testing.T) {
	t.Helper()

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		inBrowser, err := e.android.InForeground("com.android.chrome")
		if !assert.NoError(c, err) || !inBrowser {
			return
		}

		closed, err := e.android.TapAnyOf("Close tab")
		if err == nil && closed == "" {
			err = e.android.Back()
		}

		assert.NoError(c, err)
		assert.Fail(c, "browser still in front")
	}, time.Minute, 2*time.Second, "could not leave the login browser")
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

		// The emulator sits behind NAT, so the path may be direct or
		// relayed; tsic's modes each reject the other, so try both.
		ip := node.IpAddresses[0]
		timeout := tsic.WithPingTimeout(5 * time.Second)

		err := e.peer.Ping(ip, timeout, tsic.WithPingUntilDirect(false))
		if err != nil {
			err = e.peer.Ping(ip, timeout)
		}

		assert.NoError(c, err)
	}, 2*time.Minute, 5*time.Second, "peer cannot reach android node")
}

func clientFor(t *testing.T, clients []integration.TailscaleClient, hostname string) integration.TailscaleClient {
	t.Helper()

	for _, c := range clients {
		if c.Hostname() == hostname {
			return c
		}
	}

	require.FailNow(t, "no client for "+hostname)

	return nil
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
	e := setup(t, apk, noTLS)

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
	e := setup(t, apk, noTLS)

	android := e.loginInteractive(t)

	require.NoError(t, e.scenario.CreateTailscaleNodesInUser(
		user, "unstable", 1, tsic.WithNetwork(e.scenario.Networks()[0]),
	))

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

		// A Linux client on the same tailscale version as the app must
		// drop the peer too; if it does and the app does not, headscale
		// delivered the removal and the fault is in the app.
		if i == 0 {
			witness := clientFor(t, clients, peers[1].Name)

			assert.EventuallyWithT(t, func(c *assert.CollectT) {
				status, err := witness.Status()
				if !assert.NoError(c, err) {
					return
				}

				for _, k := range status.Peers() {
					assert.NotEqual(c, p.Name, status.Peer[k].HostName)
				}
			}, time.Minute, 2*time.Second, "Linux witness still has deleted peer %s", names[i])
		}

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
	e := setup(t, apk, noTLS)
	require.NoError(t, e.android.Launch())

	// The auth key screen logs in to the current control server, so point
	// the app at headscale first and back out of the browser the
	// interactive login opens, as a user would.
	e.setControlURL(t)
	require.NoError(t, e.android.WaitForBrowser())

	e.leaveBrowser(t)

	key := e.authKey(t)

	e.openAccountMenu(t)
	require.NoError(t, e.android.Tap("Use an auth key"))
	require.NoError(t, e.android.EnterText(key))
	require.NoError(t, e.android.Tap("Add account"))

	e.assertReachable(t, e.androidNode(t))
}

func TestAndroidLoginMDM(t *testing.T) {
	apk := androidSkip(t)
	e := setup(t, apk, noTLS)

	e.loginMDM(t)
}

// loginMDM logs in with a managed LoginURL and AuthKey, the way fleets
// enrol devices, returning the registered node.
func (e *env) loginMDM(t *testing.T) *clientv1.Node {
	t.Helper()

	key := e.authKey(t)

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		assert.NoError(c, e.android.SetManagedConfig(map[string]string{
			"LoginURL":       e.controlURL,
			"AuthKey":        key,
			"OnboardingFlow": "hide",
		}))
	}, time.Minute, 2*time.Second, "setting managed config")
	require.NoError(t, e.android.Launch())

	// OnboardingFlow=hide predates some supported versions, and a managed
	// auth key still waits for the user to start the login.
	// One tap: repeating it while the login is in flight starts another.
	e.dismissIntro(t, "Log in")
	require.NoError(t, e.android.Tap("Log in"))

	node := e.androidNode(t)
	e.assertReachable(t, node)

	return node
}

// TestAndroidRestart kills a logged-in app and checks it comes back
// connected as the same node when reopened.
func TestAndroidRestart(t *testing.T) {
	apk := androidSkip(t)
	e := setup(t, apk, noTLS)

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

	e := setup(t, from, noTLS)

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
	e := setup(t, apk, noTLS)

	debug, err := e.android.Debuggable()
	require.NoError(t, err)

	if !debug {
		t.Skip("release build has no integration login hook")
	}

	require.NoError(t, e.android.LoginHook(e.controlURL, e.authKey(t)))

	e.assertReachable(t, e.androidNode(t))
}

// TestAndroidLoginTLSSystemCA logs in to headscale behind a private CA in
// the system store, which all supported versions trust.
func TestAndroidLoginTLSSystemCA(t *testing.T) {
	apk := androidSkip(t)
	e := setup(t, apk, systemCA)

	e.loginInteractive(t)
}

// TestAndroidLoginTLS logs in to headscale behind a private CA the user
// installed on the device, the usual self-hosted setup.
func TestAndroidLoginTLS(t *testing.T) {
	apk := androidSkip(t)
	e := setup(t, apk, userCA)

	// The app only trusts user-installed CAs from 1.98.
	ok, err := e.android.VersionAtLeast(1, 98)
	require.NoError(t, err)

	if !ok {
		t.Skip("app predates user CA support")
	}

	e.loginInteractive(t)
}

// peerNode returns e.peer's headscale node.
func (e *env) peerNode(t *testing.T) *clientv1.Node {
	t.Helper()

	nodes, err := e.headscale.ListNodes()
	require.NoError(t, err)

	for _, n := range nodes {
		if n.Name == e.peer.Hostname() {
			return n
		}
	}

	require.FailNow(t, "peer node not found")

	return nil
}

// routedTarget is an address only e.peer holds, on its loopback, so the
// device can reach it only through the tailnet. e.peer's web server
// answers on it.
const routedTarget = "10.99.0.1"

func (e *env) addRoutedTarget(t *testing.T) {
	t.Helper()

	_, _, err := e.peer.Execute([]string{"ip", "addr", "add", routedTarget + "/32", "dev", "lo"})
	require.NoError(t, err)
}

func (e *env) approveRoutes(t *testing.T, routes ...string) {
	t.Helper()

	id, err := strconv.ParseUint(e.peerNode(t).Id, 10, 64)
	require.NoError(t, err)

	prefixes := make([]netip.Prefix, 0, len(routes))
	for _, r := range routes {
		prefixes = append(prefixes, netip.MustParsePrefix(r))
	}

	_, err = e.headscale.ApproveRoutes(id, prefixes)
	require.NoError(t, err)
}

// assertFetch checks an ordinary app on the device gets HTTP 200 from url.
func (e *env) assertFetch(t *testing.T, url string, msgAndArgs ...any) {
	t.Helper()

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		code, err := e.android.Fetch(url)
		assert.NoError(c, err)
		assert.Equal(c, 200, code)
	}, 2*time.Minute, 3*time.Second, msgAndArgs...)
}

// TestAndroidMagicDNS resolves tailnet names from an ordinary app on the
// device, through the app's DNS, and fetches a peer by its MagicDNS name:
// the Android-to-peer direction of the data plane.
func TestAndroidMagicDNS(t *testing.T) {
	apk := androidSkip(t)

	const (
		recordPath = "/tmp/extra_records.json"
		record     = "android-extra.example.com"
		recordIP   = "100.64.99.99"
	)

	records, err := json.Marshal([]tailcfg.DNSRecord{{Name: record, Type: "A", Value: recordIP}})
	require.NoError(t, err)

	e := setup(t, apk, noTLS,
		hsic.WithConfigEnv(map[string]string{"HEADSCALE_DNS_EXTRA_RECORDS_PATH": recordPath}),
		hsic.WithFileInContainer(recordPath, records),
	)

	e.loginMDM(t)

	fqdn, err := e.peer.FQDN()
	require.NoError(t, err)

	peerIPs, err := e.peer.IPs()
	require.NoError(t, err)

	name := strings.TrimSuffix(fqdn, ".")

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		addrs, err := e.android.Resolve(name)
		assert.NoError(c, err)
		assert.Contains(c, addrs, peerIPs[0].String())
	}, 2*time.Minute, 3*time.Second, "MagicDNS name %s does not resolve", name)

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		addrs, err := e.android.Resolve(record)
		assert.NoError(c, err)
		assert.Contains(c, addrs, recordIP)
	}, 2*time.Minute, 3*time.Second, "extra record %s does not resolve", record)

	e.assertFetch(t, "http://"+name+"/", "cannot fetch peer by MagicDNS name")
}

// TestAndroidSubnetRoute reaches an address only a Linux subnet router can
// reach, once headscale approves the route.
func TestAndroidSubnetRoute(t *testing.T) {
	apk := androidSkip(t)
	e := setup(t, apk, noTLS)

	e.addRoutedTarget(t)
	e.loginMDM(t)

	url := "http://" + routedTarget + "/"

	_, err := e.android.Fetch(url)
	require.Error(t, err, "%s reachable before any route exists", routedTarget)

	_, _, err = e.peer.Execute([]string{"tailscale", "set", "--advertise-routes=10.99.0.0/24"})
	require.NoError(t, err)
	e.approveRoutes(t, "10.99.0.0/24")

	e.assertFetch(t, url, "cannot reach %s through the subnet router", routedTarget)
}

// TestAndroidExitNode selects a Linux exit node through the app's
// USE_EXIT_NODE intent and reaches an address only the exit node can.
func TestAndroidExitNode(t *testing.T) {
	apk := androidSkip(t)
	e := setup(t, apk, noTLS)

	// Exit nodes drop traffic to their own addresses and connected
	// subnets, so the target is a TEST-NET address the exit node
	// forwards to its own web server.
	const target = "203.0.113.10"

	peerIP, err := e.peer.IPv4()
	require.NoError(t, err)

	_, _, err = e.peer.Execute([]string{
		"iptables", "-t", "nat", "-A", "PREROUTING", "-d", target, "-p", "tcp", "--dport", "80",
		"-j", "DNAT", "--to-destination", peerIP.String() + ":80",
	})
	require.NoError(t, err)

	e.loginMDM(t)

	_, _, err = e.peer.Execute([]string{"tailscale", "set", "--advertise-exit-node"})
	require.NoError(t, err)
	e.approveRoutes(t, "0.0.0.0/0", "::/0")

	url := "http://" + target + "/"

	_, err = e.android.Fetch(url)
	require.Error(t, err, "%s reachable without the exit node", target)

	// The intent matches peers by display name, the node's given name.
	// Sent once: each intent replaces the app's pending selection.
	name := e.peerNode(t).GivenName
	require.NoError(t, e.android.UseExitNode(name))

	e.assertFetch(t, url, "cannot reach %s through exit node %s", target, name)
}

// TestAndroidTaildrop sends a file from a Linux peer and checks it lands
// on the device, picking a Taildrop folder if the app asks for one.
func TestAndroidTaildrop(t *testing.T) {
	apk := androidSkip(t)
	e := setup(t, apk, noTLS)

	node := e.loginMDM(t)
	require.NoError(t, e.android.Launch())

	const file = "taildrop-from-linux.txt"

	body := "hello android " + e.peer.Hostname()

	_, _, err := e.peer.Execute([]string{"sh", "-c", fmt.Sprintf("printf %%s %q > /tmp/%s", body, file)})
	require.NoError(t, err)

	sent := make(chan error, 1)

	go func() {
		_, stderr, err := e.peer.Execute(
			[]string{"tailscale", "file", "cp", "/tmp/" + file, node.IpAddresses[0] + ":"},
			dockertestutil.ExecuteCommandTimeout(3*time.Minute),
		)
		if err != nil {
			err = fmt.Errorf("%w: %s", err, stderr)
		}

		sent <- err
	}()

	// Newer apps ask for a folder on the first incoming file: accept the
	// prompt and pick Download in the system folder picker, as a user
	// would. The picker opens at the storage root, which cannot be used.
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		tapped, err := e.android.TapAnyOf(
			"Open Directory Picker", "USE THIS FOLDER", "Use this folder", "ALLOW", "Allow", "Download",
		)
		t.Logf("taildrop prompt: tapped %q, err %v", tapped, err)

		got, err := e.android.FindFile(file)
		assert.NoError(c, err)
		assert.Equal(c, body, strings.TrimSpace(got))
	}, 3*time.Minute, 3*time.Second, "file never arrived on the device")

	require.NoError(t, <-sent, "tailscale file cp failed")
}

// TestAndroidNetworkChange drops the device's network and checks the app
// reconnects, with working DNS, once it returns.
func TestAndroidNetworkChange(t *testing.T) {
	apk := androidSkip(t)
	e := setup(t, apk, noTLS)

	node := e.loginMDM(t)

	require.NoError(t, e.android.SetNetwork(false))

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		assert.Error(c, e.peer.Ping(node.IpAddresses[0], tsic.WithPingTimeout(3*time.Second)))
	}, time.Minute, 3*time.Second, "device still reachable with its network off")

	require.NoError(t, e.android.SetNetwork(true))

	e.assertReachable(t, node)

	fqdn, err := e.peer.FQDN()
	require.NoError(t, err)

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		_, err := e.android.Resolve(strings.TrimSuffix(fqdn, "."))
		assert.NoError(c, err)
	}, 2*time.Minute, 3*time.Second, "MagicDNS broken after the network returned")
}
