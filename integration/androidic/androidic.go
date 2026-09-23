// Package androidic provides an AndroidInContainer (androidic) client that
// runs the official Tailscale Android app inside an Android emulator in a
// Docker container, for integration testing with headscale.
//
// The app exposes no CLI or LocalAPI over adb, so, like tsric, verification
// is done externally: headscale's node list, peer connectivity and the
// on-screen UI (uiautomator).
//
// The emulator needs hardware virtualisation: the Docker host must expose
// /dev/kvm.
package androidic

import (
	"context"
	"crypto/md5" //nolint:gosec // Android names CA files by this hash.
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/cenkalti/backoff/v5"
	"github.com/juanfont/headscale/integration/dockertestutil"
	"github.com/juanfont/headscale/integration/integrationutil"
	"github.com/ory/dockertest/v3"
	"github.com/ory/dockertest/v3/docker"
	"tailscale.com/util/rands"
)

const (
	// Package is the Tailscale Android application ID.
	Package = "com.tailscale.ipn"

	androidicHashLength = 6
	dockerfileName      = "Dockerfile.android-integration"
	dockerContextPath   = "../."

	apkPath       = "/tmp/tailscale.apk"
	dpcAPKPath    = "/opt/dpc.apk"
	dpcAdmin      = "org.headscale.dpc/.Admin"
	dpcReceiver   = "org.headscale.dpc/.SetRestrictions"
	uiDumpPath    = "/sdcard/window_dump.xml"
	logBasePath   = "/tmp/control"
	adbTimeout    = 2 * time.Minute
	pollInterval  = 2 * time.Second
	uiPollTimeout = 60 * time.Second
)

var (
	errNoNetwork   = errors.New("androidic: no network set")
	errBootTimeout = errors.New("androidic: timed out waiting for emulator boot")
	errNoUINode    = errors.New("androidic: no UI node matched")
	errInvalidCA   = errors.New("androidic: CA is not PEM")
)

// getPrebuiltImage returns the pre-built emulator image name if set.
func getPrebuiltImage() string {
	return os.Getenv("HEADSCALE_INTEGRATION_ANDROID_IMAGE")
}

// AndroidInContainer runs the Tailscale Android app in an emulator.
type AndroidInContainer struct {
	hostname string

	pool      *dockertest.Pool
	container *dockertest.Resource
	network   *dockertest.Network
}

// Option represents optional settings for an [AndroidInContainer].
type Option = func(c *AndroidInContainer)

// WithNetwork sets the Docker [dockertest.Network].
func WithNetwork(network *dockertest.Network) Option {
	return func(a *AndroidInContainer) {
		a.network = network
	}
}

// New creates and starts a new [AndroidInContainer] and waits for the
// emulator to finish booting.
func New(
	pool *dockertest.Pool,
	opts ...Option,
) (*AndroidInContainer, error) {
	hash := rands.HexString(androidicHashLength)

	hostname := "android-" + hash
	if runID := dockertestutil.GetIntegrationRunID(); runID != "" {
		hostname = fmt.Sprintf("android-%s-%s", runID[len(runID)-6:], hash)
	}

	a := &AndroidInContainer{
		hostname: hostname,
		pool:     pool,
	}

	for _, opt := range opts {
		opt(a)
	}

	if a.network == nil {
		return nil, errNoNetwork
	}

	runOptions := &dockertest.RunOptions{
		Name:     hostname,
		Networks: []*dockertest.Network{a.network},
	}

	dockertestutil.DockerAddIntegrationLabels(runOptions, "android")

	err := pool.RemoveContainerByName(hostname)
	if err != nil {
		return nil, err
	}

	// The emulator needs KVM and more memory than the shared
	// DockerMemoryLimit allows.
	hostConfig := func(config *docker.HostConfig) {
		config.Privileged = true
		config.Devices = append(config.Devices, docker.Device{
			PathOnHost:        "/dev/kvm",
			PathInContainer:   "/dev/kvm",
			CgroupPermissions: "rwm",
		})
	}

	var container *dockertest.Resource

	if prebuiltImage := getPrebuiltImage(); prebuiltImage != "" {
		log.Printf("Using pre-built android image: %s", prebuiltImage)

		repo, tag, ok := strings.Cut(prebuiltImage, ":")
		if !ok {
			return nil, fmt.Errorf("androidic: invalid image format %q, expected repository:tag", prebuiltImage) //nolint:err113
		}

		runOptions.Repository = repo
		runOptions.Tag = tag

		container, err = pool.RunWithOptions(runOptions, hostConfig)
	} else {
		log.Printf("Building android emulator container %s (first build downloads the SDK)...", hostname)

		container, err = pool.BuildAndRunWithBuildOptions(
			&dockertest.BuildOptions{
				Dockerfile: dockerfileName,
				ContextDir: dockerContextPath,
				Platform:   "linux/amd64",
			},
			runOptions,
			hostConfig,
		)
	}

	if err != nil {
		return nil, fmt.Errorf("androidic: could not start container %s: %w", hostname, err)
	}

	a.container = container

	log.Printf("Created android container %s", hostname)

	err = a.waitForBoot(5 * time.Minute)
	if err != nil {
		return a, err
	}

	return a, nil
}

func (a *AndroidInContainer) waitForBoot(timeout time.Duration) error {
	_, err := poll(timeout, func() (struct{}, error) {
		out, _, _ := a.Execute([]string{"adb", "shell", "getprop", "sys.boot_completed"})
		if strings.TrimSpace(out) != "1" {
			return struct{}{}, errBootTimeout
		}

		return struct{}{}, nil
	})
	if err != nil {
		return err
	}

	// Dismiss the lock screen so UI automation reaches the app.
	_, _ = a.Shell("input", "keyevent", "82")

	// A fresh Chrome opens login URLs on its first-run screen, which Back
	// cannot leave; users have long since passed it.
	_, err = a.Shell(
		"echo '_ --disable-fre --no-default-browser-check --no-first-run' > /data/local/tmp/chrome-command-line && " +
			"am set-debug-app --persistent com.android.chrome",
	)

	return err
}

func poll[T any](timeout time.Duration, fn func() (T, error)) (T, error) {
	return backoff.Retry(
		context.Background(),
		fn,
		backoff.WithBackOff(backoff.NewConstantBackOff(pollInterval)),
		backoff.WithMaxElapsedTime(timeout),
	)
}

// Install installs or upgrades the Tailscale app from apk, an http(s) URL
// (downloaded inside the container) or a path readable by the test
// process, granting runtime permissions and pre-approving VPN consent.
func (a *AndroidInContainer) Install(apk string) error {
	if strings.HasPrefix(apk, "http://") || strings.HasPrefix(apk, "https://") {
		_, stderr, err := a.Execute([]string{"curl", "-fsSL", "--retry", "3", "-o", apkPath, apk})
		if err != nil {
			return fmt.Errorf("downloading APK %s: %w: %s", apk, err, stderr)
		}
	} else {
		data, err := os.ReadFile(apk)
		if err != nil {
			return fmt.Errorf("reading APK: %w", err)
		}

		err = a.WriteFile(apkPath, data)
		if err != nil {
			return fmt.Errorf("copying APK: %w", err)
		}
	}

	out, stderr, err := a.Execute([]string{"adb", "install", "-r", "-g", apkPath})
	if err != nil || !strings.Contains(out, "Success") {
		return fmt.Errorf("adb install: %w: %s %s", err, out, stderr) //nolint:err113
	}

	// Stands in for the user tapping "OK" on the system VPN dialog,
	// which lives outside the app and is not scriptable from it.
	_, err = a.Shell("appops", "set", Package, "ACTIVATE_VPN", "allow")
	if err != nil {
		return fmt.Errorf("granting VPN consent: %w", err)
	}

	return nil
}

// SetManagedConfig installs the bundled device policy controller as device
// owner and replaces the app's managed configuration (MDM) with config,
// as an EMM would. Keys are the app's restriction keys, e.g. LoginURL.
func (a *AndroidInContainer) SetManagedConfig(config map[string]string) error {
	out, stderr, err := a.Execute([]string{"adb", "install", "-r", dpcAPKPath})
	if err != nil || !strings.Contains(out, "Success") {
		return fmt.Errorf("installing DPC: %w: %s %s", err, out, stderr) //nolint:err113
	}

	// Fails harmlessly with "already set" on repeat calls.
	_, _ = a.Shell("dpm", "set-device-owner", dpcAdmin)

	args := []string{"am", "broadcast", "-n", dpcReceiver}
	for k, v := range config {
		args = append(args, "--es", k, v)
	}

	out, err = a.Shell(args...)
	if err != nil || !strings.Contains(out, "data=\"ok") {
		return fmt.Errorf("setting managed config: %w: %s", err, out) //nolint:err113
	}

	return nil
}

// Debuggable reports whether the installed app is a debug build, which
// carries the integration login hook (LoginHook).
func (a *AndroidInContainer) Debuggable() (bool, error) {
	out, err := a.Shell("dumpsys", "package", Package)

	return strings.Contains(out, "DEBUGGABLE"), err
}

// LoginHook logs in via the debug-only integration broadcast, skipping the
// UI. It follows the same prefs/start/login sequence as the UI does.
func (a *AndroidInContainer) LoginHook(controlURL, authKey string) error {
	_, err := a.Shell(
		"am", "broadcast", "-a", Package+".integration.LOGIN",
		"-n", Package+"/.IPNReceiver", "--include-stopped-packages",
		"--es", "control_url", controlURL, "--es", "auth_key", authKey,
	)

	return err
}

// Crashes returns the crash log buffer if the app has crashed since boot.
func (a *AndroidInContainer) Crashes() (string, error) {
	out, _, err := a.Execute([]string{"adb", "logcat", "-d", "-b", "crash"})
	if err != nil {
		return "", err
	}

	if !strings.Contains(out, "Process: "+Package) {
		return "", nil
	}

	return out, nil
}

// InstallUserCA adds a PEM CA certificate to the device's user CA store,
// as installing it from Settings would.
func (a *AndroidInContainer) InstallUserCA(caPEM []byte) error {
	const dir = "/data/misc/user/0/cacerts-added"

	name, err := a.pushCA(caPEM)
	if err != nil {
		return err
	}

	_, err = a.Shell(fmt.Sprintf(
		"mkdir -p %[1]s && mv /data/local/tmp/%[2]s %[1]s/%[2]s && "+
			"chown -R system:system %[1]s && chmod 644 %[1]s/%[2]s && restorecon -R %[1]s",
		dir, name,
	))

	return err
}

// InstallSystemCA adds a PEM CA certificate to the device's system CA
// store, which every app version trusts. The store is overlaid with a
// tmpfs holding the stock CAs plus caPEM, so the read-only system image is
// untouched; apps started afterwards see it (Android 13 and older).
func (a *AndroidInContainer) InstallSystemCA(caPEM []byte) error {
	const dir = "/system/etc/security/cacerts"

	name, err := a.pushCA(caPEM)
	if err != nil {
		return err
	}

	_, err = a.Shell(fmt.Sprintf(
		"mkdir -p /data/local/tmp/cacerts && cp %[1]s/* /data/local/tmp/cacerts/ && "+
			"mount -t tmpfs none %[1]s && cp /data/local/tmp/cacerts/* %[1]s/ && "+
			"mv /data/local/tmp/%[2]s %[1]s/%[2]s && chown root:root %[1]s/* && "+
			"chmod 644 %[1]s/* && chcon u:object_r:system_file:s0 %[1]s/*",
		dir, name,
	))

	return err
}

// pushCA copies a PEM CA to /data/local/tmp on the device under the name
// Android's CA stores expect, leaving adbd running as root. Needs a
// google_apis image, where adbd can run as root.
func (a *AndroidInContainer) pushCA(caPEM []byte) (string, error) {
	block, _ := pem.Decode(caPEM)
	if block == nil {
		return "", errInvalidCA
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("parsing CA: %w", err)
	}

	// Android names store entries by OpenSSL's subject_hash_old: the first
	// four bytes of the subject's MD5, little endian.
	sum := md5.Sum(cert.RawSubject) //nolint:gosec
	name := fmt.Sprintf("%08x.0", binary.LittleEndian.Uint32(sum[:4]))

	err = a.WriteFile("/tmp/"+name, caPEM)
	if err != nil {
		return "", err
	}

	err = a.root()
	if err != nil {
		return "", err
	}

	_, stderr, err := a.Execute([]string{"adb", "push", "/tmp/" + name, "/data/local/tmp/" + name})
	if err != nil {
		return "", fmt.Errorf("pushing CA: %w: %s", err, stderr)
	}

	return name, nil
}

func (a *AndroidInContainer) root() error {
	_, stderr, err := a.Execute([]string{"sh", "-c", "adb root && adb wait-for-device"})
	if err != nil {
		return fmt.Errorf("adb root: %w: %s", err, stderr)
	}

	return nil
}

// VersionAtLeast reports whether the installed app is at least major.minor.
func (a *AndroidInContainer) VersionAtLeast(major, minor int) (bool, error) {
	v, err := a.Version()
	if err != nil {
		return false, err
	}

	var gotMajor, gotMinor int

	_, err = fmt.Sscanf(v, "%d.%d", &gotMajor, &gotMinor)
	if err != nil {
		return false, fmt.Errorf("parsing version %q: %w", v, err)
	}

	return gotMajor > major || gotMajor == major && gotMinor >= minor, nil
}

// Launch brings the app's main activity to the front. The app opens login
// URLs in a Chrome Custom Tab inside its own task, so Chrome is stopped
// first or relaunching would show the tab again.
func (a *AndroidInContainer) Launch() error {
	_, err := a.Shell("am", "force-stop", "com.android.chrome")
	if err != nil {
		return err
	}

	_, err = a.Shell("monkey", "-p", Package, "-c", "android.intent.category.LAUNCHER", "1")

	return err
}

// Version returns the installed app's versionName.
func (a *AndroidInContainer) Version() (string, error) {
	out, err := a.Shell("dumpsys", "package", Package)
	if err != nil {
		return "", err
	}

	for line := range strings.SplitSeq(out, "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(line), "versionName="); ok {
			return v, nil
		}
	}

	return "", nil
}

// uiNode is a node in a uiautomator hierarchy dump.
type uiNode struct {
	Text   string   `xml:"text,attr"`
	Desc   string   `xml:"content-desc,attr"`
	Class  string   `xml:"class,attr"`
	Pkg    string   `xml:"package,attr"`
	Bounds string   `xml:"bounds,attr"`
	Nodes  []uiNode `xml:"node"`
}

func (n uiNode) walk(fn func(uiNode) bool) bool {
	if fn(n) {
		return true
	}

	for _, c := range n.Nodes {
		if c.walk(fn) {
			return true
		}
	}

	return false
}

// center returns the centre of bounds "[x1,y1][x2,y2]".
func (n uiNode) center() (int, int, error) {
	var x1, y1, x2, y2 int

	_, err := fmt.Sscanf(n.Bounds, "[%d,%d][%d,%d]", &x1, &y1, &x2, &y2)
	if err != nil {
		return 0, 0, fmt.Errorf("parsing bounds %q: %w", n.Bounds, err)
	}

	return (x1 + x2) / 2, (y1 + y2) / 2, nil
}

// DumpUI returns the raw uiautomator XML of the current screen.
func (a *AndroidInContainer) DumpUI() (string, error) {
	_, err := a.Shell("uiautomator", "dump", uiDumpPath)
	if err != nil {
		return "", err
	}

	return a.Shell("cat", uiDumpPath)
}

func (a *AndroidInContainer) findNode(match func(uiNode) bool) (uiNode, bool, error) {
	raw, err := a.DumpUI()
	if err != nil {
		return uiNode{}, false, err
	}

	start := strings.Index(raw, "<hierarchy")
	if start < 0 {
		return uiNode{}, false, nil
	}

	var root uiNode

	err = xml.Unmarshal([]byte(raw[start:]), &root)
	if err != nil {
		return uiNode{}, false, fmt.Errorf("parsing UI dump: %w", err)
	}

	var found uiNode

	ok := root.walk(func(n uiNode) bool {
		if match(n) {
			found = n

			return true
		}

		return false
	})

	return found, ok, nil
}

// WaitForAny waits until a node whose text or content-desc equals one of
// labels is on screen and returns the label that matched.
func (a *AndroidInContainer) WaitForAny(labels ...string) (string, error) {
	n, err := a.waitFor(strings.Join(labels, "|"), func(n uiNode) bool {
		return slices.Contains(labels, n.Text) || slices.Contains(labels, n.Desc)
	})
	if err != nil {
		return "", err
	}

	if slices.Contains(labels, n.Text) {
		return n.Text, nil
	}

	return n.Desc, nil
}

// HasText reports whether a node whose text or content-desc equals label is
// currently on screen.
func (a *AndroidInContainer) HasText(label string) (bool, error) {
	_, ok, err := a.findNode(func(n uiNode) bool { return n.Text == label || n.Desc == label })

	return ok, err
}

func (a *AndroidInContainer) waitFor(what string, match func(uiNode) bool) (uiNode, error) {
	n, err := poll(uiPollTimeout, func() (uiNode, error) {
		n, ok, err := a.findNode(match)
		if err == nil && !ok {
			err = errNoUINode
		}

		return n, err
	})
	if err != nil {
		a.saveScreen("missing-" + sanitize(what))

		return uiNode{}, fmt.Errorf("%w: %q", err, what)
	}

	return n, nil
}

func (a *AndroidInContainer) tapNode(n uiNode) error {
	x, y, err := n.center()
	if err != nil {
		return err
	}

	_, err = a.Shell("input", "tap", strconv.Itoa(x), strconv.Itoa(y))

	return err
}

// Tap waits for a node whose text or content-desc equals label and taps it.
func (a *AndroidInContainer) Tap(label string) error {
	n, err := a.waitFor(label, func(n uiNode) bool { return n.Text == label || n.Desc == label })
	if err != nil {
		return err
	}

	return a.tapNode(n)
}

// EnterText taps the first editable text field and types s into it.
func (a *AndroidInContainer) EnterText(s string) error {
	n, err := a.waitFor("EditText", func(n uiNode) bool { return n.Class == "android.widget.EditText" })
	if err != nil {
		return err
	}

	err = a.tapNode(n)
	if err != nil {
		return err
	}

	// `input text` treats spaces as argument separators.
	_, err = a.Shell("input", "text", strings.ReplaceAll(s, " ", "%s"))

	return err
}

// WaitForBrowser waits until Chrome is in the foreground.
func (a *AndroidInContainer) WaitForBrowser() error {
	_, err := a.waitFor("browser", func(n uiNode) bool { return n.Pkg == "com.android.chrome" })

	return err
}

// Back presses the system back button.
func (a *AndroidInContainer) Back() error {
	_, err := a.Shell("input", "keyevent", "4")

	return err
}

// Shell runs a command via `adb shell` on the emulated device.
func (a *AndroidInContainer) Shell(args ...string) (string, error) {
	stdout, stderr, err := a.Execute(append([]string{"adb", "shell"}, args...))
	if err != nil {
		return stdout, fmt.Errorf("adb shell %v: %w: %s", args, err, stderr)
	}

	return stdout, nil
}

// saveScreen best-effort saves a screenshot and UI dump for debugging.
func (a *AndroidInContainer) saveScreen(name string) {
	base := path.Join(logBasePath, a.hostname+"-"+name)

	png, _, err := a.Execute([]string{"adb", "exec-out", "screencap", "-p"})
	if err == nil {
		_ = os.WriteFile(base+".png", []byte(png), 0o644) //nolint:gosec
	}

	raw, err := a.DumpUI()
	if err == nil {
		_ = os.WriteFile(base+".xml", []byte(raw), 0o644) //nolint:gosec
	}
}

func sanitize(s string) string {
	return strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' {
			return r
		}

		return '-'
	}, s)
}

// Hostname returns the container hostname.
func (a *AndroidInContainer) Hostname() string {
	return a.hostname
}

// ContainerID returns the Docker container ID.
func (a *AndroidInContainer) ContainerID() string {
	return a.container.Container.ID
}

// Shutdown saves logcat, a final screenshot and the container logs, then
// removes the container.
func (a *AndroidInContainer) Shutdown() (string, string, error) {
	err := os.MkdirAll(logBasePath, os.ModePerm)
	if err == nil {
		a.saveScreen("final")

		logcat, _, err := a.Execute([]string{"adb", "logcat", "-d", "-b", "all"})
		if err == nil {
			_ = os.WriteFile(path.Join(logBasePath, a.hostname+".logcat.log"), []byte(logcat), 0o644) //nolint:gosec
		}
	}

	stdoutPath, stderrPath, err := a.SaveLog(logBasePath)
	if err != nil {
		log.Printf("saving log from %s: %s", a.hostname, err)
	}

	return stdoutPath, stderrPath, a.pool.Purge(a.container)
}

// SaveLog saves the container stdout/stderr to the given path.
func (a *AndroidInContainer) SaveLog(path string) (string, string, error) {
	return dockertestutil.SaveLog(a.pool, a.container, path)
}

// WriteLogs writes the container stdout/stderr to the given writers.
func (a *AndroidInContainer) WriteLogs(stdout, stderr io.Writer) error {
	return dockertestutil.WriteLog(a.pool, a.container, stdout, stderr)
}

// Execute runs a command inside the emulator container (not the device).
func (a *AndroidInContainer) Execute(
	command []string,
	options ...dockertestutil.ExecuteCommandOption,
) (string, string, error) {
	if len(options) == 0 {
		options = []dockertestutil.ExecuteCommandOption{dockertestutil.ExecuteCommandTimeout(adbTimeout)}
	}

	return dockertestutil.ExecuteCommand(a.container, command, []string{}, options...)
}

// WriteFile writes a file into the emulator container.
func (a *AndroidInContainer) WriteFile(path string, data []byte) error {
	return integrationutil.WriteFileToContainer(a.pool, a.container, path, data)
}
