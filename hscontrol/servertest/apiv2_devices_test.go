package servertest_test

import (
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/servertest"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	tsclient "tailscale.com/client/tailscale/v2"
)

// baselinePolicy declares tag:ci so device SetTags is permitted. Every policy
// the device/acl tests write keeps tag:ci, so subtest order does not matter.
const baselinePolicy = `{"tagOwners":{"tag:ci":["apiv2@"]},"acls":[{"action":"accept","src":["*"],"dst":["*:*"]}]}`

// setBaselinePolicy installs baselinePolicy into both the policy manager and the
// database so device tagging and the ACL reads work.
func setBaselinePolicy(t *testing.T, srv *servertest.TestServer) {
	t.Helper()

	st := srv.State()

	_, err := st.SetPolicy([]byte(baselinePolicy))
	require.NoError(t, err)

	_, err = st.SetPolicyInDB(baselinePolicy)
	require.NoError(t, err)

	_, err = st.ReloadPolicy()
	require.NoError(t, err)
}

func goClient(t *testing.T, baseURL, apiKey string) *tsclient.Client {
	t.Helper()

	base, err := url.Parse(baseURL)
	require.NoError(t, err)

	return &tsclient.Client{BaseURL: base, APIKey: apiKey, Tailnet: "-"}
}

// srvNodeView reads the node straight from the server's NodeStore — the
// authoritative state between client steps. Handlers mutate the NodeStore
// synchronously before responding, so a read right after a 2xx is consistent.
func srvNodeView(t *testing.T, srv *servertest.TestServer, id types.NodeID) types.NodeView {
	t.Helper()

	v, ok := srv.State().GetNodeByID(id)
	require.Truef(t, ok, "node %d must exist server-side", id)
	require.True(t, v.Valid())

	return v
}

func approvedRoutesOf(nv types.NodeView) []string {
	return util.PrefixesToString(nv.ApprovedRoutes().AsSlice())
}

func nodeListed(srv *servertest.TestServer, id types.NodeID) bool {
	for _, n := range srv.State().ListNodes().All() {
		if n.ID() == id {
			return true
		}
	}

	return false
}

// apiv2DevicesGoClient drives the device lifecycle through the official SDK,
// validating each mutation three ways: the tool's own get-after-set, the
// server-side NodeStore, and (where relevant) permutations. Tagging is done late
// because it clears user ownership; delete is last.
func apiv2DevicesGoClient(t *testing.T, srv *servertest.TestServer, baseURL, apiKey string, id types.NodeID) {
	t.Helper()

	ctx := t.Context()
	dr := goClient(t, baseURL, apiKey).Devices()
	deviceID := strconv.FormatUint(uint64(id), 10)

	// Get — tool and server agree on identity and addresses.
	dev, err := dr.Get(ctx, deviceID)
	require.NoError(t, err)
	assert.Equal(t, deviceID, dev.NodeID)
	assert.NotEmpty(t, dev.Addresses)
	assert.True(t, dev.Authorized)
	assert.Equal(t, srvNodeView(t, srv, id).IPsAsString(), dev.Addresses)
	assert.Equal(t, srvNodeView(t, srv, id).GivenName(), dev.Name)

	// List — present in both the tool list and the server's node list.
	devs, err := dr.List(ctx)
	require.NoError(t, err)
	assert.True(t, containsDevice(devs, deviceID), "created device present in list")
	assert.True(t, nodeListed(srv, id))

	// SetName — get-after-set + server-side, then a second rename.
	require.NoError(t, dr.SetName(ctx, deviceID, "renamed-go"))
	dev, err = dr.Get(ctx, deviceID)
	require.NoError(t, err)
	assert.Equal(t, "renamed-go", dev.Name)
	assert.Equal(t, "renamed-go", srvNodeView(t, srv, id).GivenName())

	require.NoError(t, dr.SetName(ctx, deviceID, "renamed-go-2"))
	assert.Equal(t, "renamed-go-2", srvNodeView(t, srv, id).GivenName())

	// SetSubnetRoutes — one, two, then exit (expands to both families).
	require.NoError(t, dr.SetSubnetRoutes(ctx, deviceID, []string{"10.0.0.0/24"}))
	routes, err := dr.SubnetRoutes(ctx, deviceID)
	require.NoError(t, err)
	assert.Contains(t, routes.Enabled, "10.0.0.0/24")
	assert.Contains(t, approvedRoutesOf(srvNodeView(t, srv, id)), "10.0.0.0/24")
	assert.Empty(t, srvNodeView(t, srv, id).AnnouncedRoutes(), "route enabled without being announced")

	require.NoError(t, dr.SetSubnetRoutes(ctx, deviceID, []string{"10.0.0.0/24", "192.168.0.0/24"}))
	approved := approvedRoutesOf(srvNodeView(t, srv, id))
	assert.Contains(t, approved, "10.0.0.0/24")
	assert.Contains(t, approved, "192.168.0.0/24")

	// A single exit prefix expands to both families on the server.
	require.NoError(t, dr.SetSubnetRoutes(ctx, deviceID, []string{"0.0.0.0/0"}))
	approved = approvedRoutesOf(srvNodeView(t, srv, id))
	assert.Contains(t, approved, "0.0.0.0/0")
	assert.Contains(t, approved, "::/0")

	// SetKey — seed a real expiry first so disabling it is a state transition.
	future := time.Now().Add(24 * time.Hour)
	_, _, err = srv.State().SetNodeExpiry(id, &future)
	require.NoError(t, err)
	require.True(t, srvNodeView(t, srv, id).Expiry().Valid())

	require.NoError(t, dr.SetKey(ctx, deviceID, tsclient.DeviceKey{KeyExpiryDisabled: true}))
	dev, err = dr.Get(ctx, deviceID)
	require.NoError(t, err)
	assert.True(t, dev.KeyExpiryDisabled)
	assert.False(t, srvNodeView(t, srv, id).Expiry().Valid())

	// Re-enable is a no-op; expiry stays cleared.
	require.NoError(t, dr.SetKey(ctx, deviceID, tsclient.DeviceKey{KeyExpiryDisabled: false}))
	assert.False(t, srvNodeView(t, srv, id).Expiry().Valid())

	// SetTags — flips ownership to the tags; the user is dropped.
	require.NoError(t, dr.SetTags(ctx, deviceID, []string{"tag:ci"}))
	dev, err = dr.Get(ctx, deviceID)
	require.NoError(t, err)
	assert.Equal(t, []string{"tag:ci"}, dev.Tags)
	assert.Equal(t, types.TaggedDevices.Username(), dev.User)
	n := srvNodeView(t, srv, id)
	assert.True(t, n.IsTagged())
	assert.Equal(t, []string{"tag:ci"}, n.Tags().AsSlice())
	assert.False(t, n.User().Valid())

	// Re-tagging with the same tag is idempotent.
	require.NoError(t, dr.SetTags(ctx, deviceID, []string{"tag:ci"}))
	assert.Equal(t, []string{"tag:ci"}, srvNodeView(t, srv, id).Tags().AsSlice())

	// SetAuthorized(true) is a no-op success; de-auth is rejected and inert.
	require.NoError(t, dr.SetAuthorized(ctx, deviceID, true))
	dev, err = dr.Get(ctx, deviceID)
	require.NoError(t, err)
	assert.True(t, dev.Authorized)

	require.Error(t, dr.SetAuthorized(ctx, deviceID, false), "de-authorization is unsupported")
	assert.True(t, srvNodeView(t, srv, id).Valid(), "rejected de-auth left the node present")

	// Delete — gone from the tool and the server.
	require.NoError(t, dr.Delete(ctx, deviceID))
	_, err = dr.Get(ctx, deviceID)
	assert.Truef(t, tsclient.IsNotFound(err), "get after delete should be 404, got %v", err)

	_, ok := srv.State().GetNodeByID(id)
	assert.False(t, ok, "deleted node is gone server-side")
}

func containsDevice(devs []tsclient.Device, id string) bool {
	for _, d := range devs {
		if d.NodeID == id || d.ID == id {
			return true
		}
	}

	return false
}

// apiv2ACLGoClient round-trips the policy file: read, raw-read, conditional set.
func apiv2ACLGoClient(t *testing.T, baseURL, apiKey string) {
	t.Helper()

	ctx := t.Context()
	pf := goClient(t, baseURL, apiKey).PolicyFile()

	acl, err := pf.Get(ctx)
	require.NoError(t, err)
	assert.NotEmpty(t, acl.ETag, "GET /acl carries an ETag")

	raw, err := pf.Raw(ctx)
	require.NoError(t, err)
	assert.NotEmpty(t, raw.HuJSON)

	// Set with the current etag as If-Match; keep tag:ci.
	require.NoError(t, pf.Set(ctx, baselinePolicy, raw.ETag))

	updated, err := pf.Raw(ctx)
	require.NoError(t, err)
	assert.Contains(t, updated.HuJSON, "tag:ci")
}

// apiv2SettingsGoClient reads the tailnet settings (write is unsupported).
func apiv2SettingsGoClient(t *testing.T, baseURL, apiKey string) {
	t.Helper()

	settings, err := goClient(t, baseURL, apiKey).TailnetSettings().Get(t.Context())
	require.NoError(t, err)
	assert.Equal(t, "none", string(settings.UsersRoleAllowedToJoinExternalTailnets))
}

// tscliRun runs tscli and fails the test on a non-zero exit.
type tscliRun func(args ...string) string

// tscliRunner returns runners for tscli against the local server: one that
// requires success, and one that tolerates a non-zero exit (for the expected
// 404 after a delete).
func tscliRunner(t *testing.T, baseURL, apiKey string) (tscliRun, func(args ...string) error) {
	t.Helper()

	bin, err := exec.LookPath("tscli")
	require.NoErrorf(t, err, "tscli is required for TestAPIv2 (provided by the nix dev shell)")

	env := append(
		os.Environ(),
		"TSCLI_BASE_URL="+baseURL,
		"TAILSCALE_API_KEY="+apiKey,
		"TAILSCALE_TAILNET=-",
	)

	cmd := func(args ...string) *exec.Cmd {
		c := exec.CommandContext(t.Context(), bin, args...)
		c.Env = env

		return c
	}

	run := func(args ...string) string {
		t.Helper()

		out, err := cmd(args...).CombinedOutput()
		require.NoErrorf(t, err, "tscli %s\n%s", strings.Join(args, " "), out)

		return string(out)
	}

	runAllowErr := func(args ...string) error {
		t.Helper()

		return cmd(args...).Run()
	}

	return run, runAllowErr
}

// apiv2DevicesTSCLI drives the device verbs through tscli, asserting each
// mutation via get-after-set (tscli's own json output) and the server NodeStore.
func apiv2DevicesTSCLI(t *testing.T, srv *servertest.TestServer, baseURL, apiKey string, id types.NodeID) {
	t.Helper()

	run, runAllowErr := tscliRunner(t, baseURL, apiKey)
	deviceID := strconv.FormatUint(uint64(id), 10)

	assert.Contains(t, run("get", "device", "--device", deviceID, "-o", "json"), deviceID)
	assert.True(t, nodeListed(srv, id))

	// Name.
	run("set", "device", "name", "--device", deviceID, "--name", "renamed-tscli")
	assert.Contains(t, run("get", "device", "--device", deviceID, "-o", "json"), "renamed-tscli")
	assert.Equal(t, "renamed-tscli", srvNodeView(t, srv, id).GivenName())

	// Routes — one, two, then exit (both families).
	run("set", "device", "routes", "--device", deviceID, "--route", "10.0.0.0/24")
	assert.Contains(t, run("list", "routes", "--device", deviceID, "-o", "json"), "10.0.0.0/24")
	assert.Contains(t, approvedRoutesOf(srvNodeView(t, srv, id)), "10.0.0.0/24")

	run("set", "device", "routes", "--device", deviceID, "--route", "10.0.0.0/24", "--route", "192.168.0.0/24")

	approved := approvedRoutesOf(srvNodeView(t, srv, id))
	assert.Contains(t, approved, "10.0.0.0/24")
	assert.Contains(t, approved, "192.168.0.0/24")

	run("set", "device", "routes", "--device", deviceID, "--route", "0.0.0.0/0")

	exitApproved := approvedRoutesOf(srvNodeView(t, srv, id))
	assert.Contains(t, exitApproved, "0.0.0.0/0")
	assert.Contains(t, exitApproved, "::/0")

	// Key — seed a real expiry first so disabling it is a transition.
	future := time.Now().Add(24 * time.Hour)
	_, _, err := srv.State().SetNodeExpiry(id, &future)
	require.NoError(t, err)

	run("set", "device", "key", "--device", deviceID, "--disable-expiry")
	assert.Contains(t, run("get", "device", "--device", deviceID, "-o", "json"), `"keyExpiryDisabled": true`)
	assert.False(t, srvNodeView(t, srv, id).Expiry().Valid())

	// Tags — flips to tag ownership.
	run("set", "device", "tags", "--device", deviceID, "--tag", "tag:ci")
	assert.Contains(t, run("get", "device", "--device", deviceID, "-o", "json"), "tag:ci")
	n := srvNodeView(t, srv, id)
	assert.True(t, n.IsTagged())
	assert.Equal(t, []string{"tag:ci"}, n.Tags().AsSlice())
	assert.False(t, n.User().Valid())

	// Authorization — approve is a no-op success.
	run("set", "device", "authorization", "--device", deviceID, "--approve")
	assert.Contains(t, run("get", "device", "--device", deviceID, "-o", "json"), `"authorized": true`)

	// Delete — gone from tscli and the server.
	run("delete", "device", "--device", deviceID)
	require.Error(t, runAllowErr("get", "device", "--device", deviceID, "-o", "json"), "get after delete should fail")

	_, ok := srv.State().GetNodeByID(id)
	assert.False(t, ok)
}

// apiv2ACLTSCLI reads and writes the policy file through tscli.
func apiv2ACLTSCLI(t *testing.T, baseURL, apiKey string) {
	t.Helper()

	run, _ := tscliRunner(t, baseURL, apiKey)

	assert.Contains(t, run("get", "policy", "--json"), "acls")

	dir := t.TempDir()
	polFile := filepath.Join(dir, "policy.hujson")
	require.NoError(t, os.WriteFile(polFile, []byte(baselinePolicy), 0o600))
	run("set", "policy", "--file", polFile)
}

// apiv2SettingsTSCLI reads the tailnet settings through tscli.
func apiv2SettingsTSCLI(t *testing.T, baseURL, apiKey string) {
	t.Helper()

	run, _ := tscliRunner(t, baseURL, apiKey)
	assert.Contains(t, run("get", "settings", "-o", "json"), "devicesKeyDurationDays")
}

// devicesACLTFConfig exercises Terraform device + ACL data sources AND resources.
// %s is the test node's hostname (the tailscale_device data source key).
const devicesACLTFConfig = `
terraform {
  required_providers {
    tailscale = {
      source  = "tailscale/tailscale"
      version = "~> 0.21"
    }
  }
}

provider "tailscale" {}

resource "tailscale_acl" "policy" {
  acl = jsonencode({
    tagOwners = { "tag:ci" = ["apiv2@"] }
    acls      = [{ action = "accept", src = ["*"], dst = ["*:*"] }]
  })
  overwrite_existing_content = true
}

data "tailscale_device" "dut" {
  hostname = "%s"
  wait_for = "30s"
}

data "tailscale_devices" "all" {}

data "tailscale_acl" "current" {
  depends_on = [tailscale_acl.policy]
}

resource "tailscale_device_authorization" "dut" {
  device_id  = data.tailscale_device.dut.node_id
  authorized = true
}

resource "tailscale_device_tags" "dut" {
  device_id  = data.tailscale_device.dut.node_id
  tags       = ["tag:ci"]
  depends_on = [tailscale_acl.policy]
}

resource "tailscale_device_key" "dut" {
  device_id           = data.tailscale_device.dut.node_id
  key_expiry_disabled = true
}

resource "tailscale_device_subnet_routes" "dut" {
  device_id = data.tailscale_device.dut.node_id
  routes    = ["10.0.0.0/24"]
}

output "dut_node_id"    { value = data.tailscale_device.dut.node_id }
output "dut_addresses"  { value = data.tailscale_device.dut.addresses }
output "dut_authorized" { value = data.tailscale_device.dut.authorized }
output "device_count"   { value = length(data.tailscale_devices.all.devices) }
output "acl_hujson"     { value = data.tailscale_acl.current.hujson }
output "enabled_routes" { value = tailscale_device_subnet_routes.dut.routes }
`

// apiv2DevicesACLTerraform runs a tofu init/apply/destroy over the device and
// ACL data sources and resources, asserting no post-apply drift, the data-source
// outputs (read path) against the server truth, and the resulting server state
// (write path). parallelism=1 avoids racing concurrent mutations on the one
// shared node.
func apiv2DevicesACLTerraform(t *testing.T, srv *servertest.TestServer, baseURL, apiKey, hostname string, id types.NodeID) {
	t.Helper()

	tf := newTofu(t, baseURL, apiKey, fmt.Sprintf(devicesACLTFConfig, hostname))

	tf.run("init", "-no-color", "-input=false")
	tf.run("apply", "-auto-approve", "-no-color", "-input=false", "-parallelism=1")

	// Data sources resolved to real values that match the server.
	outputs := tf.outputs()
	assert.Equal(t, strconv.FormatUint(uint64(id), 10), outputs.str(t, "dut_node_id"))
	assert.ElementsMatch(t, srvNodeView(t, srv, id).IPsAsString(), outputs.strSlice(t, "dut_addresses"))
	outputs.jsonEq(t, "dut_authorized", true)
	assert.Equal(t, srv.State().ListNodes().Len(), int(outputs.num(t, "device_count")))
	assert.Contains(t, outputs.str(t, "acl_hujson"), "tag:ci")
	assert.Contains(t, outputs.strSlice(t, "enabled_routes"), "10.0.0.0/24")

	// Server-side: the resources actually applied (write path).
	n := srvNodeView(t, srv, id)
	assert.True(t, n.IsTagged())
	assert.Equal(t, []string{"tag:ci"}, n.Tags().AsSlice())
	assert.Contains(t, approvedRoutesOf(n), "10.0.0.0/24")
	assert.False(t, n.Expiry().Valid())

	pol, err := srv.State().GetPolicy()
	require.NoError(t, err)
	assert.Contains(t, pol.Data, "tag:ci", "tailscale_acl wrote the policy")

	// A converged config must produce an empty plan — drift is a read/write bug.
	tf.assertNoDrift()

	// destroy resets the policy; the node is a data source, so it persists.
	// Tags/expiry teardown are no-ops on Headscale, so they are not reverted.
	tf.run("destroy", "-auto-approve", "-no-color", "-input=false", "-parallelism=1")

	_, ok := srv.State().GetNodeByID(id)
	assert.True(t, ok, "data-source node persists across destroy")
}
