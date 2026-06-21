package servertest_test

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/juanfont/headscale/hscontrol/servertest"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	tsclient "tailscale.com/client/tailscale/v2"
)

// TestAPIv2 proves the v2 API's Tailscale-compatible (ported) endpoints against the three real
// clients it exists to support: the official Go SDK, tscli, and the Tailscale
// Terraform provider (via OpenTofu). All three run against one Headscale bound
// to a real loopback port, authenticating with a user-owned API key.
//
// Every mutation is validated three ways — the tool's own get-after-set, the
// server-side NodeStore/state, and (for Terraform) a no-change plan proving no
// drift — so a server/provider read-write mismatch fails loudly.
//
// tscli and tofu are required, not optional: they ship in the nix dev shell, so
// a missing binary means a broken environment and the test fails rather than
// silently skipping.
func TestAPIv2(t *testing.T) {
	srv := servertest.NewServer(t, servertest.WithRealListener())
	owner := srv.CreateUser(t, "apiv2")
	apiKey := srv.CreateAPIKey(t, owner)

	// tag:ci must exist in policy for device SetTags; every policy the tests
	// write keeps it, so subtest order is irrelevant. Terraform runs last so its
	// ACL teardown does not strand the others.
	setBaselinePolicy(t, srv)

	t.Run("GoClient", func(t *testing.T) {
		apiv2GoClient(t, srv, srv.URL, apiKey, owner)
		apiv2UsersGoClient(t, srv, srv.URL, apiKey, owner)

		node := srv.CreateRegisteredNode(t, owner, "dut-go")
		apiv2DevicesGoClient(t, srv, srv.URL, apiKey, node.ID())
		apiv2ACLGoClient(t, srv.URL, apiKey)
		apiv2SettingsGoClient(t, srv.URL, apiKey)
	})

	t.Run("TSCLI", func(t *testing.T) {
		apiv2TSCLI(t, srv, srv.URL, apiKey)
		apiv2UsersTSCLI(t, srv.URL, apiKey, owner)

		node := srv.CreateRegisteredNode(t, owner, "dut-tscli")
		apiv2DevicesTSCLI(t, srv, srv.URL, apiKey, node.ID())
		apiv2ACLTSCLI(t, srv.URL, apiKey)
		apiv2SettingsTSCLI(t, srv.URL, apiKey)
	})

	t.Run("Terraform", func(t *testing.T) {
		apiv2Terraform(t, srv, srv.URL, apiKey, owner)
		apiv2UsersTerraform(t, srv, srv.URL, apiKey, owner)

		node := srv.CreateRegisteredNode(t, owner, "dut-tf")
		apiv2DevicesACLTerraform(t, srv, srv.URL, apiKey, node.Hostname(), node.ID())
	})
}

// apiv2GoClient exercises the official SDK with untagged (user-owned) keys — the
// default Terraform/tscli path — validating each operation against the server's
// stored PreAuthKey, plus ephemeral and default-expiry permutations.
func apiv2GoClient(t *testing.T, srv *servertest.TestServer, baseURL, apiKey string, owner *types.User) {
	t.Helper()

	ctx := t.Context()
	keys := goClient(t, baseURL, apiKey).Keys()
	wantOwner := strconv.FormatUint(uint64(owner.ID), 10)

	var req tsclient.CreateKeyRequest

	req.Description = "go-client"
	req.ExpirySeconds = 3600
	req.Capabilities.Devices.Create.Reusable = true

	created, err := keys.CreateAuthKey(ctx, req)
	require.NoError(t, err)
	assert.NotEmpty(t, created.ID)
	assert.NotEmpty(t, created.Key, "secret returned on create")
	assert.Equal(t, "go-client", created.Description)
	assert.Equal(t, wantOwner, created.UserID, "user-owned key reports its owner")

	// Server-side: the stored key matches the request and is owned by the user.
	pak := srvPreAuthKey(t, srv, created.ID)
	assert.True(t, pak.Reusable)
	assert.False(t, pak.Ephemeral)
	assert.Empty(t, pak.Tags, "no tags -> user-owned")
	require.NotNil(t, pak.User)
	assert.Equal(t, owner.ID, pak.User.ID)
	assert.Equal(t, "go-client", pak.Description)
	require.NotNil(t, pak.CreatedAt)
	require.NotNil(t, pak.Expiration)
	assert.InDelta(t, 3600, pak.Expiration.Sub(*pak.CreatedAt).Seconds(), 5)

	got, err := keys.Get(ctx, created.ID)
	require.NoError(t, err)
	assert.Equal(t, created.ID, got.ID)
	assert.Empty(t, got.Key, "secret omitted on get")
	assert.Equal(t, "go-client", got.Description)
	assert.False(t, got.Invalid)
	// The SDK decodes our integer expirySeconds into a Duration of nanoseconds,
	// so never assert it numerically; the lifetime rides on Expires-Created.
	assert.InDelta(t, 3600, got.Expires.Sub(got.Created).Seconds(), 5)

	list, err := keys.List(ctx, true)
	require.NoError(t, err)
	assert.True(t, containsKeyID(list, created.ID), "created key present in list")

	// DELETE soft-revokes (Tailscale-faithful): the key stays retrievable, now
	// invalid, until the collector reaps it.
	require.NoError(t, keys.Delete(ctx, created.ID))
	revoked, err := keys.Get(ctx, created.ID)
	require.NoError(t, err, "revoked key stays retrievable")
	assert.True(t, revoked.Invalid, "revoked key reports invalid")
	require.NotNil(t, srvPreAuthKey(t, srv, created.ID).Revoked, "key soft-revoked server-side")

	// Permutation — ephemeral key.
	var ephReq tsclient.CreateKeyRequest

	ephReq.Capabilities.Devices.Create.Ephemeral = true
	eph, err := keys.CreateAuthKey(ctx, ephReq)
	require.NoError(t, err)
	assert.True(t, srvPreAuthKey(t, srv, eph.ID).Ephemeral)
	require.NoError(t, keys.Delete(ctx, eph.ID))

	// Permutation — default expiry (omit ExpirySeconds -> 90 days).
	def, err := keys.CreateAuthKey(ctx, tsclient.CreateKeyRequest{})
	require.NoError(t, err)
	defKey := srvPreAuthKey(t, srv, def.ID)
	require.NotNil(t, defKey.CreatedAt)
	require.NotNil(t, defKey.Expiration)
	assert.InDelta(t, 7776000, defKey.Expiration.Sub(*defKey.CreatedAt).Seconds(), 5)
	require.NoError(t, keys.Delete(ctx, def.ID))
}

func containsKeyID(keys []tsclient.Key, id string) bool {
	for _, k := range keys {
		if k.ID == id {
			return true
		}
	}

	return false
}

func containsUserID(users []tsclient.User, id string) bool {
	for _, u := range users {
		if u.ID == id {
			return true
		}
	}

	return false
}

// srvUserCount is the server-side ground truth for the number of users.
func srvUserCount(t *testing.T, srv *servertest.TestServer) int {
	t.Helper()

	users, err := srv.State().ListAllUsers()
	require.NoError(t, err)

	return len(users)
}

// apiv2UsersGoClient exercises the Users data sources through the official SDK:
// get-by-id, list, the type/role filters (member matches all, anything else
// matches nothing), and a typed 404 — each cross-checked against server truth.
func apiv2UsersGoClient(t *testing.T, srv *servertest.TestServer, baseURL, apiKey string, owner *types.User) {
	t.Helper()

	ctx := t.Context()
	ur := goClient(t, baseURL, apiKey).Users()
	ownerID := strconv.FormatUint(uint64(owner.ID), 10)

	got, err := ur.Get(ctx, ownerID)
	require.NoError(t, err)
	assert.Equal(t, ownerID, got.ID)
	assert.Equal(t, owner.Username(), got.LoginName)
	assert.Equal(t, tsclient.UserTypeMember, got.Type)
	assert.Equal(t, tsclient.UserStatusActive, got.Status)
	assert.Equal(t, srv.State().ListNodesByUser(types.UserID(owner.ID)).Len(), got.DeviceCount,
		"deviceCount matches the server's node count for the user")

	all, err := ur.List(ctx, nil, nil)
	require.NoError(t, err)
	assert.True(t, containsUserID(all, ownerID), "owner present in user list")
	assert.Len(t, all, srvUserCount(t, srv))

	// member matches every Headscale user; shared/admin match nothing.
	members, err := ur.List(ctx, new(tsclient.UserTypeMember), nil)
	require.NoError(t, err)
	assert.Len(t, members, len(all))

	shared, err := ur.List(ctx, new(tsclient.UserTypeShared), nil)
	require.NoError(t, err)
	assert.Empty(t, shared, "Headscale has no shared users")

	admins, err := ur.List(ctx, nil, new(tsclient.UserRoleAdmin))
	require.NoError(t, err)
	assert.Empty(t, admins, "Headscale has no admin-role users")

	_, err = ur.Get(ctx, "999999")
	require.Error(t, err)
	assert.True(t, tsclient.IsNotFound(err), "unknown user id is a typed 404")
}

// apiv2UsersTSCLI exercises the user verbs through tscli, asserting the owner is
// present in the list and retrievable by id.
func apiv2UsersTSCLI(t *testing.T, baseURL, apiKey string, owner *types.User) {
	t.Helper()

	run, _ := tscliRunner(t, baseURL, apiKey)
	ownerID := strconv.FormatUint(uint64(owner.ID), 10)

	listOut := run("list", "users", "-o", "json")
	assert.Contains(t, listOut, ownerID)
	assert.Contains(t, listOut, `"member"`)

	getOut := run("get", "user", "--user", ownerID, "-o", "json")
	assert.Contains(t, getOut, ownerID)
	assert.Contains(t, getOut, owner.Username())
}

// srvPreAuthKey is the server-side ground truth for a key id; it fails the test
// if the key is absent.
func srvPreAuthKey(t *testing.T, srv *servertest.TestServer, id string) types.PreAuthKey {
	t.Helper()

	pak := findPAKByID(t, srv, id)
	require.NotNilf(t, pak, "pre-auth key %s not found server-side", id)

	return *pak
}

// findPAKByID returns the stored key with the given stringified id, or nil.
func findPAKByID(t *testing.T, srv *servertest.TestServer, id string) *types.PreAuthKey {
	t.Helper()

	want, err := strconv.ParseUint(id, 10, 64)
	require.NoError(t, err)

	keys, err := srv.State().ListPreAuthKeys()
	require.NoError(t, err)

	for i := range keys {
		if keys[i].ID == want {
			return &keys[i]
		}
	}

	return nil
}

// apiv2TSCLI exercises tscli with a tagged key, validating server-side that the
// stored key carries the requested tags and metadata.
func apiv2TSCLI(t *testing.T, srv *servertest.TestServer, baseURL, apiKey string) {
	t.Helper()

	run, _ := tscliRunner(t, baseURL, apiKey)

	out := run(
		"create", "key",
		"--type", "authkey",
		"--description", "tscli",
		"--expiry", "1h",
		"--reusable",
		"--tags", "tag:ci",
		"-o", "json",
	)

	var created struct {
		ID  string `json:"id"`
		Key string `json:"key"`
	}
	require.NoErrorf(t, json.Unmarshal([]byte(out), &created), "tscli create output: %s", out)
	assert.NotEmpty(t, created.ID)
	assert.NotEmpty(t, created.Key, "secret returned on create")

	// Server-side: tagged, reusable, described, no owner.
	pak := srvPreAuthKey(t, srv, created.ID)
	assert.Equal(t, []string{"tag:ci"}, pak.Tags)
	assert.True(t, pak.Reusable)
	assert.Equal(t, "tscli", pak.Description)
	assert.Nil(t, pak.User, "tagged key has no owning user")

	getOut := run("get", "key", "--key", created.ID, "-o", "json")

	var got struct {
		Key string `json:"key"`
	}
	require.NoError(t, json.Unmarshal([]byte(getOut), &got))
	assert.Empty(t, got.Key, "secret omitted on get")

	assert.Contains(t, run("list", "keys", "--all", "-o", "json"), created.ID)

	// DELETE soft-revokes: the key stays retrievable (invalid) server-side until
	// the collector reaps it.
	run("delete", "key", "--key", created.ID)
	assert.Contains(t, run("get", "key", "--key", created.ID, "-o", "json"), `"invalid": true`)
	require.NotNil(t, srvPreAuthKey(t, srv, created.ID).Revoked, "key soft-revoked server-side")
}

// terraformConfig drives the tailscale_tailnet_key resource against the local
// server. No tags, so the key is owned by the API key's user — the default
// Terraform path. Outputs expose the provider's read-back for value + drift
// checks.
const terraformConfig = `
terraform {
  required_providers {
    tailscale = {
      source  = "tailscale/tailscale"
      version = "~> 0.21"
    }
  }
}

provider "tailscale" {}

resource "tailscale_tailnet_key" "test" {
  reusable      = true
  ephemeral     = false
  preauthorized = true
  expiry        = 3600
  description   = "tofu-roundtrip"
}

output "key_id"          { value = tailscale_tailnet_key.test.id }
output "key_reusable"    { value = tailscale_tailnet_key.test.reusable }
output "key_ephemeral"   { value = tailscale_tailnet_key.test.ephemeral }
output "key_description" { value = tailscale_tailnet_key.test.description }
`

// apiv2Terraform runs a tofu init→apply→(no-drift)→destroy roundtrip on a
// tailnet key, cross-checking the provider outputs and the server's stored key.
func apiv2Terraform(t *testing.T, srv *servertest.TestServer, baseURL, apiKey string, owner *types.User) {
	t.Helper()

	tf := newTofu(t, baseURL, apiKey, terraformConfig)

	tf.run("init", "-no-color", "-input=false")
	tf.run("apply", "-auto-approve", "-no-color", "-input=false", "-parallelism=1")

	outputs := tf.outputs()
	keyID := outputs.str(t, "key_id")
	require.NotEmpty(t, keyID)
	outputs.jsonEq(t, "key_reusable", true)
	outputs.jsonEq(t, "key_ephemeral", false)
	outputs.jsonEq(t, "key_description", "tofu-roundtrip")

	// Server-side: the key exists, user-owned, with the requested attributes.
	pak := srvPreAuthKey(t, srv, keyID)
	assert.Equal(t, "tofu-roundtrip", pak.Description)
	assert.True(t, pak.Reusable)
	assert.False(t, pak.Ephemeral)
	assert.Empty(t, pak.Tags, "no tags -> user-owned key")
	require.NotNil(t, pak.User)
	assert.Equal(t, owner.ID, pak.User.ID)
	require.NotNil(t, pak.CreatedAt)
	require.NotNil(t, pak.Expiration)
	assert.InDelta(t, 3600, pak.Expiration.Sub(*pak.CreatedAt).Seconds(), 5)

	// A converged config must produce an empty plan — drift is a read/write bug.
	tf.assertNoDrift()

	// destroy DELETEs the key, which soft-revokes it: the row is kept (revoked)
	// until the collector reaps it.
	tf.run("destroy", "-auto-approve", "-no-color", "-input=false", "-parallelism=1")
	require.NotNil(t, srvPreAuthKey(t, srv, keyID).Revoked, "key revoked after destroy")
}

// usersTFConfig drives the tailscale_user (by login name) and tailscale_users
// data sources, plus tailscale_4via6 (provider-local compute, no server call) to
// prove that data source resolves against Headscale unchanged. %s is the owner's
// login name. Data sources create nothing, so the assertions are value
// correctness plus no drift on re-read.
const usersTFConfig = `
terraform {
  required_providers {
    tailscale = {
      source  = "tailscale/tailscale"
      version = "~> 0.21"
    }
  }
}

provider "tailscale" {}

data "tailscale_user" "owner" {
  login_name = "%s"
}

data "tailscale_users" "all" {}

data "tailscale_4via6" "site" {
  site = 7
  cidr = "10.1.1.0/24"
}

output "user_id"           { value = data.tailscale_user.owner.id }
output "user_login_name"   { value = data.tailscale_user.owner.login_name }
output "user_type"         { value = data.tailscale_user.owner.type }
output "user_device_count" { value = data.tailscale_user.owner.device_count }
output "users_count"       { value = length(data.tailscale_users.all.users) }
output "via6"              { value = data.tailscale_4via6.site.ipv6 }
`

// apiv2UsersTerraform runs a tofu init/apply/(no-drift)/destroy over the
// tailscale_user + tailscale_users data sources (and the provider-local
// tailscale_4via6), cross-checking the data-source outputs against the server's
// stored users.
func apiv2UsersTerraform(t *testing.T, srv *servertest.TestServer, baseURL, apiKey string, owner *types.User) {
	t.Helper()

	tf := newTofu(t, baseURL, apiKey, fmt.Sprintf(usersTFConfig, owner.Username()))

	tf.run("init", "-no-color", "-input=false")
	tf.run("apply", "-auto-approve", "-no-color", "-input=false", "-parallelism=1")

	outputs := tf.outputs()
	assert.Equal(t, strconv.FormatUint(uint64(owner.ID), 10), outputs.str(t, "user_id"))
	assert.Equal(t, owner.Username(), outputs.str(t, "user_login_name"))
	assert.Equal(t, "member", outputs.str(t, "user_type"))
	assert.Equal(t, srv.State().ListNodesByUser(types.UserID(owner.ID)).Len(),
		int(outputs.num(t, "user_device_count")))
	assert.Equal(t, srvUserCount(t, srv), int(outputs.num(t, "users_count")))

	// tailscale_4via6 is computed by the provider with no server call; assert it
	// resolved to a Tailscale 4via6 address.
	assert.Contains(t, outputs.str(t, "via6"), "fd7a:115c:a1e0", "4via6 mapped address")

	// A converged data-source read must produce an empty plan — drift is a read bug.
	tf.assertNoDrift()

	// destroy removes only TF state; the users persist (they are data sources).
	tf.run("destroy", "-auto-approve", "-no-color", "-input=false", "-parallelism=1")
	assert.GreaterOrEqual(t, srvUserCount(t, srv), 1, "users persist across data-source destroy")
}

// tofu binds a tofu binary, working dir, and env for a single workspace. cmd is
// a closure capturing the looked-up binary so subprocess construction stays in
// one place.
type tofu struct {
	t   *testing.T
	cmd func(args ...string) *exec.Cmd
}

func newTofu(t *testing.T, baseURL, apiKey, config string) *tofu {
	t.Helper()

	bin, err := exec.LookPath("tofu")
	require.NoErrorf(t, err, "tofu is required for TestAPIv2 (provided by the nix dev shell)")

	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "main.tf"), []byte(config), 0o600))
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "plugin-cache"), 0o755))

	env := append(
		os.Environ(),
		"TAILSCALE_BASE_URL="+baseURL,
		"TAILSCALE_API_KEY="+apiKey,
		"TAILSCALE_TAILNET=-",
		// Keep provider plugins inside the temp dir so the run is self-contained.
		"TF_PLUGIN_CACHE_DIR="+filepath.Join(dir, "plugin-cache"),
	)

	cmd := func(args ...string) *exec.Cmd {
		c := exec.CommandContext(t.Context(), bin, args...)
		c.Dir = dir
		c.Env = env

		return c
	}

	return &tofu{t: t, cmd: cmd}
}

func (tf *tofu) run(args ...string) string {
	tf.t.Helper()

	out, err := tf.cmd(args...).CombinedOutput()
	require.NoErrorf(tf.t, err, "tofu %s\n%s", strings.Join(args, " "), out)

	return string(out)
}

// assertNoDrift fails if a no-change plan reports changes. plan
// -detailed-exitcode returns 0 = no changes, 1 = error, 2 = drift.
func (tf *tofu) assertNoDrift() {
	tf.t.Helper()

	out, err := tf.cmd("plan", "-detailed-exitcode", "-no-color", "-input=false", "-parallelism=1").CombinedOutput()
	if err == nil {
		return
	}

	var exit *exec.ExitError
	require.ErrorAsf(tf.t, err, &exit, "tofu plan\n%s", out)
	require.Equalf(tf.t, 0, exit.ExitCode(),
		"no-change plan after apply must be empty; drift means a provider read disagrees with desired state:\n%s", out)
}

func (tf *tofu) outputs() tofuOutputs {
	tf.t.Helper()

	out := tf.run("output", "-json", "-no-color")

	var raw map[string]struct {
		Value json.RawMessage `json:"value"`
	}
	require.NoError(tf.t, json.Unmarshal([]byte(out), &raw))

	o := make(tofuOutputs, len(raw))
	for k, v := range raw {
		o[k] = v.Value
	}

	return o
}

// tofuOutputs is the decoded `tofu output -json`, keyed by output name.
type tofuOutputs map[string]json.RawMessage

func (o tofuOutputs) raw(t *testing.T, key string) json.RawMessage {
	t.Helper()

	v, ok := o[key]
	require.Truef(t, ok, "output %q missing", key)

	return v
}

func (o tofuOutputs) str(t *testing.T, key string) string {
	t.Helper()

	var s string
	require.NoError(t, json.Unmarshal(o.raw(t, key), &s))

	return s
}

func (o tofuOutputs) num(t *testing.T, key string) float64 {
	t.Helper()

	var n float64
	require.NoError(t, json.Unmarshal(o.raw(t, key), &n))

	return n
}

func (o tofuOutputs) strSlice(t *testing.T, key string) []string {
	t.Helper()

	var s []string
	require.NoError(t, json.Unmarshal(o.raw(t, key), &s))

	return s
}

// jsonEq asserts the output decodes equal to want (handles bools/strings/numbers).
func (o tofuOutputs) jsonEq(t *testing.T, key string, want any) {
	t.Helper()

	wantJSON, err := json.Marshal(want)
	require.NoError(t, err)
	require.JSONEq(t, string(wantJSON), string(o.raw(t, key)))
}
