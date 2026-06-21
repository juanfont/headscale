package servertest_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/juanfont/headscale/hscontrol/servertest"
	"github.com/stretchr/testify/require"
)

// TestAPIv2OAuthScopes proves the v2 OAuth scope and tag enforcement through the
// REAL Tailscale Terraform provider's client-credentials flow: the provider mints
// a scoped access token at /api/v2/oauth/token, then runs one operation whose
// allow/deny outcome must match the token's scope and tag grant.
//
// Each client is created with exactly the scopes/tags under test, and the
// provider requests no scope narrowing, so the minted token carries the client's
// full grant. The matrix covers right-scope-allowed, wrong-scope-denied, read vs
// write, the "all" super-scope, and policy tag ownership (owned-by delegation).
//
// The oauth_keys rows drive the real provider's tailscale_oauth_client resource,
// which omits the "capabilities" body field, so the request schema must make it
// optional (it is). Drift is not asserted on the auth-key rows: the provider
// defaults preauthorized=true on create but the server reads tagged keys back as
// false, so a converged plan is never empty. That is orthogonal to scope
// enforcement, so a clean apply is the allow proof.
//
// tofu is required, not optional: it ships in the nix dev shell, so a missing
// binary means a broken environment and the test fails rather than skipping.
func TestAPIv2OAuthScopes(t *testing.T) {
	srv := servertest.NewServer(t, servertest.WithRealListener())
	owner := srv.CreateUser(t, "apiv2-oauth")
	creator := owner.ID

	// scopeMatrixPolicy declares every tag the matrix touches: tag:ci for the
	// auth-key rows, and the tag:k8s/tag:k8s-operator delegation for the
	// owned-by rows.
	setScopeMatrixPolicy(t, srv)

	// A registered node is the target for the device-scope rows. Its decimal id
	// is the device id the v2 API and the provider's device resources address.
	// A devices:core write token also grants devices:core:read, so whatever
	// get/post sequence the provider runs within the core family is satisfied;
	// the read-scope row then fails on the write, proving read vs write end to
	// end. devices:routes and feature_settings are proven exhaustively by the Go
	// matrix (apiv2_oauth_matrix_test.go), not here: the provider's routes
	// resource issues a cross-family device read a routes-only token would lack,
	// and the server's settings endpoint is read-only.
	deviceID := srv.CreateRegisteredNode(t, owner).StringID()
	deviceAuthorizeConfig := `
resource "tailscale_device_authorization" "d" {
  device_id  = "` + deviceID + `"
  authorized = true
}
`

	// The configs each exercise exactly one operation so a row's allow/deny
	// outcome is unambiguous.
	const (
		authKeyConfig = `
resource "tailscale_tailnet_key" "k" {
  reusable    = true
  ephemeral   = false
  expiry      = 3600
  description = "oauth-scope-matrix"
  tags        = ["tag:ci"]
}
`
		aclConfig = `
resource "tailscale_acl" "policy" {
  acl = jsonencode({
    tagOwners = {
      "tag:ci"           = ["apiv2-oauth@"]
      "tag:k8s-operator" = []
      "tag:k8s"          = ["tag:k8s-operator"]
      "tag:other"        = []
    }
    acls = [{ action = "accept", src = ["*"], dst = ["*:*"] }]
  })
  overwrite_existing_content = true
}
`
		devicesReadConfig = `
data "tailscale_devices" "all" {}
output "device_count" { value = length(data.tailscale_devices.all.devices) }
`
		// oauthClientConfig creates an OAuth client whose scope (oauth_keys:read)
		// is within an oauth_keys grant, so the only variable under test is whether
		// the caller may manage clients at all.
		oauthClientConfig = `
resource "tailscale_oauth_client" "c" {
  description = "oauth-scope-matrix-client"
  scopes      = ["oauth_keys:read"]
}
`
		// oauthClientEscalateConfig requests a scope (devices:core:read) that an
		// oauth_keys-only caller does not itself hold, so the escalation guard must
		// reject minting a broader client.
		oauthClientEscalateConfig = `
resource "tailscale_oauth_client" "c" {
  description = "oauth-scope-matrix-escalate"
  scopes      = ["devices:core:read"]
}
`
	)

	// k8sAuthKeyConfig templates the auth-key tag for the owned-by rows.
	k8sAuthKeyConfig := func(tag string) string {
		return `
resource "tailscale_tailnet_key" "k" {
  reusable    = true
  ephemeral   = false
  expiry      = 3600
  description = "oauth-scope-matrix"
  tags        = ["` + tag + `"]
}
`
	}

	tests := []struct {
		name string
		// scopes/tags the OAuth client (and thus its minted token) holds.
		scopes []string
		tags   []string
		// config is the single-operation HCL applied through the OAuth provider.
		config string
		// deny asserts apply fails; denyContains lists substrings, any of which
		// the failure output must contain. allow asserts a clean apply.
		deny         bool
		denyContains []string
	}{
		// auth_keys: write scope mints an auth key; read/wrong/all-read do not.
		{
			name:   "auth_keys allows tailnet_key",
			scopes: []string{"auth_keys"},
			tags:   []string{"tag:ci"},
			config: authKeyConfig,
		},
		{
			name:         "auth_keys:read denies tailnet_key",
			scopes:       []string{"auth_keys:read"},
			tags:         []string{"tag:ci"},
			config:       authKeyConfig,
			deny:         true,
			denyContains: []string{"403", "Forbidden", "missing the required scope"},
		},
		{
			name:         "devices:core denies tailnet_key",
			scopes:       []string{"devices:core"},
			tags:         []string{"tag:ci"},
			config:       authKeyConfig,
			deny:         true,
			denyContains: []string{"403", "Forbidden", "missing the required scope"},
		},
		{
			name:   "all allows tailnet_key",
			scopes: []string{"all"},
			tags:   []string{"tag:ci"},
			config: authKeyConfig,
		},
		{
			name:         "all:read denies tailnet_key",
			scopes:       []string{"all:read"},
			tags:         []string{"tag:ci"},
			config:       authKeyConfig,
			deny:         true,
			denyContains: []string{"403", "Forbidden", "missing the required scope"},
		},

		// oauth_keys: managing OAuth clients. Read and wrong scopes are denied, and
		// a caller cannot mint a client carrying authority it lacks (escalation).
		{
			name:   "oauth_keys allows oauth_client",
			scopes: []string{"oauth_keys"},
			config: oauthClientConfig,
		},
		{
			name:         "oauth_keys:read denies oauth_client",
			scopes:       []string{"oauth_keys:read"},
			config:       oauthClientConfig,
			deny:         true,
			denyContains: []string{"403", "Forbidden", "missing the required scope"},
		},
		{
			name:         "auth_keys denies oauth_client",
			scopes:       []string{"auth_keys"},
			tags:         []string{"tag:ci"},
			config:       oauthClientConfig,
			deny:         true,
			denyContains: []string{"403", "Forbidden", "missing the required scope"},
		},
		{
			name:         "oauth_keys cannot escalate client scope",
			scopes:       []string{"oauth_keys"},
			config:       oauthClientEscalateConfig,
			deny:         true,
			denyContains: []string{"403", "Forbidden", "beyond the creating token"},
		},

		// policy_file: write scope sets the ACL; read does not.
		{
			name:   "policy_file allows acl",
			scopes: []string{"policy_file"},
			config: aclConfig,
		},
		{
			name:         "policy_file:read denies acl",
			scopes:       []string{"policy_file:read"},
			config:       aclConfig,
			deny:         true,
			denyContains: []string{"403", "Forbidden", "missing the required scope"},
		},

		// devices:core:read reads the devices data source.
		{
			name:   "devices:core:read allows devices read",
			scopes: []string{"devices:core:read"},
			config: devicesReadConfig,
		},
		{
			name:         "policy_file:read denies devices read",
			scopes:       []string{"policy_file:read"},
			config:       devicesReadConfig,
			deny:         true,
			denyContains: []string{"403", "Forbidden", "missing the required scope"},
		},

		// devices:core: a write-scoped token authorizes a device; the read scope
		// and a wrong-family scope are denied (read vs write through the real
		// provider's tailscale_device_authorization resource).
		{
			name:   "devices:core allows device authorize",
			scopes: []string{"devices:core"},
			tags:   []string{"tag:ci"},
			config: deviceAuthorizeConfig,
		},
		{
			name:         "devices:core:read denies device authorize",
			scopes:       []string{"devices:core:read"},
			config:       deviceAuthorizeConfig,
			deny:         true,
			denyContains: []string{"403", "Forbidden", "missing the required scope"},
		},
		{
			name:         "policy_file denies device authorize",
			scopes:       []string{"policy_file"},
			config:       deviceAuthorizeConfig,
			deny:         true,
			denyContains: []string{"403", "Forbidden", "missing the required scope"},
		},

		// Tag owned-by: a tag:k8s-operator client may use its own tag and the
		// tag:k8s it owns, but not an unowned tag.
		{
			name:   "owned-by exact tag allowed",
			scopes: []string{"auth_keys"},
			tags:   []string{"tag:k8s-operator"},
			config: k8sAuthKeyConfig("tag:k8s-operator"),
		},
		{
			name:   "owned-by delegated tag allowed",
			scopes: []string{"auth_keys"},
			tags:   []string{"tag:k8s-operator"},
			config: k8sAuthKeyConfig("tag:k8s"),
		},
		{
			name:         "owned-by unowned tag denied",
			scopes:       []string{"auth_keys"},
			tags:         []string{"tag:k8s-operator"},
			config:       k8sAuthKeyConfig("tag:other"),
			deny:         true,
			denyContains: []string{"403", "Forbidden", "is not owned"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			secret, client, err := srv.State().CreateOAuthClient(tt.scopes, tt.tags, "scope-matrix", &creator)
			require.NoError(t, err)

			tf := newTofuOAuth(t, srv.URL, client.ClientID, secret, oauthHCL(tt.config))
			tf.run("init", "-no-color", "-input=false")

			if tt.deny {
				tf.runExpectError(t, tt.denyContains...)
				return
			}

			tf.run("apply", "-auto-approve", "-no-color", "-input=false", "-parallelism=1")
		})
	}
}

// setScopeMatrixPolicy installs the policy the scope matrix relies on: tag:ci for
// the auth-key rows, and the tag:k8s-operator → tag:k8s delegation for the
// owned-by rows.
func setScopeMatrixPolicy(t *testing.T, srv *servertest.TestServer) {
	t.Helper()

	// tag:other exists but is owned by no one, so the owned-by denial row tests a
	// grant denial (403) rather than a tag-not-in-policy rejection (400).
	const policy = `{"tagOwners":{"tag:ci":["apiv2-oauth@"],"tag:k8s-operator":[],"tag:k8s":["tag:k8s-operator"],"tag:other":[]},"acls":[{"action":"accept","src":["*"],"dst":["*:*"]}]}`

	st := srv.State()

	_, err := st.SetPolicy([]byte(policy))
	require.NoError(t, err)

	_, err = st.SetPolicyInDB(policy)
	require.NoError(t, err)

	_, err = st.ReloadPolicy()
	require.NoError(t, err)
}

// oauthHCL wraps a single-operation body with the provider block. The provider
// authenticates via the OAuth env vars newTofuOAuth sets, so the block is empty.
func oauthHCL(body string) string {
	return `
terraform {
  required_providers {
    tailscale = {
      source  = "tailscale/tailscale"
      version = "~> 0.21"
    }
  }
}

provider "tailscale" {}
` + body
}

// newTofuOAuth is a newTofu variant whose provider authenticates with OAuth
// client credentials instead of an API key: it sets TAILSCALE_OAUTH_CLIENT_ID /
// TAILSCALE_OAUTH_CLIENT_SECRET (the env vars the tailscale/tailscale provider
// honors), so the real provider runs the client-credentials grant against
// baseURL/api/v2/oauth/token. The client id is embedded in the secret, so the
// secret embeds the client id (the provider sends both; the server derives the
// client from the secret alone).
func newTofuOAuth(t *testing.T, baseURL, clientID, clientSecret, config string) *tofu {
	t.Helper()

	bin, err := exec.LookPath("tofu")
	require.NoErrorf(t, err, "tofu is required for TestAPIv2OAuthScopes (provided by the nix dev shell)")

	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "main.tf"), []byte(config), 0o600))
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "plugin-cache"), 0o755))

	env := append(
		os.Environ(),
		"TAILSCALE_BASE_URL="+baseURL,
		"TAILSCALE_OAUTH_CLIENT_ID="+clientID,
		"TAILSCALE_OAUTH_CLIENT_SECRET="+clientSecret,
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

// runExpectError runs apply expecting FAILURE, asserting the combined output
// contains at least one of mustContain. This is the deny half of every matrix
// row: a scoped token attempting an operation it lacks the scope (or tag) for.
func (tf *tofu) runExpectError(t *testing.T, mustContain ...string) {
	t.Helper()

	out, err := tf.cmd("apply", "-auto-approve", "-no-color", "-input=false", "-parallelism=1").CombinedOutput()
	require.Errorf(t, err, "expected apply to fail, but it succeeded:\n%s", out)

	combined := string(out)
	for _, want := range mustContain {
		if strings.Contains(combined, want) {
			return
		}
	}

	t.Fatalf("apply failed but output contained none of %v:\n%s", mustContain, combined)
}
