package apiv0

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/config"
	"github.com/juanfont/headscale/hscontrol/dns"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/require"
)

func TestGetVersion(t *testing.T) {
	rec := newTestAPI(t, Backend{}).Get(Prefix + "/version")
	require.Equal(t, http.StatusOK, rec.Code)

	var got types.VersionInfo
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &got))
	require.Equal(t, *types.GetVersionInfo(), got)
}

func TestGetMe(t *testing.T) {
	b := newBackend(t)
	api := newTestAPI(t, b)

	_, err := b.State.SetPolicy([]byte(`{
		"tagOwners": {"tag:k8s-operator": [], "tag:k8s": ["tag:k8s-operator"], "tag:other": []},
		"acls": [{"action": "accept", "src": ["*"], "dst": ["*:*"]}]
	}`))
	require.NoError(t, err)

	// Each name of the owner differs, so /me shows which one it read.
	bob, _, err := b.State.CreateUser(
		types.User{Name: "bob", DisplayName: "Bob Builder", Email: "bob@example.com"},
	)
	require.NoError(t, err)

	// Ahead of the clock, which the credential is checked against, whenever
	// the test runs; the API writes whole seconds as they are.
	expiry := time.Now().Add(24 * time.Hour).UTC().Truncate(time.Second)
	expiryJSON := `"` + expiry.Format(time.RFC3339) + `"`

	ownedKey, owned, err := b.State.CreateAPIKey(&expiry)
	require.NoError(t, err)
	require.NoError(t, b.State.SetAPIKeyUser(owned.ID, types.UserID(bob.ID)))

	bareKey, bare, err := b.State.CreateAPIKey(nil)
	require.NoError(t, err)

	scopes := []string{"devices:core", "auth_keys"}
	_, client, err := b.State.CreateOAuthClient(
		scopes,
		[]string{"tag:k8s-operator"},
		"kubernetes operator",
		nil,
	)
	require.NoError(t, err)

	token, at, err := b.State.MintAccessToken(
		client.ClientID,
		scopes,
		[]string{"tag:k8s-operator"},
		&expiry,
	)
	require.NoError(t, err)

	id := func(n uint64) string { return strconv.FormatUint(n, 10) }

	for _, tt := range []struct {
		name string
		key  string
		want string
	}{
		{
			name: "api key that bob owns",
			key:  ownedKey,
			want: `{
				"principal": {"kind": "apiKey", "identity": null, "user": null},
				"credential": {
					"kind": "apiKey", "id": "` + id(owned.ID) + `", "prefix": "` + owned.Prefix + `",
					"expiry": ` + expiryJSON + `,
					"owner": {"user": {"id": "` + id(uint64(bob.ID)) + `", "name": "bob", "loginName": "bob@example.com", "displayName": "Bob Builder", "email": "bob@example.com"}, "tags": []},
					"client": null
				},
				"authorization": {"scopes": ["all"], "tags": null, "resources": "all"}
			}`,
		},
		{
			name: "api key with no owner and no expiry",
			key:  bareKey,
			want: `{
				"principal": {"kind": "apiKey", "identity": null, "user": null},
				"credential": {
					"kind": "apiKey", "id": "` + id(bare.ID) + `", "prefix": "` + bare.Prefix + `",
					"expiry": null, "owner": null, "client": null
				},
				"authorization": {"scopes": ["all"], "tags": null, "resources": "all"}
			}`,
		},
		{
			name: "token of an oauth client",
			key:  token,
			want: `{
				"principal": {"kind": "oauthClient", "identity": null, "user": null},
				"credential": {
					"kind": "oauthToken", "id": "` + id(at.ID) + `", "prefix": "` + at.Prefix + `",
					"expiry": ` + expiryJSON + `, "owner": null,
					"client": {"id": "` + client.ClientID + `", "description": "kubernetes operator"}
				},
				"authorization": {"scopes": ["auth_keys", "devices:core"], "tags": ["tag:k8s", "tag:k8s-operator"], "resources": "all"}
			}`,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			rec := api.Get(Prefix+"/me", "Authorization: Bearer "+tt.key)
			require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
			require.JSONEq(t, tt.want, rec.Body.String())
		})
	}

	t.Run("the socket", func(t *testing.T) {
		me, err := whoAmI(
			t.Context(),
			b,
			allAccess(principal{kind: PrincipalLocal}, nil),
		)
		require.NoError(t, err)

		got, err := json.Marshal(me)
		require.NoError(t, err)
		require.JSONEq(t, `{
			"principal": {"kind": "local", "identity": null, "user": null},
			"credential": null,
			"authorization": {"scopes": ["all"], "tags": null, "resources": "all"}
		}`, string(got))
	})

	t.Run("a token with no tags may give none", func(t *testing.T) {
		_, c, err := b.State.CreateOAuthClient([]string{"users:read"}, nil, "", nil)
		require.NoError(t, err)

		tok, _, err := b.State.MintAccessToken(
			c.ClientID,
			[]string{"users:read"},
			nil,
			&expiry,
		)
		require.NoError(t, err)

		rec := api.Get(Prefix+"/me", "Authorization: Bearer "+tok)

		var got Me
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &got))
		require.Equal(t, []string{}, got.Authorization.Tags)
	})
}

func TestGetHealth(t *testing.T) {
	b := newBackend(t)
	api := newTestAPI(t, b)

	key, _, err := b.State.CreateAPIKey(nil)
	require.NoError(t, err)

	auth := "Authorization: Bearer " + key

	rec := api.Get(Prefix+"/health", auth)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.JSONEq(
		t,
		`{"healthy": true, "databaseConnectivity": true, "warnings": []}`,
		rec.Body.String(),
	)

	user := b.State.CreateUserForTest("user")
	tooLong := strings.Repeat("a", 300)

	for _, n := range []*types.Node{
		{ID: 41, UserID: &user.ID, GivenName: tooLong},
		{ID: 42, UserID: &user.ID, GivenName: tooLong + "b"},
		{ID: 43, UserID: &user.ID, GivenName: "ok", Expiry: new(time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC))},
	} {
		b.State.PutNodeInStoreForTest(*n)
	}

	rec = api.Get(Prefix+"/health", auth)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.JSONEq(t, `{"healthy": true, "databaseConnectivity": true, "warnings": [
		{"code": "node_name_invalid", "message": "2 nodes have a name that is not valid.", "details": {"count": 2}},
		{"code": "node_expiry_invalid", "message": "1 node has a key expiry that is not valid.", "details": {"count": 1}}
	]}`, rec.Body.String())

	t.Run("a database that does not answer is unhealthy", func(t *testing.T) {
		down := newBackend(t)
		require.NoError(t, down.State.Close())

		// Over the socket: a key could not be checked either.
		rec := httptest.NewRecorder()
		WithLocalTrust(
			Handler(down),
		).ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, Prefix+"/health", nil))

		p := decodeProblem(t, rec, CodeUnhealthy)
		require.Equal(t, map[string]any{"reasons": []any{
			map[string]any{
				"code":    "database_unreachable",
				"message": "The database does not answer.",
				"details": map[string]any{},
			},
		}}, p.Details)
	})
}

// TestGetConfig: GET /config is what generate config prints for the running
// configuration, redacted and without the cli section, and reads like the
// rest of the server. It needs all: the answer names internal hosts, paths
// and accounts, which all:read does not open.
func TestGetConfig(t *testing.T) {
	b := newBackend(t)
	b.Cfg.OIDC.ClientSecret = "marker-oidc-secret"
	api := newTestAPI(t, b)

	key, _, err := b.State.CreateAPIKey(nil)
	require.NoError(t, err)

	for _, docs := range []bool{true, false} {
		path := Prefix + "/config"
		if !docs {
			path += "?docs=false"
		}

		rec := api.Get(path, "Authorization: Bearer "+key)
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		require.Equal(t, "application/yaml", rec.Header().Get("Content-Type"))

		want, err := config.GenerateExample(
			b.Cfg,
			config.ExampleOptions{Docs: docs, Redact: true, OmitClientOnly: true},
		)
		require.NoError(t, err)
		require.Equal(t, string(want), rec.Body.String())
		require.NotContains(t, rec.Body.String(), "marker-oidc-secret")
	}

	for _, scopes := range []string{"all", "all:read", "users:read"} {
		_, client, err := b.State.CreateOAuthClient([]string{scopes}, nil, "ci", nil)
		require.NoError(t, err)

		token, _, err := b.State.MintAccessToken(
			client.ClientID,
			[]string{scopes},
			nil,
			new(time.Now().Add(time.Hour)),
		)
		require.NoError(t, err)

		rec := api.Get(Prefix+"/config", "Authorization: Bearer "+token)
		if scopes == "all" {
			require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

			continue
		}

		p := decodeProblem(t, rec, CodeForbidden)
		require.Equal(t, []any{"all"}, p.Details["scopes"], scopes)
	}
}

// TestGetConfigHidesEverySecret: every secret of the configuration, the
// userinfo of every URL and every setting of every DNS provider but its
// name, set to a marker in the file and in the environment, is nowhere in
// GET /config. A secret that a new key declares as a plain string fails
// here; TestSecretNamesAreSecrets says which key.
func TestGetConfigHidesEverySecret(t *testing.T) {
	b := newBackend(t)
	api := newTestAPI(t, b)

	key, _, err := b.State.CreateAPIKey(nil)
	require.NoError(t, err)

	d := config.Default()

	file := map[string]any{}
	env := []string{}

	set := func(path string, v any) {
		m := file

		parts := strings.Split(path, ".")
		for _, p := range parts[:len(parts)-1] {
			if m[p] == nil {
				m[p] = map[string]any{}
			}

			m = m[p].(map[string]any) //nolint:forcetypeassert // built here
		}

		m[parts[len(parts)-1]] = v

		b, err := json.Marshal(v)
		require.NoError(t, err)

		text := string(b)
		if s, ok := v.(string); ok {
			text = s
		}

		env = append(
			env,
			"HEADSCALE_"+strings.ToUpper(strings.ReplaceAll(path, ".", "_"))+"="+text,
		)
	}

	for _, f := range types.ConfigFields(&d) {
		switch f.Field.Type {
		case reflect.TypeFor[types.Secret]():
			set(f.Path, "marker-"+f.Path)
		case reflect.TypeFor[types.HTTPURL]():
			set(
				f.Path,
				"https://marker-user:marker-pass@"+strings.ReplaceAll(
					f.Path,
					".",
					"-",
				)+".example.com/x",
			)
		case reflect.TypeFor[[]types.HTTPURL]():
			set(f.Path, []string{"https://marker-user:marker-pass@a.example.com/x"})
		}
	}

	for _, name := range dns.ProviderNames() {
		provider := map[string]any{ //nolint:gosec // markers, not credentials
			"name":       name,
			"api_token":  "marker-token",
			"api_key":    "marker-key",
			"key":        "marker-key",
			"key_name":   "marker-key-name",
			"server":     "marker-server",
			"server_url": "https://marker-user:marker-pass@dns.example.com",
			"username":   "marker-user",
			"port":       4242424242,
			"config": map[string]any{
				"tailnet.example.com": map[string]any{"password": "marker-password"},
			},
		}
		set("dns.challenge.provider", provider)

		fileJSON, err := json.Marshal(file)
		require.NoError(t, err)

		fromFile, err := config.LoadData("config.json", ".json", fileJSON, nil)
		require.NoError(t, err)

		fromEnv, err := config.Load("", true, env)
		require.NoError(t, err)

		for source, cfg := range map[string]*types.Config{"file": fromFile.Config, "environment": fromEnv.Config} {
			// What the source set reached the configuration.
			require.Equal(
				t,
				types.Secret("marker-oidc.client_secret"),
				cfg.OIDC.ClientSecret,
				source,
			)
			require.Contains(t, string(cfg.OIDC.Issuer), "marker-user", source)
			require.Equal(
				t,
				"marker-token",
				cfg.DNSConfig.Challenge.ProviderSettings["api_token"],
				source,
			)

			*b.Cfg = *cfg

			for _, path := range []string{Prefix + "/config", Prefix + "/config?docs=false"} {
				rec := api.Get(path, "Authorization: Bearer "+key)
				require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
				body := rec.Body.String()
				require.Contains(
					t,
					body,
					"name: "+name,
					"%s, %s: the name is shown",
					name,
					source,
				)
				require.NotContains(
					t,
					body,
					"4242424242",
					"%s, %s: a number is a setting too, and hidden",
					name,
					source,
				)

				for line := range strings.Lines(body) {
					require.NotContains(
						t,
						line,
						"marker",
						"%s, %s: %s",
						name,
						source,
						path,
					)
				}
			}
		}

		env = env[:len(env)-1]
	}
}
