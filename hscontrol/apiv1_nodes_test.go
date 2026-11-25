package hscontrol

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/types/testcapture"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

// nodeSeed carries fixed key material so isolated apps in a mutation parity test
// register byte-identical nodes; otherwise random keys would defeat body
// comparison.
type nodeSeed struct {
	user       string
	machineKey key.MachinePrivate
	nodeKey    key.NodePrivate
	hostname   string
	tags       []string
}

func newNodeSeed(user, hostname string, tags ...string) nodeSeed {
	return nodeSeed{
		user:       user,
		machineKey: key.NewMachine(),
		nodeKey:    key.NewNode(),
		hostname:   hostname,
		tags:       tags,
	}
}

// register inserts the user, a matching pre-auth key, and the node itself using
// the seed's fixed keys, returning the created node ID.
func (s nodeSeed) register(t *testing.T, app *Headscale) types.NodeID {
	t.Helper()

	user := app.state.CreateUserForTest(s.user)

	pak, err := app.state.CreatePreAuthKey(user.TypedID(), false, false, nil, s.tags)
	require.NoError(t, err)

	req := tailcfg.RegisterRequest{
		Auth:     &tailcfg.RegisterResponseAuth{AuthKey: pak.Key},
		NodeKey:  s.nodeKey.Public(),
		Hostinfo: &tailcfg.Hostinfo{Hostname: s.hostname},
	}

	_, err = app.handleRegisterWithAuthKey(req, s.machineKey.Public())
	require.NoError(t, err)

	node, found := app.state.GetNodeByNodeKey(s.nodeKey.Public())
	require.True(t, found)

	return node.ID()
}

func seedNodes(seeds ...nodeSeed) func(t *testing.T, app *Headscale) {
	return func(t *testing.T, app *Headscale) {
		t.Helper()

		for _, s := range seeds {
			s.register(t, app)
		}
	}
}

func TestAPIV1NodeGet(t *testing.T) {
	t.Run("happy parity", func(t *testing.T) {
		h := newAPIV1Harness(t)
		seedNodes(newNodeSeed("alice", "node-a"))(t, h.app)
		h.assertParity(t, http.MethodGet, "/api/v1/node/1", nil)
	})

	t.Run("tagged node parity", func(t *testing.T) {
		h := newAPIV1Harness(t)
		// No tagOwners means policy won't authorise a tag, so register via the
		// pre-auth key path, which forces tags regardless of policy.
		seedNodes(newNodeSeed("bob", "node-b", "tag:initial"))(t, h.app)
		h.assertParity(t, http.MethodGet, "/api/v1/node/1", nil)
	})

	t.Run("not found parity", func(t *testing.T) {
		h := newAPIV1Harness(t)
		res := h.assertParity(t, http.MethodGet, "/api/v1/node/99999", nil)
		assertStatus(t, res, http.StatusNotFound)
	})

	t.Run("invalid id parity", func(t *testing.T) {
		h := newAPIV1Harness(t)
		res := h.assertParity(t, http.MethodGet, "/api/v1/node/abc", nil)
		assertStatus(t, res, http.StatusBadRequest)
	})

	t.Run("huma response shape", func(t *testing.T) {
		h := newAPIV1Harness(t)
		seedNodes(newNodeSeed("carol", "node-c"))(t, h.app)

		res := h.callHuma(http.MethodGet, "/api/v1/node/1", nil)
		require.Equal(t, http.StatusOK, res.status)

		var got struct {
			Node map[string]any `json:"node"`
		}
		require.NoError(t, json.Unmarshal(res.body, &got))

		assert.Equal(t, "1", got.Node["id"])
		assert.Equal(t, "node-c", got.Node["name"])
		assert.Equal(t, "REGISTER_METHOD_AUTH_KEY", got.Node["registerMethod"])
		// EmitUnpopulated parity: slices present as [], expiry as null.
		assert.Equal(t, []any{}, got.Node["approvedRoutes"])
		assert.Equal(t, []any{}, got.Node["tags"])
		assert.Nil(t, got.Node["expiry"])
		assert.Contains(t, got.Node, "user")
		assert.Contains(t, got.Node, "preAuthKey")
		assert.Contains(t, got.Node, "createdAt")
	})

	// A login with a key of the other kind keeps the node's flag; the
	// embedded key shows the key's own.
	t.Run("ephemeral is the node's, not its key's", func(t *testing.T) {
		for _, created := range []bool{true, false} {
			h := newAPIV1Harness(t)
			user := h.app.state.CreateUserForTest("dave")
			machineKey := key.NewMachine()

			for _, ephemeral := range []bool{created, !created} {
				pak, err := h.app.state.CreatePreAuthKey(user.TypedID(), false, ephemeral, nil, nil)
				require.NoError(t, err)

				_, err = h.app.handleRegisterWithAuthKey(tailcfg.RegisterRequest{
					Auth:     &tailcfg.RegisterResponseAuth{AuthKey: pak.Key},
					NodeKey:  key.NewNode().Public(),
					Hostinfo: &tailcfg.Hostinfo{Hostname: "node-d"},
				}, machineKey.Public())
				require.NoError(t, err)
			}

			res := h.callHuma(http.MethodGet, "/api/v1/node/1", nil)
			require.Equal(t, http.StatusOK, res.status)

			var got struct {
				Node struct {
					Ephemeral  bool `json:"ephemeral"`
					PreAuthKey struct {
						Ephemeral bool `json:"ephemeral"`
					} `json:"preAuthKey"`
				} `json:"node"`
			}
			require.NoError(t, json.Unmarshal(res.body, &got))
			assert.Equal(t, created, got.Node.Ephemeral, "node created ephemeral=%v", created)
			assert.Equal(t, !created, got.Node.PreAuthKey.Ephemeral, "node created ephemeral=%v", created)
		}
	})
}

func TestAPIV1NodeList(t *testing.T) {
	t.Run("empty returns empty array", func(t *testing.T) {
		h := newAPIV1Harness(t)

		res := h.callHuma(http.MethodGet, "/api/v1/node", nil)
		require.Equal(t, http.StatusOK, res.status)
		assert.JSONEq(t, `{"nodes":[]}`, string(res.body))
	})

	t.Run("empty parity", func(t *testing.T) {
		h := newAPIV1Harness(t)
		h.assertParity(t, http.MethodGet, "/api/v1/node", nil)
	})

	t.Run("all parity", func(t *testing.T) {
		h := newAPIV1Harness(t)
		seedNodes(
			newNodeSeed("alice", "node-a"),
			newNodeSeed("bob", "node-b"),
		)(t, h.app)
		h.assertParity(t, http.MethodGet, "/api/v1/node", nil)
	})

	t.Run("filter by user parity", func(t *testing.T) {
		h := newAPIV1Harness(t)
		seedNodes(
			newNodeSeed("alice", "node-a"),
			newNodeSeed("bob", "node-b"),
		)(t, h.app)
		h.assertParity(t, http.MethodGet, "/api/v1/node?user=alice", nil)
	})

	t.Run("unknown user parity", func(t *testing.T) {
		h := newAPIV1Harness(t)
		seedNodes(newNodeSeed("alice", "node-a"))(t, h.app)
		res := h.assertParity(t, http.MethodGet, "/api/v1/node?user=nope", nil)
		assertStatus(t, res, http.StatusNotFound)
	})
}

func TestAPIV1NodeDelete(t *testing.T) {
	t.Run("happy parity", func(t *testing.T) {
		assertParityIsolated(t, seedNodes(newNodeSeed("alice", "node-a")),
			http.MethodDelete, "/api/v1/node/1", nil)
	})

	t.Run("not found parity", func(t *testing.T) {
		h := newAPIV1Harness(t)
		res := h.assertParity(t, http.MethodDelete, "/api/v1/node/99999", nil)
		assertStatus(t, res, http.StatusNotFound)
	})

	t.Run("invalid id parity", func(t *testing.T) {
		h := newAPIV1Harness(t)
		res := h.assertParity(t, http.MethodDelete, "/api/v1/node/abc", nil)
		assertStatus(t, res, http.StatusBadRequest)
	})

	// 0.29 read a path ID with base 0, so 01 was node 1 and 010 node 8:
	// refused rather than read another way.
	t.Run("leading zero", func(t *testing.T) {
		h := newAPIV1Harness(t)
		seedNodes(newNodeSeed("alice", "node-a"))(t, h.app)

		for _, id := range []string{"01", "00"} {
			res := h.callHuma(http.MethodDelete, "/api/v1/node/"+id, nil)
			assertStatus(t, res, http.StatusBadRequest)
		}

		_, ok := h.app.state.GetNodeByID(1)
		assert.True(t, ok, "the node must not be deleted")

		res := h.callHuma(http.MethodDelete, "/api/v1/user/01", nil)
		assertStatus(t, res, http.StatusBadRequest)
	})
}

func TestAPIV1NodeExpire(t *testing.T) {
	// The embedded pre-auth key's masked prefix is random per app, so isolated
	// body comparison is impossible. GetNode/ListNodes prove full serialisation;
	// here we just assert the mutation took effect.
	t.Run("huma expires node", func(t *testing.T) {
		h := newAPIV1Harness(t)
		seedNodes(newNodeSeed("alice", "node-a"))(t, h.app)

		res := h.callHuma(http.MethodPost, "/api/v1/node/1/expire", nil)
		require.Equal(t, http.StatusOK, res.status)

		var got struct {
			Node map[string]any `json:"node"`
		}
		require.NoError(t, json.Unmarshal(res.body, &got))

		assert.Equal(t, "1", got.Node["id"])
		// Expiry was nil before; expiring sets it to a concrete timestamp.
		assert.NotNil(t, got.Node["expiry"])
	})

	// As before the key expiry switch existed: v1 expire logs the node out.
	t.Run("huma expires a node with key expiry off", func(t *testing.T) {
		h := newAPIV1Harness(t)
		seedNodes(newNodeSeed("alice", "node-a"))(t, h.app)

		_, _, err := h.app.state.SetNodeKeyExpiryDisabled(1, true)
		require.NoError(t, err)

		res := h.callHuma(http.MethodPost, "/api/v1/node/1/expire", nil)
		require.Equal(t, http.StatusOK, res.status)

		node, ok := h.app.state.GetNodeByID(1)
		require.True(t, ok)
		assert.False(t, node.KeyExpiryDisabled())
		assert.True(t, node.IsExpired())
	})

	// disableExpiry turns the switch on and keeps the time, so turning key
	// expiry on again (v2 POST /device/{id}/key) brings it back.
	t.Run("huma disable keeps the expiry", func(t *testing.T) {
		h := newAPIV1Harness(t)
		seedNodes(newNodeSeed("alice", "node-a"))(t, h.app)

		future := time.Now().Add(30 * 24 * time.Hour).UTC().Truncate(time.Second)
		_, _, err := h.app.state.ExpireNodeAt(1, future)
		require.NoError(t, err)

		res := h.callHuma(http.MethodPost, "/api/v1/node/1/expire", []byte(`{"disableExpiry":true}`))
		require.Equal(t, http.StatusOK, res.status)

		var got struct {
			Node map[string]any `json:"node"`
		}
		require.NoError(t, json.Unmarshal(res.body, &got))
		assert.Nil(t, got.Node["expiry"], "v1 shows no expiry while key expiry is off")

		node, ok := h.app.state.GetNodeByID(1)
		require.True(t, ok)
		assert.True(t, node.KeyExpiryDisabled())
		assert.False(t, node.IsExpiredAt(future.Add(time.Hour)))

		node, _, err = h.app.state.SetNodeKeyExpiryDisabled(1, false)
		require.NoError(t, err)

		exp, ok := node.KeyExpiry()
		require.True(t, ok, "turning key expiry on must bring the time back")
		assert.True(t, future.Equal(exp))
	})

	t.Run("huma refuses an unencodable expiry", func(t *testing.T) {
		h := newAPIV1Harness(t)
		seedNodes(newNodeSeed("alice", "node-a"))(t, h.app)

		res := h.callHuma(http.MethodPost, "/api/v1/node/1/expire",
			[]byte(`{"expiry":"9999-12-31T23:59:59-23:59"}`))
		assertStatus(t, res, http.StatusBadRequest)
	})

	// The query forms and what 0.29 stored for each, from the pinned
	// gateway's parser (runtime/query.go at grpc-gateway v2.29.0) and
	// ExpireNode in hscontrol/grpcv1.go at v0.29.7. Every node starts with an
	// expiry in 2099; a refused request must leave it there. Only the bare
	// call expires the node now, as in 0.29.
	t.Run("query and body forms", func(t *testing.T) {
		start := time.Date(2099, 6, 15, 0, 0, 0, 0, time.UTC)
		at := func(s string) *time.Time {
			v, err := time.Parse(time.RFC3339Nano, s)
			require.NoError(t, err)

			return &v
		}

		const (
			keep    = "keep"    // refused: the 2099 expiry stays
			off     = "off"     // key expiry off, the time kept
			set     = "set"     // expiry stored as want
			expired = "expired" // expired now
		)

		tests := []struct {
			name   string
			query  string
			body   string
			status int
			want   string
			at     *time.Time
		}{
			// The reviewer's thirteen, against the tagged parser.
			{name: "disableExpiry=true", query: "disableExpiry=true", status: http.StatusOK, want: off},
			{name: "disable_expiry=true", query: "disable_expiry=true", status: http.StatusOK, want: off},
			{name: "disableExpiry empty", query: "disableExpiry=", status: http.StatusBadRequest, want: keep},
			{name: "disableExpiry twice", query: "disableExpiry=true&disableExpiry=false", status: http.StatusBadRequest, want: keep},
			{name: "expiry empty", query: "expiry=", status: http.StatusBadRequest, want: keep},
			{name: "expiry date only", query: "expiry=2030-01-02", status: http.StatusBadRequest, want: keep},
			{name: "expiry", query: "expiry=2030-01-02T00:00:00Z", status: http.StatusOK, want: set, at: at("2030-01-02T00:00:00Z")},
			{name: "expiry year 1", query: "expiry=0001-01-01T00:00:00Z", status: http.StatusOK, want: set, at: at("0001-01-01T00:00:00Z")},
			{name: "expiry.seconds", query: "expiry.seconds=1893456000", status: http.StatusOK, want: set, at: at("2030-01-01T00:00:00Z")},
			{name: "expiry twice", query: "expiry=2030-01-02T00:00:00Z&expiry=2040-01-02T00:00:00Z", status: http.StatusBadRequest, want: keep},
			{name: "expiry year 0", query: "expiry=0000-01-01T00:00:00Z", status: http.StatusBadRequest, want: keep},
			{name: "expiry offset and nanos", query: "expiry=2030-01-02T03:04:05.123456789%2B01:30", status: http.StatusOK, want: set, at: at("2030-01-02T01:34:05.123456789Z")},
			{name: "semicolon", query: "expiry=invalid;other=x", status: http.StatusBadRequest, want: keep},

			// 0.29 ignored a parameter it did not know and expired the node:
			// the caller asked for something, so it is refused.
			{name: "unknown parameter", query: "unrelated=1", status: http.StatusBadRequest, want: keep},
			{name: "unknown spelling", query: "DisableExpiry=true", status: http.StatusBadRequest, want: keep},
			{name: "unknown subfield", query: "expiry.foo=1", status: http.StatusBadRequest, want: keep},
			// The path's field in the query was filtered out, by either name.
			{name: "path field by proto name", query: "node_id=2&disableExpiry=true", status: http.StatusOK, want: off},
			{name: "path field by JSON name", query: "nodeId=2&disableExpiry=true", status: http.StatusOK, want: off},
			{name: "path field by JSON name, dotted", query: "nodeId.x=2&disableExpiry=true", status: http.StatusBadRequest, want: keep},
			{name: "path field by JSON name, bracketed", query: "nodeId[x]=2&disableExpiry=true", status: http.StatusOK, want: off},
			// Without its closing bracket the key is one unknown name.
			{name: "unclosed bracket after nodeId", query: "nodeId[old=2&expiry=2031-01-01T00:00:00Z", status: http.StatusBadRequest, want: keep},
			{name: "bracket form", query: "disableExpiry[true]=", status: http.StatusBadRequest, want: keep},
			{name: "both names agree", query: "disableExpiry=true&disable_expiry=1", status: http.StatusOK, want: off},
			{name: "both names differ", query: "disableExpiry=true&disable_expiry=false", status: http.StatusBadRequest, want: keep},
			{name: "expiry whole and by fields", query: "expiry=2030-01-02T00:00:00Z&expiry.seconds=1", status: http.StatusBadRequest, want: keep},
			{name: "expiry and disableExpiry", query: "expiry=2030-01-02T00:00:00Z&disableExpiry=true", status: http.StatusBadRequest, want: keep},
			{name: "disableExpiry=false", query: "disableExpiry=false", status: http.StatusOK, want: expired},
			{name: "bare call", status: http.StatusOK, want: expired},

			// The body the CLI sends, and the body against the query.
			{name: "body expiry", body: `{"expiry":"2030-01-02T00:00:00Z"}`, status: http.StatusOK, want: set, at: at("2030-01-02T00:00:00Z")},
			{name: "body disableExpiry", body: `{"disableExpiry":true}`, status: http.StatusOK, want: off},
			{name: "body proto name", body: `{"disable_expiry":true}`, status: http.StatusBadRequest, want: keep},
			{name: "same expiry in both", query: "expiry=2030-01-02T00:00:00Z", body: `{"expiry":"2030-01-02T00:00:00Z"}`, status: http.StatusOK, want: set, at: at("2030-01-02T00:00:00Z")},
			{name: "different expiry in both", query: "expiry=2030-01-02T00:00:00Z", body: `{"expiry":"2040-01-02T00:00:00Z"}`, status: http.StatusBadRequest, want: keep},
			{name: "query expiry and body disableExpiry", query: "expiry=2030-01-02T00:00:00Z", body: `{"disableExpiry":true}`, status: http.StatusBadRequest, want: keep},
			{name: "query false and body true", query: "disableExpiry=false", body: `{"disableExpiry":true}`, status: http.StatusBadRequest, want: keep},
			{name: "query true and body false", query: "disableExpiry=true", body: `{"disableExpiry":false}`, status: http.StatusBadRequest, want: keep},
			{name: "query true and body true", query: "disableExpiry=true", body: `{"disableExpiry":true}`, status: http.StatusOK, want: off},
			{name: "query true and body null", query: "disableExpiry=true", body: `{"disableExpiry":null}`, status: http.StatusOK, want: off},
			{name: "query true and body empty", query: "disableExpiry=true", body: `{}`, status: http.StatusOK, want: off},
			{name: "body false alone", body: `{"disableExpiry":false}`, status: http.StatusOK, want: expired},
			{name: "query expiry and body null expiry", query: "expiry=2030-01-02T00:00:00Z", body: `{"expiry":null}`, status: http.StatusOK, want: set, at: at("2030-01-02T00:00:00Z")},
			{name: "query expiry and body zero expiry", query: "expiry=2030-01-02T00:00:00Z", body: `{"expiry":"0001-01-01T00:00:00Z"}`, status: http.StatusBadRequest, want: keep},
			{name: "query zero expiry and body expiry", query: "expiry=0001-01-01T00:00:00Z", body: `{"expiry":"2030-01-02T00:00:00Z"}`, status: http.StatusBadRequest, want: keep},
			{name: "body zero expiry", body: `{"expiry":"0001-01-01T00:00:00Z"}`, status: http.StatusOK, want: set, at: at("0001-01-01T00:00:00Z")},
		}

		// One server; each row starts from the same stored node.
		h := newFastAPIV1Harness(t)
		seedNodes(newNodeSeed("alice", "node-a"))(t, h.app)

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				_, _, err := h.app.state.SetNodeKeyExpiryDisabled(1, false)
				require.NoError(t, err)

				_, _, err = h.app.state.SetNodeExpiry(1, &start)
				require.NoError(t, err)

				var body []byte
				if tt.body != "" {
					body = []byte(tt.body)
				}

				path := "/api/v1/node/1/expire"
				if tt.query != "" {
					path += "?" + tt.query
				}

				res := h.callHuma(http.MethodPost, path, body)
				assert.Equal(t, tt.status, res.status, "body: %s", res.body)

				node, ok := h.app.state.GetNodeByID(1)
				require.True(t, ok)

				switch tt.want {
				case keep:
					require.True(t, node.Expiry().Valid())
					assert.True(t, start.Equal(node.Expiry().Get()), "stored %v", node.Expiry().Get())
				case off:
					// Key expiry off keeps the stored time (#3735); v1 shows none.
					assert.True(t, node.KeyExpiryDisabled(), "key expiry off")
					require.True(t, node.Expiry().Valid())
					assert.True(t, start.Equal(node.Expiry().Get()), "stored %v", node.Expiry().Get())
				case set:
					require.True(t, node.Expiry().Valid())
					assert.True(t, tt.at.Equal(node.Expiry().Get()), "stored %v", node.Expiry().Get())
				case expired:
					assert.True(t, node.IsExpired())

					return
				}

				assert.False(t, node.IsExpired(), "the node must not be logged out")
			})
		}
	})

	t.Run("not found parity", func(t *testing.T) {
		h := newAPIV1Harness(t)
		res := h.assertParity(t, http.MethodPost, "/api/v1/node/99999/expire", nil)
		assertStatus(t, res, http.StatusNotFound)
	})

	t.Run("invalid id parity", func(t *testing.T) {
		h := newAPIV1Harness(t)
		res := h.assertParity(t, http.MethodPost, "/api/v1/node/abc/expire", nil)
		assertStatus(t, res, http.StatusBadRequest)
	})
}

func TestAPIV1NodeRename(t *testing.T) {
	t.Run("huma renames node", func(t *testing.T) {
		h := newAPIV1Harness(t)
		seedNodes(newNodeSeed("alice", "node-a"))(t, h.app)

		res := h.callHuma(http.MethodPost, "/api/v1/node/1/rename/renamed-node", nil)
		require.Equal(t, http.StatusOK, res.status)

		var got struct {
			Node map[string]any `json:"node"`
		}
		require.NoError(t, json.Unmarshal(res.body, &got))

		assert.Equal(t, "renamed-node", got.Node["givenName"])
	})

	t.Run("not found parity", func(t *testing.T) {
		h := newAPIV1Harness(t)
		res := h.assertParity(t, http.MethodPost, "/api/v1/node/99999/rename/whatever", nil)
		assertStatus(t, res, http.StatusNotFound)
	})

	t.Run("invalid id parity", func(t *testing.T) {
		h := newAPIV1Harness(t)
		res := h.assertParity(t, http.MethodPost, "/api/v1/node/abc/rename/whatever", nil)
		assertStatus(t, res, http.StatusBadRequest)
	})
}

func TestAPIV1NodeSetTags(t *testing.T) {
	t.Run("not found parity", func(t *testing.T) {
		h := newAPIV1Harness(t)
		res := h.assertParity(t, http.MethodPost, "/api/v1/node/99999/tags",
			[]byte(`{"tags":["tag:foo"]}`))
		assertStatus(t, res, http.StatusNotFound)
	})

	t.Run("empty tags parity", func(t *testing.T) {
		h := newAPIV1Harness(t)
		seedNodes(newNodeSeed("alice", "node-a"))(t, h.app)
		res := h.assertParity(t, http.MethodPost, "/api/v1/node/1/tags", []byte(`{"tags":[]}`))
		assertStatus(t, res, http.StatusBadRequest)
	})

	t.Run("unauthorized tag parity", func(t *testing.T) {
		h := newAPIV1Harness(t)
		seedNodes(newNodeSeed("alice", "node-a"))(t, h.app)
		// No tagOwners in policy → SetNodeTags rejects with InvalidArgument (400).
		res := h.assertParity(t, http.MethodPost, "/api/v1/node/1/tags",
			[]byte(`{"tags":["tag:server"]}`))
		assertStatus(t, res, http.StatusBadRequest)
	})

	t.Run("invalid id parity", func(t *testing.T) {
		h := newAPIV1Harness(t)
		res := h.assertParity(t, http.MethodPost, "/api/v1/node/abc/tags",
			[]byte(`{"tags":["tag:foo"]}`))
		assertStatus(t, res, http.StatusBadRequest)
	})
}

func TestAPIV1NodeSetApprovedRoutes(t *testing.T) {
	t.Run("huma sets approved routes", func(t *testing.T) {
		h := newAPIV1Harness(t)
		seedNodes(newNodeSeed("alice", "node-a"))(t, h.app)

		res := h.callHuma(http.MethodPost, "/api/v1/node/1/approve_routes",
			[]byte(`{"routes":[]}`))
		require.Equal(t, http.StatusOK, res.status)

		var got struct {
			Node map[string]any `json:"node"`
		}
		require.NoError(t, json.Unmarshal(res.body, &got))

		assert.Equal(t, "1", got.Node["id"])
		// SubnetRoutes is recomputed from primary routes; empty here but present.
		assert.Equal(t, []any{}, got.Node["approvedRoutes"])
		assert.Equal(t, []any{}, got.Node["subnetRoutes"])
	})

	t.Run("not found parity", func(t *testing.T) {
		h := newAPIV1Harness(t)
		res := h.assertParity(t, http.MethodPost, "/api/v1/node/99999/approve_routes",
			[]byte(`{"routes":["10.0.0.0/24"]}`))
		assertStatus(t, res, http.StatusNotFound)
	})

	t.Run("invalid id parity", func(t *testing.T) {
		h := newAPIV1Harness(t)
		res := h.assertParity(t, http.MethodPost, "/api/v1/node/abc/approve_routes",
			[]byte(`{"routes":[]}`))
		assertStatus(t, res, http.StatusBadRequest)
	})

	// The admin's v2 route calls on routers announcing the tailnet's own
	// addresses, replayed against v1: the same routes accepted or refused.
	// Test data source: policy/v2/testdata/routes_results/routes-t4-admin.hujson.
	t.Run("saas compat", func(t *testing.T) {
		c := readRoutesCapture(t, "routes-t4-admin")
		h := newAPIV1Harness(t)
		devices := seedCaptureRouters(t, h.app, c)

		replayRouteCalls(t, c, "v1-", func(a testcapture.Action, alias string) routeCall {
			target := "/api/v1/node/" + devices[alias]
			if a.Method == http.MethodPost {
				target += "/approve_routes"
			}

			res := h.callHuma(a.Method, target, a.Body)

			var body struct {
				Node struct {
					Available []string `json:"availableRoutes"`
					Approved  []string `json:"approvedRoutes"`
				} `json:"node"`
				Message string `json:"message"`
			}
			require.NoErrorf(t, json.Unmarshal(res.body, &body), "body: %s", res.body)

			return routeCall{res.status, body.Node.Available, body.Node.Approved, body.Message}
		})
	})
}

func TestAPIV1NodeRegister(t *testing.T) {
	t.Run("happy parity", func(t *testing.T) {
		authID := types.MustAuthID()
		mk := key.NewMachine()
		nk := key.NewNode()

		seed := func(t *testing.T, app *Headscale) {
			t.Helper()

			app.state.CreateUserForTest("alice")

			regData := &types.RegistrationData{
				NodeKey:    nk.Public(),
				MachineKey: mk.Public(),
				Hostname:   "registered-node",
			}
			require.NoError(t, app.state.SetAuthCacheEntry(authID, types.NewRegisterAuthRequest(regData)))
		}

		assertParityIsolated(t, seed, http.MethodPost,
			"/api/v1/node/register?user=alice&key="+authID.String(), nil)
	})

	t.Run("invalid key parity", func(t *testing.T) {
		h := newAPIV1Harness(t)
		seedNodes(newNodeSeed("alice", "node-a"))(t, h.app)
		res := h.assertParity(t, http.MethodPost,
			"/api/v1/node/register?user=alice&key=invalidkey", nil)
		assertStatus(t, res, http.StatusBadRequest)
	})

	t.Run("unknown user parity", func(t *testing.T) {
		h := newAPIV1Harness(t)
		res := h.assertParity(t, http.MethodPost,
			"/api/v1/node/register?user=nope&key="+types.MustAuthID().String(), nil)
		assertStatus(t, res, http.StatusNotFound)
	})
}

func TestAPIV1NodeBackfillIPs(t *testing.T) {
	t.Run("confirmed empty parity", func(t *testing.T) {
		assertParityIsolated(t, nil, http.MethodPost,
			"/api/v1/node/backfillips?confirmed=true", nil)
	})

	t.Run("confirmed returns empty array", func(t *testing.T) {
		h := newAPIV1Harness(t)

		res := h.callHuma(http.MethodPost, "/api/v1/node/backfillips?confirmed=true", nil)
		require.Equal(t, http.StatusOK, res.status)
		assert.JSONEq(t, `{"changes":[]}`, string(res.body))
	})

	t.Run("unconfirmed parity", func(t *testing.T) {
		h := newAPIV1Harness(t)
		res := h.assertParity(t, http.MethodPost, "/api/v1/node/backfillips", nil)
		assertStatus(t, res, http.StatusBadRequest)
	})
}

func TestAPIV1NodeDebugCreate(t *testing.T) {
	t.Run("unknown user parity", func(t *testing.T) {
		h := newAPIV1Harness(t)
		body := []byte(`{"user":"nope","key":"` + types.MustAuthID().String() +
			`","name":"dbg","routes":[]}`)
		res := h.assertParity(t, http.MethodPost, "/api/v1/debug/node", body)
		assertStatus(t, res, http.StatusNotFound)
	})

	t.Run("invalid key parity", func(t *testing.T) {
		h := newAPIV1Harness(t)
		seedNodes(newNodeSeed("alice", "node-a"))(t, h.app)

		body := []byte(`{"user":"alice","key":"badkey","name":"dbg","routes":[]}`)
		res := h.assertParity(t, http.MethodPost, "/api/v1/debug/node", body)
		assertStatus(t, res, http.StatusBadRequest)
	})

	// The handler mints fresh key material per call, so isolated apps can't
	// produce byte-identical bodies; assert the shape directly instead.
	t.Run("huma response shape", func(t *testing.T) {
		h := newAPIV1Harness(t)
		h.app.state.CreateUserForTest("alice")

		body := []byte(`{"user":"alice","key":"` + types.MustAuthID().String() +
			`","name":"dbgnode","routes":["10.0.0.0/24"]}`)

		res := h.callHuma(http.MethodPost, "/api/v1/debug/node", body)
		require.Equal(t, http.StatusOK, res.status)

		var got struct {
			Node map[string]any `json:"node"`
		}
		require.NoError(t, json.Unmarshal(res.body, &got))

		assert.Equal(t, "dbgnode", got.Node["name"])
		assert.Equal(t, "REGISTER_METHOD_UNSPECIFIED", got.Node["registerMethod"])
		assert.Equal(t, []any{"10.0.0.0/24"}, got.Node["availableRoutes"])
		// The synthetic echo node has no pre-auth key: emitted as null.
		assert.Nil(t, got.Node["preAuthKey"])
		// Zero-time expiry/lastSeen are emitted as the zero instant, not null.
		assert.Equal(t, "0001-01-01T00:00:00Z", got.Node["expiry"])
		assert.Equal(t, "0001-01-01T00:00:00Z", got.Node["lastSeen"])
	})
}

func TestAPIV1NodeDebugCreateAdmissionFailure(t *testing.T) {
	app := createTestApp(t, func(cfg *types.Config) {
		cfg.Tuning.RegisterCacheMaxEntries = 1
	})
	defer func() { require.NoError(t, app.state.Close()) }()

	app.state.CreateUserForTest("alice")
	require.NoError(t, app.state.SetAuthCacheEntry(types.MustAuthID(), types.NewAuthRequest()))

	id := types.MustAuthID()
	body := []byte(`{"user":"alice","key":"` + id.String() + `","name":"node","routes":[]}`)
	res := callHandler(newHumaTestHandler(app), http.MethodPost, "/api/v1/debug/node", body)
	require.Equal(t, http.StatusServiceUnavailable, res.status)

	_, ok := app.state.GetAuthCacheEntry(id)
	require.False(t, ok)
}
