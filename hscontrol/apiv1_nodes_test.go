package hscontrol

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/juanfont/headscale/hscontrol/types"
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
		assert.Equal(t, []any{}, got.Node["ipAddresses"])
		assert.Equal(t, []any{}, got.Node["tags"])
		assert.Nil(t, got.Node["expiry"])
		assert.Contains(t, got.Node, "user")
		assert.Contains(t, got.Node, "preAuthKey")
		assert.Contains(t, got.Node, "createdAt")
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
			app.state.SetAuthCacheEntry(authID, types.NewRegisterAuthRequest(regData))
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
