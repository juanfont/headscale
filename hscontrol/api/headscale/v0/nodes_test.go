package apiv0

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/danielgtaylor/huma/v2/humatest"
	"github.com/go-chi/chi/v5"
	"github.com/juanfont/headscale/hscontrol/policy"
	"github.com/juanfont/headscale/hscontrol/state"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

const nodesPolicy = `{
	"tagOwners": {"tag:ci": [], "tag:build": [], "tag:web": ["tag:ci"], "tag:unused": []},
	"acls": [{"action": "accept", "src": ["*"], "dst": ["*:*"]}]
}`

// nodesAPI is v0 with a policy, alice with three nodes and bob with one,
// all in the database and the NodeStore.
func nodesAPI(t *testing.T) (Backend, humatest.TestAPI, string, []types.NodeView) {
	t.Helper()

	b, api, auth := usersAPI(t)

	_, _, err := b.State.UpdatePolicy([]byte(nodesPolicy))
	require.NoError(t, err)

	alice := b.State.CreateUserForTest("alice")
	bob := b.State.CreateUserForTest("bob")

	nodes := make([]types.NodeView, 0, 4)

	for i, owner := range []*types.User{alice, alice, alice, bob} {
		n := b.State.CreateRegisteredNodeForTest(owner, "node"+strconv.Itoa(i))
		n.CreatedByUserID = new(owner.ID)
		nodes = append(nodes, b.State.PutNodeInStoreForTest(*n))
	}

	return b, api, auth, nodes
}

func decodeNode(t *testing.T, rec *httptest.ResponseRecorder) Node {
	t.Helper()

	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	var n Node
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &n), rec.Body.String())

	return n
}

func nodePath(nv types.NodeView, rest ...string) string {
	return Prefix + "/nodes/" + nv.StringID() + strings.Join(rest, "")
}

func ifMatch(rev string) string { return `If-Match: "` + rev + `"` }

func TestListNodes(t *testing.T) {
	b, api, auth, nodes := nodesAPI(t)

	_, _, err := b.State.SetNodeTags(nodes[2].ID(), []string{"tag:ci"})
	require.NoError(t, err)

	page := func(t *testing.T, query string) (NodeList, *Problem) {
		t.Helper()

		rec := api.Get(Prefix+"/nodes?"+query, auth)
		if rec.Code != http.StatusOK {
			p := decodeProblem(t, rec, Code(problemCode(rec.Body.Bytes())))

			return NodeList{}, &p
		}

		require.NotContains(t, rec.Body.String(), `"nextPageToken":""`)

		var l NodeList
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &l))

		return l, nil
	}

	walk := func(t *testing.T, filters string) ([]string, int) {
		t.Helper()

		var (
			ids   []string
			pages int
			token string
		)

		for {
			q := "pageSize=2&" + filters
			if token != "" {
				q += "&pageToken=" + url.QueryEscape(token)
			}

			l, p := page(t, q)
			require.Nil(t, p)

			pages++

			for _, n := range l.Nodes {
				ids = append(ids, n.ID)
			}

			if l.NextPageToken == "" {
				return ids, pages
			}

			token = l.NextPageToken
		}
	}

	all := []string{nodes[0].StringID(), nodes[1].StringID(), nodes[2].StringID(), nodes[3].StringID()}

	t.Run("walk every node", func(t *testing.T) {
		ids, pages := walk(t, "")
		require.Equal(t, all, ids)
		require.Equal(t, 2, pages)
	})

	t.Run("filter by user; tagged nodes never match", func(t *testing.T) {
		ids, _ := walk(t, "user="+strconv.FormatUint(uint64(nodes[0].TypedUserID()), 10))
		require.Equal(t, all[:2], ids)
	})

	t.Run("filter by tag", func(t *testing.T) {
		ids, _ := walk(t, "tag=tag:ci")
		require.Equal(t, all[2:3], ids)
	})

	t.Run("an unknown user is an empty list", func(t *testing.T) {
		rec := api.Get(Prefix+"/nodes?user=999", auth)
		require.Equal(t, http.StatusOK, rec.Code)
		require.JSONEq(t, `{"nodes": []}`, rec.Body.String())
	})

	t.Run("a user that is not an ID", func(t *testing.T) {
		_, p := page(t, "user=alice")
		require.Equal(t, CodeInvalidField, p.Code)
		require.Equal(t, []string{"query.user"}, locations(*p))
	})

	first, _ := page(t, "pageSize=2")
	require.NotEmpty(t, first.NextPageToken)

	token := url.QueryEscape(first.NextPageToken)

	for name, query := range map[string]string{
		"forged":        "pageSize=2&pageToken=" + url.QueryEscape(first.NextPageToken[:len(first.NextPageToken)-2]+"AA"),
		"other filters": "pageSize=2&tag=tag:ci&pageToken=" + token,
		"another list": func() string {
			pg, _ := openPage[uint64](PageQuery{PageSize: 2}, "users", "", "")
			_, other := cutPage(pg, []uint64{1, 2, 3}, func(n uint64) uint64 { return n })

			return "pageSize=2&pageToken=" + url.QueryEscape(other)
		}(),
	} {
		t.Run("token "+name, func(t *testing.T) {
			_, p := page(t, query)
			require.NotNil(t, p)
			require.Equal(t, CodeInvalidPageToken, p.Code)
		})
	}
}

func TestGetNode(t *testing.T) {
	b, api, auth, nodes := nodesAPI(t)

	rec := api.Get(nodePath(nodes[0]), auth)
	n := decodeNode(t, rec)

	stored, _ := b.State.GetNodeByID(nodes[0].ID())
	require.Equal(t, `"`+stored.Revision()+`"`, rec.Header().Get("ETag"))
	require.Equal(t, stored.Revision(), n.Revision)
	require.Equal(t, "alice", n.Owner.User.LoginName)
	require.Equal(t, []string{}, n.Owner.Tags)
	require.Equal(t, &UserReference{ID: n.Owner.User.ID, LoginName: "alice"}, n.CreatedBy)
	require.Equal(t, RegisterMethod("authKey"), n.RegisterMethod, "the stored authkey in the API's word")
	require.Equal(t, []string{}, n.Problems)
	require.Equal(t, n.Name+"."+b.Cfg.DNSConfig.BaseDomain, n.FQDN)

	for _, path := range []string{"999", "abc", "007", "0"} {
		decodeProblem(t, api.Get(Prefix+"/nodes/"+path, auth), CodeNotFound)
	}

	t.Run("a user's node older than the creator: the creator is the owner", func(t *testing.T) {
		old := *nodes[1].AsStruct()
		old.CreatedByUserID = nil
		old.RegisterMethod = ""
		b.State.PutNodeInStoreForTest(old)

		got := decodeNode(t, api.Get(nodePath(nodes[1]), auth))
		require.Equal(t, &UserReference{ID: got.Owner.User.ID, LoginName: "alice"}, got.CreatedBy)
		require.Equal(t, RegisterMethod(""), got.RegisterMethod, "a node that records no method")
	})

	t.Run("a tagged node older than the creator has none", func(t *testing.T) {
		old := *nodes[2].AsStruct()
		old.CreatedByUserID = nil
		old.UserID, old.User, old.Tags = nil, nil, []string{"tag:ci"}
		b.State.PutNodeInStoreForTest(old)

		require.Nil(t, decodeNode(t, api.Get(nodePath(nodes[2]), auth)).CreatedBy)
	})
}

// TestNodeServingRoutes: servingRoutes is the routes the node was chosen to
// serve, with its exit routes.
func TestNodeServingRoutes(t *testing.T) {
	b, api, auth, nodes := nodesAPI(t)

	subnet := netip.MustParsePrefix("10.0.0.0/8")
	offered := []netip.Prefix{subnet, netip.MustParsePrefix("192.168.0.0/24"), netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")}

	n := *nodes[0].AsStruct()
	n.Hostinfo = &tailcfg.Hostinfo{RoutableIPs: offered, OS: "linux", IPNVersion: "1.80.0-t123"}
	n.ActiveSessions = 1
	b.State.PutNodeInStoreForTest(n)

	_, _, err := b.State.SetApprovedRoutes(n.ID, []netip.Prefix{subnet, netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")})
	require.NoError(t, err)

	got := decodeNode(t, api.Get(nodePath(nodes[0]), auth))
	require.Equal(t, []string{"0.0.0.0/0", "10.0.0.0/8", "::/0"}, got.EnabledRoutes)
	require.Equal(t, []string{"0.0.0.0/0", "10.0.0.0/8", "192.168.0.0/24", "::/0"}, got.AdvertisedRoutes)
	require.Equal(t, []string{"0.0.0.0/0", "10.0.0.0/8", "::/0"}, got.ServingRoutes)
	require.True(t, got.ConnectedToControl)
	require.NotNil(t, got.LastSeen)
	require.Equal(t, "1.80.0", got.ClientVersion)
	require.Equal(t, "linux", got.OS)

	// An expired node that holds its connection is connected, as on
	// Tailscale; it is not online to its peers.
	_, _, err = b.State.ExpireNodeIf(n.ID, "")
	require.NoError(t, err)

	got = decodeNode(t, api.Get(nodePath(nodes[0]), auth))
	require.True(t, got.Expired)
	require.True(t, got.ConnectedToControl)
}

// TestNodeExpiryOutOfRange: a node whose stored expiry cannot be written as
// RFC 3339 is still listed and read, with a null expiry and the problem
// named, and a PATCH of the expiry repairs it.
func TestNodeExpiryOutOfRange(t *testing.T) {
	b, api, auth, nodes := nodesAPI(t)

	n := *nodes[0].AsStruct()
	n.Expiry = new(time.Date(10000, time.January, 1, 0, 0, 0, 0, time.UTC))
	b.State.PutNodeInStoreForTest(n)

	rec := api.Get(Prefix+"/nodes", auth)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	got := decodeNode(t, api.Get(nodePath(nodes[0]), auth))
	require.Nil(t, got.Expiry)
	require.Equal(t, []string{"node_expiry_invalid"}, got.Problems)

	later := time.Now().Add(48 * time.Hour).UTC().Truncate(time.Second)
	got = decodeNode(t, api.Patch(nodePath(nodes[0]), auth, ifMatch(got.Revision), "Content-Type: application/json",
		strings.NewReader(`{"expiry": "`+later.Format(time.RFC3339)+`"}`)))
	require.Equal(t, &later, got.Expiry)
	require.Equal(t, []string{}, got.Problems)
}

func TestUpdateNode(t *testing.T) {
	b, api, auth, nodes := nodesAPI(t)

	patch := func(body string, headers ...any) *httptest.ResponseRecorder {
		return api.Patch(nodePath(nodes[0]), append([]any{auth, "Content-Type: application/merge-patch+json", strings.NewReader(body)}, headers...)...)
	}

	current := func() types.NodeView {
		nv, _ := b.State.GetNodeByID(nodes[0].ID())

		return nv
	}

	t.Run("name and expiry together", func(t *testing.T) {
		later := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
		got := decodeNode(t, patch(`{"name": "web-1", "expiry": "`+later.Format(time.RFC3339)+`"}`, ifMatch(current().Revision())))
		require.Equal(t, "web-1", got.Name)
		require.Equal(t, &later, got.Expiry)
		require.False(t, got.Expired)
	})

	t.Run("expiry null keeps the stored time", func(t *testing.T) {
		before := current().Expiry().Get()
		got := decodeNode(t, patch(`{"expiry": null}`))
		require.Nil(t, got.Expiry)
		require.True(t, current().KeyExpiryDisabled())
		require.True(t, current().Expiry().Get().Equal(before))
	})

	t.Run("an empty name resets it", func(t *testing.T) {
		got := decodeNode(t, patch(`{"name": ""}`))
		require.Equal(t, nodes[0].Hostname(), got.Name)
	})

	t.Run("now expires", func(t *testing.T) {
		got := decodeNode(t, patch(`{"expiry": "now"}`))
		require.True(t, got.Expired)
		require.False(t, current().KeyExpiryDisabled())
	})

	t.Run("a name another node has", func(t *testing.T) {
		before := current().Revision()
		p := decodeProblem(t, patch(`{"name": "`+nodes[1].GivenName()+`", "expiry": null}`), CodeNameTaken)
		require.Equal(t, &ProblemObject{Kind: "node", ID: nodes[1].StringID(), Name: nodes[1].GivenName()}, p.Object)
		require.Equal(t, nodes[1].GivenName(), p.Details["name"], "the name as sent")
		require.Equal(t, before, current().Revision(), "neither field changed")
	})

	for name, tt := range map[string]struct {
		body string
		code Code
		at   string
	}{
		"a time in the past":    {`{"expiry": "2001-01-01T00:00:00Z"}`, CodeExpiryInPast, ""},
		"not a time":            {`{"expiry": "tomorrow"}`, CodeInvalidField, "body.expiry"},
		"a year out of range":   {`{"expiry": "10000-01-01T00:00:00Z"}`, CodeInvalidField, "body.expiry"},
		"not a DNS label":       {`{"name": "Bad Name!"}`, CodeInvalidField, "body.name"},
		"a capital letter":      {`{"name": "Web-1"}`, CodeInvalidField, "body.name"},
		"a field never changed": {`{"hostname": "x"}`, CodeInvalidField, "body.hostname"},
		"no field":              {`{}`, CodeEmptyPatch, ""},
		"null name":             {`{"name": null}`, CodeInvalidField, "body.name"},
	} {
		t.Run(name, func(t *testing.T) {
			p := decodeProblem(t, patch(tt.body), tt.code)
			if tt.at != "" {
				require.Equal(t, []string{tt.at}, locations(p))
			}
		})
	}

	t.Run("a bad field before not found", func(t *testing.T) {
		decodeProblem(t, api.Patch(Prefix+"/nodes/999", auth, "Content-Type: application/json", strings.NewReader(`{"name": "Bad Name!"}`)), CodeInvalidField)
	})

	t.Run("If-Match", func(t *testing.T) {
		old := current().Revision()
		decodeNode(t, patch(`{"name": "renamed"}`, ifMatch(old)))

		p := decodeProblem(t, patch(`{"name": "again"}`, ifMatch(old)), CodePreconditionFailed)
		require.Equal(t, nodes[0].StringID(), p.Object.ID)
		require.Equal(t, "renamed", current().GivenName(), "nothing written")

		decodeProblem(t, patch(`{"name": "again"}`, `If-Match: W/"`+current().Revision()+`"`), CodePreconditionFailed)
		decodeNode(t, patch(`{"name": "again"}`, "If-Match: *"))

		for _, h := range []string{`If-Match: abc`, `If-Match: "a", "b"`} {
			p := decodeProblem(t, patch(`{"name": "x"}`, h), CodeInvalidField)
			require.Equal(t, []string{"header.If-Match"}, locations(p))
		}

		decodeProblem(t, api.Patch(Prefix+"/nodes/999", auth, ifMatch(old), "Content-Type: application/json", strings.NewReader(`{"name": "x"}`)), CodeNotFound)
	})
}

func TestExpireNode(t *testing.T) {
	b, api, auth, nodes := nodesAPI(t)

	// A tagged node with key expiry off is logged out too.
	_, _, err := b.State.SetNodeTags(nodes[0].ID(), []string{"tag:ci"})
	require.NoError(t, err)
	_, _, err = b.State.SetNodeKeyExpiryDisabled(nodes[0].ID(), true)
	require.NoError(t, err)

	nv, _ := b.State.GetNodeByID(nodes[0].ID())
	old := nv.Revision()

	got := decodeNode(t, api.Post(nodePath(nodes[0], "/expire"), auth, ifMatch(old)))
	require.True(t, got.Expired)
	require.NotNil(t, got.Expiry)

	decodeProblem(t, api.Post(nodePath(nodes[0], "/expire"), auth, ifMatch(old)), CodePreconditionFailed)
	decodeProblem(t, api.Post(Prefix+"/nodes/999/expire", auth), CodeNotFound)
}

func TestDeleteNode(t *testing.T) {
	b, api, auth, nodes := nodesAPI(t)

	old := nodes[0].Revision()
	_, _, err := b.State.PatchNode(nodes[0].ID(), "", state.NodePatch{Name: new("moved")})
	require.NoError(t, err)

	decodeProblem(t, api.Delete(nodePath(nodes[0]), auth, ifMatch(old)), CodePreconditionFailed)

	_, ok := b.State.GetNodeByID(nodes[0].ID())
	require.True(t, ok, "nothing deleted")

	rec := api.Delete(nodePath(nodes[0]), auth)
	require.Equal(t, http.StatusNoContent, rec.Code, rec.Body.String())
	require.Empty(t, rec.Body.String())

	decodeProblem(t, api.Delete(nodePath(nodes[0]), auth), CodeNotFound)
}

func TestSetNodeTags(t *testing.T) {
	b, api, auth, nodes := nodesAPI(t)

	put := func(nv types.NodeView, body string, headers ...any) *httptest.ResponseRecorder {
		return api.Put(nodePath(nv, "/tags"), append([]any{headers[0], "Content-Type: application/json", strings.NewReader(body)}, headers[1:]...)...)
	}

	t.Run("a user's node becomes a tagged node; key expiry stays", func(t *testing.T) {
		got := decodeNode(t, put(nodes[0], `{"tags": ["tag:ci"]}`, auth, ifMatch(nodes[0].Revision())))
		require.Nil(t, got.Owner.User)
		require.Equal(t, []string{"tag:ci"}, got.Owner.Tags)
		require.Equal(t, &UserReference{ID: strconv.FormatUint(uint64(nodes[0].TypedUserID()), 10), LoginName: "alice"}, got.CreatedBy, "the creator stays")

		nv, _ := b.State.GetNodeByID(nodes[0].ID())
		require.False(t, nv.KeyExpiryDisabled())
	})

	t.Run("no tag", func(t *testing.T) {
		decodeProblem(t, put(nodes[1], `{"tags": []}`, auth), CodeTagsRequired)
	})

	t.Run("a tag the policy does not name", func(t *testing.T) {
		p := decodeProblem(t, put(nodes[1], `{"tags": ["tag:ci", "tag:nope", "tag:nope"]}`, auth), CodeTagsNotPermitted)
		require.Equal(t, []any{"tag:nope"}, p.Details["tags"])
	})

	t.Run("two writes from one revision: one is refused", func(t *testing.T) {
		rev := nodes[1].Revision()
		codes := make([]int, 2)

		var wg sync.WaitGroup
		for i, tag := range []string{"tag:ci", "tag:build"} {
			wg.Go(func() { codes[i] = put(nodes[1], `{"tags": ["`+tag+`"]}`, auth, ifMatch(rev)).Code })
		}

		wg.Wait()
		require.ElementsMatch(t, []int{http.StatusOK, http.StatusPreconditionFailed}, codes)
	})

	_, client, err := b.State.CreateOAuthClient([]string{"devices:core"}, []string{"tag:ci"}, "", nil)
	require.NoError(t, err)

	token, _, err := b.State.MintAccessToken(client.ClientID, []string{"devices:core"}, []string{"tag:ci"}, new(time.Now().Add(time.Hour)))
	require.NoError(t, err)

	bearer := "Authorization: Bearer " + token

	t.Run("a token must own every tag", func(t *testing.T) {
		decodeNode(t, put(nodes[2], `{"tags": ["tag:ci"]}`, auth))

		// tag:ci owns tag:web, but not tag:build.
		decodeNode(t, put(nodes[2], `{"tags": ["tag:web"]}`, bearer))

		p := decodeProblem(t, put(nodes[2], `{"tags": ["tag:build"]}`, bearer), CodeForbidden)
		require.Equal(t, "token_must_own_tags", p.Details["rule"])

		decodeNode(t, put(nodes[3], `{"tags": ["tag:build"]}`, auth))
		p = decodeProblem(t, put(nodes[3], `{"tags": ["tag:ci"]}`, bearer), CodeForbidden)
		require.Equal(t, "token_must_own_tags", p.Details["rule"], "taking tag:build off needs it too")
	})

	t.Run("a token may tag a user's node with a tag it owns", func(t *testing.T) {
		// As /api/v2 and Tailscale; only the tags limit a token.
		user := b.State.CreateRegisteredNodeForTest(b.State.CreateUserForTest("carol"), "carols-laptop")
		nv := b.State.PutNodeInStoreForTest(*user)

		got := decodeNode(t, put(nv, `{"tags": ["tag:ci"]}`, bearer))
		require.Equal(t, []string{"tag:ci"}, got.Owner.Tags)
	})

	t.Run("what the request shows comes before the node", func(t *testing.T) {
		missing := Prefix + "/nodes/999/tags"
		putPath := func(body string, h string) *httptest.ResponseRecorder {
			return api.Put(missing, h, "Content-Type: application/json", strings.NewReader(body))
		}

		p := decodeProblem(t, putPath(`{"tags": ["tag:build"]}`, bearer), CodeForbidden)
		require.Equal(t, "token_must_own_tags", p.Details["rule"], "a tag the token lacks, before the lookup")
		decodeProblem(t, putPath(`{"tags": []}`, bearer), CodeTagsRequired)
		decodeProblem(t, putPath(`{"tags": ["tag:nope"]}`, auth), CodeTagsNotPermitted)
		decodeProblem(t, putPath(`{"tags": ["tag:ci"]}`, bearer), CodeNotFound)
	})

	t.Run("a token's write is guarded by the node its rules read", func(t *testing.T) {
		// The probe: a token with tag:ci writes tag:ci with no If-Match while
		// an admin puts tag:build, which the token does not own, on the
		// node. The token must never take tag:build off.
		nv := nodes[2]

		for range 300 {
			decodeNode(t, put(nv, `{"tags": ["tag:ci"]}`, auth))

			var admin, tok int

			var wg sync.WaitGroup
			wg.Go(func() { tok = put(nv, `{"tags": ["tag:ci"]}`, bearer).Code })
			wg.Go(func() { admin = put(nv, `{"tags": ["tag:build"]}`, auth).Code })
			wg.Wait()

			require.Equal(t, http.StatusOK, admin)
			require.Contains(t, []int{http.StatusOK, http.StatusPreconditionFailed, http.StatusForbidden}, tok)

			after, _ := b.State.GetNodeByID(nv.ID())
			if tok == http.StatusOK {
				// The token wrote first; the admin's tag:build came after.
				require.Equal(t, []string{"tag:build"}, after.Tags().AsSlice(), "a token took off a tag it does not own")
			}

			require.Equal(t, []string{"tag:build"}, after.Tags().AsSlice())
		}
	})

	t.Run("a token with an old revision", func(t *testing.T) {
		decodeNode(t, put(nodes[2], `{"tags": ["tag:ci"]}`, auth))
		old, _ := b.State.GetNodeByID(nodes[2].ID())
		decodeNode(t, put(nodes[2], `{"tags": ["tag:web"]}`, auth))

		decodeProblem(t, put(nodes[2], `{"tags": ["tag:ci"]}`, bearer, ifMatch(old.Revision())), CodePreconditionFailed)
	})
}

// TestSetNodeTagsPolicyChange: a policy that drops a tag between the
// handler's check and the write answers tags_not_permitted, not a fault.
func TestSetNodeTagsPolicyChange(t *testing.T) {
	b, api, auth, nodes := nodesAPI(t)

	b.State.WrapPolicyManagerForTest(func(pm policy.PolicyManager) policy.PolicyManager {
		return &dropTagOnSecondAsk{PolicyManager: pm, tag: "tag:build"}
	})

	p := decodeProblem(t, api.Put(nodePath(nodes[0], "/tags"), auth, "Content-Type: application/json",
		strings.NewReader(`{"tags": ["tag:build"]}`)), CodeTagsNotPermitted)
	require.Equal(t, []any{"tag:build"}, p.Details["tags"])
}

// dropTagOnSecondAsk names tag in the policy once: the handler sees it,
// the write in state does not, as when the policy changes in between.
type dropTagOnSecondAsk struct {
	policy.PolicyManager

	tag   string
	asked atomic.Int32
}

func (d *dropTagOnSecondAsk) TagExists(tag string) bool {
	if tag == d.tag && d.asked.Add(1) > 1 {
		return false
	}

	return d.PolicyManager.TagExists(tag)
}

func TestSetNodeRoutes(t *testing.T) {
	_, api, auth, nodes := nodesAPI(t)

	put := func(body string, headers ...any) *httptest.ResponseRecorder {
		return api.Put(nodePath(nodes[0], "/routes"), append([]any{auth, "Content-Type: application/json", strings.NewReader(body)}, headers...)...)
	}

	got := decodeNode(t, put(`{"routes": ["10.0.0.0/8", "0.0.0.0/0"]}`, ifMatch(nodes[0].Revision())))
	require.Equal(t, []string{"0.0.0.0/0", "10.0.0.0/8", "::/0"}, got.EnabledRoutes)

	decodeProblem(t, put(`{"routes": []}`, ifMatch(nodes[0].Revision())), CodePreconditionFailed)

	got = decodeNode(t, put(`{"routes": []}`))
	require.Equal(t, []string{}, got.EnabledRoutes)

	p := decodeProblem(t, put(`{"routes": ["10.0.0.0/8", "10.0.0.1/8", "x"]}`), CodeInvalidField)
	require.Equal(t, []string{"body.routes[1]", "body.routes[2]"}, locations(p))
}

func TestUpdateNodeClient(t *testing.T) {
	_, api, auth, nodes := nodesAPI(t)

	p := decodeProblem(t, api.Post(nodePath(nodes[0], "/update-client"), auth), CodeUpdateRefused)
	require.Equal(t, map[string]any{"reason": "notConnected", "clientError": ""}, p.Details)

	decodeProblem(t, api.Post(Prefix+"/nodes/999/update-client", auth), CodeNotFound)
}

// BenchmarkWalkNodes walks every page of a large tailnet, as a client with
// the read scope can, for the nodes and for the tags.
func BenchmarkWalkNodes(b *testing.B) {
	const nodeCount, userCount, tagCount = 10_000, 100, 200

	be := newBackend(b)

	users := be.State.CreateUsersForTest(userCount, "user")
	nodes := make([]types.Node, nodeCount)

	for i := range nodes {
		u := users[i%userCount]

		nodes[i] = types.Node{
			MachineKey: key.NewMachine().Public(),
			NodeKey:    key.NewNode().Public(),
			DiscoKey:   key.NewDisco().Public(),
			Hostname:   "node-" + strconv.Itoa(i),
			GivenName:  "node-" + strconv.Itoa(i),
			UserID:     &u.ID,
			// Old rows have no creator; the answer reads the owner.
			RegisterMethod: "cli",
		}

		if i%10 == 0 {
			nodes[i].UserID = nil
			nodes[i].Tags = []string{"tag:t" + strconv.Itoa(i%tagCount)}
		}
	}

	require.NoError(b, be.State.DB().DB.CreateInBatches(nodes, 500).Error)
	require.NoError(b, be.State.Close())

	st, err := state.NewState(be.Cfg)
	require.NoError(b, err)
	b.Cleanup(func() { _ = st.Close() })

	be.State = st

	apiKey, _, err := st.CreateAPIKey(nil)
	require.NoError(b, err)

	auth := "Authorization: Bearer " + apiKey
	api := humatest.Wrap(b, newAPI(chi.NewMux(), be, Config("bench")))

	walk := func(b *testing.B, path string, size int) int {
		b.Helper()

		var rows int

		token := ""

		for {
			q := path + "?pageSize=" + strconv.Itoa(size)
			if token != "" {
				q += "&pageToken=" + url.QueryEscape(token)
			}

			rec := api.Get(q, auth)
			require.Equal(b, http.StatusOK, rec.Code, rec.Body.String())

			var page struct {
				Nodes         []json.RawMessage `json:"nodes"`
				Tags          []json.RawMessage `json:"tags"`
				NextPageToken string            `json:"nextPageToken"`
			}
			require.NoError(b, json.Unmarshal(rec.Body.Bytes(), &page))

			rows += len(page.Nodes) + len(page.Tags)
			if page.NextPageToken == "" {
				return rows
			}

			token = page.NextPageToken
		}
	}

	for _, size := range []int{25, 1000} {
		b.Run("nodes/pageSize="+strconv.Itoa(size), func(b *testing.B) {
			for b.Loop() {
				require.Equal(b, nodeCount, walk(b, Prefix+"/nodes", size))
			}
		})
	}

	b.Run("tags/pageSize=1", func(b *testing.B) {
		for b.Loop() {
			require.Equal(b, tagCount/10, walk(b, Prefix+"/tags", 1))
		}
	})
}
