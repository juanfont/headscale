package servertest_test

import (
	"context"
	"net/http"
	"strconv"
	"testing"
	"time"

	clientv0 "github.com/juanfont/headscale/gen/client/headscale/v0"
	"github.com/juanfont/headscale/hscontrol/servertest"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
)

const apiv0NodesPolicy = `{
	"tagOwners": {"tag:ci": [], "tag:build": []},
	"acls": [{"action": "accept", "src": ["*"], "dst": ["*:*"]}]
}`

// v0Client is the generated client on srv with a new API key.
func v0Client(t *testing.T, srv *servertest.TestServer) *clientv0.ClientWithResponses {
	t.Helper()

	apiKey := srv.CreateAPIKey(t, nil)

	c, err := clientv0.NewClientWithResponses(srv.URL,
		clientv0.WithHTTPClient(&http.Client{Transport: &http.Transport{DialContext: srv.MemNet().Dial}}),
		clientv0.WithRequestEditorFn(func(_ context.Context, req *http.Request) error {
			req.Header.Set("Authorization", "Bearer "+apiKey)

			return nil
		}))
	require.NoError(t, err)

	return c
}

func quoted(rev string) *string { return new(`"` + rev + `"`) }

// TestAPIv0Nodes runs each node operation and the tag list through the
// generated client against a real server with connected nodes.
func TestAPIv0Nodes(t *testing.T) { //nolint:tparallel // the steps build on each other
	t.Parallel()

	h := servertest.NewHarness(t, 3)
	h.ChangePolicy(t, []byte(apiv0NodesPolicy))

	refusing := &fakeUpdater{res: tailcfg.C2NUpdateResponse{Enabled: true, Err: "not supported"}}
	updatable := h.AddClient(t,
		servertest.WithHostinfo(&tailcfg.Hostinfo{BackendLogID: "servertest-v0-updatable", Hostname: "updatable", AllowsUpdate: true}),
		servertest.WithC2NHandler(refusing))

	c := v0Client(t, h.Server)
	ctx := t.Context()

	id := func(cl *servertest.TestClient) string {
		return strconv.FormatInt(int64(cl.Netmap().SelfNode.ID()), 10)
	}

	ids := make([]string, 0, len(h.Clients()))
	for _, cl := range h.Clients() {
		ids = append(ids, id(cl))
	}

	t.Run("walk the list two at a time", func(t *testing.T) {
		var (
			got   []string
			token *string
		)

		for {
			resp, err := c.ListNodesWithResponse(ctx, &clientv0.ListNodesParams{PageSize: new(int64(2)), PageToken: token})
			require.NoError(t, err)
			require.Equal(t, http.StatusOK, resp.StatusCode(), string(resp.Body))

			for _, n := range resp.JSON200.Nodes {
				got = append(got, n.Id)
				require.True(t, n.ConnectedToControl, "%s is connected", n.Name)
			}

			token = resp.JSON200.NextPageToken
			if token == nil {
				break
			}
		}

		require.Equal(t, ids, got)

		resp, err := c.ListNodesWithResponse(ctx, &clientv0.ListNodesParams{PageSize: new(int64(2)), PageToken: new("forged")})
		require.NoError(t, err)
		require.Equal(t, http.StatusUnprocessableEntity, resp.StatusCode())
		require.Equal(t, clientv0.InvalidPageToken, resp.ApplicationproblemJSON422.Code)
	})

	node := ids[0]

	get := func(t *testing.T) clientv0.Node {
		t.Helper()

		resp, err := c.GetNodeWithResponse(ctx, node)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, resp.StatusCode(), string(resp.Body))
		require.Equal(t, `"`+resp.JSON200.Revision+`"`, resp.HTTPResponse.Header.Get("ETag"))

		return *resp.JSON200
	}

	t.Run("rename with the revision, then with an old one", func(t *testing.T) {
		old := get(t).Revision

		resp, err := c.UpdateNodeWithResponse(ctx, node, &clientv0.UpdateNodeParams{IfMatch: quoted(old)}, clientv0.UpdateNodeBody{Name: new("web-1")})
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, resp.StatusCode(), string(resp.Body))
		require.Equal(t, "web-1", resp.JSON200.Name)

		resp, err = c.UpdateNodeWithResponse(ctx, node, &clientv0.UpdateNodeParams{IfMatch: quoted(old)}, clientv0.UpdateNodeBody{Name: new("web-2")})
		require.NoError(t, err)
		require.Equal(t, http.StatusPreconditionFailed, resp.StatusCode(), string(resp.Body))
		require.Equal(t, clientv0.PreconditionFailed, resp.ApplicationproblemJSON412.Code)
		require.Equal(t, "web-1", get(t).Name)
	})

	t.Run("routes; one exit prefix approves both", func(t *testing.T) {
		resp, err := c.SetNodeRoutesWithResponse(ctx, node, &clientv0.SetNodeRoutesParams{IfMatch: quoted(get(t).Revision)},
			clientv0.SetNodeRoutesBody{Routes: []string{"10.0.0.0/8", "::/0"}})
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, resp.StatusCode(), string(resp.Body))
		require.Equal(t, []string{"0.0.0.0/0", "10.0.0.0/8", "::/0"}, resp.JSON200.EnabledRoutes)
	})

	t.Run("tags make the node tagged", func(t *testing.T) {
		resp, err := c.SetNodeTagsWithResponse(ctx, node, &clientv0.SetNodeTagsParams{IfMatch: quoted(get(t).Revision)},
			clientv0.SetNodeTagsBody{Tags: []string{"tag:ci"}})
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, resp.StatusCode(), string(resp.Body))
		require.True(t, resp.JSON200.Owner.MustGet().User.IsNull())
		require.Equal(t, []string{"tag:ci"}, resp.JSON200.Owner.MustGet().Tags)

		tags, err := c.ListTagsWithResponse(ctx, &clientv0.ListTagsParams{PageSize: new(int64(2))})
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, tags.StatusCode(), string(tags.Body))
		require.Len(t, tags.JSON200.Tags, 2)
		require.Equal(t, "tag:build", tags.JSON200.Tags[0].Tag)
		require.Equal(t, 1, int(tags.JSON200.Tags[1].NodeCount))
		require.Nil(t, tags.JSON200.NextPageToken)
	})

	t.Run("expire logs the node out", func(t *testing.T) {
		resp, err := c.ExpireNodeWithResponse(ctx, node, &clientv0.ExpireNodeParams{IfMatch: quoted(get(t).Revision)})
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, resp.StatusCode(), string(resp.Body))
		require.True(t, resp.JSON200.Expired)
		require.True(t, resp.JSON200.ConnectedToControl, "an expired node still holds its connection, as on Tailscale")
	})

	t.Run("update-client says why the node did not start it", func(t *testing.T) {
		resp, err := c.UpdateNodeClientWithResponse(ctx, id(updatable))
		require.NoError(t, err)
		require.Equal(t, http.StatusConflict, resp.StatusCode(), string(resp.Body))
		require.Equal(t, clientv0.UpdateRefused, resp.ApplicationproblemJSON409.Code)
		require.Equal(t, map[string]any{"reason": "clientRefused", "clientError": "not supported"}, resp.ApplicationproblemJSON409.Details)

		resp, err = c.UpdateNodeClientWithResponse(ctx, ids[1])
		require.NoError(t, err)
		require.Equal(t, map[string]any{"reason": "updatesNotAllowed", "clientError": ""}, resp.ApplicationproblemJSON409.Details)
	})

	t.Run("delete with an old revision, then without", func(t *testing.T) {
		old := get(t).Revision

		_, err := c.UpdateNodeWithResponse(ctx, node, nil, clientv0.UpdateNodeBody{Name: new("web-3")})
		require.NoError(t, err)

		resp, err := c.DeleteNodeWithResponse(ctx, node, &clientv0.DeleteNodeParams{IfMatch: quoted(old)})
		require.NoError(t, err)
		require.Equal(t, http.StatusPreconditionFailed, resp.StatusCode(), string(resp.Body))

		resp, err = c.DeleteNodeWithResponse(ctx, node, nil)
		require.NoError(t, err)
		require.Equal(t, http.StatusNoContent, resp.StatusCode(), string(resp.Body))

		got, err := c.GetNodeWithResponse(ctx, node)
		require.NoError(t, err)
		require.Equal(t, http.StatusNotFound, got.StatusCode())
	})
}

// TestAPIv0NodeTagWriteAfterUserLogin: a tagged node that logs in again as
// a user changes its revision through the real login path, so a tag write
// made from the page read before is refused and the node stays the user's.
func TestAPIv0NodeTagWriteAfterUserLogin(t *testing.T) {
	t.Parallel()

	srv := servertest.NewServer(t)

	_, err := srv.State().SetPolicy([]byte(apiv0NodesPolicy))
	require.NoError(t, err)

	alice := srv.CreateUser(t, "alice")
	hi := &tailcfg.Hostinfo{BackendLogID: "servertest-v0-laptop", Hostname: "laptop"}
	cl := servertest.NewClient(t, srv, "laptop", servertest.WithUser(alice), servertest.WithTags("tag:ci"), servertest.WithHostinfo(hi))

	c := v0Client(t, srv)
	ctx := t.Context()
	node := strconv.FormatInt(int64(cl.Netmap().SelfNode.ID()), 10)

	read, err := c.GetNodeWithResponse(ctx, node)
	require.NoError(t, err)
	require.Equal(t, []string{"tag:ci"}, read.JSON200.Owner.MustGet().Tags)

	loginCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	require.NoError(t, cl.Relogin(loginCtx, srv.CreatePreAuthKey(t, types.UserID(alice.ID)), true, hi.Clone()))

	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		now, err := c.GetNodeWithResponse(ctx, node)
		assert.NoError(ct, err)
		assert.False(ct, now.JSON200.Owner.MustGet().User.IsNull(), "the node is alice's again")
	}, 10*time.Second, 50*time.Millisecond)

	resp, err := c.SetNodeTagsWithResponse(ctx, node, &clientv0.SetNodeTagsParams{IfMatch: quoted(read.JSON200.Revision)},
		clientv0.SetNodeTagsBody{Tags: []string{"tag:build"}})
	require.NoError(t, err)
	require.Equal(t, http.StatusPreconditionFailed, resp.StatusCode(), string(resp.Body))

	after, err := c.GetNodeWithResponse(ctx, node)
	require.NoError(t, err)
	require.Equal(t, "alice", after.JSON200.Owner.MustGet().User.MustGet().LoginName)
}
