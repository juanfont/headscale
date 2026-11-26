package apiv0

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/juanfont/headscale/hscontrol/policy"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/require"
)

func TestListTags(t *testing.T) {
	b, api, auth, nodes := nodesAPI(t)

	_, _, err := b.State.SetNodeTags(nodes[0].ID(), []string{"tag:ci", "tag:build"})
	require.NoError(t, err)
	_, _, err = b.State.SetNodeTags(nodes[1].ID(), []string{"tag:ci"})
	require.NoError(t, err)

	list := func(t *testing.T, query string) TagList {
		t.Helper()

		rec := api.Get(Prefix+"/tags?"+query, auth)
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

		var l TagList
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &l))

		return l
	}

	ref := func(nv types.NodeView) NodeReference {
		n, _ := b.State.GetNodeByID(nv.ID())

		return NodeReference{ID: n.StringID(), Name: n.GivenName()}
	}

	all := list(t, "")
	require.Equal(t, []Tag{
		{
			Tag:       "tag:build",
			InPolicy:  true,
			NodeCount: 1,
			Nodes:     []NodeReference{ref(nodes[0])},
		},
		{
			Tag:       "tag:ci",
			InPolicy:  true,
			NodeCount: 2,
			Nodes:     []NodeReference{ref(nodes[0]), ref(nodes[1])},
		},
		{Tag: "tag:unused", InPolicy: true, NodeCount: 0, Nodes: []NodeReference{}},
		{Tag: "tag:web", InPolicy: true, NodeCount: 0, Nodes: []NodeReference{}},
	}, all.Tags)

	only := list(t, "node="+nodes[1].StringID())
	require.Equal(t, []Tag{all.Tags[1]}, only.Tags, "the counts still cover every node")

	require.Equal(t, []Tag{}, list(t, "node=999").Tags)

	t.Run("a node filter that is not an ID", func(t *testing.T) {
		for _, v := range []string{"007", "abc", "0"} {
			rec := api.Get(Prefix+"/tags?node="+v, auth)
			p := decodeProblem(t, rec, CodeInvalidField)
			require.Equal(t, []string{"query.node"}, locations(p), v)
		}
	})

	t.Run("walk with a page size of 2", func(t *testing.T) {
		first := list(t, "pageSize=2")
		require.Equal(t, all.Tags[:2], first.Tags)
		require.NotEmpty(t, first.NextPageToken)

		second := list(t, "pageSize=2&pageToken="+url.QueryEscape(first.NextPageToken))
		require.Equal(t, all.Tags[2:], second.Tags)
		require.Empty(t, second.NextPageToken)

		for name, query := range map[string]string{
			"forged":        "pageSize=2&pageToken=" + url.QueryEscape(forgedToken(first.NextPageToken)),
			"other filters": "pageSize=2&node=1&pageToken=" + url.QueryEscape(first.NextPageToken),
		} {
			t.Run(name, func(t *testing.T) {
				decodeProblem(
					t,
					api.Get(Prefix+"/tags?"+query, auth),
					CodeInvalidPageToken,
				)
			})
		}

		t.Run("another list", func(t *testing.T) {
			pg, _ := openPage[uint64](PageQuery{PageSize: 2}, "nodes", "", "")
			_, other := cutPage(
				pg,
				[]uint64{1, 2, 3},
				func(n uint64) uint64 { return n },
			)
			decodeProblem(
				t,
				api.Get(
					Prefix+"/tags?pageSize=2&pageToken="+url.QueryEscape(other),
					auth,
				),
				CodeInvalidPageToken,
			)
		})
	})

	// A tag that the policy drops stays while a node has it.
	_, _, err = b.State.UpdatePolicy(
		[]byte(
			`{"tagOwners": {"tag:ci": []}, "acls": [{"action": "accept", "src": ["*"], "dst": ["*:*"]}]}`,
		),
	)
	require.NoError(t, err)
	require.Equal(
		t,
		Tag{
			Tag:       "tag:build",
			InPolicy:  false,
			NodeCount: 1,
			Nodes:     []NodeReference{ref(nodes[0])},
		},
		list(t, "").Tags[0],
	)
}

type afterPolicyTags struct {
	policy.PolicyManager

	after func()
}

func (p afterPolicyTags) PolicyTags() []string {
	tags := p.PolicyManager.PolicyTags()
	p.after()

	return tags
}

// TestTagsAreOneMoment: the tags of the policy and those of the nodes are
// read at one moment; a policy that adds a tag, and a node that then takes
// it, wait for the read.
func TestTagsAreOneMoment(t *testing.T) {
	b, api, auth, nodes := nodesAPI(t)

	var once sync.Once

	b.State.WrapPolicyManagerForTest(
		func(pm policy.PolicyManager) policy.PolicyManager {
			return afterPolicyTags{pm, func() {
				once.Do(func() {
					whileBlocked(t, func() {
						_, _, err := b.State.UpdatePolicy(
							[]byte(
								strings.Replace(
									nodesPolicy,
									"tag:unused",
									"tag:next",
									1,
								),
							),
						)
						if err != nil {
							t.Error(err)
						}

						_, _, err = b.State.SetNodeTags(
							nodes[0].ID(),
							[]string{"tag:next"},
						)
						if err != nil {
							t.Error(err)
						}
					})
				})
			}}
		},
	)

	rec := api.Get(Prefix+"/tags?node="+nodes[0].StringID(), auth)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	var list TagList
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &list))

	for _, tag := range list.Tags {
		require.True(t, tag.InPolicy, "%s is on a node, so the policy had it", tag.Tag)
	}
}

// TestListTagsWalksALongTag: a tag of any length is a page boundary like any
// other; a walk one tag a page returns every tag once.
func TestListTagsWalksALongTag(t *testing.T) {
	for _, name := range []string{"tag:" + strings.Repeat("a", 385), "tag:m"} {
		t.Run(fmt.Sprintf("%d bytes", len(name)), func(t *testing.T) {
			b, api, auth := usersAPI(t)

			_, _, err := b.State.UpdatePolicy(
				[]byte(`{"tagOwners": {"tag:a": [], "` + name + `": [], "tag:z": []}}`),
			)
			require.NoError(t, err)

			var (
				seen []string
				tok  string
			)

			for {
				q := Prefix + "/tags?pageSize=1"
				if tok != "" {
					q += "&pageToken=" + url.QueryEscape(tok)
				}

				rec := api.Get(q, auth)
				require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

				var l TagList
				require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &l))

				for _, tag := range l.Tags {
					seen = append(seen, tag.Tag)
				}

				tok = l.NextPageToken
				if tok == "" {
					break
				}
			}

			require.Equal(t, []string{"tag:a", name, "tag:z"}, seen)
		})
	}
}
