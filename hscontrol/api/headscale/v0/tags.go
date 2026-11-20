package apiv0

import (
	"context"
	"net/http"
	"slices"

	"github.com/danielgtaylor/huma/v2"
	"github.com/juanfont/headscale/hscontrol/scope"
	"github.com/juanfont/headscale/hscontrol/types"
)

// Tag is a tag of the policy or of a node. A tag is stored nowhere on its
// own.
type Tag struct {
	Tag       string          `json:"tag"`
	InPolicy  bool            `doc:"The tag is in tagOwners of the policy; false for a tag nodes still have that the policy no longer names." json:"inPolicy"`
	NodeCount int             `doc:"Every node that has the tag, also with the node filter."                                                  json:"nodeCount"`
	Nodes     []NodeReference `doc:"The same nodes, in ID order."                                                                             json:"nodes"     nullable:"false"`
}

// TagList is a page of tags.
type TagList struct {
	Tags          []Tag  `json:"tags"                                                                                   nullable:"false"`
	NextPageToken string `doc:"Present when more rows can follow; send it back as pageToken. Missing on the last page." json:"nextPageToken,omitempty"`
}

type listTagsInput struct {
	PageQuery

	Node string `doc:"Only the tags of the node with this ID; the counts still cover every node." query:"node"`
}

func registerTags(api huma.API, b Backend) {
	register(api, huma.Operation{
		OperationID: "listTags",
		Method:      http.MethodGet,
		Path:        Prefix + "/tags",
		Summary:     "List tags",
		Description: "Every tag in tagOwners of the policy and every tag on a node, by name, byte by byte.",
		Tags:        []string{"Tags"},
	}, needs(scope.DevicesCoreRead), nil, func(_ context.Context, in *listTagsInput) (*struct{ Body TagList }, error) {
		var node types.NodeID

		if in.Node != "" {
			id, err := pathID[types.NodeID](in.Node)
			if err != nil {
				p := newProblem(CodeInvalidField, "A query parameter is not valid.")
				p.Errors = []FieldError{{Location: "query.node", Message: "is not a node ID"}}

				return nil, p
			}

			node = id
		}

		pg, err := openPage[string](in.PageQuery, "tags", in.Node)
		if err != nil {
			return nil, err
		}

		policy := b.State.PolicyTags()
		idx := b.State.NodeIndex()

		names := []string{}

		if node != 0 {
			// A node no node has gives an empty list, as every filter does.
			if nv, ok := idx.Node(node); ok {
				names = nv.Tags().AsSlice()
			}
		} else {
			names = append(slices.Clone(policy), idx.Tags()...)
		}

		slices.Sort(names)
		names = slices.Compact(names)

		names, next := cutPage(pg, names, func(t string) string { return t })

		list := TagList{Tags: make([]Tag, 0, len(names)), NextPageToken: next}
		for _, t := range names {
			nodes := idx.NodesWithTag(t)

			refs := make([]NodeReference, 0, len(nodes))
			for _, nv := range nodes {
				refs = append(refs, NodeReference{ID: nv.StringID(), Name: nv.GivenName()})
			}

			list.Tags = append(list.Tags, Tag{
				Tag:       t,
				InPolicy:  slices.Contains(policy, t),
				NodeCount: len(refs),
				Nodes:     refs,
			})
		}

		return &struct{ Body TagList }{Body: list}, nil
	})
}
