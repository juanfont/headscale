package apiv0

import (
	"cmp"
	"context"
	"errors"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/juanfont/headscale/hscontrol/scope"
	"github.com/juanfont/headscale/hscontrol/state"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"tailscale.com/net/tsaddr"
	"tailscale.com/util/dnsname"
)

// Node is a node, the same object in a list, a get and the answer to every
// write.
type Node struct {
	ID                 string            `json:"id"`
	Name               string            `doc:"The name in Headscale, which can be changed."                                                                                                                                                                                                         json:"name"`
	Hostname           string            `doc:"What the node reports. Read-only."                                                                                                                                                                                                                    json:"hostname"`
	FQDN               string            `doc:"name and the base domain, without a trailing dot; \"\" when no base domain is set, or when name is not a DNS label (problems has node_name_invalid)."                                                                                                 json:"fqdn"`
	Owner              *UserOrTags       `doc:"One user, or tags."                                                                                                                                                                                                                                   json:"owner"`
	Addresses          []string          `doc:"IPv4 first."                                                                                                                                                                                                                                          json:"addresses"          nullable:"false"`
	ConnectedToControl bool              `doc:"The node holds a session with the server, expired or not. A node that is not expired stays connected for a short grace after its session ends; an expired node is released at once."                                                                  json:"connectedToControl"`
	LastSeen           *time.Time        `doc:"Now while the node is connected; otherwise its last connection, or its registration if it has not connected since."                                                                                                                                   json:"lastSeen"`
	Expiry             *time.Time        `doc:"null: the node never expires, or its stored expiry is out of range (problems names it)."                                                                                                                                                              json:"expiry"`
	Expired            bool              `doc:"The expiry has passed, by the server's clock."                                                                                                                                                                                                        json:"expired"`
	Created            time.Time         `json:"created"`
	ClientVersion      string            `doc:"The short version of the Tailscale client; \"\" when unknown."                                                                                                                                                                                        json:"clientVersion"`
	UpdateAvailable    bool              `doc:"A newer stable Tailscale client exists; false also when the server does not know."                                                                                                                                                                    json:"updateAvailable"`
	OS                 string            `doc:"As the node reports it; \"\" when unknown."                                                                                                                                                                                                           json:"os"`
	EnabledRoutes      []string          `doc:"Routes an admin or the policy approved."                                                                                                                                                                                                              json:"enabledRoutes"      nullable:"false"`
	AdvertisedRoutes   []string          `doc:"Routes the node offers."                                                                                                                                                                                                                              json:"advertisedRoutes"   nullable:"false"`
	ServingRoutes      []string          `doc:"Routes the node serves to others now: approved, offered, and with this node chosen to serve them; exit routes too."                                                                                                                                   json:"servingRoutes"      nullable:"false"`
	Ephemeral          bool              `doc:"The node is removed some time after it disconnects."                                                                                                                                                                                                  json:"ephemeral"`
	RegisterMethod     RegisterMethod    `json:"registerMethod"`
	AuthKeyID          *string           `doc:"The ID of the auth key the node joined with."                                                                                                                                                                                                         json:"authKeyId"`
	CreatedBy          *UserReference    `doc:"The user whose key or login last registered the node in place: for a tagged node the maker of its key, for a node a user took back that user. null for a key an OAuth client made, or when the server does not know. Not the owner of a tagged node." json:"createdBy"`
	MachineKey         string            `json:"machineKey"`
	NodeKey            string            `json:"nodeKey"`
	DiscoKey           string            `json:"discoKey"`
	Attributes         map[string]string `doc:"Node attributes, by name."                                                                                                                                                                                                                            json:"attributes"         nullable:"false"`
	Revision           string            `doc:"Changes when the owner, the tags, the enabled routes, the name or the expiry change. Send it back in If-Match."                                                                                                                                       json:"revision"`
	Problems           []string          `doc:"The codes of the health checks the node fails, as in the warnings of GET /health; [] for a good node."                                                                                                                                                json:"problems"           nullable:"false"`
}

// RegisterMethod is how a node registered.
type RegisterMethod string

// Schema is an enum with "": huma's enum tag cannot hold an empty value.
func (RegisterMethod) Schema(huma.Registry) *huma.Schema {
	return &huma.Schema{
		Type:        huma.TypeString,
		Enum:        []any{"authKey", "cli", "oidc", ""},
		Description: "How the node registered; \"\" for a node that does not record it, as os and clientVersion are \"\" when unknown. A client must accept a value it does not know.",
	}
}

// NodeList is a page of nodes.
type NodeList struct {
	Nodes         []Node `json:"nodes"                                                                                  nullable:"false"`
	NextPageToken string `doc:"Present when more rows can follow; send it back as pageToken. Missing on the last page." json:"nextPageToken,omitempty"`
}

// UpdateNodeBody is the body of PATCH /nodes/{id}.
type UpdateNodeBody struct {
	Name   Optional[string] `doc:"A DNS label; \"\" resets it to the name made from the hostname."                                                json:"name,omitzero"   maxLength:"63"`
	Expiry Optional[string] `doc:"An RFC 3339 time in the future, \"now\" for the server's clock, or null for never. A time turns key expiry on." json:"expiry,omitzero" maxLength:"64" nullable:"true"`
}

// SetNodeTagsBody is the body of PUT /nodes/{id}/tags.
type SetNodeTagsBody struct {
	Tags []string `doc:"At least one tag, each in tagOwners of the policy." json:"tags" maxItems:"256" nullable:"false"`
}

// SetNodeRoutesBody is the body of PUT /nodes/{id}/routes.
type SetNodeRoutesBody struct {
	Routes []string `doc:"IP prefixes; [] removes them all. One exit prefix approves both." json:"routes" maxItems:"4096" nullable:"false"`
}

// maxNodeBody bounds a node body. A route list is the longest.
const maxNodeBody = 256 << 10

// nowWord is the expiry that the server replaces with its clock.
const nowWord = "now"

func (b *UpdateNodeBody) fieldErrors() []FieldError {
	var errs []FieldError

	if n := b.Name.Value; b.Name.Set && n != "" {
		switch {
		case types.ValidateUserText(n) != nil:
			errs = append(
				errs,
				FieldError{
					Location: "body.name",
					Message:  "has a control character or a bidirectional formatting character",
				},
			)
		case n != strings.ToLower(n):
			errs = append(
				errs,
				FieldError{
					Location: "body.name",
					Message:  "has a capital letter; a name is lower case",
				},
			)
		case dnsname.ValidLabel(n) != nil:
			errs = append(
				errs,
				FieldError{
					Location: "body.name",
					Message:  "is not a DNS label: letters, digits and '-', not at either end, at most 63",
				},
			)
		}
	}

	if b.Expiry.Set && !b.Expiry.Null && b.Expiry.Value != nowWord {
		t, err := time.Parse(time.RFC3339Nano, b.Expiry.Value)
		if err == nil {
			_, err = types.ValidateExpiry(t)
		}

		if err != nil {
			errs = append(
				errs,
				FieldError{
					Location: "body.expiry",
					Message:  "is not an RFC 3339 time between the years 0 and 9999, \"now\" or null",
				},
			)
		}
	}

	return errs
}

func (b *SetNodeRoutesBody) fieldErrors() []FieldError {
	var errs []FieldError

	for i, r := range b.Routes {
		p, err := netip.ParsePrefix(r)
		if err == nil {
			err = util.CheckRouteMasked(p)
		}

		if err != nil {
			errs = append(
				errs,
				FieldError{
					Location: "body.routes[" + strconv.Itoa(i) + "]",
					Message:  "is not an IP prefix with no host bits",
				},
			)
		}
	}

	return errs
}

// tokenMustOwnTags keeps a token from putting a tag on a node, or taking
// one off, or making an auth key for one, that its grant does not reach.
// The tags of a node are its owner and decide what it may reach. Its check
// is the function GET /me shows as authorization.tags.
var tokenMustOwnTags = tokenRule{
	name: "token_must_own_tags",
	why:  "An OAuth access token must hold, or own in the policy's tagOwners, every tag it gives: to a node, where it must also own every tag the node has now, and to an auth key. GET /me lists these tags as authorization.tags. An API key may give any tag of the policy.",
}

type (
	listNodesInput struct {
		PageQuery

		User string `doc:"Only the nodes of the user with this ID; tagged nodes never match." query:"user"`
		Tag  string `doc:"Only the nodes with this tag."                                      query:"tag"`
	}

	nodeIDInput struct {
		ID string `doc:"The ID of the node." path:"id"`
	}

	// IfMatchHeader is the revision a write expects the node to have.
	IfMatchHeader struct {
		IfMatch string `doc:"The revision of the node, as its ETag: \"<revision>\". The write is refused with precondition_failed when the node changed; leave it out to write whatever it holds." header:"If-Match"`
	}

	nodeWriteInput struct {
		IfMatchHeader

		ID string `doc:"The ID of the node." path:"id"`
	}

	updateNodeInput struct {
		IfMatchHeader

		ID string `doc:"The ID of the node." path:"id"`

		Body UpdateNodeBody
	}

	setTagsInput struct {
		IfMatchHeader

		ID string `doc:"The ID of the node." path:"id"`

		Body SetNodeTagsBody
	}

	setRoutesInput struct {
		IfMatchHeader

		ID string `doc:"The ID of the node." path:"id"`

		Body SetNodeRoutesBody
	}

	nodeOutput struct {
		ETag string `doc:"The revision of the node, quoted." header:"ETag"`
		Body Node
	}
)

var (
	nodeNotFound = []answer{
		onError(state.ErrNodeNotInNodeStore, CodeNotFound, "No node has this ID."),
		onError(state.ErrNodeNotFound, CodeNotFound, "No node has this ID."),
	}
	nodeChanged = onError(
		state.ErrNodeRevisionChanged,
		CodePreconditionFailed,
		"The node changed since its revision was read; nothing was written.",
	)
)

func registerNodes(api huma.API, b Backend) {
	tags := []string{"Nodes"}

	register(api, huma.Operation{
		OperationID: "listNodes",
		Method:      http.MethodGet,
		Path:        Prefix + "/nodes",
		Summary:     "List nodes",
		Description: "In ID order. A page and its computed fields show one moment.",
		Tags:        tags,
	}, needs(scope.DevicesCoreRead), nil, func(_ context.Context, in *listNodesInput) (*struct{ Body NodeList }, error) {
		var user types.UserID

		if in.User != "" {
			id, err := pathID[types.UserID](in.User)
			if err != nil {
				p := newProblem(CodeInvalidField, "A query parameter is not valid.")
				p.Errors = []FieldError{
					{Location: "query.user", Message: "is not a user ID"},
				}

				return nil, p
			}

			user = id
		}

		pg, err := openPage[uint64](in.PageQuery, "nodes", in.User, in.Tag)
		if err != nil {
			return nil, err
		}

		// The page and the users it names are of one moment.
		defer b.State.UsersMoment()()

		idx := b.State.NodeIndex()

		after := types.NodeID(pg.after)

		from := idx.NodesAfter(after)
		if in.Tag != "" {
			from = idsAfter(idx.NodesWithTag(in.Tag), after)
		}

		// A page reads its own rows and one more, not the tailnet.
		rows := make([]types.NodeView, 0, pg.limit())

		for _, nv := range from {
			if len(rows) == pg.limit() {
				break
			}

			if user == 0 || (!nv.IsTagged() && nv.TypedUserID() == user) {
				rows = append(rows, nv)
			}
		}

		rows, next := cutPage(
			pg,
			rows,
			func(nv types.NodeView) uint64 { return uint64(nv.ID()) },
		)

		nodes, err := b.nodes(idx.Snapshot, rows)
		if err != nil {
			return nil, err
		}

		return &struct{ Body NodeList }{
			Body: NodeList{Nodes: nodes, NextPageToken: next},
		}, nil
	})

	register(api, huma.Operation{
		OperationID: "getNode",
		Method:      http.MethodGet,
		Path:        Prefix + "/nodes/{id}",
		Summary:     "Read one node",
		Description: "The ETag is the revision, to send back in If-Match.",
		Tags:        tags,
	}, needs(scope.DevicesCoreRead), nodeNotFound, func(_ context.Context, in *nodeIDInput) (*nodeOutput, error) {
		id, err := pathID[types.NodeID](in.ID)
		if err != nil {
			return nil, err
		}

		return b.nodeOutput(id, types.NodeView{})
	})

	registerNodeWrites(api, b, tags)
	registerNodeActions(api, b, tags)
}

// registerNodeWrites registers the writes of a node's own fields.
func registerNodeWrites(api huma.API, b Backend, tags []string) {
	register(api, huma.Operation{
		OperationID:  "updateNode",
		Method:       http.MethodPatch,
		Path:         Prefix + "/nodes/{id}",
		Summary:      "Change the name or the expiry of a node",
		Description:  "Changes the fields that are sent, as JSON Merge Patch (RFC 7396); both change, or neither. A name another node has is name_taken.",
		Tags:         tags,
		MaxBodyBytes: maxNodeBody,
	}, needs(scope.DevicesCore), append([]answer{
		nodeChanged,
		{code: CodeNameTaken},
		{code: CodeExpiryInPast},
	}, nodeNotFound...), func(_ context.Context, in *updateNodeInput) (*nodeOutput, error) {
		var patch state.NodePatch

		body := in.Body

		if body.Expiry.Set {
			switch {
			case body.Expiry.Null:
				patch.NeverExpires = true
			case body.Expiry.Value == nowWord:
				patch.Expiry = new(time.Now())
			default:
				t, _ := time.Parse(
					time.RFC3339Nano,
					body.Expiry.Value,
				) // checked in fieldErrors
				if t.Before(time.Now()) {
					return nil, newProblem(
						CodeExpiryInPast,
						"The expiry is before now; send \"now\" to expire the node at the server's clock.",
					)
				}

				patch.Expiry = &t
			}
		}

		if body.Name.Set {
			patch.Name = new(body.Name.Value)
		}

		id, rev, err := b.nodeWrite(in.ID, in.IfMatch)
		if err != nil {
			return nil, err
		}

		nv, c, err := b.State.PatchNode(id, rev, patch)
		b.Change(c)

		switch {
		case errors.Is(err, state.ErrNodeNameNotUnique):
			return nil, b.nameTaken(body.Name.Value)
		case errors.Is(err, state.ErrGivenNameInvalid):
			p := newProblem(CodeInvalidField, "A field is not valid.")
			p.Errors = []FieldError{
				{
					Location: "body.name",
					Message:  "with the base domain, makes a name longer than a DNS name may be",
				},
			}

			return nil, p
		case err != nil:
			return nil, about(err, nodeObject(id, b.State))
		}

		return b.nodeOutput(id, nv)
	})

	register(api, huma.Operation{
		OperationID:   "deleteNode",
		Method:        http.MethodDelete,
		Path:          Prefix + "/nodes/{id}",
		Summary:       "Delete a node",
		Description:   "The node must register again to come back.",
		Tags:          tags,
		DefaultStatus: http.StatusNoContent,
	}, needs(scope.DevicesCore), append([]answer{nodeChanged}, nodeNotFound...), func(_ context.Context, in *nodeWriteInput) (*struct{}, error) {
		id, rev, err := b.nodeWrite(in.ID, in.IfMatch)
		if err != nil {
			return nil, err
		}

		obj := nodeObject(id, b.State)

		cs, err := b.State.DeleteNodeIf(id, rev)
		b.Change(cs...)

		if err != nil {
			return nil, about(err, obj)
		}

		return nil, nil //nolint:nilnil // 204 has no body
	})

	register(api, huma.Operation{
		OperationID: "expireNode",
		Method:      http.MethodPost,
		Path:        Prefix + "/nodes/{id}/expire",
		Summary:     "Expire a node now",
		Description: "Sets the expiry to the server's clock and turns key expiry on, so the node must log in again, tagged or not.",
		Tags:        tags,
	}, needs(scope.DevicesCore), append([]answer{nodeChanged}, nodeNotFound...), func(_ context.Context, in *nodeWriteInput) (*nodeOutput, error) {
		id, rev, err := b.nodeWrite(in.ID, in.IfMatch)
		if err != nil {
			return nil, err
		}

		nv, c, err := b.State.ExpireNodeIf(id, rev)
		b.Change(c)

		if err != nil {
			return nil, about(err, nodeObject(id, b.State))
		}

		return b.nodeOutput(id, nv)
	})
}

// registerNodeActions registers the actions on a node and the writes of its
// tags and routes.
func registerNodeActions(api huma.API, b Backend, tags []string) {
	register(api, huma.Operation{
		OperationID: "updateNodeClient",
		Method:      http.MethodPost,
		Path:        Prefix + "/nodes/{id}/update-client",
		Summary:     "Ask a node to update its Tailscale client",
		Description: "Answers once the node started the update, not when it is done. A node that does not start it is update_refused, with the reason.",
		Tags:        tags,
	}, needs(scope.DevicesCore), append([]answer{{code: CodeUpdateRefused}}, nodeNotFound...), func(ctx context.Context, in *nodeIDInput) (*nodeOutput, error) {
		id, err := pathID[types.NodeID](in.ID)
		if err != nil {
			return nil, err
		}

		err = b.State.RequestClientUpdate(ctx, id, b.Connected(id), b.Change)
		if refused, ok := errors.AsType[*state.ClientUpdateRefusedError](err); ok {
			p := newProblem(
				CodeUpdateRefused,
				"The node did not start the update; details.reason says why.",
			)
			p.Details["reason"] = refused.Reason
			p.Details["clientError"] = refused.ClientError

			return nil, about(p, nodeObject(id, b.State))
		}

		if err != nil {
			return nil, about(err, nodeObject(id, b.State))
		}

		return b.nodeOutput(id, types.NodeView{})
	})

	register(api, huma.Operation{
		OperationID:  "setNodeTags",
		Method:       http.MethodPut,
		Path:         Prefix + "/nodes/{id}/tags",
		Summary:      "Replace the tags of a node",
		Description:  "A user-owned node becomes a tagged node, and the API cannot undo that. Key expiry stays as it was.",
		Tags:         tags,
		MaxBodyBytes: maxNodeBody,
	}, needs(scope.DevicesCore).withTokenRules(&tokenMustOwnTags), append([]answer{
		nodeChanged,
		{code: CodeTagsRequired},
		{code: CodeTagsNotPermitted},
	}, nodeNotFound...), func(ctx context.Context, in *setTagsInput) (*nodeOutput, error) {
		want := in.Body.Tags

		// What the request alone shows comes first: the tags it names,
		// then the node.
		var owned []string

		token := isToken(ctx)
		if token {
			owned = b.State.TagsOwnedByTags(callerFrom(ctx).tags)

			if !ownsAll(owned, want) {
				return nil, ruleForbidden(&tokenMustOwnTags)
			}
		}

		if len(want) == 0 {
			return nil, newProblem(
				CodeTagsRequired,
				"A node needs at least one tag; the API cannot give a tagged node back to a user.",
			)
		}

		refused := tagsNotPermitted(b.State, want)
		if refused != nil {
			return nil, refused
		}

		id, rev, err := b.nodeWrite(in.ID, in.IfMatch)
		if err != nil {
			return nil, err
		}

		if token {
			nv, ok := b.State.GetNodeByID(id)
			if !ok {
				return nil, about(
					state.ErrNodeNotInNodeStore,
					ProblemObject{Kind: "node", ID: in.ID},
				)
			}

			// The rules read this node, so the write is guarded by its
			// revision whether or not the caller sent one: a change
			// between the check and the write is refused, not written.
			rev, err = checkedRevision(rev, nv)
			if err != nil {
				return nil, about(err, nodeObject(id, b.State))
			}

			if !ownsAll(owned, nv.Tags().AsSlice()) {
				return nil, ruleForbidden(&tokenMustOwnTags)
			}
		}

		nv, c, err := b.State.SetNodeTagsIf(id, want, rev)
		if errors.Is(err, state.ErrRequestedTagsInvalidOrNotPermitted) {
			// The policy changed since the check above.
			refused = tagsNotPermitted(b.State, want)
			if refused != nil {
				return nil, refused
			}

			p := newProblem(
				CodeTagsNotPermitted,
				"Every tag must be in tagOwners of the policy; details.tags names the others.",
			)
			p.Details["tags"] = want

			return nil, p
		}

		if err != nil {
			return nil, about(err, nodeObject(id, b.State))
		}

		b.Change(c)

		return b.nodeOutput(id, nv)
	})

	register(api, huma.Operation{
		OperationID:  "setNodeRoutes",
		Method:       http.MethodPut,
		Path:         Prefix + "/nodes/{id}/routes",
		Summary:      "Replace the enabled routes of a node",
		Description:  "Replaces enabledRoutes, the policy's approvals too. A route the node does not offer is stored and takes effect when it does. One exit prefix approves both.",
		Tags:         tags,
		MaxBodyBytes: maxNodeBody,
	}, needs(scope.DevicesRoutes, scope.DevicesCoreRead), append([]answer{nodeChanged}, nodeNotFound...), func(_ context.Context, in *setRoutesInput) (*nodeOutput, error) {
		routes := make([]netip.Prefix, 0, len(in.Body.Routes))

		for _, r := range in.Body.Routes {
			p := netip.MustParsePrefix(r) // checked in fieldErrors
			if tsaddr.IsExitRoute(p) {
				routes = append(routes, tsaddr.AllIPv4(), tsaddr.AllIPv6())
			} else {
				routes = append(routes, p)
			}
		}

		slices.SortFunc(routes, netip.Prefix.Compare)
		routes = slices.Compact(routes)

		id, rev, err := b.nodeWrite(in.ID, in.IfMatch)
		if err != nil {
			return nil, err
		}

		nv, c, err := b.State.SetApprovedRoutesIf(id, routes, rev)
		b.Change(c)

		if err != nil {
			return nil, about(err, nodeObject(id, b.State))
		}

		return b.nodeOutput(id, nv)
	})
}

// isToken reports whether the caller is an OAuth access token, which the
// token rules hold.
func isToken(ctx context.Context) bool {
	c := callerFrom(ctx)

	return c != nil && c.credential != nil && c.credential.kind == CredentialOAuthToken
}

// ownsAll reports whether owned has every tag of tags.
func ownsAll(owned, tags []string) bool {
	return !slices.ContainsFunc(
		tags,
		func(t string) bool { return !slices.Contains(owned, t) },
	)
}

// tagsNotPermitted is tags_not_permitted naming each tag of want that the
// policy does not name, or nil when it names them all.
func tagsNotPermitted(s *state.State, want []string) *Problem {
	var unknown []string

	for _, t := range want {
		if !s.TagExists(t) && !slices.Contains(unknown, t) {
			unknown = append(unknown, t)
		}
	}

	if len(unknown) == 0 {
		return nil
	}

	p := newProblem(
		CodeTagsNotPermitted,
		"Every tag must be in tagOwners of the policy; details.tags names the others.",
	)
	p.Details["tags"] = unknown

	return p
}

// checkedRevision is the revision to guard a write with once a check read
// nv: nv's own, so the write fails if the node changed after the check.
// A revision the caller sent that nv no longer has is refused now.
func checkedRevision(sent string, nv types.NodeView) (string, error) {
	if sent != "" && sent != nv.Revision() {
		return "", state.ErrNodeRevisionChanged
	}

	return nv.Revision(), nil
}

// idsAfter is the nodes of nvs, in ID order, with an ID above after.
func idsAfter(nvs []types.NodeView, after types.NodeID) []types.NodeView {
	i, _ := slices.BinarySearchFunc(
		nvs,
		after+1,
		func(nv types.NodeView, id types.NodeID) int {
			return cmp.Compare(nv.ID(), id)
		},
	)

	return nvs[i:]
}

// nodeWrite reads the path ID and the If-Match of a node write. A missing
// If-Match, and "*", guard nothing. A list guards with the member that is
// the node's revision now, if any: the state compares again under its lock,
// and refuses when the node changed since. A weak tag never matches, as RFC
// 9110 compares If-Match strongly.
func (b Backend) nodeWrite(path, ifMatch string) (types.NodeID, string, error) {
	tags, ok := ifMatchTags(ifMatch)
	if !ok {
		p := newProblem(CodeInvalidField, "A header is not valid.")
		p.Errors = []FieldError{
			{
				Location: "header.If-Match",
				Message:  "is not *, or a list of entity tags such as \"<revision>\"",
			},
		}

		return 0, "", p
	}

	id, err := pathID[types.NodeID](path)
	if err != nil || tags == nil {
		return id, "", err
	}

	if nv, ok := b.State.GetNodeByID(id); ok && slices.Contains(tags, nv.Revision()) {
		return id, nv.Revision(), nil
	}

	// No revision is weak, so this never matches.
	return id, `W/""`, nil
}

// joinIfMatch hands on If-Match sent as several field lines as the one list
// they are (RFC 9110 §5.3), joined in order; huma reads only the first line.
func joinIfMatch(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if lines := r.Header.Values("If-Match"); len(lines) > 1 {
			r = r.Clone(r.Context())
			r.Header.Set("If-Match", strings.Join(lines, ", "))
		}

		next.ServeHTTP(w, r)
	})
}

// ifMatchTags reads If-Match as RFC 9110 §13.1.1 has it: "*" or a list of
// entity tags. It returns the values of the strong tags, and nil for a
// missing header or "*", which guard nothing.
func ifMatchTags(h string) ([]string, bool) {
	h = strings.Trim(h, " \t")
	if h == "" || h == "*" {
		return nil, true
	}

	strong := []string{}

	for {
		// A recipient accepts empty members of a list.
		h = strings.TrimLeft(h, " \t,")
		if h == "" {
			return strong, true
		}

		weak := strings.HasPrefix(h, "W/")
		h = strings.TrimPrefix(h, "W/")

		if h == "" || h[0] != '"' {
			return nil, false
		}

		end := strings.IndexByte(h[1:], '"')
		if end < 0 {
			return nil, false
		}

		tag := h[1 : 1+end]
		if strings.ContainsFunc(
			tag,
			func(r rune) bool { return r <= ' ' || r == 0x7f },
		) {
			return nil, false
		}

		if !weak {
			strong = append(strong, tag)
		}

		h = strings.TrimLeft(h[2+end:], " \t")
		if h != "" && h[0] != ',' {
			return nil, false
		}
	}
}

// nameTaken is name_taken naming the node that has name.
func (b Backend) nameTaken(name string) error {
	p := newProblem(CodeNameTaken, "Another node has this name; object names it.")
	p.Details["name"] = name

	for _, nv := range b.State.ListNodes().All() {
		if nv.GivenName() == strings.ToLower(name) {
			p.Object = &ProblemObject{
				Kind: "node",
				ID:   nv.StringID(),
				Name: nv.GivenName(),
			}

			break
		}
	}

	return p
}

// nodeObject is the object of a problem about the node with id.
func nodeObject(id types.NodeID, s *state.State) ProblemObject {
	obj := ProblemObject{Kind: "node", ID: strconv.FormatUint(uint64(id), 10)}
	if nv, ok := s.GetNodeByID(id); ok {
		obj.Name = nv.GivenName()
	}

	return obj
}

// nodeOutput is the node with id as the newest snapshot holds it, else
// written, the node a write returned; not_found when neither has it.
func (b Backend) nodeOutput(
	id types.NodeID,
	written types.NodeView,
) (*nodeOutput, error) {
	defer b.State.UsersMoment()()

	snap := b.State.NodeSnapshot()

	nv, ok := snap.Node(id)
	if !ok {
		if !written.Valid() {
			return nil, about(
				state.ErrNodeNotInNodeStore,
				ProblemObject{Kind: "node", ID: strconv.FormatUint(uint64(id), 10)},
			)
		}

		nv = written
	}

	ns, err := b.nodes(snap, []types.NodeView{nv})
	if err != nil {
		return nil, err
	}

	return &nodeOutput{ETag: `"` + ns[0].Revision + `"`, Body: ns[0]}, nil
}

// nodes is nvs with the fields computed from snap. The users a page names
// and the NodeStore does not hold are read in one query.
func (b Backend) nodes(snap *state.Snapshot, nvs []types.NodeView) ([]Node, error) {
	var missing []types.UserID

	for _, nv := range nvs {
		if id, ok := creator(
			nv,
		); ok &&
			(!nv.User().Valid() || types.UserID(nv.User().ID()) != id) {
			missing = append(missing, id)
		}

		if id, ok := nv.UserID().GetOk(); ok && !nv.IsTagged() && !nv.User().Valid() {
			missing = append(missing, types.UserID(id))
		}
	}

	slices.Sort(missing)

	users, err := b.State.GetUsersByIDs(slices.Compact(missing))
	if err != nil {
		return nil, err
	}

	user := func(nv types.NodeView, id types.UserID) types.UserView {
		if u := nv.User(); u.Valid() && types.UserID(u.ID()) == id {
			return u
		}

		return users[id]
	}

	now := time.Now()
	out := make([]Node, 0, len(nvs))
	updateAvailable := b.State.UpdateAvailable()

	for _, nv := range nvs {
		n := nodeFromView(
			nv,
			snap.PrimaryRoutesForNode(nv.ID()),
			now,
			b.Cfg.DNSConfig.BaseDomain,
		)
		if n.ConnectedToControl && b.ConnectedSeen != nil {
			n.LastSeen = new(b.ConnectedSeen().UTC())
		}

		n.UpdateAvailable = updateAvailable(nv)
		n.Problems = b.State.NodeProblems(nv)

		if id, ok := creator(nv); ok {
			if u := user(nv, id); u.Valid() {
				n.CreatedBy = &UserReference{
					ID:        strconv.FormatUint(uint64(id), 10),
					LoginName: u.Username(),
				}
			}
		}

		// The NodeStore's copy of the owner, else the stored user.
		if n.Owner == nil && !nv.IsTagged() {
			if id, ok := nv.UserID().GetOk(); ok {
				if u := user(nv, types.UserID(id)); u.Valid() {
					n.Owner = &UserOrTags{User: ownerUser(u), Tags: []string{}}
				}
			}
		}

		out = append(out, n)
	}

	return out, nil
}

// creator is who registered nv: the stored creator, else, for a node a
// user owns that is older than the record, that user.
func creator(nv types.NodeView) (types.UserID, bool) {
	if id, ok := nv.CreatedByUserID().GetOk(); ok {
		return types.UserID(id), true
	}

	if id, ok := nv.UserID().GetOk(); ok && !nv.IsTagged() {
		return types.UserID(id), true
	}

	return 0, false
}

// UserOrTags is the owner of a node or an auth key, which has one: a user,
// or tags. The Go client reads it as the nullable [Owner] of an API key,
// so one helper reads every owner.
type UserOrTags Owner

func (UserOrTags) TransformSchema(_ huma.Registry, s *huma.Schema) *huma.Schema {
	s.Nullable = false
	s.OneOf = []*huma.Schema{
		{
			Properties: map[string]*huma.Schema{
				"user": {Type: huma.TypeObject},
				"tags": {Type: huma.TypeArray, MaxItems: new(0)},
			},
		},
		{
			Properties: map[string]*huma.Schema{
				"user": {Type: "null"},
				"tags": {Type: huma.TypeArray, MinItems: new(1)},
			},
		},
	}
	s.Extensions = map[string]any{"x-go-type": "nullable.Nullable[Owner]"}

	return s
}

// nodeFromView is the node's own fields; primaries are the routes it was
// chosen to serve, from the same snapshot.
func nodeFromView(
	nv types.NodeView,
	primaries []netip.Prefix,
	now time.Time,
	baseDomain string,
) Node {
	n := Node{
		ID:                 nv.StringID(),
		Name:               nv.GivenName(),
		Hostname:           nv.Hostname(),
		Addresses:          emptyIfNil(nv.IPsAsString()),
		ConnectedToControl: nv.ActiveSessions() > 0,
		Expired:            nv.IsExpiredAt(now),
		Created:            nv.CreatedAt().UTC(),
		EnabledRoutes:      prefixes(nv.ApprovedRoutes().AsSlice()),
		AdvertisedRoutes:   prefixes(nv.AnnouncedRoutes()),
		ServingRoutes: prefixes(
			append(slices.Clone(primaries), nv.ExitRoutes()...),
		),
		Ephemeral:      nv.IsEphemeral(),
		RegisterMethod: registerMethod(nv.RegisterMethod()),
		MachineKey:     nv.MachineKey().String(),
		NodeKey:        nv.NodeKey().String(),
		DiscoKey:       nv.DiscoKey().String(),
		Attributes:     map[string]string{},
		Revision:       nv.Revision(),
	}

	// Config takes base_domain with a trailing dot, and an old row can hold
	// a name that is no DNS label; neither may reach the field.
	baseDomain = strings.TrimSuffix(baseDomain, ".")
	if baseDomain != "" && types.ValidateGivenName(n.Name, baseDomain) == nil {
		n.FQDN = n.Name + "." + baseDomain
	}

	if nv.IsTagged() {
		n.Owner = &UserOrTags{Tags: nv.Tags().AsSlice()}
	} else if u := nv.User(); u.Valid() {
		n.Owner = &UserOrTags{User: ownerUser(u), Tags: []string{}}
	}

	switch {
	case n.ConnectedToControl:
		n.LastSeen = new(now.UTC())
	case nv.LastSeen().Valid():
		n.LastSeen = new(nv.LastSeen().Get().UTC())
	}

	// A stored time out of range cannot be written as RFC 3339; problems
	// names it, and a PATCH of the expiry repairs it.
	if exp, ok := nv.KeyExpiry(); ok {
		utc, err := types.ValidateExpiry(exp)
		if err == nil {
			n.Expiry = &utc
		}
	}

	if hi := nv.Hostinfo(); hi.Valid() {
		n.OS = hi.OS()
		n.ClientVersion, _, _ = strings.Cut(hi.IPNVersion(), "-")
	}

	if id, ok := nv.AuthKeyID().GetOk(); ok {
		n.AuthKeyID = new(strconv.FormatUint(id, 10))
	}

	if addr, ok := nv.LastControlAddress().GetOk(); ok {
		n.Attributes["ip:publicAddress"] = addr.String()
	}

	return n
}

// registerMethod is the stored method in the API's words; "" for a node
// that records none, or a word the API does not have.
func registerMethod(m string) RegisterMethod {
	switch m {
	case util.RegisterMethodAuthKey:
		return "authKey"
	case util.RegisterMethodCLI, util.RegisterMethodOIDC:
		return RegisterMethod(m)
	default:
		return ""
	}
}

func prefixes(ps []netip.Prefix) []string {
	ps = slices.Clone(ps)
	slices.SortFunc(ps, netip.Prefix.Compare)
	ps = slices.Compact(ps)

	out := make([]string, len(ps))
	for i, p := range ps {
		out[i] = p.String()
	}

	return out
}

func emptyIfNil(s []string) []string {
	if s == nil {
		return []string{}
	}

	return s
}

// ownerUser is the user side of an owner.
func ownerUser(u types.UserView) *OwnerUser {
	return &OwnerUser{
		ID:          strconv.FormatUint(uint64(u.ID()), 10),
		Name:        u.Name(),
		LoginName:   u.Username(),
		DisplayName: u.DisplayName(),
		Email:       u.Email(),
	}
}
