package apiv1

import (
	"context"
	"errors"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"tailscale.com/net/tsaddr"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

func init() {
	registrations = append(registrations, registerNodes)
}

// errBackfillNotConfirmed guards BackfillNodeIPs behind explicit confirmed=true.
var errBackfillNotConfirmed = errors.New("not confirmed, aborting")

// registerMethodToV1Enum maps the stored register method onto the
// SCREAMING_SNAKE enum string the v1 contract emits.
var registerMethodToV1Enum = map[string]string{
	util.RegisterMethodAuthKey: "REGISTER_METHOD_AUTH_KEY",
	util.RegisterMethodOIDC:    "REGISTER_METHOD_OIDC",
	util.RegisterMethodCLI:     "REGISTER_METHOD_CLI",
}

// Node mirrors the v1 Node message. The protojson contract emits unpopulated
// fields: scalars and slices always (no omitempty), nested messages and optional
// timestamps as JSON null when unset.
type Node struct {
	ID              string          `format:"uint64"                                                                                      json:"id"`
	MachineKey      string          `json:"machineKey"`
	NodeKey         string          `json:"nodeKey"`
	DiscoKey        string          `json:"discoKey"`
	IPAddresses     []string        `json:"ipAddresses"                                                                                   nullable:"false"`
	Name            string          `json:"name"`
	User            *User           `json:"user"`
	LastSeen        *time.Time      `json:"lastSeen"                                                                                      nullable:"true"`
	Expiry          *time.Time      `json:"expiry"                                                                                        nullable:"true"`
	PreAuthKey      *NodePreAuthKey `json:"preAuthKey"`
	CreatedAt       time.Time       `json:"createdAt"`
	RegisterMethod  string          `enum:"REGISTER_METHOD_UNSPECIFIED,REGISTER_METHOD_AUTH_KEY,REGISTER_METHOD_CLI,REGISTER_METHOD_OIDC" json:"registerMethod"`
	GivenName       string          `json:"givenName"`
	Online          bool            `json:"online"`
	ApprovedRoutes  []string        `json:"approvedRoutes"                                                                                nullable:"false"`
	AvailableRoutes []string        `json:"availableRoutes"                                                                               nullable:"false"`
	SubnetRoutes    []string        `json:"subnetRoutes"                                                                                  nullable:"false"`
	Tags            []string        `json:"tags"                                                                                          nullable:"false"`
}

// NodePreAuthKey is the PreAuthKey shape embedded in a Node response. The
// /preauthkey endpoints own the standalone request/response surface.
type NodePreAuthKey struct {
	User       *User      `json:"user"`
	ID         string     `format:"uint64"   json:"id"`
	Key        string     `json:"key"`
	Reusable   bool       `json:"reusable"`
	Ephemeral  bool       `json:"ephemeral"`
	Used       bool       `json:"used"`
	Expiration *time.Time `json:"expiration" nullable:"true"`
	CreatedAt  *time.Time `json:"createdAt"  nullable:"true"`
	AclTags    []string   `json:"aclTags"    nullable:"false"`
}

// SetTagsRequestBody mirrors v1.SetTagsRequest.
type SetTagsRequestBody struct {
	Tags []string `json:"tags,omitempty"`
}

// SetApprovedRoutesRequestBody mirrors v1.SetApprovedRoutesRequest.
type SetApprovedRoutesRequestBody struct {
	Routes []string `json:"routes,omitempty"`
}

// DebugCreateNodeRequestBody mirrors v1.DebugCreateNodeRequest.
type DebugCreateNodeRequestBody struct {
	User   string   `json:"user,omitempty"`
	Key    string   `json:"key,omitempty"`
	Name   string   `json:"name,omitempty"`
	Routes []string `json:"routes,omitempty"`
}

type (
	getNodeInput struct {
		NodeID string `format:"uint64" path:"nodeId"`
	}
	nodeOutput struct {
		Body struct {
			Node Node `json:"node"`
		}
	}
)

type (
	listNodesInput struct {
		User string `query:"user"`
	}
	listNodesOutput struct {
		Body struct {
			Nodes []Node `json:"nodes" nullable:"false"`
		}
	}
)

type (
	deleteNodeInput struct {
		NodeID string `format:"uint64" path:"nodeId"`
	}
	deleteNodeOutput struct {
		Body struct{}
	}
)

// ExpireNodeRequestBody mirrors v1.ExpireNodeRequest. Both fields are optional;
// an absent or all-zero body expires the node immediately, as gRPC does.
type ExpireNodeRequestBody struct {
	Expiry        *time.Time `json:"expiry,omitempty"`
	DisableExpiry bool       `json:"disableExpiry,omitempty"`
}

type expireNodeInput struct {
	NodeID string                 `format:"uint64"  path:"nodeId"`
	Body   *ExpireNodeRequestBody `required:"false"`
}

type renameNodeInput struct {
	NodeID  string `format:"uint64" path:"nodeId"`
	NewName string `path:"newName"`
}

type setTagsInput struct {
	NodeID string `format:"uint64" path:"nodeId"`
	Body   SetTagsRequestBody
}

type setApprovedRoutesInput struct {
	NodeID string `format:"uint64" path:"nodeId"`
	Body   SetApprovedRoutesRequestBody
}

type registerNodeInput struct {
	User string `query:"user"`
	Key  string `query:"key"`
}

type backfillNodeIPsInput struct {
	Confirmed bool `query:"confirmed"`
}

type backfillNodeIPsOutput struct {
	Body struct {
		Changes []string `json:"changes" nullable:"false"`
	}
}

type debugCreateNodeInput struct {
	Body DebugCreateNodeRequestBody
}

func registerNodes(api huma.API, b Backend) {
	registerNodeReadOps(api, b)
	registerNodeWriteOps(api, b)
	registerNodeAdminOps(api, b)
}

func registerNodeReadOps(api huma.API, b Backend) {
	huma.Register(api, huma.Operation{
		OperationID: "getNode",
		Method:      http.MethodGet,
		Path:        "/api/v1/node/{nodeId}",
		Summary:     "Get node",
		Tags:        []string{"Nodes"},
		Security:    bearerAuth,
	}, func(ctx context.Context, in *getNodeInput) (*nodeOutput, error) {
		nodeID, err := parseNodeID(in.NodeID)
		if err != nil {
			return nil, err
		}

		node, ok := b.State.GetNodeByID(nodeID)
		if !ok {
			return nil, huma.Error404NotFound("node not found")
		}

		out := &nodeOutput{}
		out.Body.Node = nodeFromView(node)

		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "listNodes",
		Method:      http.MethodGet,
		Path:        "/api/v1/node",
		Summary:     "List nodes",
		Tags:        []string{"Nodes"},
		Security:    bearerAuth,
	}, func(ctx context.Context, in *listNodesInput) (*listNodesOutput, error) {
		nodes := b.State.ListNodes()
		if in.User != "" {
			user, err := b.State.GetUserByName(in.User)
			if err != nil {
				return nil, mapError("listing nodes", err)
			}

			nodes = b.State.ListNodesByUser(types.UserID(user.ID))
		}

		out := &listNodesOutput{}
		out.Body.Nodes = make([]Node, nodes.Len())

		for i, node := range nodes.All() {
			n := nodeFromView(node)

			// Tags-as-identity: tagged nodes are presented as the special
			// TaggedDevices user.
			if node.IsTagged() {
				user := userFromView(types.TaggedDevices.View())
				n.User = &user
			}

			// SubnetRoutes is the routes actively served, exit routes included.
			n.SubnetRoutes = util.PrefixesToString(
				append(b.State.GetNodePrimaryRoutes(node.ID()), node.ExitRoutes()...),
			)

			out.Body.Nodes[i] = n
		}

		// Match the gRPC handler's ascending-ID ordering.
		slices.SortFunc(out.Body.Nodes, func(a, b Node) int {
			return cmpNodeID(a.ID, b.ID)
		})

		return out, nil
	})
}

func registerNodeWriteOps(api huma.API, b Backend) {
	huma.Register(api, huma.Operation{
		OperationID: "deleteNode",
		Method:      http.MethodDelete,
		Path:        "/api/v1/node/{nodeId}",
		Summary:     "Delete node",
		Tags:        []string{"Nodes"},
		Security:    bearerAuth,
	}, func(ctx context.Context, in *deleteNodeInput) (*deleteNodeOutput, error) {
		nodeID, err := parseNodeID(in.NodeID)
		if err != nil {
			return nil, err
		}

		node, ok := b.State.GetNodeByID(nodeID)
		if !ok {
			return nil, huma.Error404NotFound("node not found")
		}

		nodeChange, err := b.State.DeleteNode(node)
		if err != nil {
			return nil, huma.Error500InternalServerError("deleting node", err)
		}

		b.Change(nodeChange)

		return &deleteNodeOutput{}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "expireNode",
		Method:      http.MethodPost,
		Path:        "/api/v1/node/{nodeId}/expire",
		Summary:     "Expire node",
		Tags:        []string{"Nodes"},
		Security:    bearerAuth,
	}, func(ctx context.Context, in *expireNodeInput) (*nodeOutput, error) {
		nodeID, err := parseNodeID(in.NodeID)
		if err != nil {
			return nil, err
		}

		// gRPC parity: disableExpiry => nil expiry (never expires); explicit
		// expiry honoured; absent/zero body expires now. Both set is a 400.
		var (
			disableExpiry bool
			customExpiry  *time.Time
		)

		if in.Body != nil {
			disableExpiry = in.Body.DisableExpiry
			customExpiry = in.Body.Expiry
		}

		if disableExpiry && customExpiry != nil {
			return nil, huma.Error400BadRequest("cannot set both disable_expiry and expiry")
		}

		expiry := time.Now()

		switch {
		case disableExpiry:
			node, nodeChange, expErr := b.State.SetNodeExpiry(nodeID, nil)
			if expErr != nil {
				return nil, mapError("expiring node", expErr)
			}

			b.Change(nodeChange)

			out := &nodeOutput{}
			out.Body.Node = nodeFromView(node)

			return out, nil
		case customExpiry != nil:
			expiry = *customExpiry
		}

		node, nodeChange, err := b.State.SetNodeExpiry(nodeID, &expiry)
		if err != nil {
			return nil, mapError("expiring node", err)
		}

		b.Change(nodeChange)

		out := &nodeOutput{}
		out.Body.Node = nodeFromView(node)

		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "renameNode",
		Method:      http.MethodPost,
		Path:        "/api/v1/node/{nodeId}/rename/{newName}",
		Summary:     "Rename node",
		Tags:        []string{"Nodes"},
		Security:    bearerAuth,
	}, func(ctx context.Context, in *renameNodeInput) (*nodeOutput, error) {
		nodeID, err := parseNodeID(in.NodeID)
		if err != nil {
			return nil, err
		}

		node, nodeChange, err := b.State.RenameNode(nodeID, in.NewName)
		if err != nil {
			return nil, mapError("renaming node", err)
		}

		b.Change(nodeChange)

		out := &nodeOutput{}
		out.Body.Node = nodeFromView(node)

		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "setTags",
		Method:      http.MethodPost,
		Path:        "/api/v1/node/{nodeId}/tags",
		Summary:     "Set tags",
		Tags:        []string{"Nodes"},
		Security:    bearerAuth,
	}, func(ctx context.Context, in *setTagsInput) (*nodeOutput, error) {
		nodeID, err := parseNodeID(in.NodeID)
		if err != nil {
			return nil, err
		}

		// Tagged nodes must keep at least one tag, so reject an empty set
		// before touching state, as gRPC does.
		if len(in.Body.Tags) == 0 {
			return nil, huma.Error400BadRequest(
				"cannot remove all tags from a node - tagged nodes must have at least one tag",
			)
		}

		for _, tag := range in.Body.Tags {
			tagErr := validateTag(tag)
			if tagErr != nil {
				return nil, huma.Error400BadRequest("setting tags", tagErr)
			}
		}

		_, found := b.State.GetNodeByID(nodeID)
		if !found {
			return nil, huma.Error404NotFound("node not found")
		}

		node, nodeChange, err := b.State.SetNodeTags(nodeID, in.Body.Tags)
		if err != nil {
			return nil, huma.Error400BadRequest("setting tags", err)
		}

		b.Change(nodeChange)

		out := &nodeOutput{}
		out.Body.Node = nodeFromView(node)

		return out, nil
	})
}

func registerNodeAdminOps(api huma.API, b Backend) {
	huma.Register(api, huma.Operation{
		OperationID: "setApprovedRoutes",
		Method:      http.MethodPost,
		Path:        "/api/v1/node/{nodeId}/approve_routes",
		Summary:     "Set approved routes",
		Tags:        []string{"Nodes"},
		Security:    bearerAuth,
	}, func(ctx context.Context, in *setApprovedRoutesInput) (*nodeOutput, error) {
		nodeID, err := parseNodeID(in.NodeID)
		if err != nil {
			return nil, err
		}

		var newApproved []netip.Prefix

		for _, route := range in.Body.Routes {
			prefix, parseErr := netip.ParsePrefix(route)
			if parseErr != nil {
				return nil, huma.Error400BadRequest("parsing route", parseErr)
			}

			// One exit route implies both families, else the client won't
			// annotate the node as an exit node.
			if prefix == tsaddr.AllIPv4() || prefix == tsaddr.AllIPv6() {
				newApproved = append(newApproved, tsaddr.AllIPv4(), tsaddr.AllIPv6())
			} else {
				newApproved = append(newApproved, prefix)
			}
		}

		slices.SortFunc(newApproved, netip.Prefix.Compare)
		newApproved = slices.Compact(newApproved)

		node, nodeChange, err := b.State.SetApprovedRoutes(nodeID, newApproved)
		if err != nil {
			return nil, mapError("setting approved routes", err)
		}

		b.Change(nodeChange)

		out := &nodeOutput{}
		out.Body.Node = nodeFromView(node)
		// SubnetRoutes here excludes exit routes, unlike the list handler.
		out.Body.Node.SubnetRoutes = util.PrefixesToString(
			b.State.GetNodePrimaryRoutes(node.ID()),
		)

		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "registerNode",
		Method:      http.MethodPost,
		Path:        "/api/v1/node/register",
		Summary:     "Register node",
		Tags:        []string{"Nodes"},
		Security:    bearerAuth,
	}, func(ctx context.Context, in *registerNodeInput) (*nodeOutput, error) {
		registrationID, err := types.AuthIDFromString(in.Key)
		if err != nil {
			return nil, huma.Error400BadRequest("registering node", err)
		}

		user, err := b.State.GetUserByName(in.User)
		if err != nil {
			return nil, mapError("looking up user", err)
		}

		node, nodeChange, err := b.State.HandleNodeFromAuthPath(
			registrationID,
			types.UserID(user.ID),
			nil,
			util.RegisterMethodCLI,
		)
		if err != nil {
			return nil, mapError("registering node", err)
		}

		routeChange, err := b.State.AutoApproveRoutes(node)
		if err != nil {
			return nil, huma.Error500InternalServerError("auto approving routes", err)
		}

		// Empty changes are ignored by the change sink.
		b.Change(nodeChange, routeChange)

		out := &nodeOutput{}
		out.Body.Node = nodeFromView(node)

		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "backfillNodeIPs",
		Method:      http.MethodPost,
		Path:        "/api/v1/node/backfillips",
		Summary:     "Backfill node IPs",
		Tags:        []string{"Nodes"},
		Security:    bearerAuth,
	}, func(ctx context.Context, in *backfillNodeIPsInput) (*backfillNodeIPsOutput, error) {
		if !in.Confirmed {
			return nil, huma.Error400BadRequest("backfilling node IPs", errBackfillNotConfirmed)
		}

		changes, err := b.State.BackfillNodeIPs()
		if err != nil {
			return nil, huma.Error500InternalServerError("backfilling node IPs", err)
		}

		out := &backfillNodeIPsOutput{}
		out.Body.Changes = changes

		if out.Body.Changes == nil {
			out.Body.Changes = []string{}
		}

		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "debugCreateNode",
		Method:      http.MethodPost,
		Path:        "/api/v1/debug/node",
		Summary:     "Debug create node",
		Tags:        []string{"Nodes"},
		Security:    bearerAuth,
	}, func(ctx context.Context, in *debugCreateNodeInput) (*nodeOutput, error) {
		user, err := b.State.GetUserByName(in.Body.User)
		if err != nil {
			return nil, mapError("looking up user", err)
		}

		routes, err := util.StringToIPPrefix(in.Body.Routes)
		if err != nil {
			return nil, huma.Error400BadRequest("parsing routes", err)
		}

		registrationID, err := types.AuthIDFromString(in.Body.Key)
		if err != nil {
			return nil, huma.Error400BadRequest("debug creating node", err)
		}

		regData := &types.RegistrationData{
			NodeKey:    key.NewNode().Public(),
			MachineKey: key.NewMachine().Public(),
			Hostname:   in.Body.Name,
			Expiry:     &time.Time{}, // zero time, not nil, to keep proto JSON round-trip semantics
		}

		authRegReq := types.NewRegisterAuthRequest(regData)
		b.State.SetAuthCacheEntry(registrationID, authRegReq)

		// Synthetic echo; the real node is created later via the auth path
		// from the cached registration data.
		echoNode := types.Node{
			NodeKey:    regData.NodeKey,
			MachineKey: regData.MachineKey,
			Hostname:   regData.Hostname,
			User:       user,
			Expiry:     &time.Time{},
			LastSeen:   &time.Time{},
			Hostinfo: &tailcfg.Hostinfo{
				Hostname:    in.Body.Name,
				OS:          "TestOS",
				RoutableIPs: routes,
			},
		}

		out := &nodeOutput{}
		out.Body.Node = nodeFromView(echoNode.View())

		return out, nil
	})
}

// nodeFromView builds the Node response from a NodeView, reading through the
// view accessors. SubnetRoutes is left empty; callers that serve routes set it
// explicitly.
func nodeFromView(view types.NodeView) Node {
	n := Node{
		ID:              view.StringID(),
		MachineKey:      view.MachineKey().String(),
		NodeKey:         view.NodeKey().String(),
		DiscoKey:        view.DiscoKey().String(),
		IPAddresses:     nonNilStrings(view.IPsAsString()),
		Name:            view.Hostname(),
		CreatedAt:       view.CreatedAt(),
		RegisterMethod:  registerMethodEnum(view.RegisterMethod()),
		GivenName:       view.GivenName(),
		Online:          view.IsOnline().Valid() && view.IsOnline().Get(),
		ApprovedRoutes:  nonNilStrings(util.PrefixesToString(view.ApprovedRoutes().AsSlice())),
		AvailableRoutes: nonNilStrings(util.PrefixesToString(view.AnnouncedRoutes())),
		SubnetRoutes:    []string{},
		Tags:            nonNilStrings(view.Tags().AsSlice()),
	}

	if view.User().Valid() {
		user := userFromView(view.User())
		n.User = &user
	}

	if view.AuthKey().Valid() {
		n.PreAuthKey = nodePreAuthKeyFromView(view.AuthKey())
	}

	if view.LastSeen().Valid() {
		ls := view.LastSeen().Get()
		n.LastSeen = &ls
	}

	if view.Expiry().Valid() {
		exp := view.Expiry().Get()
		n.Expiry = &exp
	}

	return n
}

// nodePreAuthKeyFromView builds the embedded NodePreAuthKey, masking the key to
// its prefix (legacy plaintext keys are shown in full).
func nodePreAuthKeyFromView(key types.PreAuthKeyView) *NodePreAuthKey {
	pak := &NodePreAuthKey{
		ID:        formatID(key.ID()),
		Key:       maskedPreAuthKey(key),
		Reusable:  key.Reusable(),
		Ephemeral: key.Ephemeral(),
		Used:      key.Used(),
		AclTags:   nonNilStrings(key.Tags().AsSlice()),
	}

	if key.User().Valid() {
		user := userFromView(key.User())
		pak.User = &user
	}

	if key.Expiration().Valid() {
		exp := key.Expiration().Get()
		pak.Expiration = &exp
	}

	if key.CreatedAt().Valid() {
		created := key.CreatedAt().Get()
		pak.CreatedAt = &created
	}

	return pak
}

// registerMethodEnum maps the stored register method onto the v1 enum string,
// defaulting to REGISTER_METHOD_UNSPECIFIED for unknown values.
func registerMethodEnum(method string) string {
	if enum, ok := registerMethodToV1Enum[method]; ok {
		return enum
	}

	return "REGISTER_METHOD_UNSPECIFIED"
}

func nonNilStrings(s []string) []string {
	if s == nil {
		return []string{}
	}

	return s
}

// cmpNodeID orders two decimal node-ID strings numerically, matching the gRPC
// handler's ascending-ID ordering.
func cmpNodeID(a, b string) int {
	ai, _ := strconv.ParseUint(a, 10, 64)
	bi, _ := strconv.ParseUint(b, 10, 64)

	switch {
	case ai < bi:
		return -1
	case ai > bi:
		return 1
	default:
		return 0
	}
}

func parseNodeID(s string) (types.NodeID, error) {
	id, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0, huma.Error400BadRequest(
			"type mismatch, parameter: node_id, error: " + err.Error(),
		)
	}

	return types.NodeID(id), nil
}
