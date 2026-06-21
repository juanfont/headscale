package apiv2

import (
	"context"
	"net/http"
	"net/netip"
	"slices"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/juanfont/headscale/hscontrol/scope"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"tailscale.com/net/tsaddr"
)

func init() {
	registrations = append(registrations, registerDevices)
}

// Device is the Tailscale device response. Headscale nodes map onto it; fields
// Headscale does not track are emitted as their zero value. The route slices
// are only populated for the fields=all variant, matching Tailscale.
type Device struct {
	Addresses         []string   `json:"addresses"          nullable:"false"`
	Name              string     `json:"name"`
	ID                string     `json:"id"`
	NodeID            string     `json:"nodeId"`
	Authorized        bool       `json:"authorized"`
	User              string     `json:"user"`
	Tags              []string   `json:"tags"               nullable:"false"`
	KeyExpiryDisabled bool       `json:"keyExpiryDisabled"`
	Created           time.Time  `json:"created"`
	Expires           *time.Time `json:"expires,omitempty"`
	Hostname          string     `json:"hostname"`
	IsEphemeral       bool       `json:"isEphemeral"`
	LastSeen          *time.Time `json:"lastSeen,omitempty"`
	MachineKey        string     `json:"machineKey"`
	NodeKey           string     `json:"nodeKey"`
	OS                string     `json:"os"`
	ClientVersion     string     `json:"clientVersion"`
	UpdateAvailable   bool       `json:"updateAvailable"`

	// Populated only when fields=all is requested.
	AdvertisedRoutes []string `json:"advertisedRoutes,omitempty"`
	EnabledRoutes    []string `json:"enabledRoutes,omitempty"`
}

// DeviceRoutes is the GET /device/{id}/routes response: what the node announces
// vs which of those are approved (Tailscale calls approved routes "enabled").
type DeviceRoutes struct {
	Advertised []string `json:"advertisedRoutes" nullable:"false"`
	Enabled    []string `json:"enabledRoutes"    nullable:"false"`
}

// Request bodies match the Tailscale SDK wire shapes.
type (
	setAuthorizedRequest struct {
		Authorized bool `json:"authorized"`
	}
	setNameRequest struct {
		Name string `json:"name"`
	}
	// setTagsRequest.Tags is intentionally not nullable:"false": the SDK sends
	// "tags":null for "make untagged", which the handler accepts as a no-op
	// rather than failing to decode (Headscale cannot untag a node).
	setTagsRequest struct {
		Tags []string `json:"tags"`
	}
	setKeyRequest struct {
		KeyExpiryDisabled bool `json:"keyExpiryDisabled"`
	}
	setSubnetRoutesRequest struct {
		Routes []string `json:"routes" nullable:"false"`
	}
)

type (
	deviceByIDInput struct {
		DeviceID string `doc:"Device id (the decimal node id)." path:"id"`
		Fields   string `doc:"Set to \"all\" for route fields." query:"fields"`
	}
	listDevicesInput struct {
		Tailnet string `doc:"Tailnet; must be \"-\"." path:"tailnet"`
		Fields  string `query:"fields"`
	}
	setAuthorizedInput struct {
		DeviceID string `path:"id"`
		Body     setAuthorizedRequest
	}
	setNameInput struct {
		DeviceID string `path:"id"`
		Body     setNameRequest
	}
	setTagsInput struct {
		DeviceID string `path:"id"`
		Body     setTagsRequest
	}
	setKeyInput struct {
		DeviceID string `path:"id"`
		Body     setKeyRequest
	}
	setSubnetRoutesInput struct {
		DeviceID string `path:"id"`
		Body     setSubnetRoutesRequest
	}

	deviceOutput       struct{ Body Device }
	deviceRoutesOutput struct{ Body DeviceRoutes }
	listDevicesOutput  struct {
		Body struct {
			Devices []Device `json:"devices" nullable:"false"`
		}
	}
	emptyOutput struct{ Body struct{} }
)

func registerDevices(api huma.API, b Backend) {
	deviceTags := []string{"Devices", "Tailscale compat"}

	huma.Register(api, requireScope(huma.Operation{
		OperationID: "getDevice",
		Method:      http.MethodGet,
		Path:        "/api/v2/device/{id}",
		Summary:     "Get a device",
		Tags:        deviceTags,
		Security:    security,
		Errors:      []int{http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound},
	}, scope.DevicesCoreRead), func(ctx context.Context, in *deviceByIDInput) (*deviceOutput, error) {
		node, err := lookupNode(b, in.DeviceID)
		if err != nil {
			return nil, err
		}

		return &deviceOutput{Body: deviceFromView(node, in.Fields == "all")}, nil
	})

	huma.Register(api, requireScope(huma.Operation{
		OperationID: "listDevices",
		Method:      http.MethodGet,
		Path:        "/api/v2/tailnet/{tailnet}/devices",
		Summary:     "List devices",
		Tags:        deviceTags,
		Security:    security,
		Errors:      []int{http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound},
	}, scope.DevicesCoreRead), func(ctx context.Context, in *listDevicesInput) (*listDevicesOutput, error) {
		err := requireDefaultTailnet(in.Tailnet)
		if err != nil {
			return nil, err
		}

		nodes := b.State.ListNodes()
		allFields := in.Fields == "all"

		out := &listDevicesOutput{}
		out.Body.Devices = make([]Device, 0, nodes.Len())

		for _, node := range nodes.All() {
			out.Body.Devices = append(out.Body.Devices, deviceFromView(node, allFields))
		}

		return out, nil
	})

	huma.Register(api, requireScope(huma.Operation{
		OperationID:   "deleteDevice",
		Method:        http.MethodDelete,
		Path:          "/api/v2/device/{id}",
		Summary:       "Delete a device",
		Tags:          deviceTags,
		Security:      security,
		DefaultStatus: http.StatusOK,
		Errors:        []int{http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound},
	}, scope.DevicesCore), func(ctx context.Context, in *deviceByIDInput) (*emptyOutput, error) {
		node, err := lookupNode(b, in.DeviceID)
		if err != nil {
			return nil, err
		}

		nodeChange, err := b.State.DeleteNode(node)
		if err != nil {
			return nil, mapError("deleting device", err)
		}

		b.Change(nodeChange)

		return &emptyOutput{}, nil
	})

	huma.Register(api, requireScope(huma.Operation{
		OperationID:   "authorizeDevice",
		Method:        http.MethodPost,
		Path:          "/api/v2/device/{id}/authorized",
		Summary:       "Authorize a device",
		Tags:          deviceTags,
		Security:      security,
		DefaultStatus: http.StatusOK,
		Errors:        []int{http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound},
	}, scope.DevicesCore), func(ctx context.Context, in *setAuthorizedInput) (*emptyOutput, error) {
		_, err := lookupNode(b, in.DeviceID)
		if err != nil {
			return nil, err
		}

		// Headscale nodes are authorized the moment they register; there is no
		// de-authorize state. Accept authorized=true as a no-op; reject false so
		// callers are not misled into thinking the device is fenced off.
		if !in.Body.Authorized {
			return nil, huma.Error400BadRequest(
				"Headscale does not support de-authorizing a device; delete or expire it instead",
			)
		}

		return &emptyOutput{}, nil
	})

	huma.Register(api, requireScope(huma.Operation{
		OperationID:   "setDeviceName",
		Method:        http.MethodPost,
		Path:          "/api/v2/device/{id}/name",
		Summary:       "Set a device's name",
		Tags:          deviceTags,
		Security:      security,
		DefaultStatus: http.StatusOK,
		Errors:        []int{http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound},
	}, scope.DevicesCore), func(ctx context.Context, in *setNameInput) (*emptyOutput, error) {
		node, err := lookupNode(b, in.DeviceID)
		if err != nil {
			return nil, err
		}

		_, nodeChange, err := b.State.RenameNode(node.ID(), in.Body.Name)
		if err != nil {
			return nil, mapError("renaming device", err)
		}

		b.Change(nodeChange)

		return &emptyOutput{}, nil
	})

	huma.Register(api, requireScope(huma.Operation{
		OperationID:   "setDeviceTags",
		Method:        http.MethodPost,
		Path:          "/api/v2/device/{id}/tags",
		Summary:       "Set a device's tags",
		Tags:          deviceTags,
		Security:      security,
		DefaultStatus: http.StatusOK,
		Errors:        []int{http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound},
	}, scope.DevicesCore), func(ctx context.Context, in *setTagsInput) (*emptyOutput, error) {
		node, err := lookupNode(b, in.DeviceID)
		if err != nil {
			return nil, err
		}

		// Headscale cannot make a node untagged (tags-as-identity is one-way), so
		// an empty/null tag set is accepted as a no-op rather than rejected. This
		// keeps tooling lifecycles such as Terraform destroy working; the SDK
		// sends "tags":null for "make untagged".
		if len(in.Body.Tags) == 0 {
			return &emptyOutput{}, nil
		}

		// An OAuth token may only assign tags within its grant (held directly or
		// owned by a held tag per policy); an admin API key is unrestricted. The
		// devices:core scope alone must not let a token stamp an arbitrary policy
		// tag (e.g. tag:prod) onto any node. SetNodeTags still enforces that each
		// tag exists in policy.
		if tokenTags, isOAuth := principalTags(ctx); isOAuth {
			for _, tag := range in.Body.Tags {
				if !b.State.TagOwnedByTags(tag, tokenTags) {
					return nil, huma.Error403Forbidden("token may not assign tag " + tag)
				}
			}
		}

		_, nodeChange, err := b.State.SetNodeTags(node.ID(), in.Body.Tags)
		if err != nil {
			return nil, mapError("setting device tags", err)
		}

		b.Change(nodeChange)

		return &emptyOutput{}, nil
	})

	huma.Register(api, requireScope(huma.Operation{
		OperationID:   "setDeviceKey",
		Method:        http.MethodPost,
		Path:          "/api/v2/device/{id}/key",
		Summary:       "Set a device's key settings",
		Tags:          deviceTags,
		Security:      security,
		DefaultStatus: http.StatusOK,
		Errors:        []int{http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound},
	}, scope.DevicesCore), func(ctx context.Context, in *setKeyInput) (*emptyOutput, error) {
		node, err := lookupNode(b, in.DeviceID)
		if err != nil {
			return nil, err
		}

		// Only disabling expiry maps cleanly (expiry=nil never expires).
		// Re-enabling has no target expiry in the Tailscale request and Headscale
		// stores no original, so it is accepted as a no-op (keeps Terraform
		// destroy working) rather than guessing a lifetime.
		if !in.Body.KeyExpiryDisabled {
			return &emptyOutput{}, nil
		}

		_, nodeChange, err := b.State.SetNodeExpiry(node.ID(), nil)
		if err != nil {
			return nil, mapError("setting device key expiry", err)
		}

		b.Change(nodeChange)

		return &emptyOutput{}, nil
	})

	huma.Register(api, requireScope(huma.Operation{
		OperationID:   "setDeviceRoutes",
		Method:        http.MethodPost,
		Path:          "/api/v2/device/{id}/routes",
		Summary:       "Set a device's enabled subnet routes",
		Tags:          deviceTags,
		Security:      security,
		DefaultStatus: http.StatusOK,
		Errors:        []int{http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound},
	}, scope.DevicesRoutes), func(ctx context.Context, in *setSubnetRoutesInput) (*deviceRoutesOutput, error) {
		node, err := lookupNode(b, in.DeviceID)
		if err != nil {
			return nil, err
		}

		approved, err := parseRoutes(in.Body.Routes)
		if err != nil {
			return nil, err
		}

		updated, nodeChange, err := b.State.SetApprovedRoutes(node.ID(), approved)
		if err != nil {
			return nil, mapError("setting device routes", err)
		}

		b.Change(nodeChange)

		return &deviceRoutesOutput{Body: routesFromView(updated)}, nil
	})

	huma.Register(api, requireScope(huma.Operation{
		OperationID: "getDeviceRoutes",
		Method:      http.MethodGet,
		Path:        "/api/v2/device/{id}/routes",
		Summary:     "Get a device's subnet routes",
		Tags:        deviceTags,
		Security:    security,
		Errors:      []int{http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound},
	}, scope.DevicesRoutesRead), func(ctx context.Context, in *deviceByIDInput) (*deviceRoutesOutput, error) {
		node, err := lookupNode(b, in.DeviceID)
		if err != nil {
			return nil, err
		}

		return &deviceRoutesOutput{Body: routesFromView(node)}, nil
	})
}

// lookupNode resolves a device id to its NodeView, mapping a malformed or
// unknown id to 404 (the Tailscale SDK keys IsNotFound off the status code).
func lookupNode(b Backend, rawID string) (types.NodeView, error) {
	nodeID, err := parseNodeID(rawID)
	if err != nil {
		return types.NodeView{}, err
	}

	node, ok := b.State.GetNodeByID(nodeID)
	if !ok {
		return types.NodeView{}, huma.Error404NotFound("device not found")
	}

	return node, nil
}

// parseRoutes parses the enabled-route strings, expanding an exit route to both
// families (else the node is not annotated as an exit node), then sorts/dedups.
func parseRoutes(routes []string) ([]netip.Prefix, error) {
	var approved []netip.Prefix

	for _, route := range routes {
		prefix, err := netip.ParsePrefix(route)
		if err != nil {
			return nil, huma.Error400BadRequest("parsing route", err)
		}

		if prefix == tsaddr.AllIPv4() || prefix == tsaddr.AllIPv6() {
			approved = append(approved, tsaddr.AllIPv4(), tsaddr.AllIPv6())
		} else {
			approved = append(approved, prefix)
		}
	}

	slices.SortFunc(approved, netip.Prefix.Compare)

	return slices.Compact(approved), nil
}

// deviceFromView maps a Headscale node onto the Tailscale Device, reading
// through the [types.NodeView] accessors. allFields gates the route slices,
// which Tailscale only returns for fields=all.
func deviceFromView(view types.NodeView, allFields bool) Device {
	id := view.StringID()

	d := Device{
		Addresses:         emptyIfNil(view.IPsAsString()),
		Name:              view.GivenName(),
		ID:                id,
		NodeID:            id,
		Authorized:        true, // Headscale has no post-registration de-auth state.
		User:              deviceUser(view),
		Tags:              emptyIfNil(view.Tags().AsSlice()),
		KeyExpiryDisabled: !view.Expiry().Valid(),
		Created:           view.CreatedAt(),
		Hostname:          view.Hostname(),
		IsEphemeral:       view.IsEphemeral(),
		MachineKey:        view.MachineKey().String(),
		NodeKey:           view.NodeKey().String(),
		OS:                hostinfoOS(view),
		ClientVersion:     hostinfoVersion(view),
	}

	if view.Expiry().Valid() {
		exp := view.Expiry().Get()
		d.Expires = &exp
	}

	// LastSeen is reported only when the device is offline, matching tailcfg.
	if view.LastSeen().Valid() && view.IsOnline().Valid() && !view.IsOnline().Get() {
		ls := view.LastSeen().Get()
		d.LastSeen = &ls
	}

	if allFields {
		d.AdvertisedRoutes = emptyIfNil(util.PrefixesToString(view.AnnouncedRoutes()))
		d.EnabledRoutes = emptyIfNil(util.PrefixesToString(view.ApprovedRoutes().AsSlice()))
	}

	return d
}

func routesFromView(view types.NodeView) DeviceRoutes {
	return DeviceRoutes{
		Advertised: emptyIfNil(util.PrefixesToString(view.AnnouncedRoutes())),
		Enabled:    emptyIfNil(util.PrefixesToString(view.ApprovedRoutes().AsSlice())),
	}
}

// deviceUser is the owning login. [types.NodeView.Owner] already resolves the
// tags-as-identity rule: tagged nodes present the special TaggedDevices user,
// user-owned nodes present their login, orphaned nodes present nothing.
func deviceUser(view types.NodeView) string {
	owner := view.Owner()
	if owner.Valid() {
		return owner.Username()
	}

	return ""
}

// hostinfoOS / hostinfoVersion read Hostinfo fields, returning "" when the node
// has not reported Hostinfo yet.
func hostinfoOS(view types.NodeView) string {
	if hi := view.Hostinfo(); hi.Valid() {
		return hi.OS()
	}

	return ""
}

func hostinfoVersion(view types.NodeView) string {
	if hi := view.Hostinfo(); hi.Valid() {
		return hi.IPNVersion()
	}

	return ""
}
