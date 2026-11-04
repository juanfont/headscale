package apiv2

import (
	"cmp"
	"context"
	"encoding/json"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/juanfont/headscale/hscontrol/scope"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/rs/zerolog/log"
	"tailscale.com/net/tsaddr"
	"tailscale.com/tailcfg"
)

func init() {
	registrations = append(registrations, registerDevices)
}

// Device is the Tailscale device response. Headscale nodes map onto it; fields
// Headscale does not track are left out, apart from UpdateAvailable. The route
// slices and the host detail are only populated for the fields=all variant,
// matching Tailscale.
type Device struct {
	Addresses         []string   `json:"addresses"         nullable:"false"`
	Name              string     `json:"name"`
	ID                string     `json:"id"`
	NodeID            string     `json:"nodeId"`
	Authorized        bool       `json:"authorized"`
	User              string     `json:"user"`
	Tags              []string   `json:"tags"              nullable:"false"`
	KeyExpiryDisabled bool       `json:"keyExpiryDisabled"`
	Created           time.Time  `json:"created"`
	Expires           *time.Time `json:"expires,omitempty"`
	Hostname          string     `json:"hostname"`
	IsEphemeral       bool       `json:"isEphemeral"`
	// ConnectedToControl and LastSeen follow what Tailscale sends, not its SDK's
	// comment: every connected device has both.
	ConnectedToControl bool       `json:"connectedToControl"`
	LastSeen           *time.Time `json:"lastSeen,omitempty"`
	MachineKey         string     `json:"machineKey"`
	NodeKey            string     `json:"nodeKey"`
	OS                 string     `json:"os"`
	ClientVersion      string     `json:"clientVersion"`
	UpdateAvailable    bool       `json:"updateAvailable"`

	BlocksIncomingConnections bool `json:"blocksIncomingConnections"`

	// OAuthClientID names the auth key the device joined with. For a key a
	// token made, Tailscale names the token's OAuth client, which headscale
	// does not record, so it is left out.
	OAuthClientID string `json:"oauthClientId,omitempty"`

	// Populated only when fields=all is requested, then as [] when empty.
	AdvertisedRoutes []string `json:"advertisedRoutes,omitzero"`
	EnabledRoutes    []string `json:"enabledRoutes,omitzero"`

	SSHEnabled         *bool               `json:"sshEnabled,omitempty"`
	Distro             *Distro             `json:"distro,omitempty"`
	ClientConnectivity *ClientConnectivity `json:"clientConnectivity,omitempty"`
}

// Distro is the Linux distribution a device reports.
type Distro struct {
	Name     string `json:"name"`
	Version  string `json:"version"`
	CodeName string `json:"codeName"`
}

// ClientConnectivity is how a device reaches the network, from what it reports.
// Latency stays empty: headscale drops a client's DERP latency on arrival.
type ClientConnectivity struct {
	Endpoints             []string       `json:"endpoints"             nullable:"false"`
	MappingVariesByDestIP bool           `json:"mappingVariesByDestIP"`
	Latency               map[string]any `json:"latency"               nullable:"false"`
	ClientSupports        ClientSupports `json:"clientSupports"`
}

// ClientSupports is what a device's network allows. HairPinning stays null:
// clients no longer report it.
type ClientSupports struct {
	HairPinning *bool `json:"hairPinning"`
	IPv6        bool  `json:"ipv6"`
	PCP         bool  `json:"pcp"`
	PMP         bool  `json:"pmp"`
	UDP         bool  `json:"udp"`
	UPnP        bool  `json:"upnp"`
}

// DeviceRoutes is the GET /device/{id}/routes response: what the node announces
// vs which of those are approved (Tailscale calls approved routes "enabled").
type DeviceRoutes struct {
	Advertised []string `json:"advertisedRoutes" nullable:"false"`
	Enabled    []string `json:"enabledRoutes"    nullable:"false"`
}

// DevicePostureAttributes is the GET /device/{id}/attributes response. Of
// Tailscale's attributes, headscale sets only ip:publicAddress, and like
// Tailscale leaves expiries out when no attribute has one.
type DevicePostureAttributes struct {
	Attributes map[string]any       `json:"attributes"         nullable:"false"`
	Expiries   map[string]time.Time `json:"expiries,omitempty"`
}

// DeviceUpdateStatus is the GET /device/{id}/update-status response.
type DeviceUpdateStatus struct {
	Status string `enum:"updating,not-updating" json:"status"`
}

// Request bodies match the Tailscale SDK wire shapes and, like Tailscale's,
// ignore properties they do not define.
type (
	setAuthorizedRequest struct {
		_ struct{} `additionalProperties:"true"`

		Authorized bool `json:"authorized"`
	}
	setNameRequest struct {
		_ struct{} `additionalProperties:"true"`

		Name string `json:"name"`
	}
	// setTagsRequest.Tags is intentionally not nullable:"false": the SDK sends
	// "tags":null for "make untagged", which the handler accepts as a no-op
	// rather than failing to decode (Headscale cannot untag a node).
	setTagsRequest struct {
		_ struct{} `additionalProperties:"true"`

		Tags []string `json:"tags"`
	}
	setKeyRequest struct {
		_ struct{} `additionalProperties:"true"`

		KeyExpiryDisabled bool `json:"keyExpiryDisabled"`
	}
	setSubnetRoutesRequest struct {
		_ struct{} `additionalProperties:"true"`

		Routes []string `json:"routes" nullable:"false"`
	}
)

type (
	deviceByIDInput struct {
		DeviceID string `doc:"Device id (the decimal node id)." path:"id"`
		Fields   string `doc:"Set to \"all\" for route fields." query:"fields"`
	}
	deviceAttributesInput struct {
		DeviceID string `doc:"Device id (the decimal node id)." path:"id"`
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
	deviceIDInput struct {
		DeviceID string `path:"id"`
	}

	deviceOutput                  struct{ Body Device }
	deviceRoutesOutput            struct{ Body DeviceRoutes }
	devicePostureAttributesOutput struct{ Body DevicePostureAttributes }
	listDevicesOutput             struct {
		Body struct {
			Devices []Device `json:"devices" nullable:"false"`
		}
	}
	emptyOutput struct{ Body struct{} }

	deviceUpdateStatusOutput struct{ Body DeviceUpdateStatus }
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

		return &deviceOutput{Body: deviceFromView(node, in.Fields == "all", b.Cfg.BaseDomain)}, nil
	})

	huma.Register(api, requireScope(huma.Operation{
		OperationID: "getDevicePostureAttributes",
		Method:      http.MethodGet,
		Path:        "/api/v2/device/{id}/attributes",
		Summary:     "Get device posture attributes",
		Tags:        deviceTags,
		Security:    security,
		Errors:      []int{http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound},
	}, scope.DevicesPostureAttributesRead), func(ctx context.Context, in *deviceAttributesInput) (*devicePostureAttributesOutput, error) {
		node, err := lookupNode(b, in.DeviceID)
		if err != nil {
			return nil, err
		}

		return &devicePostureAttributesOutput{Body: devicePostureAttributesFromView(node)}, nil
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
			out.Body.Devices = append(out.Body.Devices, deviceFromView(node, allFields, b.Cfg.BaseDomain))
		}

		// The NodeStore holds no order, and Tailscale lists devices by name.
		slices.SortFunc(out.Body.Devices, func(a, b Device) int {
			return cmp.Compare(a.Name, b.Name)
		})

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

		changes, err := b.State.DeleteNode(node)
		b.Change(changes...)

		if err != nil {
			return nil, mapError("deleting device", err)
		}

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
		MaxBodyBytes:  maxBodyBytes,
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
		MaxBodyBytes:  maxBodyBytes,
		Errors:        []int{http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound},
	}, scope.DevicesCore), func(ctx context.Context, in *setNameInput) (*emptyOutput, error) {
		node, err := lookupNode(b, in.DeviceID)
		if err != nil {
			return nil, err
		}

		_, nodeChange, err := b.State.RenameNode(node.ID(), in.Body.Name)
		b.Change(nodeChange)

		if err != nil {
			return nil, mapError("renaming device", err)
		}

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
		MaxBodyBytes:  maxBodyBytes,
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
		// tag exists in policy. SetNodeTags replaces the set, so the token must
		// also own every tag the device holds; as on Tailscale SaaS, the refusal
		// then names them all.
		if tokenTags, isOAuth := principalTags(ctx); isOAuth {
			current := node.Tags().AsSlice()
			if len(unownedTags(b, current, tokenTags)) > 0 {
				return nil, tagsRefused("cannot remove current tags: ", current)
			}

			if refused := unownedTags(b, in.Body.Tags, tokenTags); len(refused) > 0 {
				return nil, tagsRefused("", refused)
			}
		}

		_, nodeChange, err := b.State.SetNodeTags(node.ID(), in.Body.Tags)
		b.Change(nodeChange)

		if err != nil {
			return nil, mapError("setting device tags", err)
		}

		return &emptyOutput{}, nil
	})

	huma.Register(api, requireScope(huma.Operation{
		OperationID:   "expireDevice",
		Method:        http.MethodPost,
		Path:          "/api/v2/device/{id}/expire",
		Summary:       "Expire a device's key",
		Tags:          deviceTags,
		Security:      security,
		DefaultStatus: http.StatusOK,
		Errors:        []int{http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound},
	}, scope.DevicesCore), func(ctx context.Context, in *deviceByIDInput) (*emptyOutput, error) {
		node, err := lookupNode(b, in.DeviceID)
		if err != nil {
			return nil, err
		}

		now := time.Now()

		_, nodeChange, err := b.State.SetNodeExpiry(node.ID(), &now)
		b.Change(nodeChange)

		if err != nil {
			return nil, mapError("expiring device", err)
		}

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
		MaxBodyBytes:  maxBodyBytes,
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
		b.Change(nodeChange)

		if err != nil {
			return nil, mapError("setting device key expiry", err)
		}

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
		MaxBodyBytes:  maxBodyBytes,
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
		b.Change(nodeChange)

		if err != nil {
			return nil, mapError("setting device routes", err)
		}

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

	huma.Register(api, requireScope(huma.Operation{
		OperationID:   "updateDeviceClient",
		Method:        http.MethodPost,
		Path:          "/api/v2/device/{id}/update-client",
		Summary:       "Update a device's Tailscale client",
		Description:   "Asks a connected device over c2n to update its Tailscale client. A device that does not allow remote updates, is not connected, or refuses is not found.",
		Tags:          deviceTags,
		Security:      security,
		DefaultStatus: http.StatusOK,
		Errors: []int{
			http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound,
			http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout,
		},
	}, scope.DevicesCore), func(ctx context.Context, in *deviceIDInput) (*emptyOutput, error) {
		node, err := lookupNode(b, in.DeviceID)
		if err != nil {
			return nil, err
		}

		// Tailscale answers every device it will not update with the same 404.
		hi := node.Hostinfo()
		if !hi.Valid() || !hi.AllowsUpdate() || !b.Connected(node.ID()) {
			return nil, huma.Error404NotFound("not found")
		}

		res, err := sendC2N(ctx, b, node.ID(), "/update")
		if err != nil {
			return nil, err
		}
		defer res.Body.Close()

		var update tailcfg.C2NUpdateResponse

		err = json.NewDecoder(res.Body).Decode(&update)
		if err != nil {
			return nil, huma.Error502BadGateway("decoding client update response", err)
		}

		if !update.Started {
			log.Info().EmbedObject(node).Str("reason", update.Err).Msg("node refused client update")

			return nil, huma.Error404NotFound("not found")
		}

		b.State.ClientUpdateStarted(node.ID(), hi.IPNVersion())

		return &emptyOutput{}, nil
	})

	huma.Register(api, requireScope(huma.Operation{
		OperationID: "getDeviceUpdateStatus",
		Method:      http.MethodGet,
		Path:        "/api/v2/device/{id}/update-status",
		Summary:     "Get a device's client update status",
		Description: "updating from a started client update until the device runs a new version, else not-updating.",
		Tags:        deviceTags,
		Security:    security,
		Errors:      []int{http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound},
	}, scope.DevicesCoreRead), func(_ context.Context, in *deviceIDInput) (*deviceUpdateStatusOutput, error) {
		node, err := lookupNode(b, in.DeviceID)
		if err != nil {
			return nil, err
		}

		var version string
		if hi := node.Hostinfo(); hi.Valid() {
			version = hi.IPNVersion()
		}

		status := "not-updating"
		if b.State.ClientUpdating(node.ID(), version) {
			status = "updating"
		}

		return &deviceUpdateStatusOutput{Body: DeviceUpdateStatus{Status: status}}, nil
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
		return types.NodeView{}, huma.Error404NotFound("no manageable device matching this ID found")
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

		err = util.CheckRouteMasked(prefix)
		if err != nil {
			return nil, huma.Error400BadRequest(prefix.String() + " " + err.Error())
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
func deviceFromView(view types.NodeView, allFields bool, baseDomain string) Device {
	id := view.StringID()

	// Tailscale names a device by its MagicDNS FQDN, without the root dot.
	name := view.GivenName()
	if baseDomain != "" {
		name += "." + baseDomain
	}

	d := Device{
		Addresses:          emptyIfNil(view.IPsAsString()),
		Name:               name,
		ID:                 id,
		NodeID:             id,
		Authorized:         true, // Headscale has no post-registration de-auth state.
		User:               deviceUser(view),
		Tags:               emptyIfNil(view.Tags().AsSlice()),
		KeyExpiryDisabled:  !view.Expiry().Valid(),
		Created:            view.CreatedAt(),
		Hostname:           view.Hostname(),
		IsEphemeral:        view.IsEphemeral(),
		ConnectedToControl: view.IsOnline().Valid() && view.IsOnline().Get(),
		MachineKey:         view.MachineKey().String(),
		NodeKey:            view.NodeKey().String(),
		OS:                 hostinfoOS(view),
		ClientVersion:      hostinfoVersion(view),
	}

	if key := view.AuthKey(); key.Valid() && !key.CreatedByToken() {
		d.OAuthClientID = strconv.FormatUint(key.ID(), util.Base10)
	}

	if view.Expiry().Valid() {
		exp := view.Expiry().Get()
		d.Expires = &exp
	}

	// The stored time does not move while a client idles. A connected device
	// reads now, so a "not seen for a while" script cannot pick a live device.
	switch {
	case d.ConnectedToControl:
		now := time.Now().UTC()
		d.LastSeen = &now
	case view.LastSeen().Valid():
		ls := view.LastSeen().Get()
		d.LastSeen = &ls
	}

	hi := view.Hostinfo()
	d.BlocksIncomingConnections = hi.Valid() && hi.ShieldsUp()

	if allFields {
		d.AdvertisedRoutes = emptyIfNil(util.PrefixesToString(view.AnnouncedRoutes()))
		d.EnabledRoutes = emptyIfNil(util.PrefixesToString(view.ApprovedRoutes().AsSlice()))

		sshEnabled := hi.Valid() && hi.TailscaleSSHEnabled()
		d.SSHEnabled = &sshEnabled
		d.Distro = &Distro{}
		d.ClientConnectivity = &ClientConnectivity{
			Endpoints: make([]string, 0, view.Endpoints().Len()),
			Latency:   map[string]any{},
		}

		for _, ep := range view.Endpoints().All() {
			d.ClientConnectivity.Endpoints = append(d.ClientConnectivity.Endpoints, ep.String())
		}

		if hi.Valid() {
			d.Distro = &Distro{Name: hi.Distro(), Version: hi.DistroVersion(), CodeName: hi.DistroCodeName()}

			if ni := hi.NetInfo(); ni.Valid() {
				d.ClientConnectivity.MappingVariesByDestIP = ni.MappingVariesByDestIP().EqualBool(true)
				d.ClientConnectivity.ClientSupports = ClientSupports{
					IPv6: ni.WorkingIPv6().EqualBool(true),
					PCP:  ni.PCP().EqualBool(true),
					PMP:  ni.PMP().EqualBool(true),
					UDP:  ni.WorkingUDP().EqualBool(true),
					UPnP: ni.UPnP().EqualBool(true),
				}
			}
		}
	}

	return d
}

func devicePostureAttributesFromView(view types.NodeView) DevicePostureAttributes {
	attributes := make(map[string]any)
	if addr := view.LastControlAddress(); addr.Valid() {
		attributes["ip:publicAddress"] = addr.Get().String()
	}

	return DevicePostureAttributes{Attributes: attributes}
}

func routesFromView(view types.NodeView) DeviceRoutes {
	return DeviceRoutes{
		Advertised: emptyIfNil(util.PrefixesToString(view.AnnouncedRoutes())),
		Enabled:    emptyIfNil(util.PrefixesToString(view.ApprovedRoutes().AsSlice())),
	}
}

// deviceUser is the owning login. A tagged device, owned by its tags, shows
// the login that made the key it joined with, as Tailscale does: nothing when
// a token made that key.
func deviceUser(view types.NodeView) string {
	if view.IsTagged() {
		if key := view.AuthKey(); key.Valid() && key.User().Valid() {
			return key.User().Username()
		}

		return ""
	}

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
