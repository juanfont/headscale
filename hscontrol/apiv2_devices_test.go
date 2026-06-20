package hscontrol

import (
	"encoding/json"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/danielgtaylor/huma/v2/humatest"
	apiv2 "github.com/juanfont/headscale/hscontrol/api/v2"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// registerAPIV2 builds a humatest API with the v2 operations registered over the
// app's state, with no auth middleware (the contract tests exercise wire shapes;
// auth is covered by TestAPIv2). The full Backend (Change + Cfg) is wired so the
// device/acl write handlers work.
func registerAPIV2(t *testing.T, app *Headscale) humatest.TestAPI {
	t.Helper()

	_, api := humatest.New(t, apiv2.Config())
	apiv2.Register(api, apiv2.Backend{State: app.state, Change: app.Change, Cfg: app.cfg})

	return api
}

// deviceTestEnv is one seeded, registered, user-owned node plus the v2 API.
type deviceTestEnv struct {
	app      *Headscale
	api      humatest.TestAPI
	user     *types.User
	nodeID   types.NodeID
	deviceID string
}

// newDeviceTestEnv seeds a registered user-owned node into the NodeStore, with
// tag:ci and tag:prod declared in policy so tagging is permitted.
func newDeviceTestEnv(t *testing.T) deviceTestEnv {
	t.Helper()

	app := createTestApp(t)
	user := app.state.CreateUserForTest("dut-user")

	_, err := app.state.SetPolicy([]byte(
		`{"tagOwners":{"tag:ci":["` + user.Name + `@"],"tag:prod":["` + user.Name + `@"]},` +
			`"acls":[{"action":"accept","src":["*"],"dst":["*:*"]}]}`,
	))
	require.NoError(t, err)

	node := app.state.CreateRegisteredNodeForTest(user, "contract-dut")
	node.User = user
	view := app.state.PutNodeInStoreForTest(*node)

	return deviceTestEnv{
		app:      app,
		api:      registerAPIV2(t, app),
		user:     user,
		nodeID:   view.ID(),
		deviceID: strconv.FormatUint(uint64(view.ID()), 10),
	}
}

// srvNode reloads the node from the NodeStore — the server-side source of truth.
func (e deviceTestEnv) srvNode(t *testing.T) types.NodeView {
	t.Helper()

	v, ok := e.app.state.GetNodeByID(e.nodeID)
	require.True(t, ok, "node must exist in the NodeStore")
	require.True(t, v.Valid())

	return v
}

// seedExpiry stamps a future expiry so set-key(disable) is a real transition.
func (e deviceTestEnv) seedExpiry(t *testing.T, at time.Time) {
	t.Helper()

	_, _, err := e.app.state.SetNodeExpiry(e.nodeID, &at)
	require.NoError(t, err)
}

func getDevice(t *testing.T, api humatest.TestAPI, deviceID string) apiv2.Device {
	t.Helper()

	resp := api.Get("/api/v2/device/" + deviceID)
	require.Equalf(t, http.StatusOK, resp.Code, "body: %s", resp.Body)

	var dev apiv2.Device
	require.NoError(t, json.Unmarshal(resp.Body.Bytes(), &dev))

	return dev
}

func getDeviceRoutes(t *testing.T, api humatest.TestAPI, deviceID string) apiv2.DeviceRoutes {
	t.Helper()

	resp := api.Get("/api/v2/device/" + deviceID + "/routes")
	require.Equalf(t, http.StatusOK, resp.Code, "body: %s", resp.Body)

	var routes apiv2.DeviceRoutes
	require.NoError(t, json.Unmarshal(resp.Body.Bytes(), &routes))

	return routes
}

func approvedRouteStrings(nv types.NodeView) []string {
	return util.PrefixesToString(nv.ApprovedRoutes().AsSlice())
}

func TestAPIv2Device_Get(t *testing.T) {
	e := newDeviceTestEnv(t)

	resp := e.api.Get("/api/v2/device/" + e.deviceID + "?fields=all")
	require.Equalf(t, http.StatusOK, resp.Code, "body: %s", resp.Body)

	var dev apiv2.Device
	require.NoError(t, json.Unmarshal(resp.Body.Bytes(), &dev))
	assert.Equal(t, e.deviceID, dev.ID)
	assert.Equal(t, e.deviceID, dev.NodeID)
	assert.Equal(t, "contract-dut", dev.Hostname)
	assert.Equal(t, "contract-dut", dev.Name)
	assert.True(t, dev.Authorized)
	assert.Equal(t, e.user.Username(), dev.User)
	assert.NotNil(t, dev.Tags)
	assert.True(t, dev.KeyExpiryDisabled, "seeded node has no expiry")
	assert.NotEmpty(t, dev.Addresses)

	// Server-side cross-check.
	n := e.srvNode(t)
	assert.Equal(t, n.GivenName(), dev.Name)
	assert.False(t, n.IsTagged())
	assert.True(t, n.User().Valid())
	assert.False(t, n.Expiry().Valid())
	assert.Equal(t, n.IPsAsString(), dev.Addresses)
}

func TestAPIv2Device_Get_UnknownID_404(t *testing.T) {
	e := newDeviceTestEnv(t)

	assert.Equal(t, http.StatusNotFound, e.api.Get("/api/v2/device/999999").Code)
	assert.Equal(t, http.StatusNotFound, e.api.Get("/api/v2/device/not-a-number").Code)
}

func TestAPIv2Device_List(t *testing.T) {
	e := newDeviceTestEnv(t)

	list := func() []apiv2.Device {
		t.Helper()

		resp := e.api.Get("/api/v2/tailnet/-/devices")
		require.Equalf(t, http.StatusOK, resp.Code, "body: %s", resp.Body)

		var out struct {
			Devices []apiv2.Device `json:"devices"`
		}
		require.NoError(t, json.Unmarshal(resp.Body.Bytes(), &out))

		return out.Devices
	}

	assert.True(t, containsDeviceID(list(), e.deviceID))
	assert.Len(t, list(), e.app.state.ListNodes().Len(), "list count == ListNodes")

	// A second node appears; deleting it removes it from both the list and state.
	node2 := e.app.state.CreateRegisteredNodeForTest(e.user, "contract-dut-2")
	node2.User = e.user
	view2 := e.app.state.PutNodeInStoreForTest(*node2)
	id2 := strconv.FormatUint(uint64(view2.ID()), 10)
	assert.True(t, containsDeviceID(list(), id2))

	require.Equal(t, http.StatusOK, e.api.Delete("/api/v2/device/"+id2).Code)
	assert.False(t, containsDeviceID(list(), id2))

	_, ok := e.app.state.GetNodeByID(view2.ID())
	assert.False(t, ok)

	assert.Equal(t, http.StatusNotFound, e.api.Get("/api/v2/tailnet/example.com/devices").Code)
}

func TestAPIv2Device_SetName(t *testing.T) {
	e := newDeviceTestEnv(t)

	require.Equal(t, http.StatusOK,
		e.api.Post("/api/v2/device/"+e.deviceID+"/name", map[string]any{"name": "renamed-dut"}).Code)
	assert.Equal(t, "renamed-dut", getDevice(t, e.api, e.deviceID).Name)
	assert.Equal(t, "renamed-dut", e.srvNode(t).GivenName())

	// Rename again.
	require.Equal(t, http.StatusOK,
		e.api.Post("/api/v2/device/"+e.deviceID+"/name", map[string]any{"name": "renamed-again"}).Code)
	assert.Equal(t, "renamed-again", getDevice(t, e.api, e.deviceID).Name)
	assert.Equal(t, "renamed-again", e.srvNode(t).GivenName())

	// Invalid DNS label is rejected; the name is unchanged.
	bad := e.api.Post("/api/v2/device/"+e.deviceID+"/name", map[string]any{"name": "Invalid_Name!"})
	assert.Equal(t, http.StatusBadRequest, bad.Code)
	assert.Contains(t, bad.Body.String(), `"message"`)
	assert.Equal(t, "renamed-again", e.srvNode(t).GivenName())
}

func TestAPIv2Device_SetTags(t *testing.T) {
	e := newDeviceTestEnv(t)

	setTags := func(tags []string) int {
		return e.api.Post("/api/v2/device/"+e.deviceID+"/tags", map[string]any{"tags": tags}).Code
	}

	// One tag flips the node to tag-owned.
	require.Equal(t, http.StatusOK, setTags([]string{"tag:ci"}))
	assert.Equal(t, []string{"tag:ci"}, getDevice(t, e.api, e.deviceID).Tags)
	n := e.srvNode(t)
	assert.True(t, n.IsTagged())
	assert.Equal(t, []string{"tag:ci"}, n.Tags().AsSlice())
	assert.False(t, n.User().Valid())
	assert.Equal(t, types.TaggedDevices.Username(), getDevice(t, e.api, e.deviceID).User)

	// Two tags (sorted).
	require.Equal(t, http.StatusOK, setTags([]string{"tag:ci", "tag:prod"}))
	assert.Equal(t, []string{"tag:ci", "tag:prod"}, getDevice(t, e.api, e.deviceID).Tags)
	assert.Equal(t, []string{"tag:ci", "tag:prod"}, e.srvNode(t).Tags().AsSlice())

	// A different single tag replaces the set.
	require.Equal(t, http.StatusOK, setTags([]string{"tag:prod"}))
	assert.Equal(t, []string{"tag:prod"}, e.srvNode(t).Tags().AsSlice())

	// Remove-all is a no-op: tags survive.
	require.Equal(t, http.StatusOK, setTags([]string{}))
	assert.Equal(t, []string{"tag:prod"}, e.srvNode(t).Tags().AsSlice())
	assert.True(t, e.srvNode(t).IsTagged())

	// An undeclared tag is rejected with 400 (mapError now maps the sentinel),
	// and the server-side tags are unchanged.
	assert.Equal(t, http.StatusBadRequest, setTags([]string{"tag:nope"}))
	assert.Equal(t, []string{"tag:prod"}, e.srvNode(t).Tags().AsSlice())
}

func TestAPIv2Device_SetKey(t *testing.T) {
	e := newDeviceTestEnv(t)
	e.seedExpiry(t, time.Now().Add(24*time.Hour))

	require.True(t, e.srvNode(t).Expiry().Valid(), "precondition: node has an expiry")
	assert.False(t, getDevice(t, e.api, e.deviceID).KeyExpiryDisabled)

	require.Equal(t, http.StatusOK,
		e.api.Post("/api/v2/device/"+e.deviceID+"/key", map[string]any{"keyExpiryDisabled": true}).Code)
	assert.True(t, getDevice(t, e.api, e.deviceID).KeyExpiryDisabled)
	assert.False(t, e.srvNode(t).Expiry().Valid(), "expiry cleared")

	// Re-enable is accepted as a no-op; expiry stays cleared.
	require.Equal(t, http.StatusOK,
		e.api.Post("/api/v2/device/"+e.deviceID+"/key", map[string]any{"keyExpiryDisabled": false}).Code)
	assert.True(t, getDevice(t, e.api, e.deviceID).KeyExpiryDisabled)
	assert.False(t, e.srvNode(t).Expiry().Valid())
}

func TestAPIv2Device_SetRoutes(t *testing.T) {
	e := newDeviceTestEnv(t)

	setRoutes := func(routes []string) apiv2.DeviceRoutes {
		t.Helper()

		resp := e.api.Post("/api/v2/device/"+e.deviceID+"/routes", map[string]any{"routes": routes})
		require.Equalf(t, http.StatusOK, resp.Code, "body: %s", resp.Body)

		var dr apiv2.DeviceRoutes
		require.NoError(t, json.Unmarshal(resp.Body.Bytes(), &dr))

		return dr
	}

	// One route: enabled reflects it; advertised stays empty (nothing announced).
	dr := setRoutes([]string{"10.0.0.0/24"})
	assert.Contains(t, dr.Enabled, "10.0.0.0/24")
	assert.Empty(t, dr.Advertised)
	assert.Contains(t, getDeviceRoutes(t, e.api, e.deviceID).Enabled, "10.0.0.0/24")
	assert.Contains(t, approvedRouteStrings(e.srvNode(t)), "10.0.0.0/24")
	assert.Empty(t, e.srvNode(t).AnnouncedRoutes())

	// Two routes.
	setRoutes([]string{"10.0.0.0/24", "192.168.0.0/24"})

	approved := approvedRouteStrings(e.srvNode(t))
	assert.Contains(t, approved, "10.0.0.0/24")
	assert.Contains(t, approved, "192.168.0.0/24")

	// Exit route expands to both families.
	setRoutes([]string{"0.0.0.0/0"})

	approved = approvedRouteStrings(e.srvNode(t))
	assert.Contains(t, approved, "0.0.0.0/0")
	assert.Contains(t, approved, "::/0")

	// Clear.
	dr = setRoutes([]string{})
	assert.Empty(t, dr.Enabled)
	assert.Empty(t, approvedRouteStrings(e.srvNode(t)))

	// Malformed prefix is rejected; routes unchanged.
	bad := e.api.Post("/api/v2/device/"+e.deviceID+"/routes", map[string]any{"routes": []string{"not-a-cidr"}})
	assert.Equal(t, http.StatusBadRequest, bad.Code)
	assert.Empty(t, approvedRouteStrings(e.srvNode(t)))
}

func TestAPIv2Device_SetAuthorized(t *testing.T) {
	e := newDeviceTestEnv(t)

	require.Equal(t, http.StatusOK,
		e.api.Post("/api/v2/device/"+e.deviceID+"/authorized", map[string]any{"authorized": true}).Code)
	assert.True(t, getDevice(t, e.api, e.deviceID).Authorized)

	// De-authorize is rejected; the node stays present and authorized.
	bad := e.api.Post("/api/v2/device/"+e.deviceID+"/authorized", map[string]any{"authorized": false})
	assert.Equal(t, http.StatusBadRequest, bad.Code)
	assert.Contains(t, bad.Body.String(), `"message"`)
	assert.True(t, getDevice(t, e.api, e.deviceID).Authorized)
}

func TestAPIv2Device_Delete(t *testing.T) {
	e := newDeviceTestEnv(t)

	require.Equal(t, http.StatusOK, e.api.Delete("/api/v2/device/"+e.deviceID).Code)
	assert.Equal(t, http.StatusNotFound, e.api.Get("/api/v2/device/"+e.deviceID).Code)

	_, ok := e.app.state.GetNodeByID(e.nodeID)
	assert.False(t, ok, "node gone from the NodeStore")

	// Delete again is 404.
	assert.Equal(t, http.StatusNotFound, e.api.Delete("/api/v2/device/"+e.deviceID).Code)
}

func containsDeviceID(devs []apiv2.Device, id string) bool {
	for _, d := range devs {
		if d.ID == id || d.NodeID == id {
			return true
		}
	}

	return false
}
