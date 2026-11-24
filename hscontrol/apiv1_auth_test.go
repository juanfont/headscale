package hscontrol

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

// seedAuthRequest stores a pending registration auth cache entry under authID so
// an AuthRegister/Approve/Reject call has a real session to act on. Capturing
// the keys/authID at the call site keeps isolated apps identical.
func seedAuthRequest(
	user string,
	authID types.AuthID,
	machineKey key.MachinePublic,
	nodeKey key.NodePublic,
	discoKey key.DiscoPublic,
	hostname string,
) func(t *testing.T, app *Headscale) {
	return func(t *testing.T, app *Headscale) {
		t.Helper()

		app.state.CreateUserForTest(user)

		regData := &types.RegistrationData{
			MachineKey: machineKey,
			NodeKey:    nodeKey,
			DiscoKey:   discoKey,
			Hostname:   hostname,
			Hostinfo:   &tailcfg.Hostinfo{Hostname: hostname},
		}

		require.NoError(t, app.state.SetAuthCacheEntry(authID, types.NewRegisterAuthRequest(regData)))
	}
}

func TestAPIV1AuthRegister(t *testing.T) {
	t.Run("happy path parity", func(t *testing.T) {
		// Capture keys/authID once so both isolated apps register the identical
		// node and produce byte-equal bodies.
		authID := types.MustAuthID()
		machineKey := key.NewMachine().Public()
		nodeKey := key.NewNode().Public()
		discoKey := key.NewDisco().Public()

		seed := seedAuthRequest("alice", authID, machineKey, nodeKey, discoKey, "regnode")
		body := fmt.Appendf(nil, `{"user":"alice","authId":%q}`, authID.String())

		assertParityIsolated(t, seed, http.MethodPost, "/api/v1/auth/register", body)
	})

	t.Run("happy path response shape", func(t *testing.T) {
		h := newAPIV1Harness(t)

		authID := types.MustAuthID()
		seedAuthRequest(
			"alice", authID,
			key.NewMachine().Public(),
			key.NewNode().Public(),
			key.NewDisco().Public(),
			"regnode",
		)(t, h.app)

		body := fmt.Appendf(nil, `{"user":"alice","authId":%q}`, authID.String())
		res := h.callHuma(http.MethodPost, "/api/v1/auth/register", body)
		require.Equal(t, http.StatusOK, res.status)

		var got struct {
			Node map[string]any `json:"node"`
		}
		require.NoError(t, json.Unmarshal(res.body, &got))

		assert.Equal(t, "1", got.Node["id"])
		assert.Equal(t, "REGISTER_METHOD_CLI", got.Node["registerMethod"])
		// EmitUnpopulated parity: an unset expiry (we passed none) is null, an
		// unset embedded pre-auth key is null, and repeated fields are []
		// rather than omitted.
		assert.Contains(t, got.Node, "expiry")
		assert.Nil(t, got.Node["expiry"])
		assert.Contains(t, got.Node, "preAuthKey")
		assert.Nil(t, got.Node["preAuthKey"])
		assert.Equal(t, []any{}, got.Node["subnetRoutes"])
		assert.NotNil(t, got.Node["user"])
	})

	// A malformed auth_id is bad input (400), matching AuthApprove/AuthReject.
	t.Run("invalid auth_id parity", func(t *testing.T) {
		h := newAPIV1Harness(t)
		seedUsers("alice")(t, h.app)
		res := h.assertParity(t, http.MethodPost, "/api/v1/auth/register",
			[]byte(`{"user":"alice","authId":"not-a-valid-auth-id"}`))
		assertStatus(t, res, http.StatusBadRequest)
	})

	t.Run("unknown user parity", func(t *testing.T) {
		h := newAPIV1Harness(t)
		body := fmt.Appendf(nil, `{"user":"ghost","authId":%q}`, types.MustAuthID().String())
		res := h.assertParity(t, http.MethodPost, "/api/v1/auth/register", body)
		assertStatus(t, res, http.StatusNotFound)
	})

	// Valid auth_id but no cached session: HandleNodeFromAuthPath returns
	// ErrNodeNotFoundRegistrationCache, which maps to 404.
	t.Run("no pending session parity", func(t *testing.T) {
		h := newAPIV1Harness(t)
		seedUsers("alice")(t, h.app)

		body := fmt.Appendf(nil, `{"user":"alice","authId":%q}`, types.MustAuthID().String())
		res := h.assertParity(t, http.MethodPost, "/api/v1/auth/register", body)
		assertStatus(t, res, http.StatusNotFound)
	})
}

func TestAPIV1AuthApprove(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		h := newAPIV1Harness(t)

		authID := types.MustAuthID()
		authReq := types.NewSSHCheckAuthRequest(1, 2)
		require.NoError(t, h.app.state.SetAuthCacheEntry(authID, authReq))

		body := fmt.Appendf(nil, `{"authId":%q}`, authID.String())
		res := h.callHuma(http.MethodPost, "/api/v1/auth/approve", body)

		require.Equal(t, http.StatusOK, res.status)
		assert.JSONEq(t, `{}`, string(res.body))

		verdict := authReq.Verdict()
		assert.True(t, verdict.Accept(), "approve must finish the session with a passing verdict")
	})

	// A registration is approved by auth register, which makes its node;
	// finished here it would tell the client to start over.
	t.Run("registration refused", func(t *testing.T) {
		h := newAPIV1Harness(t)

		authID := types.MustAuthID()
		reg := types.NewRegisterAuthRequest(&types.RegistrationData{
			MachineKey: key.NewMachine().Public(),
			NodeKey:    key.NewNode().Public(),
			Hostname:   "pending-login",
		})
		require.NoError(t, h.app.state.SetAuthCacheEntry(authID, reg))

		body := fmt.Appendf(nil, `{"authId":%q}`, authID.String())
		res := h.callHuma(http.MethodPost, "/api/v1/auth/approve", body)

		assertStatus(t, res, http.StatusBadRequest)
		assert.False(t, reg.IsFinished(), "the registration must stay pending")
	})

	// Malformed auth_id: AuthApprove returns codes.InvalidArgument → 400.
	t.Run("invalid auth_id parity", func(t *testing.T) {
		h := newAPIV1Harness(t)
		res := h.assertParity(t, http.MethodPost, "/api/v1/auth/approve",
			[]byte(`{"authId":"not-a-valid-auth-id"}`))
		assertStatus(t, res, http.StatusBadRequest)
	})

	// Well-formed auth_id with no pending session: codes.NotFound → 404.
	t.Run("no pending session parity", func(t *testing.T) {
		h := newAPIV1Harness(t)
		body := fmt.Appendf(nil, `{"authId":%q}`, types.MustAuthID().String())
		res := h.assertParity(t, http.MethodPost, "/api/v1/auth/approve", body)
		assertStatus(t, res, http.StatusNotFound)
	})
}

func TestAPIV1AuthReject(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		h := newAPIV1Harness(t)

		authID := types.MustAuthID()
		authReq := types.NewAuthRequest()
		require.NoError(t, h.app.state.SetAuthCacheEntry(authID, authReq))

		body := fmt.Appendf(nil, `{"authId":%q}`, authID.String())
		res := h.callHuma(http.MethodPost, "/api/v1/auth/reject", body)

		require.Equal(t, http.StatusOK, res.status)
		assert.JSONEq(t, `{}`, string(res.body))

		verdict := authReq.Verdict()
		assert.False(t, verdict.Accept(), "reject must finish the session with a failing verdict")
	})

	t.Run("invalid auth_id parity", func(t *testing.T) {
		h := newAPIV1Harness(t)
		res := h.assertParity(t, http.MethodPost, "/api/v1/auth/reject",
			[]byte(`{"authId":"not-a-valid-auth-id"}`))
		assertStatus(t, res, http.StatusBadRequest)
	})

	t.Run("no pending session parity", func(t *testing.T) {
		h := newAPIV1Harness(t)
		body := fmt.Appendf(nil, `{"authId":%q}`, types.MustAuthID().String())
		res := h.assertParity(t, http.MethodPost, "/api/v1/auth/reject", body)
		assertStatus(t, res, http.StatusNotFound)
	})
}

// The two endpoints are deliberately asymmetric on a pending node
// registration: approve refuses it (a registration is approved by auth
// register, which makes its node) and leaves the login pending, while
// reject accepts the ID because refusing a login through the API is the
// feature — the waiting client is told its request was rejected and the
// session is released, never to be decided again.
func TestAPIV1AuthApproveRefusesARegistrationThatRejectRefuses(t *testing.T) {
	h := newAPIV1Harness(t)

	authID := types.MustAuthID()
	reg := types.NewRegisterAuthRequest(&types.RegistrationData{
		MachineKey: key.NewMachine().Public(),
		NodeKey:    key.NewNode().Public(),
		Hostname:   "pending-login",
	})
	require.NoError(t, h.app.state.SetAuthCacheEntry(authID, reg))

	body := fmt.Appendf(nil, `{"authId":%q}`, authID.String())

	res := h.callHuma(http.MethodPost, "/api/v1/auth/approve", body)
	assertStatus(t, res, http.StatusBadRequest)
	assert.False(t, reg.IsFinished(), "approve must leave the registration pending")

	res = h.callHuma(http.MethodPost, "/api/v1/auth/reject", body)
	require.Equal(t, http.StatusOK, res.status)

	verdict := reg.Verdict()
	assert.False(t, verdict.Accept(), "reject must tell the waiting client its login was refused")

	_, pending := h.app.state.GetAuthCacheEntry(authID)
	assert.False(t, pending, "the rejected session must be released")
}
