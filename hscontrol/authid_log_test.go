package hscontrol

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"

	"github.com/juanfont/headscale/hscontrol/capver"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/oauth2-proxy/mockoidc"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

// fullAuthID is an auth ID as the server makes it, whole.
var fullAuthID = regexp.MustCompile(`hskey-authreq-[0-9a-f]{24}`)

// TestAuthIDNotLogged: every line that named an auth request printed its
// ID, which lets whoever reads the log answer the request. Each is reached
// here at trace level, and none may carry the ID.
func TestAuthIDNotLogged(t *testing.T) {
	logged := captureLog(t, zerolog.TraceLevel)

	// A line written later, by code that names an ID in a lazy way.
	t.Run("lazy", func(t *testing.T) {
		id := types.MustAuthID()

		log.Info().
			Stringer("stringer", id).
			Interface("interface", id).
			Interface("inside", struct{ ID types.AuthID }{id}).
			Msgf("formatted %v %s %+v", id, id, struct{ ID types.AuthID }{id})
		log.Error().Err(fmt.Errorf("%w: %v", types.ErrInvalidAuthIDChars, id)).Msg("lazy error")
	})

	t.Run("registration", func(t *testing.T) {
		app := createTestApp(t)
		ns := &noiseServer{headscale: app, machineKey: key.NewMachine().Public()}

		for _, followup := range []string{"", "http://localhost:8080/register/" + types.MustAuthID().Raw()} {
			rec := serveRegister(t, ns, tailcfg.RegisterRequest{
				Version:  capver.MinSupportedCapabilityVersion,
				NodeKey:  key.NewNode().Public(),
				Hostinfo: &tailcfg.Hostinfo{Hostname: "node"},
				Followup: followup,
			})
			require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		}

		// A machine that has a node of one user registers for another.
		machine := key.NewMachine().Public()

		for _, name := range []string{"first", "second"} {
			user := app.state.CreateUserForTest(name)
			authID := types.MustAuthID()
			require.NoError(t, app.state.SetAuthCacheEntry(authID, types.NewRegisterAuthRequest(&types.RegistrationData{
				MachineKey: machine, NodeKey: key.NewNode().Public(), Hostname: "moved",
			})))

			_, _, err := app.state.HandleNodeFromAuthPath(authID, types.UserID(user.ID), nil, util.RegisterMethodCLI)
			require.NoError(t, err)
		}
	})

	t.Run("ssh check", func(t *testing.T) {
		f := newSSHVerdictFixture(t)
		f.mint(t)

		f.followUp(t, types.MustAuthID())

		registration := types.MustAuthID()
		require.NoError(t, f.ns.headscale.state.SetAuthCacheEntry(registration, types.NewRegisterAuthRequest(&types.RegistrationData{
			MachineKey: key.NewMachine().Public(), NodeKey: key.NewNode().Public(), Hostname: "node",
		})))

		rec := f.followUp(t, registration)
		require.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("oidc", func(t *testing.T) {
		b := newOIDCBrowser(t)
		provider, ok := b.app.authProvider.(*AuthProviderOIDC)
		require.True(t, ok)

		sshID, nodes := b.pendingSSHCheck(t)
		b.idp.QueueUser(&mockoidc.MockUser{Subject: "other-ssh-user", PreferredUsername: "other"})
		status, _, _ := b.get(t, b.publicURL+"/auth/"+sshID.Raw())
		require.Equal(t, http.StatusForbidden, status)

		owner := nodes[0].User
		sshReq, ok := b.app.state.GetAuthCacheEntry(sshID)
		require.True(t, ok)

		regID, _ := b.pendingNode(t)
		regReq, ok := b.app.state.GetAuthCacheEntry(regID)
		require.True(t, ok)

		_, err := provider.sshCheckSource(regID, regReq, owner)
		require.Error(t, err)

		provider.beginConfirmation(httptest.NewRecorder(), httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil), sshID, true, owner, nil)
		provider.beginConfirmation(httptest.NewRecorder(), httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil), types.MustAuthID(), true, owner, nil)

		tagged := nodes[0].Clone()
		tagged.Tags = []string{"tag:changed"}
		b.app.state.PutNodeInStoreForTest(*tagged)

		_, err = provider.sshCheckSource(sshID, sshReq, owner)
		require.Error(t, err)

		_, err = b.app.state.DeleteNode(nodes[0].View())
		require.NoError(t, err)
		_, err = provider.sshCheckSource(sshID, sshReq, owner)
		require.Error(t, err)
	})

	out := logged.String()

	// Each line that named an auth request is reached.
	for _, line := range []string{
		"starting node registration", "new followup node registration", "Creating new node for different user",
		"SSH check pending", "SSH check auth session missing", "auth session is not for SSH check",
		"OIDC user is not the owner", "non-registration path", "registration path with auth request that is not",
		"auth session expired before authorization", "src node has no user owner", "src node no longer exists",
		"formatted", "lazy error",
	} {
		require.Contains(t, out, line)
	}

	require.NotRegexp(t, fullAuthID, out)
}
