package servertest_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	clientv0 "github.com/juanfont/headscale/gen/client/headscale/v0"
	"github.com/juanfont/headscale/hscontrol/servertest"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
)

// syncBuffer is a log sink the server's goroutines may write at once.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.buf.String()
}

var wholeAuthID = regexp.MustCompile(`hskey-authreq-[0-9a-f]{24}`)

// sshPoll is one /machine/ssh/action poll of node, over its Noise
// connection; authID "" is the first poll.
func sshPoll(ctx context.Context, srv *servertest.TestServer, node *servertest.TestClient, src, dst types.NodeID, authID string) (tailcfg.SSHAction, error) {
	u := fmt.Sprintf("%s/machine/ssh/action/%d/to/%d?local_user=%s", strings.Replace(srv.URL, "http://", "https://", 1), src, dst, sshCheckLocalUser)
	if authID != "" {
		u += "&auth_id=" + authID
	}

	var action tailcfg.SSHAction

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return action, err
	}

	resp, err := node.Direct().DoNoiseRequest(req)
	if err != nil {
		return action, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return action, fmt.Errorf("ssh action poll: %d", resp.StatusCode) //nolint:err113
	}

	err = json.NewDecoder(resp.Body).Decode(&action)

	return action, err
}

// TestAPIv0AuthRequests answers real clients that wait, through the
// generated client: registrations, SSH checks, each wrong verb, a request
// that timed out, answers at once and a register racing the delete of its
// user. Every line the server logs meanwhile, at trace level, is checked for
// an auth ID. It does not run in parallel: it owns the global logger.
func TestAPIv0AuthRequests(t *testing.T) {
	logged := &syncBuffer{}

	old, oldLevel := log.Logger, zerolog.GlobalLevel()
	log.Logger = zerolog.New(logged)

	zerolog.SetGlobalLevel(zerolog.TraceLevel)

	t.Cleanup(func() {
		log.Logger = old

		zerolog.SetGlobalLevel(oldLevel)
	})

	srv := servertest.NewServer(t)
	alice := srv.CreateUser(t, "alice")
	bob := srv.CreateUser(t, "bob")
	c := v0Client(t, srv)
	userID := func(u *types.User) string { return strconv.FormatUint(uint64(u.ID), 10) }

	var problems []string // every problem body, for the check at the end

	problem := func(p *clientv0.Problem, body []byte) *clientv0.Problem {
		t.Helper()
		require.NotNil(t, p, string(body))

		problems = append(problems, string(body))

		return p
	}

	t.Run("a registration an admin registers", func(t *testing.T) {
		var created *clientv0.Node

		laptop := servertest.NewClient(t, srv, "laptop", servertest.WithUser(alice), servertest.WithInteractiveLogin(func(id string) error {
			got, err := c.GetAuthRequestWithResponse(t.Context(), id)
			require.NoError(t, err)
			require.Equal(t, http.StatusOK, got.StatusCode(), string(got.Body))
			assert.Equal(t, clientv0.AuthRequestKindRegistration, got.JSON200.Kind)
			assert.Equal(t, "laptop", got.JSON200.Hostname)
			assert.True(t, got.JSON200.Source.IsNull())

			kind, err := c.ApproveAuthRequestWithResponse(t.Context(), id)
			require.NoError(t, err)

			p := problem(kind.ApplicationproblemJSON409, kind.Body)
			assert.Equal(t, clientv0.ProblemCodeAuthRequestKind, p.Code)
			assert.Equal(t, "registration", p.Details["kind"])

			reg, err := c.RegisterAuthRequestWithResponse(t.Context(), id, clientv0.RegisterAuthRequestJSONRequestBody{UserId: userID(alice)})
			require.NoError(t, err)
			require.Equal(t, http.StatusCreated, reg.StatusCode(), string(reg.Body))
			assert.Equal(t, "/api/headscale/v0/nodes/"+reg.JSON201.Id, reg.HTTPResponse.Header.Get("Location"))
			created = reg.JSON201

			again, err := c.RejectAuthRequestWithResponse(t.Context(), id)
			require.NoError(t, err)
			assert.Equal(t, clientv0.ProblemCodeNotFound, problem(again.ApplicationproblemJSON404, again.Body).Code)

			return nil
		}))

		require.Equal(t, created.Id, strconv.FormatInt(int64(laptop.Netmap().SelfNode.ID()), 10), "the client is the node")
		require.Equal(t, clientv0.NodeRegisterMethodCli, created.RegisterMethod)
	})

	t.Run("a registration an admin rejects", func(t *testing.T) {
		// The client is not told no: it is handed a new auth ID, as today.
		rejected, _ := servertest.TryNewClient(t, srv, "rejected", servertest.WithUser(alice), servertest.WithInteractiveLogin(func(id string) error {
			resp, err := c.RejectAuthRequestWithResponse(t.Context(), id)
			require.NoError(t, err)
			require.Equal(t, http.StatusNoContent, resp.StatusCode(), string(resp.Body))

			return nil
		}))
		require.Nil(t, rejected.Netmap(), "the client is not in the tailnet")

		for _, n := range srv.State().ListNodes().All() {
			require.NotEqual(t, "rejected", n.Hostname())
		}
	})

	t.Run("answers at once", func(t *testing.T) {
		var winner string

		servertest.NewClient(t, srv, "contested", servertest.WithUser(alice), servertest.WithInteractiveLogin(func(id string) error {
			var (
				wg   sync.WaitGroup
				mu   sync.Mutex
				wins []string
			)

			for _, u := range []*types.User{alice, bob} {
				wg.Go(func() {
					reg, err := c.RegisterAuthRequestWithResponse(t.Context(), id, clientv0.RegisterAuthRequestJSONRequestBody{UserId: userID(u)})
					if err != nil {
						t.Error(err)

						return
					}

					mu.Lock()
					defer mu.Unlock()

					switch reg.StatusCode() {
					case http.StatusCreated:
						wins = append(wins, u.Name)
					case http.StatusNotFound:
						problems = append(problems, string(reg.Body))
					default:
						t.Errorf("register: %d %s", reg.StatusCode(), reg.Body)
					}
				})
			}

			wg.Wait()
			require.Len(t, wins, 1, "one answer, one not_found")
			winner = wins[0]

			return nil
		}))

		var owners []string

		for _, n := range srv.State().ListNodes().All() {
			if n.Hostname() == "contested" {
				owners = append(owners, n.User().Name())
			}
		}

		require.Equal(t, []string{winner}, owners, "one node, the winner's")
	})

	t.Run("a register for a user being deleted", func(t *testing.T) {
		doomed := srv.CreateUser(t, "doomed")

		_, _ = servertest.TryNewClient(t, srv, "orphan", servertest.WithUser(alice), servertest.WithInteractiveLogin(func(id string) error {
			var (
				wg  sync.WaitGroup
				reg *clientv0.RegisterAuthRequestResponse
				del *clientv0.DeleteUserResponse
			)

			wg.Go(func() {
				var err error

				reg, err = c.RegisterAuthRequestWithResponse(t.Context(), id, clientv0.RegisterAuthRequestJSONRequestBody{UserId: userID(doomed)})
				assert.NoError(t, err)
			})
			wg.Go(func() {
				var err error

				del, err = c.DeleteUserWithResponse(t.Context(), userID(doomed), &clientv0.DeleteUserParams{WithNodes: new(true)})
				assert.NoError(t, err)
			})
			wg.Wait()

			require.Equal(t, http.StatusOK, del.StatusCode(), string(del.Body))

			if reg.StatusCode() == http.StatusCreated {
				require.Equal(t, []clientv0.NodeReference{{Id: reg.JSON201.Id, Name: reg.JSON201.Name}}, del.JSON200.Nodes, "the delete took the node")

				return nil
			}

			p := problem(reg.ApplicationproblemJSON422, reg.Body)
			require.Equal(t, "body.userId", p.Errors[0].Location)
			require.Empty(t, del.JSON200.Nodes)

			// The request still waits: it goes to another user.
			again, err := c.RegisterAuthRequestWithResponse(t.Context(), id, clientv0.RegisterAuthRequestJSONRequestBody{UserId: userID(bob)})
			require.NoError(t, err)
			require.Equal(t, http.StatusCreated, again.StatusCode(), string(again.Body))

			return nil
		}))

		for _, n := range srv.State().ListNodes().All() {
			require.False(t, n.UserID().Valid() && n.UserID().Get() == doomed.ID, "no node of the deleted user")
		}
	})

	t.Run("ssh checks", func(t *testing.T) {
		h := servertest.NewHarness(t, 2)
		hc := v0Client(t, h.Server)
		src := types.NodeID(h.Client(0).Netmap().SelfNode.ID()) //nolint:gosec
		dst := types.NodeID(h.Client(1).Netmap().SelfNode.ID()) //nolint:gosec

		h.ChangePolicy(t, []byte(`{"ssh": [{
			"action": "check", "checkPeriod": "always",
			"src": ["harness-default@"], "dst": ["autogroup:self"], "users": ["autogroup:nonroot"]
		}]}`))

		for _, approve := range []bool{true, false} {
			first, err := sshPoll(t.Context(), h.Server, h.Client(1), src, dst, "")
			require.NoError(t, err)
			require.NotEmpty(t, first.HoldAndDelegate)

			id := string(authIDFromHoldURL(t, first.HoldAndDelegate))

			got, err := hc.GetAuthRequestWithResponse(t.Context(), id)
			require.NoError(t, err)
			require.Equal(t, http.StatusOK, got.StatusCode(), string(got.Body))
			require.Equal(t, clientv0.AuthRequestKindSshCheck, got.JSON200.Kind)
			require.Equal(t, strconv.FormatUint(uint64(src), 10), got.JSON200.Source.MustGet().Id)
			require.Equal(t, strconv.FormatUint(uint64(dst), 10), got.JSON200.Destination.MustGet().Id)

			kind, err := hc.RegisterAuthRequestWithResponse(t.Context(), id, clientv0.RegisterAuthRequestJSONRequestBody{UserId: "1"})
			require.NoError(t, err)
			require.Equal(t, "sshCheck", problem(kind.ApplicationproblemJSON409, kind.Body).Details["kind"])

			verdict := make(chan tailcfg.SSHAction, 1)

			go func() {
				action, err := sshPoll(t.Context(), h.Server, h.Client(1), src, dst, id)
				assert.NoError(t, err)

				verdict <- action
			}()

			// The follow-up must be waiting before the answer, or it would
			// find the request answered and start again.
			require.Eventually(t, func() bool {
				_, waits := h.Server.State().AuthRequest(types.AuthID(id))
				return waits && len(verdict) == 0
			}, 10*time.Second, 10*time.Millisecond)

			var status int

			if approve {
				resp, err := hc.ApproveAuthRequestWithResponse(t.Context(), id)
				require.NoError(t, err)

				status = resp.StatusCode()
			} else {
				resp, err := hc.RejectAuthRequestWithResponse(t.Context(), id)
				require.NoError(t, err)

				status = resp.StatusCode()
			}

			require.Equal(t, http.StatusNoContent, status)

			action := <-verdict
			require.Equal(t, approve, action.Accept, "%+v", action)
			require.Equal(t, !approve, action.Reject, "%+v", action)

			gone, err := hc.ApproveAuthRequestWithResponse(t.Context(), id)
			require.NoError(t, err)
			require.Equal(t, clientv0.ProblemCodeNotFound, problem(gone.ApplicationproblemJSON404, gone.Body).Code)
		}
	})

	t.Run("a request that timed out", func(t *testing.T) {
		short := servertest.NewServer(t, servertest.WithRegisterCacheExpiration(200*time.Millisecond))
		sc := v0Client(t, short)
		user := short.CreateUser(t, "late")

		_, _ = servertest.TryNewClient(t, short, "late", servertest.WithUser(user), servertest.WithInteractiveLogin(func(id string) error {
			require.Eventually(t, func() bool {
				got, err := sc.GetAuthRequestWithResponse(t.Context(), id)

				return err == nil && got.StatusCode() == http.StatusNotFound
			}, 10*time.Second, 20*time.Millisecond)

			reg, err := sc.RegisterAuthRequestWithResponse(t.Context(), id, clientv0.RegisterAuthRequestJSONRequestBody{UserId: userID(user)})
			require.NoError(t, err)
			require.Equal(t, clientv0.ProblemCodeNotFound, problem(reg.ApplicationproblemJSON404, reg.Body).Code)

			for _, answer := range []func(context.Context, string, ...clientv0.RequestEditorFn) (*http.Response, error){
				sc.ApproveAuthRequest, sc.RejectAuthRequest,
			} {
				resp, err := answer(t.Context(), id)
				require.NoError(t, err)
				resp.Body.Close()
				require.Equal(t, http.StatusNotFound, resp.StatusCode)
			}

			return nil
		}))
	})

	for _, p := range problems {
		require.NotRegexp(t, wholeAuthID, p, "a problem names no auth ID")
	}

	require.Contains(t, logged.String(), "starting node registration", "the log was captured")
	require.NotRegexp(t, wholeAuthID, logged.String(), "the log names no auth ID")
}
