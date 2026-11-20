package apiv0

import (
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"maps"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"unicode"

	"github.com/danielgtaylor/huma/v2/humatest"
	"github.com/juanfont/headscale/hscontrol/config"
	"github.com/juanfont/headscale/hscontrol/db"
	"github.com/juanfont/headscale/hscontrol/state"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/types/change"
	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

// pendingRegistration is a registration of a new machine with hostname.
func pendingRegistration(t *testing.T, b Backend, hostname string) (types.AuthID, *types.AuthRequest) {
	t.Helper()

	id := types.MustAuthID()
	req := types.NewRegisterAuthRequest(&types.RegistrationData{
		MachineKey: key.NewMachine().Public(),
		NodeKey:    key.NewNode().Public(),
		Hostname:   hostname,
		Hostinfo:   &tailcfg.Hostinfo{Hostname: hostname},
	})
	require.NoError(t, b.State.SetAuthCacheEntry(id, req))

	return id, req
}

// pendingSSHCheck is an SSH check between two nodes of alice.
func pendingSSHCheck(t *testing.T, b Backend, alice *types.User) (types.AuthID, *types.AuthRequest, [2]types.NodeView) {
	t.Helper()

	var nodes [2]types.NodeView

	for i, name := range []string{"src", "dst"} {
		k, err := b.State.CreatePreAuthKey(new(types.UserID(alice.ID)), false, false, nil, nil)
		require.NoError(t, err)

		nodes[i], _, err = b.State.HandleNodeFromPreAuthKey(tailcfg.RegisterRequest{
			Auth:     &tailcfg.RegisterResponseAuth{AuthKey: k.Key},
			NodeKey:  key.NewNode().Public(),
			Hostinfo: &tailcfg.Hostinfo{Hostname: name},
		}, key.NewMachine().Public())
		require.NoError(t, err)
	}

	id := types.MustAuthID()
	req := types.NewSSHCheckAuthRequest(nodes[0].ID(), nodes[1].ID())
	require.NoError(t, b.State.SetAuthCacheEntry(id, req))

	return id, req, nodes
}

func authRequestPath(id types.AuthID, verb string) string {
	p := Prefix + "/auth-requests/" + string(id)
	if verb != "" {
		p += "/" + verb
	}

	return p
}

func postJSON(api humatest.TestAPI, path, auth, body string) *httptest.ResponseRecorder {
	return api.Post(path, auth, "Content-Type: application/json", strings.NewReader(body))
}

// secretProblem is decodeProblem, and holds that neither the body nor a
// header carries the auth ID.
func secretProblem(t *testing.T, rec *httptest.ResponseRecorder, want Code, id types.AuthID) Problem {
	t.Helper()

	require.NotContains(t, rec.Body.String(), string(id))

	for name, vs := range rec.Header() {
		require.NotContains(t, strings.Join(vs, " "), string(id), name)
	}

	return decodeProblem(t, rec, want)
}

func verdictOf(t *testing.T, req *types.AuthRequest) types.AuthVerdict {
	t.Helper()

	select {
	case v := <-req.WaitForAuth():
		return v
	default:
		t.Fatal("the request has no verdict")

		return types.AuthVerdict{}
	}
}

func userIDOf(u *types.User) string { return strconv.FormatUint(uint64(u.ID), 10) }

func TestGetAuthRequest(t *testing.T) {
	b, api, auth, alice, _ := authKeysAPI(t)

	t.Run("a registration", func(t *testing.T) {
		id, _ := pendingRegistration(t, b, "newlaptop")

		rec := api.Get(authRequestPath(id, ""), auth)
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		requireAnswer(t, `{"id": "`+string(id)+`", "kind": "registration", "hostname": "newlaptop", "source": null, "destination": null}`, rec.Body.Bytes())

		read := keysToken(t, b, nil, "devices:core:read")
		require.Equal(t, http.StatusOK, api.Get(authRequestPath(id, ""), read).Code)

		p := secretProblem(t, api.Get(authRequestPath(id, ""), keysToken(t, b, nil, "users")), CodeForbidden, id)
		require.Equal(t, []any{"devices:core:read"}, p.Details["scopes"])
	})

	t.Run("an SSH check", func(t *testing.T) {
		id, _, nodes := pendingSSHCheck(t, b, alice)

		rec := api.Get(authRequestPath(id, ""), auth)
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		requireAnswer(t, `{"id": "`+string(id)+`", "kind": "sshCheck", "hostname": "",
			"source": {"id": "`+nodes[0].StringID()+`", "name": "src"},
			"destination": {"id": "`+nodes[1].StringID()+`", "name": "dst"}}`, rec.Body.Bytes())
	})

	t.Run("an ID no request has", func(t *testing.T) {
		id := types.MustAuthID()

		p := secretProblem(t, api.Get(authRequestPath(id, ""), auth), CodeNotFound, id)
		require.Equal(t, &ProblemObject{Kind: "authRequest"}, p.Object, "the kind, never the ID")
	})

	t.Run("a path of another form is refused before any read", func(t *testing.T) {
		id := string(types.MustAuthID())

		for _, path := range []string{
			strings.ToUpper(id), id + "0", id[:len(id)-1], "hskey-api-" + id[len("hskey-authreq-"):], "12",
		} {
			p := decodeProblem(t, api.Get(Prefix+"/auth-requests/"+path, auth), CodeNotFound)
			require.Nil(t, p.Object, path)
			require.NotContains(t, p.Detail, path)
		}
	})
}

func TestRegisterAuthRequest(t *testing.T) {
	b, api, auth, alice, _ := authKeysAPI(t)
	body := `{"userId": "` + userIDOf(alice) + `"}`

	t.Run("register", func(t *testing.T) {
		id, req := pendingRegistration(t, b, "newlaptop")

		rec := postJSON(api, authRequestPath(id, "register"), auth, body)
		require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())

		var n Node
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &n))
		require.Equal(t, Prefix+"/nodes/"+n.ID, rec.Header().Get("Location"))
		require.Equal(t, `"`+n.Revision+`"`, rec.Header().Get("ETag"))
		require.Equal(t, "newlaptop", n.Hostname)
		require.Equal(t, "alice", n.Owner.User.LoginName)
		require.Equal(t, RegisterMethod("cli"), n.RegisterMethod)
		require.Equal(t, n.ID, verdictOf(t, req).Node.StringID(), "the node is told")

		for _, path := range []string{authRequestPath(id, "")} {
			secretProblem(t, api.Get(path, auth), CodeNotFound, id)
		}

		for _, verb := range []string{"register", "approve", "reject"} {
			secretProblem(t, postJSON(api, authRequestPath(id, verb), auth, body), CodeNotFound, id)
		}
	})

	t.Run("a token is refused before the body is read", func(t *testing.T) {
		id, req := pendingRegistration(t, b, "token")
		token := keysToken(t, b, []string{"tag:ci"}, "all")

		for _, sent := range []string{body, `{"userId": "x"}`, `nope`} {
			p := secretProblem(t, postJSON(api, authRequestPath(id, "register"), token, sent), CodeForbidden, id)
			require.Equal(t, "token_cannot_register_node_to_user", p.Details["rule"], sent)
			require.Equal(t, []any{}, p.Details["scopes"])
		}

		require.False(t, req.IsFinished())
	})

	t.Run("a user that is not there", func(t *testing.T) {
		id, req := pendingRegistration(t, b, "nobody")

		for sent, msg := range map[string]string{
			`{"userId": "999999"}`: "no user has this ID",
			`{"userId": "alice"}`:  notUserID,
			`{"userId": "007"}`:    notUserID,
		} {
			p := secretProblem(t, postJSON(api, authRequestPath(id, "register"), auth, sent), CodeInvalidField, id)
			require.Equal(t, []FieldError{{Location: "body.userId", Message: msg}}, p.Errors, sent)
		}

		require.False(t, req.IsFinished(), "the request still waits")
		require.Equal(t, http.StatusCreated, postJSON(api, authRequestPath(id, "register"), auth, body).Code)
	})

	t.Run("an SSH check", func(t *testing.T) {
		id, req, _ := pendingSSHCheck(t, b, alice)

		p := secretProblem(t, postJSON(api, authRequestPath(id, "register"), auth, body), CodeAuthRequestKind, id)
		require.Equal(t, "sshCheck", p.Details["kind"])
		require.Equal(t, &ProblemObject{Kind: "authRequest"}, p.Object)
		require.False(t, req.IsFinished())
	})
}

func TestAnswerAuthRequest(t *testing.T) {
	b, api, auth, alice, _ := authKeysAPI(t)
	core := keysToken(t, b, nil, "devices:core")

	t.Run("approve an SSH check", func(t *testing.T) {
		id, req, _ := pendingSSHCheck(t, b, alice)

		rec := api.Post(authRequestPath(id, "approve"), auth)
		require.Equal(t, http.StatusNoContent, rec.Code, rec.Body.String())
		require.Empty(t, rec.Body.String())
		require.True(t, verdictOf(t, req).Accept())

		for _, verb := range []string{"approve", "reject"} {
			secretProblem(t, api.Post(authRequestPath(id, verb), auth), CodeNotFound, id)
		}

		secretProblem(t, api.Get(authRequestPath(id, ""), auth), CodeNotFound, id)
	})

	t.Run("approve a registration", func(t *testing.T) {
		id, req := pendingRegistration(t, b, "newlaptop")

		p := secretProblem(t, api.Post(authRequestPath(id, "approve"), auth), CodeAuthRequestKind, id)
		require.Equal(t, "registration", p.Details["kind"])
		require.Equal(t, &ProblemObject{Kind: "authRequest", Name: "newlaptop"}, p.Object)
		require.False(t, req.IsFinished(), "the node is not told; it still waits")
	})

	for _, kind := range []string{"registration", "sshCheck"} {
		t.Run("reject a "+kind, func(t *testing.T) {
			id, req := pendingRegistration(t, b, "rejected")
			if kind == "sshCheck" {
				id, req, _ = pendingSSHCheck(t, b, alice)
			}

			require.Equal(t, http.StatusNoContent, api.Post(authRequestPath(id, "reject"), core).Code)
			require.False(t, verdictOf(t, req).Accept())
			secretProblem(t, api.Post(authRequestPath(id, "reject"), auth), CodeNotFound, id)
		})
	}

	t.Run("a token cannot approve an SSH check, and may reject one", func(t *testing.T) {
		id, req, _ := pendingSSHCheck(t, b, alice)

		for _, token := range []string{core, keysToken(t, b, []string{"tag:ci"}, "all"), keysToken(t, b, nil, "users")} {
			p := secretProblem(t, api.Post(authRequestPath(id, "approve"), token), CodeForbidden, id)
			require.Equal(t, "token_cannot_approve_ssh_check", p.Details["rule"])
			require.Equal(t, []any{}, p.Details["scopes"], "before the scopes")
		}

		require.False(t, req.IsFinished())

		socket := httptest.NewRecorder()
		WithLocalTrust(Handler(b)).ServeHTTP(socket, httptest.NewRequestWithContext(t.Context(), http.MethodPost, authRequestPath(id, "approve"), nil))
		require.Equal(t, http.StatusNoContent, socket.Code, socket.Body.String())
		require.True(t, verdictOf(t, req).Accept())

		id, req, _ = pendingSSHCheck(t, b, alice)
		require.Equal(t, http.StatusNoContent, api.Post(authRequestPath(id, "reject"), core).Code)
		require.False(t, verdictOf(t, req).Accept())
	})

	t.Run("gone has one form", func(t *testing.T) {
		_, req := pendingRegistration(t, b, "read-then-answered")

		err := mapError(t.Context(), b.authRequestProblem(db.ErrNodeNotFoundRegistrationCache, req), []Code{CodeNotFound}, []answer{authRequestGone})
		p, ok := errors.AsType[*Problem](err)
		require.True(t, ok)
		require.Equal(t, &ProblemObject{Kind: "authRequest"}, p.Object, "a request answered since it was read names no hostname")
	})

	t.Run("a read scope is not enough", func(t *testing.T) {
		id, _ := pendingRegistration(t, b, "read")

		p := secretProblem(t, api.Post(authRequestPath(id, "reject"), keysToken(t, b, nil, "devices:core:read")), CodeForbidden, id)
		require.Equal(t, []any{"devices:core"}, p.Details["scopes"])
	})

	t.Run("answers at once", func(t *testing.T) {
		for range 10 {
			id, req := pendingRegistration(t, b, "race")

			var (
				wg    sync.WaitGroup
				codes = make(chan int, 4)
			)

			for _, call := range []func() *httptest.ResponseRecorder{
				func() *httptest.ResponseRecorder {
					return postJSON(api, authRequestPath(id, "register"), auth, `{"userId": "`+userIDOf(alice)+`"}`)
				},
				func() *httptest.ResponseRecorder { return api.Post(authRequestPath(id, "reject"), auth) },
				func() *httptest.ResponseRecorder { return api.Post(authRequestPath(id, "reject"), auth) },
			} {
				wg.Go(func() { codes <- call().Code })
			}

			wg.Wait()
			close(codes)

			var answered, gone int

			for c := range codes {
				switch c {
				case http.StatusCreated, http.StatusNoContent:
					answered++
				case http.StatusNotFound:
					gone++
				}
			}

			require.Equal(t, 1, answered)
			require.Equal(t, 2, gone)
			require.True(t, req.IsFinished())
		}
	})
}

// TestRegisterDuringUserDelete: a register and the delete of its user at
// once. Whichever comes first, the node is the user's and goes with it, or
// the register finds no user and the request still waits.
func TestRegisterDuringUserDelete(t *testing.T) {
	b, api, auth, _, bob := authKeysAPI(t)

	for round := range 10 {
		u := b.State.CreateUserForTest("doomed" + strconv.Itoa(round))
		id, req := pendingRegistration(t, b, "doomed")

		var (
			wg       sync.WaitGroup
			reg, del *httptest.ResponseRecorder
		)

		wg.Go(func() { reg = postJSON(api, authRequestPath(id, "register"), auth, `{"userId": "`+userIDOf(u)+`"}`) })
		wg.Go(func() { del = api.Delete(userPath(u, "?withNodes=true"), auth) })
		wg.Wait()

		require.Equal(t, http.StatusOK, del.Code, del.Body.String())
		d := decodeDeletedUser(t, del)

		switch reg.Code {
		case http.StatusCreated:
			var n Node
			require.NoError(t, json.Unmarshal(reg.Body.Bytes(), &n))
			require.Equal(t, []NodeReference{{ID: n.ID, Name: n.Name}}, d.Nodes, "the delete took the node")
			decodeProblem(t, api.Get(Prefix+"/nodes/"+n.ID, auth), CodeNotFound)
		default:
			p := secretProblem(t, reg, CodeInvalidField, id)
			require.Equal(t, "body.userId", p.Errors[0].Location)
			require.Empty(t, d.Nodes)
			require.False(t, req.IsFinished(), "the request still waits")
			require.Equal(t, http.StatusCreated, postJSON(api, authRequestPath(id, "register"), auth, `{"userId": "`+userIDOf(bob)+`"}`).Code)
		}
	}
}

func TestCreateDebugNode(t *testing.T) {
	b, api, auth, alice, _ := authKeysAPI(t)
	id := types.MustAuthID()
	body := `{"authId": "` + string(id) + `", "hostname": "fake-1", "routes": ["10.0.0.0/24"]}`

	rec := postJSON(api, Prefix+"/debug/nodes", auth, body)
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
	require.Empty(t, rec.Header().Get("Location"), "the auth ID is a secret")
	requireAnswer(t, `{"id": "`+string(id)+`", "kind": "registration", "hostname": "fake-1", "source": null, "destination": null}`, rec.Body.Bytes())

	p := secretProblem(t, postJSON(api, Prefix+"/debug/nodes", auth, body), CodeInvalidField, id)
	require.Equal(t, []FieldError{{Location: "body.authId", Message: "an auth request has this ID"}}, p.Errors)

	reg := postJSON(api, authRequestPath(id, "register"), auth, `{"userId": "`+userIDOf(alice)+`"}`)
	require.Equal(t, http.StatusCreated, reg.Code, reg.Body.String())

	var n Node
	require.NoError(t, json.Unmarshal(reg.Body.Bytes(), &n))
	require.Equal(t, "fake-1", n.Hostname)
	require.Equal(t, []string{"10.0.0.0/24"}, n.AdvertisedRoutes)

	other := string(types.MustAuthID())

	for sent, want := range map[string]FieldError{
		`{"authId": "hskey-api-x", "hostname": "h", "routes": []}`:                  {"body.authId", "is not an auth ID: hskey-authreq- and 24 lower-case hex digits"},
		`{"authId": "` + other + `", "hostname": "h", "routes": ["10.0.0.1/8"]}`:    {"body.routes[0]", "is not an IP prefix with no host bits"},
		`{"userId": "1", "authId": "` + other + `", "hostname": "h", "routes": []}`: {"body.userId", "unexpected property"},
	} {
		p := decodeProblem(t, postJSON(api, Prefix+"/debug/nodes", auth, sent), CodeInvalidField)
		require.Equal(t, []FieldError{want}, p.Errors, sent)
		require.NotContains(t, p.Detail+p.Errors[0].Message, other)
	}

	forbidden := decodeProblem(t, postJSON(api, Prefix+"/debug/nodes", keysToken(t, b, []string{"tag:ci"}, "devices:core"), body), CodeForbidden)
	require.Equal(t, []any{"all"}, forbidden.Details["scopes"])
}

// TestRegisterAuthRequestErrors: each error of a registration that is not
// a fault of the server has an answer, and the request still waits after
// it. A node that asks for tags its user may give joins tagged.
func TestRegisterAuthRequestErrors(t *testing.T) {
	b, api, auth, alice, bob := authKeysAPI(t)

	_, _, err := b.State.UpdatePolicy([]byte(`{
		"tagOwners": {"tag:prod": ["alice@"], "tag:other": []},
		"acls": [{"action": "accept", "src": ["*"], "dst": ["*:*"]}]
	}`))
	require.NoError(t, err)
	// alice was made beside the State; the policy learns users from it.
	require.NoError(t, b.State.UpdatePolicyManagerUsersForTest())

	body := `{"userId": "` + userIDOf(alice) + `"}`
	registration := func(t *testing.T, data types.RegistrationData) (types.AuthID, *types.AuthRequest) {
		t.Helper()

		id := types.MustAuthID()
		req := types.NewRegisterAuthRequest(&data)
		require.NoError(t, b.State.SetAuthCacheEntry(id, req))

		return id, req
	}

	t.Run("tags the user may give", func(t *testing.T) {
		id, req := registration(t, types.RegistrationData{
			MachineKey: key.NewMachine().Public(), NodeKey: key.NewNode().Public(), Hostname: "prod",
			Hostinfo: &tailcfg.Hostinfo{Hostname: "prod", RequestTags: []string{"tag:prod"}},
		})

		rec := postJSON(api, authRequestPath(id, "register"), auth, body)
		require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())

		var n Node
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &n))
		require.Nil(t, n.Owner.User, "owned by its tags")
		require.Equal(t, []string{"tag:prod"}, n.Owner.Tags)
		require.Equal(t, n.ID, verdictOf(t, req).Node.StringID())
	})

	t.Run("tags the user may not give", func(t *testing.T) {
		id, req := registration(t, types.RegistrationData{
			MachineKey: key.NewMachine().Public(), NodeKey: key.NewNode().Public(), Hostname: "other",
			Hostinfo: &tailcfg.Hostinfo{Hostname: "other", RequestTags: []string{"tag:prod", "tag:other"}},
		})

		p := secretProblem(t, postJSON(api, authRequestPath(id, "register"), auth, body), CodeTagsNotPermitted, id)
		require.Equal(t, []any{"tag:other"}, p.Details["tags"])
		require.Equal(t, &ProblemObject{Kind: "authRequest", Name: "other"}, p.Object)
		require.False(t, req.IsFinished(), "the request still waits")
	})

	t.Run("a node key another machine has", func(t *testing.T) {
		_, _, nodes := pendingSSHCheck(t, b, alice)
		id, req := registration(t, types.RegistrationData{
			MachineKey: key.NewMachine().Public(), NodeKey: nodes[0].NodeKey(), Hostname: "cloned",
			Hostinfo: &tailcfg.Hostinfo{Hostname: "cloned"},
		})

		p := secretProblem(t, postJSON(api, authRequestPath(id, "register"), auth, body), CodeRegistrationRefused, id)
		require.Equal(t, "nodeKeyInUse", p.Details["reason"])
		require.False(t, req.IsFinished(), "the request still waits")
	})

	t.Run("a report over the limit", func(t *testing.T) {
		_, _, nodes := pendingSSHCheck(t, b, alice)
		big := nodes[0].AsStruct()
		big.Hostinfo = &tailcfg.Hostinfo{Hostname: big.Hostname, OSVersion: "v"}
		encoded, err := json.Marshal(big.Hostinfo)
		require.NoError(t, err)

		big.Hostinfo.OSVersion = strings.Repeat("v", types.MaxHostinfoSize-len(encoded))
		b.State.PutNodeInStoreForTest(*big)

		hostname := strings.Repeat("h", types.MaxHostnameLength)
		id, req := registration(t, types.RegistrationData{
			MachineKey: big.MachineKey, NodeKey: key.NewNode().Public(), Hostname: hostname,
			Hostinfo: &tailcfg.Hostinfo{Hostname: hostname},
		})

		p := secretProblem(t, postJSON(api, authRequestPath(id, "register"), auth, body), CodeRegistrationRefused, id)
		require.Equal(t, "reportTooLarge", p.Details["reason"])
		require.False(t, req.IsFinished(), "the request still waits")

		// Only the merge with alice's node is too large: bob has no node of
		// this machine, so the machine joins as a new node of bob.
		rec := postJSON(api, authRequestPath(id, "register"), auth, `{"userId": "`+userIDOf(bob)+`"}`)
		require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
	})
}

// TestRegistrationErrorsAnswered walks the errors the registration can
// hand back: every sentinel named in State.HandleNodeFromAuthPath and what
// it calls in the state package, and the few that come from other
// packages. Each has an answer that is not internal, or is a fault of the
// server listed here with why. A new error fails this test until it is one
// or the other.
func TestRegistrationErrorsAnswered(t *testing.T) {
	answered := map[string]Code{
		"ErrNodeNotFoundRegistrationCache":      CodeNotFound,
		"ErrAuthRequestKind":                    CodeAuthRequestKind,
		"ErrRequestedTagsInvalidOrNotPermitted": CodeTagsNotPermitted,
		"ErrNodeKeyInUse":                       CodeRegistrationRefused,
		"ErrHostinfoTooLarge":                   CodeRegistrationRefused, // types.ValidateHostinfo
		"ErrUserNotFound":                       CodeInvalidField,        // the read of the user
	}
	faults := map[string]string{
		"ErrNodeHasNeitherUserNorTags":    "the ownership the server built is wrong",
		"ErrNodeMarkedTaggedButHasNoTags": "the ownership the server built is wrong",
		"ErrTaggedNodeHasUser":            "the ownership the server built is wrong",
		"ErrInvalidNodeView":              "the server lost the node it was writing",
		"ErrNodeNotFound":                 "the server lost the node it was writing",
		"ErrNodeNotInNodeStore":           "a node of the machine went away beside the registration, which the server does not retry",
		"ErrNodeStoreStopped":             "the server is shutting down",
	}

	var unknown []string

	for _, name := range registrationErrors(t) {
		_, ok := answered[name]
		_, fault := faults[name]

		if !ok && !fault {
			unknown = append(unknown, name)
		}
	}

	require.Empty(t, unknown, "answer each in registrationProblem or the register handler, or list it as a fault")

	errs := map[string]error{
		"ErrRequestedTagsInvalidOrNotPermitted": &state.TagsNotPermittedError{Tags: []string{"tag:x"}},
		"ErrNodeKeyInUse":                       state.ErrNodeKeyInUse,
		"ErrHostinfoTooLarge":                   fmt.Errorf("%w: big", types.ErrHostinfoTooLarge),
	}
	for name, err := range errs {
		p := registrationProblem(err)
		require.NotNil(t, p, name)
		require.Equal(t, answered[name], p.Code, name)
	}

	for name := range faults {
		require.Nil(t, registrationProblem(errors.New(name)), name) //nolint:err113 // a name, to show it is not answered
	}
}

// registrationErrors is every Err... name in HandleNodeFromAuthPath and in
// every function of the state package it reaches, followed by name through
// any call (s.X, s.nodeStore.X, a view's X), so it may follow too much. It
// does not enter other packages: what db, ipAlloc, types or the policy
// return is the hand list of TestRegistrationErrorsAnswered, as are errors
// held in a variable rather than named.
func registrationErrors(t *testing.T) []string {
	t.Helper()

	fset := token.NewFileSet()
	funcs := map[string][]*ast.FuncDecl{}

	files, err := filepath.Glob("../../../state/*.go")
	require.NoError(t, err)
	require.NotEmpty(t, files)

	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}

		af, err := parser.ParseFile(fset, f, nil, 0)
		require.NoError(t, err)

		for _, d := range af.Decls {
			if fd, ok := d.(*ast.FuncDecl); ok && fd.Body != nil {
				funcs[fd.Name.Name] = append(funcs[fd.Name.Name], fd)
			}
		}
	}

	seen := map[string]bool{}
	found := map[string]bool{}
	queue := []string{"HandleNodeFromAuthPath"}

	for len(queue) > 0 {
		name := queue[0]
		queue = queue[1:]

		if seen[name] {
			continue
		}

		seen[name] = true

		for _, fd := range funcs[name] {
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				switch e := n.(type) {
				case *ast.CallExpr:
					switch f := e.Fun.(type) {
					case *ast.Ident:
						queue = append(queue, f.Name)
					case *ast.SelectorExpr:
						// Any receiver: s.X, s.nodeStore.X, a view's X.
						// Only names the state package defines are
						// followed, by name, so it may follow too much.
						queue = append(queue, f.Sel.Name)
					}
				case *ast.Ident:
					if len(e.Name) > 3 && strings.HasPrefix(e.Name, "Err") && unicode.IsUpper(rune(e.Name[3])) {
						found[e.Name] = true
					}
				}

				return true
			})
		}
	}

	require.True(t, seen["createAndSaveNewNode"], "the walk reaches the write of a new node")

	return slices.Sorted(maps.Keys(found))
}

// TestCreateDebugNodeFull: a server that holds as many auth requests as it
// may cannot make one now, which is no fault of the server.
func TestCreateDebugNodeFull(t *testing.T) {
	cfg := config.Default()
	cfg.Database.Type = types.DatabaseSqlite
	cfg.Database.Sqlite.Path = t.TempDir() + "/headscale.db"
	cfg.Tuning.RegisterCacheMaxEntries = 1

	st, err := state.NewState(&cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })

	b := Backend{State: st, Change: func(...change.Change) {}, Cfg: &cfg, Connected: func(types.NodeID) bool { return false }}
	pendingRegistration(t, b, "first")

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, Prefix+"/debug/nodes",
		strings.NewReader(`{"authId": "`+string(types.MustAuthID())+`", "hostname": "h", "routes": []}`))
	req.Header.Set("Content-Type", "application/json")

	rec := httptest.NewRecorder()
	WithLocalTrust(Handler(b)).ServeHTTP(rec, req)

	decodeProblem(t, rec, CodeUnhealthy)
	require.Contains(t, rec.Body.String(), `"code":"`+string(ReasonAuthRequestsFull)+`"`)
}
