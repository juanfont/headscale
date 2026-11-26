package apiv0

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/juanfont/headscale/hscontrol/db"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/require"
)

// TestNodeLastSeenMicro: lastSeen is written to the microsecond, for a
// node online now as for one seen before, as every time of v0 is.
func TestNodeLastSeenMicro(t *testing.T) {
	t.Parallel()

	now := time.Now().UTC().Truncate(time.Second).Add(123456789)
	seen := now.Add(-time.Hour)

	online := nodeFromView((&types.Node{ID: 1, ActiveSessions: 1}).View(), nil, now, "")
	offline := nodeFromView((&types.Node{ID: 2, LastSeen: &seen}).View(), nil, now, "")

	require.Equal(
		t,
		[]time.Time{now.Truncate(time.Microsecond), seen.Truncate(time.Microsecond)},
		[]time.Time{*online.LastSeen, *offline.LastSeen},
	)
}

// TestAPIKeyExpiredAtTheCheck: the state of an API key is expired exactly
// when the check of a key refuses it as expired, also within the
// microsecond v0 writes.
func TestAPIKeyExpiredAtTheCheck(t *testing.T) {
	t.Parallel()

	now := time.Now().UTC().Truncate(time.Microsecond)

	for _, at := range []time.Duration{-time.Microsecond, -time.Nanosecond, 0, 500, time.Microsecond} {
		exp := now.Add(at)
		state := apiKeyFromView(
			(&types.Credential{Expiration: &exp}).View(),
			now,
			0,
		).State
		require.Equal(
			t,
			types.ExpiredAt(exp, now),
			state == APIKeyExpired,
			"expiry %s from now: %s",
			at,
			state,
		)
	}
}

// TestCredentialsAnswerAlike: auth keys, API keys and OAuth clients answer
// the same things in the same cases: the secret in the 201 and in no other
// answer or log line, a get after the revoke, a repeated delete, and removal
// in each of its states.
func TestCredentialsAnswerAlike(t *testing.T) {
	var logged bytes.Buffer

	old, oldLevel := log.Logger, zerolog.GlobalLevel()
	log.Logger = zerolog.New(&logged).Level(zerolog.TraceLevel)
	zerolog.SetGlobalLevel(zerolog.TraceLevel)

	t.Cleanup(func() {
		log.Logger = old

		zerolog.SetGlobalLevel(oldLevel)
	})

	b, api, auth, _, _ := authKeysAPI(t)

	for _, k := range []struct {
		kind, path, body string
	}{
		{"auth key", "/auth-keys", `{"tags": ["tag:ci"], "expiry": "` + inAnHour() + `"}`},
		{"API key", "/api-keys", `{"expiry": "` + inAnHour() + `"}`},
		{"OAuth client", "/oauth-clients", `{"scopes": ["auth_keys"], "tags": ["tag:ci"]}`},
	} {
		t.Run(k.kind, func(t *testing.T) {
			rec := api.Post(
				Prefix+k.path,
				auth,
				"Content-Type: application/json",
				strings.NewReader(k.body),
			)
			require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())

			var made map[string]any
			require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &made))

			id, _ := made["id"].(string)
			key, _ := made["key"].(string)
			secret := key[strings.LastIndex(key, "-")+1:]
			require.Len(t, secret, 64)

			get := func() map[string]any {
				rec := api.Get(Prefix+k.path+"/"+id, auth)
				require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

				var m map[string]any
				require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &m))

				return m
			}

			valid := get()
			require.Equal(t, "valid", valid["state"])
			require.Nil(t, valid["revoked"])
			require.Nil(t, valid["removal"], "not revoked")
			require.NotContains(t, valid, "key")

			require.Equal(
				t,
				http.StatusNoContent,
				api.Delete(Prefix+k.path+"/"+id, auth).Code,
			)

			revoked := get()
			require.Equal(t, "revoked", revoked["state"])

			revokedAt, _ := revoked["revoked"].(string)
			at, err := time.Parse(time.RFC3339Nano, revokedAt)
			require.NoError(t, err)
			require.Equal(
				t,
				at.Add(7*24*time.Hour).Format(time.RFC3339Nano),
				revoked["removal"],
				"after the retention",
			)

			again := api.Delete(Prefix+k.path+"/"+id, auth)
			require.Equal(t, http.StatusNoContent, again.Code)
			require.Empty(t, again.Body.String())
			require.Equal(t, revoked, get(), "a repeated delete changes nothing")

			b.Cfg.Credentials.RevokedRetention = 0
			kept := get()
			b.Cfg.Credentials.RevokedRetention = 7 * 24 * time.Hour

			require.Nil(t, kept["removal"], "kept for ever")

			for _, rec := range []*httptest.ResponseRecorder{
				api.Get(Prefix+k.path, auth),
				api.Get(Prefix+k.path+"/"+id, auth),
				api.Get(Prefix+k.path+"/"+key, auth),
				api.Delete(Prefix+k.path+"/"+key, auth),
				api.Get(Prefix+"/me", "Authorization: Bearer "+key),
			} {
				require.NotContains(t, rec.Body.String(), secret)
			}

			require.NotContains(t, logged.String(), secret)
		})
	}

	require.NotEmpty(t, logged.String(), "the log was written")
}

// TestCredentialEndedDuringItsRequest: a create that a credential asked for
// before its revoke answered, and that writes after it, is refused and
// answered unauthorized. The write checks the credential in its own
// transaction; db's TestCredentialMadeByAnEndedCredential holds that.
func TestCredentialEndedDuringItsRequest(t *testing.T) {
	b, _, _, _, _ := authKeysAPI(t) //nolint:dogsled // the backend is all it needs

	_, key, err := b.State.CreateAPIKey(new(time.Now().Add(time.Hour)))
	require.NoError(t, err)

	// Authenticated, then revoked before the handler writes.
	ctx := context.WithValue(
		t.Context(),
		callerKey,
		allAccess(
			principal{kind: PrincipalAPIKey},
			&credential{kind: CredentialAPIKey, id: key.ID},
		),
	)
	require.NoError(t, b.State.RevokeAPIKey(key.ID))

	_, err = b.createAuthKey(ctx, CreateAuthKeyBody{
		Tags:   Optional[[]string]{Set: true, Value: []string{"tag:ci"}},
		Expiry: Optional[time.Time]{Set: true, Value: time.Now().Add(time.Hour)},
	})
	require.ErrorIs(t, err, db.ErrCredentialEnded)

	_, err = b.createOAuthClient(ctx, CreateOAuthClientBody{Scopes: []string{"users"}})
	require.ErrorIs(t, err, db.ErrCredentialEnded)

	p, ok := errors.AsType[*Problem](
		mapError(ctx, err, []Code{CodeUnauthorized, CodeInternal}, nil),
	)
	require.True(t, ok)
	require.Equal(t, CodeUnauthorized, p.Code)
}

// requireAnswer compares the whole JSON answer got with want, so a member
// that is missing, extra or renamed fails, which a Go struct would drop.
func requireAnswer(t *testing.T, want string, got []byte) {
	t.Helper()

	var w, g any
	require.NoError(t, json.Unmarshal([]byte(want), &w), want)
	require.NoError(t, json.Unmarshal(got, &g), string(got))

	if d := cmp.Diff(w, g); d != "" {
		t.Fatalf("answer (-want +got):\n%s", d)
	}
}

func rfc3339(t time.Time) string { return t.Format(time.RFC3339Nano) }

// TestCredentialAnswersWhole: every member of an API key and an OAuth client,
// with each kind of owner and maker, and a problem. A time another API
// stored is answered to the microsecond, as 002 has a time.
func TestCredentialAnswersWhole(t *testing.T) {
	b, api, auth, alice, bob := authKeysAPI(t)

	aliceID := strconv.FormatUint(uint64(alice.ID), 10)
	bobID := strconv.FormatUint(uint64(bob.ID), 10)
	nanos := time.Date(2099, time.January, 2, 3, 4, 5, 123456789, time.UTC)

	t.Run("an API key with an owner", func(t *testing.T) {
		rec := postAPIKey(
			api,
			auth,
			`{"userId": "`+aliceID+`", "expiry": "2099-01-02T03:04:05Z"}`,
		)
		k := decodeCreatedAPIKey(t, rec)
		requireAnswer(t, `{"id": "`+k.ID+`", "prefix": "`+k.Prefix+`",
			"owner": {"user": {"id": "`+aliceID+`", "name": "alice", "loginName": "alice", "displayName": "", "email": ""}, "tags": []},
			"state": "valid", "expiry": "2099-01-02T03:04:05Z", "created": "`+rfc3339(*k.Created)+`",
			"lastSeen": null, "revoked": null, "removal": null, "key": "`+k.Key+`"}`, rec.Body.Bytes())
	})

	t.Run("an API key with no owner, revoked", func(t *testing.T) {
		k := decodeCreatedAPIKey(
			t,
			postAPIKey(api, auth, `{"expiry": "2099-01-02T03:04:05Z"}`),
		)
		require.Equal(
			t,
			http.StatusNoContent,
			api.Delete(Prefix+"/api-keys/"+k.ID, auth).Code,
		)

		rec := api.Get(Prefix+"/api-keys/"+k.ID, auth)
		got := getAPIKey(t, api, auth, k.ID)
		requireAnswer(t, `{"id": "`+k.ID+`", "prefix": "`+k.Prefix+`", "owner": null,
			"state": "revoked", "expiry": "2099-01-02T03:04:05Z", "created": "`+rfc3339(*k.Created)+`",
			"lastSeen": null, "revoked": "`+rfc3339(*got.Revoked)+`", "removal": "`+rfc3339(got.Revoked.Add(7*24*time.Hour))+`"}`, rec.Body.Bytes())
	})

	t.Run("an API key made by the old API", func(t *testing.T) {
		_, old, err := b.State.CreateAPIKey(&nanos)
		require.NoError(t, err)

		stored, err := b.State.GetAPIKeyCredential(old.ID)
		require.NoError(t, err)

		id := strconv.FormatUint(old.ID, 10)
		requireAnswer(t, `{"id": "`+id+`", "prefix": "`+old.Prefix+`", "owner": null,
			"state": "valid", "expiry": "2099-01-02T03:04:05.123456Z", "created": "`+rfc3339(micro(*stored.CreatedAt))+`",
			"lastSeen": null, "revoked": null, "removal": null}`, api.Get(Prefix+"/api-keys/"+id, auth).Body.Bytes())
	})

	t.Run("an OAuth client", func(t *testing.T) {
		rec := postClient(
			api,
			auth,
			`{"scopes": ["auth_keys"], "tags": ["tag:ci"], "description": "runners"}`,
		)
		c := decodeCreatedClient(t, rec)
		requireAnswer(
			t,
			`{"id": "`+c.ID+`", "description": "runners", "scopes": ["auth_keys"], "tags": ["tag:ci"],
			"createdBy": {"id": "`+bobID+`", "loginName": "bob"}, "created": "`+rfc3339(
				*c.Created,
			)+`",
			"state": "valid", "revoked": null, "removal": null, "key": "`+c.Key+`"}`,
			rec.Body.Bytes(),
		)
	})

	t.Run("an OAuth client a token made", func(t *testing.T) {
		rec := postClient(
			api,
			keysToken(t, b, nil, "oauth_keys"),
			`{"scopes": ["oauth_keys:read"]}`,
		)
		c := decodeCreatedClient(t, rec)
		requireAnswer(
			t,
			`{"id": "`+c.ID+`", "description": "", "scopes": ["oauth_keys:read"], "tags": [],
			"createdBy": null, "created": "`+rfc3339(
				*c.Created,
			)+`",
			"state": "valid", "revoked": null, "removal": null, "key": "`+c.Key+`"}`,
			rec.Body.Bytes(),
		)
	})

	t.Run("an OAuth client made by /api/v2", func(t *testing.T) {
		_, made, err := b.State.CreateOAuthClient([]string{"users"}, nil, "", nil)
		require.NoError(t, err)

		requireAnswer(
			t,
			`{"id": "`+made.ClientID+`", "description": "", "scopes": ["users"], "tags": [],
			"createdBy": null, "created": "`+rfc3339(
				micro(*made.CreatedAt),
			)+`",
			"state": "valid", "revoked": null, "removal": null}`,
			api.Get(Prefix+"/oauth-clients/"+made.ClientID, auth).Body.Bytes(),
		)
	})

	t.Run("the expiry of a token", func(t *testing.T) {
		_, client, err := b.State.CreateOAuthClient(
			[]string{"oauth_keys"},
			nil,
			"",
			nil,
		)
		require.NoError(t, err)

		token, _, err := b.State.MintAccessToken(
			client.ClientID,
			[]string{"oauth_keys"},
			nil,
			&nanos,
		)
		require.NoError(t, err)

		var me Me
		require.NoError(
			t,
			json.Unmarshal(
				api.Get(Prefix+"/me", "Authorization: Bearer "+token).Body.Bytes(),
				&me,
			),
		)
		require.Equal(t, micro(nanos), *me.Credential.Expiry)
	})

	t.Run("a problem", func(t *testing.T) {
		requireAnswer(
			t,
			`{"type": "https://headscale.net/stable/ref/api/problems/#invalid_scope", "title": "The scope does not exist",
			"status": 422, "code": "invalid_scope", "detail": "Every scope must be one the server knows; details.scopes names the others.",
			"requestId": "", "object": null, "errors": [], "details": {"scopes": ["nope"]}}`,
			postClient(api, auth, `{"scopes": ["nope"]}`).Body.Bytes(),
		)
	})
}

// TestCredentialOperationsAnswerTheirCodes: the codes the operations of API
// keys and OAuth clients declare that no other test makes.
func TestCredentialOperationsAnswerTheirCodes(t *testing.T) {
	_, api, auth, alice, _ := authKeysAPI(t)

	k := decodeCreatedAPIKey(t, postAPIKey(api, auth, `{"expiry": "`+inAnHour()+`"}`))
	c := decodeCreatedClient(t, postClient(api, auth, `{"scopes": ["users"]}`))
	decodeCreatedClient(t, postClient(api, auth, `{"scopes": ["users"]}`))

	// A token the server made, for the first page of size one.
	next := func(query string) string {
		var page struct{ NextPageToken string }
		require.NoError(
			t,
			json.Unmarshal(
				api.Get(Prefix+query+"pageSize=1", auth).Body.Bytes(),
				&page,
			),
		)
		require.NotEmpty(t, page.NextPageToken, query)

		return page.NextPageToken
	}

	keys, clients := next("/api-keys?"), next("/oauth-clients?")

	for _, tt := range []struct{ path, own, other string }{{"/api-keys", keys, clients}, {"/oauth-clients", clients, keys}} {
		t.Run("a page token not of this list "+tt.path, func(t *testing.T) {
			require.Equal(
				t,
				http.StatusOK,
				api.Get(
					Prefix+tt.path+"?pageSize=1&pageToken="+url.QueryEscape(tt.own),
					auth,
				).Code,
				"its own token",
			)
			decodeProblem(
				t,
				api.Get(
					Prefix+tt.path+"?pageSize=1&pageToken="+url.QueryEscape(tt.other),
					auth,
				),
				CodeInvalidPageToken,
			)
			decodeProblem(
				t,
				api.Get(Prefix+tt.path+"?pageSize=1&pageToken=nope", auth),
				CodeInvalidPageToken,
			)
		})
	}

	t.Run("a page token with a byte changed", func(t *testing.T) {
		forged := []byte(keys)
		forged[len(forged)/2] ^= 1
		decodeProblem(
			t,
			api.Get(
				Prefix+"/api-keys?pageSize=1&pageToken="+url.QueryEscape(
					string(forged),
				),
				auth,
			),
			CodeInvalidPageToken,
		)
	})

	t.Run("a page token for another filter", func(t *testing.T) {
		decodeProblem(
			t,
			api.Get(
				Prefix+"/api-keys?pageSize=1&user="+strconv.FormatUint(
					uint64(alice.ID),
					10,
				)+"&pageToken="+url.QueryEscape(
					keys,
				),
				auth,
			),
			CodeInvalidPageToken,
		)
	})

	for _, path := range []string{"/api-keys/" + k.ID, "/oauth-clients/" + c.ID} {
		t.Run("an unknown query parameter "+path, func(t *testing.T) {
			p := decodeProblem(
				t,
				api.Get(Prefix+path+"?state=valid", auth),
				CodeInvalidField,
			)
			require.Equal(t, "query.state", p.Errors[0].Location)

			p = decodeProblem(
				t,
				api.Delete(Prefix+path+"?state=valid", auth),
				CodeInvalidField,
			)
			require.Equal(t, "query.state", p.Errors[0].Location)
		})
	}
}
