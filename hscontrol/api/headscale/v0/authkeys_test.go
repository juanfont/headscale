package apiv0

import (
	"bytes"
	"context"
	"encoding/json"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/danielgtaylor/huma/v2/humatest"
	"github.com/google/go-cmp/cmp"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

const authKeysPolicy = `{
	"tagOwners": {"tag:ci": [], "tag:build": [], "tag:web": ["tag:ci"], "tag:prod": []},
	"acls": [{"action": "accept", "src": ["*"], "dst": ["*:*"]}]
}`

// authKeysAPI is v0 with the policy and alice, with the header of an API
// key bob owns.
func authKeysAPI(t *testing.T) (Backend, humatest.TestAPI, string, *types.User, *types.User) {
	t.Helper()

	b := newBackend(t)

	_, _, err := b.State.UpdatePolicy([]byte(authKeysPolicy))
	require.NoError(t, err)

	alice := b.State.CreateUserForTest("alice")
	bob := b.State.CreateUserForTest("bob")

	apiKey, stored, err := b.State.CreateAPIKey(nil)
	require.NoError(t, err)
	require.NoError(t, b.State.SetAPIKeyUser(stored.ID, types.UserID(bob.ID)))

	return b, newTestAPI(t, b), "Authorization: Bearer " + apiKey, alice, bob
}

// keysToken is an OAuth access token with scopes that holds tags.
func keysToken(t *testing.T, b Backend, tags []string, scopes ...string) string {
	t.Helper()

	_, client, err := b.State.CreateOAuthClient(scopes, tags, "", nil)
	require.NoError(t, err)

	token, _, err := b.State.MintAccessToken(client.ClientID, scopes, tags, new(time.Now().Add(time.Hour)))
	require.NoError(t, err)

	return "Authorization: Bearer " + token
}

func inAnHour() string { return time.Now().Add(time.Hour).UTC().Format(time.RFC3339) }

func postKey(api humatest.TestAPI, auth, body string) *httptest.ResponseRecorder {
	return api.Post(Prefix+"/auth-keys", auth, "Content-Type: application/json", strings.NewReader(body))
}

func decodeCreated(t *testing.T, rec *httptest.ResponseRecorder) CreatedAuthKey {
	t.Helper()

	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())

	var k CreatedAuthKey
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &k), rec.Body.String())

	return k
}

func getKey(t *testing.T, api humatest.TestAPI, auth, id string) AuthKey {
	t.Helper()

	rec := api.Get(Prefix+"/auth-keys/"+id, auth)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	var k AuthKey
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &k))

	return k
}

// join registers a new node with the key.
func join(t *testing.T, b Backend, secret string) error {
	t.Helper()

	_, _, err := b.State.HandleNodeFromPreAuthKey(tailcfg.RegisterRequest{
		Auth:     &tailcfg.RegisterResponseAuth{AuthKey: secret},
		NodeKey:  key.NewNode().Public(),
		Hostinfo: &tailcfg.Hostinfo{Hostname: "joiner"},
	}, key.NewMachine().Public())

	return err
}

func TestCreateAuthKey(t *testing.T) {
	b, api, auth, alice, bob := authKeysAPI(t)

	t.Run("a tagged key", func(t *testing.T) {
		expiry := time.Now().Add(7 * 24 * time.Hour).UTC().Truncate(time.Second)
		rec := postKey(api, auth, `{"tags": ["tag:ci", "tag:build", "tag:ci"], "ephemeral": true, "expiry": "`+expiry.Format(time.RFC3339)+`", "description": "CI runners"}`)
		k := decodeCreated(t, rec)

		require.Equal(t, Prefix+"/auth-keys/"+k.ID, rec.Header().Get("Location"))
		require.True(t, strings.HasPrefix(k.Key, "hskey-auth-"+k.Prefix+"-"), "the secret carries its prefix")
		require.Equal(t, &Owner{Tags: []string{"tag:build", "tag:ci"}}, k.Owner)
		require.Equal(t, &UserReference{ID: strconv.FormatUint(uint64(bob.ID), 10), LoginName: "bob"}, k.CreatedBy, "the owner of the API key")
		require.Equal(t, AuthKeyValid, k.State)
		require.True(t, k.Ephemeral)
		require.False(t, k.Reusable)
		require.Equal(t, expiry, *k.Expiry)
		require.Equal(t, "CI runners", k.Description)
		require.Nil(t, k.Revoked)
		require.Nil(t, k.Removal)

		require.Equal(t, k.AuthKey, getKey(t, api, auth, k.ID), "a get answers the same key, without the secret")
		require.NoError(t, join(t, b, k.Key), "the key works")
	})

	t.Run("a user's key", func(t *testing.T) {
		k := decodeCreated(t, postKey(api, auth, `{"userId": "`+strconv.FormatUint(uint64(alice.ID), 10)+`", "reusable": true, "expiry": "`+inAnHour()+`"}`))
		require.Equal(t, "alice", k.Owner.User.LoginName)
		require.Equal(t, []string{}, k.Owner.Tags)
		require.Equal(t, "bob", k.CreatedBy.LoginName, "made by bob's key, owned by alice")
		require.True(t, k.Reusable)
	})

	t.Run("an API key with no owner records no creator", func(t *testing.T) {
		bare, _, err := b.State.CreateAPIKey(nil)
		require.NoError(t, err)

		k := decodeCreated(t, postKey(api, "Authorization: Bearer "+bare, `{"tags": ["tag:ci"], "expiry": "`+inAnHour()+`"}`))
		require.Nil(t, k.CreatedBy)
	})

	for _, tt := range []struct {
		name string
		body string
		want Code
		at   []string
	}{
		{"both owners", `{"userId": "1", "tags": ["tag:ci"], "expiry": "` + inAnHour() + `"}`, CodeOwnerConflict, nil},
		{"neither owner", `{"expiry": "` + inAnHour() + `"}`, CodeOwnerConflict, nil},
		{"an empty tag list", `{"tags": [], "expiry": "` + inAnHour() + `"}`, CodeTagsRequired, nil},
		{"a user and an empty tag list", `{"userId": "1", "tags": [], "expiry": "` + inAnHour() + `"}`, CodeOwnerConflict, nil},
		{"no expiry", `{"tags": ["tag:ci"]}`, CodeExpiryRequired, nil},
		{"an expiry in the past", `{"tags": ["tag:ci"], "expiry": "2020-01-01T00:00:00Z"}`, CodeExpiryInPast, nil},
		{"a null expiry is no expiry", `{"tags": ["tag:ci"], "expiry": null}`, CodeExpiryRequired, nil},
		{"an expiry that is not a time", `{"tags": ["tag:ci"], "expiry": "next week"}`, CodeInvalidField, []string{"body.expiry"}},
		{"a userId that is not an ID", `{"userId": "alice", "expiry": "` + inAnHour() + `"}`, CodeInvalidField, []string{"body.userId"}},
		{"a userId no user has", `{"userId": "999", "expiry": "` + inAnHour() + `"}`, CodeInvalidField, []string{"body.userId"}},
		{"a control character in the description", `{"tags": ["tag:ci"], "expiry": "` + inAnHour() + `", "description": "a\u001b[31mb"}`, CodeInvalidField, []string{"body.description"}},
		{"a description too long", `{"tags": ["tag:ci"], "expiry": "` + inAnHour() + `", "description": "` + strings.Repeat("x", 51) + `"}`, CodeInvalidField, []string{"body.description"}},
		{"an unknown field", `{"tags": ["tag:ci"], "expiry": "` + inAnHour() + `", "preauthorized": true}`, CodeInvalidField, []string{"body.preauthorized"}},
		{"a field before the owner", `{"userId": "x", "tags": ["tag:ci"]}`, CodeInvalidField, []string{"body.userId"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			p := decodeProblem(t, postKey(api, auth, tt.body), tt.want)
			if tt.at != nil {
				require.Equal(t, tt.at, locations(p))
			}
		})
	}

	t.Run("tags the policy does not name", func(t *testing.T) {
		p := decodeProblem(t, postKey(api, auth, `{"tags": ["tag:ci", "tag:nope", "ci"], "expiry": "`+inAnHour()+`"}`), CodeTagsNotPermitted)
		require.Equal(t, []any{"ci", "tag:nope"}, p.Details["tags"])
	})

	t.Run("a refused create makes no key", func(t *testing.T) {
		before := listAll(t, api, auth, "")
		postKey(api, auth, `{"tags": ["tag:nope"], "expiry": "`+inAnHour()+`"}`)
		postKey(api, auth, `{"userId": "999", "expiry": "`+inAnHour()+`"}`)
		require.Equal(t, before, listAll(t, api, auth, ""))
	})
}

// TestCreateAuthKeyTokenRules holds a token to its tags and away from users.
func TestCreateAuthKeyTokenRules(t *testing.T) {
	b, api, auth, alice, _ := authKeysAPI(t)

	token := keysToken(t, b, []string{"tag:ci"}, "auth_keys")
	userID := strconv.FormatUint(uint64(alice.ID), 10)

	t.Run("a tag it holds and one its tag owns", func(t *testing.T) {
		k := decodeCreated(t, postKey(api, token, `{"tags": ["tag:ci", "tag:web"], "expiry": "`+inAnHour()+`"}`))
		require.Nil(t, k.CreatedBy, "a token stands for a client, never a person")

		stored, _, err := b.State.GetAuthKey(mustID(t, k.ID))
		require.NoError(t, err)
		require.True(t, stored.CreatedByToken)
	})

	for name, body := range map[string]string{
		"a tag it does not own":        `{"tags": ["tag:build"], "expiry": "` + inAnHour() + `"}`,
		"one tag of two it cannot own": `{"tags": ["tag:ci", "tag:prod"], "expiry": "` + inAnHour() + `"}`,
	} {
		t.Run(name, func(t *testing.T) {
			p := decodeProblem(t, postKey(api, token, body), CodeForbidden)
			require.Equal(t, "token_must_own_tags", p.Details["rule"])
			require.Equal(t, []any{}, p.Details["scopes"])
		})
	}

	for name, body := range map[string]string{
		"a user's key":               `{"userId": "` + userID + `", "expiry": "` + inAnHour() + `"}`,
		"a user no one is, no owner": `{"userId": "999", "expiry": "` + inAnHour() + `"}`,
	} {
		t.Run(name, func(t *testing.T) {
			p := decodeProblem(t, postKey(api, token, body), CodeForbidden)
			require.Equal(t, "token_cannot_create_key_for_user", p.Details["rule"])
		})
	}

	// The rule is checked on a body that is right in itself.
	for name, tc := range map[string]struct {
		body string
		code Code
	}{
		"a user and tags":       {`{"userId": "` + userID + `", "tags": ["tag:ci"], "expiry": "` + inAnHour() + `"}`, CodeOwnerConflict},
		"a user that is no ID":  {`{"userId": "nobody"}`, CodeInvalidField},
		"a user given as null":  {`{"userId": null, "tags": ["tag:ci"], "expiry": "` + inAnHour() + `"}`, CodeInvalidField},
		"a user and no expiry":  {`{"userId": "` + userID + `"}`, CodeExpiryRequired},
		"a user, expiry passed": {`{"userId": "` + userID + `", "expiry": "2000-01-01T00:00:00Z"}`, CodeExpiryInPast},
	} {
		t.Run(name, func(t *testing.T) {
			decodeProblem(t, postKey(api, token, tc.body), tc.code)
		})
	}

	t.Run("a tag it holds that the policy does not name", func(t *testing.T) {
		gone := keysToken(t, b, []string{"tag:gone"}, "auth_keys")
		p := decodeProblem(t, postKey(api, gone, `{"tags": ["tag:gone"], "expiry": "`+inAnHour()+`"}`), CodeTagsNotPermitted)
		require.Equal(t, []any{"tag:gone"}, p.Details["tags"])
	})

	t.Run("the read scope makes no key", func(t *testing.T) {
		reader := keysToken(t, b, []string{"tag:ci"}, "auth_keys:read")
		p := decodeProblem(t, postKey(api, reader, `{"tags": ["tag:ci"], "expiry": "`+inAnHour()+`"}`), CodeForbidden)
		require.Equal(t, []any{"auth_keys"}, p.Details["scopes"])
		decodeProblem(t, api.Delete(Prefix+"/auth-keys/1", reader), CodeForbidden)
		require.Equal(t, http.StatusOK, api.Get(Prefix+"/auth-keys", reader).Code)
	})

	t.Run("an API key may make a key for a user", func(t *testing.T) {
		decodeCreated(t, postKey(api, auth, `{"userId": "`+userID+`", "expiry": "`+inAnHour()+`"}`))
	})
}

// TestAuthKeyTagsAgreeWithMe: authorization.tags of GET /me is what a web UI
// offers. For a token, every tag in it makes an auth key, and a tag outside
// it is refused by the token rule. Both read [State.TagsOwnedByTags].
func TestAuthKeyTagsAgreeWithMe(t *testing.T) {
	b, api, _, _, _ := authKeysAPI(t) //nolint:dogsled // only tokens call here

	for _, held := range [][]string{{"tag:ci"}, {"tag:build"}, {"tag:ci", "tag:prod"}, {}} {
		t.Run(strings.Join(held, ","), func(t *testing.T) {
			token := keysToken(t, b, held, "auth_keys")

			rec := api.Get(Prefix+"/me", token)
			require.Equal(t, http.StatusOK, rec.Code)

			var me Me
			require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &me))
			require.NotNil(t, me.Authorization.Tags)

			for _, tag := range []string{"tag:ci", "tag:build", "tag:web", "tag:prod"} {
				rec := postKey(api, token, `{"tags": ["`+tag+`"], "expiry": "`+inAnHour()+`"}`)
				if slices.Contains(me.Authorization.Tags, tag) {
					require.Equal(t, http.StatusCreated, rec.Code, "%s is in authorization.tags: %s", tag, rec.Body.String())

					continue
				}

				p := decodeProblem(t, rec, CodeForbidden)
				require.Equal(t, "token_must_own_tags", p.Details["rule"], tag)
			}
		})
	}
}

func mustID(t *testing.T, id string) uint64 {
	t.Helper()

	n, err := strconv.ParseUint(id, 10, 64)
	require.NoError(t, err)

	return n
}

// listAll walks the list two at a time with query and returns every key.
func listAll(t *testing.T, api humatest.TestAPI, auth, query string) []AuthKey {
	t.Helper()

	var (
		all   []AuthKey
		token string
	)

	for {
		q := "pageSize=2&" + query
		if token != "" {
			q += "&pageToken=" + url.QueryEscape(token)
		}

		rec := api.Get(Prefix+"/auth-keys?"+q, auth)
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		require.NotContains(t, rec.Body.String(), `"nextPageToken":""`)

		var l AuthKeyList
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &l))

		all = append(all, l.AuthKeys...)

		if l.NextPageToken == "" {
			return all
		}

		token = l.NextPageToken
	}
}

func TestListAuthKeys(t *testing.T) {
	b, api, auth, alice, bob := authKeysAPI(t)

	create := func(body string) CreatedAuthKey {
		return decodeCreated(t, postKey(api, auth, body))
	}

	valid := create(`{"tags": ["tag:ci"], "expiry": "` + inAnHour() + `"}`)
	used := create(`{"userId": "` + strconv.FormatUint(uint64(alice.ID), 10) + `", "expiry": "` + inAnHour() + `"}`)
	require.NoError(t, join(t, b, used.Key))

	reusedReusable := create(`{"tags": ["tag:build"], "reusable": true, "expiry": "` + inAnHour() + `"}`)
	require.NoError(t, join(t, b, reusedReusable.Key))

	revoked := create(`{"tags": ["tag:ci", "tag:build"], "expiry": "` + inAnHour() + `"}`)
	require.Equal(t, http.StatusNoContent, api.Delete(Prefix+"/auth-keys/"+revoked.ID, auth).Code)

	pastExpiry := time.Now().Add(-time.Hour)
	expired, err := b.State.CreatePreAuthKey(new(types.UserID(bob.ID)), false, false, &pastExpiry, nil)
	require.NoError(t, err)

	all := listAll(t, api, auth, "")

	state := map[string]AuthKeyState{}
	usedFlag := map[string]bool{}
	ids := make([]string, 0, len(all))

	for _, k := range all {
		ids = append(ids, k.ID)
		state[k.ID] = k.State
		usedFlag[k.ID] = k.Used
	}

	require.Equal(t, []string{valid.ID, used.ID, reusedReusable.ID, revoked.ID, strconv.FormatUint(expired.ID, 10)}, ids, "every key once, in ID order")
	require.Equal(t, map[string]AuthKeyState{
		valid.ID: AuthKeyValid, used.ID: AuthKeyUsed, reusedReusable.ID: AuthKeyValid,
		revoked.ID: AuthKeyRevoked, strconv.FormatUint(expired.ID, 10): AuthKeyExpired,
	}, state)
	require.True(t, usedFlag[reusedReusable.ID], "a reusable key a node joined with is used, and still valid")
	require.False(t, usedFlag[valid.ID])

	t.Run("revoked wins over used, used over expired", func(t *testing.T) {
		require.Equal(t, http.StatusNoContent, api.Delete(Prefix+"/auth-keys/"+used.ID, auth).Code)
		require.Equal(t, AuthKeyRevoked, getKey(t, api, auth, used.ID).State)

		gone := time.Now().Add(-time.Minute)
		k, err := b.State.CreatePreAuthKey(new(types.UserID(alice.ID)), false, false, &gone, nil)
		require.NoError(t, err)

		stored, _, err := b.State.GetAuthKey(k.ID)
		require.NoError(t, err)

		stored.Used = true

		require.Equal(t, AuthKeyUsed, authKeyFromView(stored.View(), false, time.Now(), 0).State)
	})

	t.Run("no answer but the create has a secret", func(t *testing.T) {
		for _, k := range []CreatedAuthKey{valid, used, reusedReusable, revoked} {
			secret := k.Key[len("hskey-auth-"+k.Prefix+"-"):]
			require.NotEmpty(t, secret)

			for _, rec := range []*httptest.ResponseRecorder{
				api.Get(Prefix+"/auth-keys?pageSize=1000", auth),
				api.Get(Prefix+"/auth-keys/"+k.ID, auth),
			} {
				require.NotContains(t, rec.Body.String(), secret)
			}
		}
	})

	t.Run("filters match the owner", func(t *testing.T) {
		byTag := listAll(t, api, auth, "tag=tag:ci")
		require.Equal(t, []string{valid.ID, revoked.ID}, keyIDs(byTag))

		byUser := listAll(t, api, auth, "user="+strconv.FormatUint(uint64(bob.ID), 10))
		require.Equal(t, []string{strconv.FormatUint(expired.ID, 10)}, keyIDs(byUser), "not the keys bob's API key made for tags or for alice")

		aliceID := strconv.FormatUint(uint64(alice.ID), 10)
		require.Contains(t, keyIDs(listAll(t, api, auth, "user="+aliceID)), used.ID)
		require.Empty(t, listAll(t, api, auth, "user="+aliceID+"&tag=tag:ci"), "both filters must match")

		require.Empty(t, listAll(t, api, auth, "user=999"))
		require.Empty(t, listAll(t, api, auth, "tag=tag:nope"))

		p := decodeProblem(t, api.Get(Prefix+"/auth-keys?user=bob", auth), CodeInvalidField)
		require.Equal(t, []string{"query.user"}, locations(p))
	})

	first := api.Get(Prefix+"/auth-keys?pageSize=2", auth)

	var l AuthKeyList
	require.NoError(t, json.Unmarshal(first.Body.Bytes(), &l))
	require.NotEmpty(t, l.NextPageToken)

	for name, query := range map[string]string{
		"forged":        "pageSize=2&pageToken=" + url.QueryEscape(l.NextPageToken[:len(l.NextPageToken)-2]+"AA"),
		"other filters": "pageSize=2&tag=tag:ci&pageToken=" + url.QueryEscape(l.NextPageToken),
		"another list": func() string {
			pg, _ := openPage[uint64](PageQuery{PageSize: 2}, "nodes", "", "")
			_, other := cutPage(pg, []uint64{1, 2, 3}, func(n uint64) uint64 { return n })

			return "pageSize=2&pageToken=" + url.QueryEscape(other)
		}(),
	} {
		t.Run("token "+name, func(t *testing.T) {
			decodeProblem(t, api.Get(Prefix+"/auth-keys?"+query, auth), CodeInvalidPageToken)
		})
	}
}

func keyIDs(ks []AuthKey) []string {
	out := make([]string, len(ks))
	for i, k := range ks {
		out[i] = k.ID
	}

	return out
}

func TestGetAuthKey(t *testing.T) {
	b, api, auth, alice, _ := authKeysAPI(t)

	for _, id := range []string{"999", "abc", "007", "0", "-1", "18446744073709551616"} {
		t.Run("not found "+id, func(t *testing.T) {
			decodeProblem(t, api.Get(Prefix+"/auth-keys/"+id, auth), CodeNotFound)
		})
	}

	t.Run("the key of a deleted user is removed with the user", func(t *testing.T) {
		carol := b.State.CreateUserForTest("carol")
		k := decodeCreated(t, postKey(api, auth, `{"userId": "`+strconv.FormatUint(uint64(carol.ID), 10)+`", "expiry": "`+inAnHour()+`"}`))

		_, err := b.State.DeleteUser(types.UserID(carol.ID))
		require.NoError(t, err)

		p := decodeProblem(t, api.Get(Prefix+"/auth-keys/"+k.ID, auth), CodeNotFound)
		require.Equal(t, &ProblemObject{Kind: "authKey", ID: k.ID}, p.Object)
	})

	t.Run("a tagged key outlives its creator, who is then unknown", func(t *testing.T) {
		dave := b.State.CreateUserForTest("dave")

		daveKey, stored, err := b.State.CreateAPIKey(nil)
		require.NoError(t, err)
		require.NoError(t, b.State.SetAPIKeyUser(stored.ID, types.UserID(dave.ID)))

		k := decodeCreated(t, postKey(api, "Authorization: Bearer "+daveKey, `{"tags": ["tag:ci"], "expiry": "`+inAnHour()+`"}`))
		require.Equal(t, "dave", k.CreatedBy.LoginName)

		_, err = b.State.DeleteUser(types.UserID(dave.ID))
		require.NoError(t, err)

		got := getKey(t, api, auth, k.ID)
		require.Nil(t, got.CreatedBy)
		require.Equal(t, AuthKeyValid, got.State)
	})

	t.Run("a key whose tag left the policy is shown as it is", func(t *testing.T) {
		k := decodeCreated(t, postKey(api, auth, `{"tags": ["tag:prod"], "expiry": "`+inAnHour()+`"}`))

		_, _, err := b.State.UpdatePolicy([]byte(strings.Replace(authKeysPolicy, `, "tag:prod": []`, "", 1)))
		require.NoError(t, err)
		require.False(t, b.State.TagExists("tag:prod"))

		got := getKey(t, api, auth, k.ID)
		require.Equal(t, []string{"tag:prod"}, got.Owner.Tags)
		require.Equal(t, AuthKeyValid, got.State, "the server does not revoke a key for the policy")

		decodeProblem(t, postKey(api, auth, `{"tags": ["tag:prod"], "expiry": "`+inAnHour()+`"}`), CodeTagsNotPermitted)
	})

	t.Run("a tagged key /api/v1 made for a named user has no known maker", func(t *testing.T) {
		legacy, err := b.State.CreatePreAuthKey(new(types.UserID(alice.ID)), false, false, nil, []string{"tag:ci"})
		require.NoError(t, err)

		got := getKey(t, api, auth, strconv.FormatUint(legacy.ID, 10))
		require.Nil(t, got.CreatedBy, "the user a request names need not be the maker")
		require.Equal(t, &Owner{Tags: []string{"tag:ci"}}, got.Owner)
	})
}

func TestDeleteAuthKey(t *testing.T) {
	b, api, auth, alice, _ := authKeysAPI(t)

	k := decodeCreated(t, postKey(api, auth, `{"tags": ["tag:ci"], "reusable": true, "expiry": "`+inAnHour()+`"}`))

	require.Equal(t, http.StatusNoContent, api.Delete(Prefix+"/auth-keys/"+k.ID, auth).Code)

	got := getKey(t, api, auth, k.ID)
	require.Equal(t, AuthKeyRevoked, got.State)
	require.NotNil(t, got.Revoked)
	require.Equal(t, got.Revoked.Add(7*24*time.Hour), *got.Removal, "removed after the retention")

	t.Run("again is 204 and changes nothing", func(t *testing.T) {
		rec := api.Delete(Prefix+"/auth-keys/"+k.ID, auth)
		require.Equal(t, http.StatusNoContent, rec.Code)
		require.Empty(t, rec.Body.String())
		require.Equal(t, got, getKey(t, api, auth, k.ID))
	})

	t.Run("a revoked key registers no node", func(t *testing.T) {
		require.ErrorContains(t, join(t, b, k.Key), "authkey revoked")
	})

	t.Run("a key a node refers to is kept", func(t *testing.T) {
		inUse := decodeCreated(t, postKey(api, auth, `{"userId": "`+strconv.FormatUint(uint64(alice.ID), 10)+`", "expiry": "`+inAnHour()+`"}`))
		require.NoError(t, join(t, b, inUse.Key))
		require.Equal(t, http.StatusNoContent, api.Delete(Prefix+"/auth-keys/"+inUse.ID, auth).Code)

		got := getKey(t, api, auth, inUse.ID)
		require.Equal(t, AuthKeyRevoked, got.State)
		require.Nil(t, got.Removal)
	})

	t.Run("a retention of 0 keeps it for ever", func(t *testing.T) {
		b.Cfg.Credentials.RevokedRetention = 0

		t.Cleanup(func() { b.Cfg.Credentials.RevokedRetention = 7 * 24 * time.Hour })

		require.Nil(t, getKey(t, api, auth, k.ID).Removal)
	})

	for _, id := range []string{"999", "abc", "007"} {
		t.Run("not found "+id, func(t *testing.T) {
			decodeProblem(t, api.Delete(Prefix+"/auth-keys/"+id, auth), CodeNotFound)
		})
	}
}

// TestAuthKeySecretIsNotLogged: the secret leaves the server in the answer
// to the create, and in no log line of the calls around it. The access log
// is the router's, not v0's: hscontrol's TestAccessLogHidesSecrets holds it.
func TestAuthKeySecretIsNotLogged(t *testing.T) {
	var logged bytes.Buffer

	old, oldLevel := log.Logger, zerolog.GlobalLevel()
	log.Logger = zerolog.New(&logged).Level(zerolog.TraceLevel)
	zerolog.SetGlobalLevel(zerolog.TraceLevel)

	t.Cleanup(func() {
		log.Logger = old

		zerolog.SetGlobalLevel(oldLevel)
	})

	b, api, auth, _, _ := authKeysAPI(t)

	k := decodeCreated(t, postKey(api, auth, `{"tags": ["tag:ci"], "expiry": "`+inAnHour()+`"}`))
	secret := k.Key[len("hskey-auth-"+k.Prefix+"-"):]

	require.NoError(t, join(t, b, k.Key))
	require.Equal(t, http.StatusNoContent, api.Delete(Prefix+"/auth-keys/"+k.ID, auth).Code)
	require.Error(t, join(t, b, k.Key))

	for _, rec := range []*httptest.ResponseRecorder{
		api.Get(Prefix+"/auth-keys", auth),
		api.Get(Prefix+"/auth-keys/"+k.ID, auth),
		api.Get(Prefix+"/auth-keys/"+k.Key, auth),
		postKey(api, auth, `{"tags": ["tag:nope"], "expiry": "`+inAnHour()+`"}`),
	} {
		require.NotContains(t, rec.Body.String(), secret)
	}

	require.NotEmpty(t, logged.String(), "the log was written")
	require.NotContains(t, logged.String(), secret)
}

// TestAuthKeyAnswersWhole compares whole answers, so a field too many or an
// owner of another shape shows. Values the server makes are taken from the
// answer; the other tests hold them.
func TestAuthKeyAnswersWhole(t *testing.T) {
	_, api, auth, alice, bob := authKeysAPI(t)

	decode := func(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
		t.Helper()

		var m map[string]any
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &m), rec.Body.String())

		return m
	}

	bobRef := map[string]any{"id": strconv.FormatUint(uint64(bob.ID), 10), "loginName": "bob"}
	expiry := time.Now().Add(time.Hour).UTC().Truncate(time.Second).Format(time.RFC3339)

	key := func(got map[string]any, owner, state any, extra map[string]any) map[string]any {
		want := map[string]any{
			"id": got["id"], "prefix": got["prefix"], "description": "", "owner": owner, "createdBy": bobRef,
			"state": state, "used": false, "reusable": false, "ephemeral": false,
			"expiry": expiry, "created": got["created"], "revoked": nil, "removal": nil,
		}
		maps.Copy(want, extra)

		return want
	}

	t.Run("a tagged create", func(t *testing.T) {
		got := decode(t, postKey(api, auth, `{"tags": ["tag:ci"], "expiry": "`+expiry+`"}`))
		want := key(got, map[string]any{"user": nil, "tags": []any{"tag:ci"}}, "valid", map[string]any{"key": got["key"]})
		require.Empty(t, cmp.Diff(want, got))
	})

	t.Run("a user's create", func(t *testing.T) {
		got := decode(t, postKey(api, auth, `{"userId": "`+strconv.FormatUint(uint64(alice.ID), 10)+`", "reusable": true, "expiry": "`+expiry+`"}`))
		owner := map[string]any{
			"user": map[string]any{"id": strconv.FormatUint(uint64(alice.ID), 10), "name": "alice", "loginName": "alice", "displayName": "", "email": ""},
			"tags": []any{},
		}
		want := key(got, owner, "valid", map[string]any{"key": got["key"], "reusable": true})
		require.Empty(t, cmp.Diff(want, got))
	})

	t.Run("a revoked get", func(t *testing.T) {
		made := decodeCreated(t, postKey(api, auth, `{"tags": ["tag:ci"], "expiry": "`+expiry+`", "description": "gone"}`))
		require.Equal(t, http.StatusNoContent, api.Delete(Prefix+"/auth-keys/"+made.ID, auth).Code)

		got := decode(t, api.Get(Prefix+"/auth-keys/"+made.ID, auth))
		want := key(got, map[string]any{"user": nil, "tags": []any{"tag:ci"}}, "revoked", map[string]any{
			"description": "gone", "revoked": got["revoked"], "removal": got["removal"],
		})
		require.Empty(t, cmp.Diff(want, got))
		require.NotNil(t, got["revoked"])
		require.NotNil(t, got["removal"])
	})

	t.Run("a problem", func(t *testing.T) {
		got := decode(t, postKey(api, auth, `{"tags": [], "expiry": "`+expiry+`"}`))
		want := map[string]any{
			"type":      problemTypeBase + "tags_required",
			"title":     codes[CodeTagsRequired].title,
			"status":    float64(http.StatusUnprocessableEntity),
			"code":      "tags_required",
			"detail":    "A key for tags needs at least one tag.",
			"requestId": got["requestId"],
			"errors":    []any{},
			"details":   map[string]any{},
			"object":    nil,
		}
		require.Empty(t, cmp.Diff(want, got))
	})

	t.Run("a time with nanoseconds is kept to the microsecond", func(t *testing.T) {
		sent := time.Now().Add(time.Hour).UTC().Truncate(time.Second).Add(123456789)
		k := decodeCreated(t, postKey(api, auth, `{"tags": ["tag:ci"], "expiry": "`+sent.Format(time.RFC3339Nano)+`"}`))
		require.Equal(t, sent.Truncate(time.Microsecond), *k.Expiry)
		require.Zero(t, k.Created.Nanosecond()%int(time.Microsecond), "created")
		require.Equal(t, k.AuthKey, getKey(t, api, auth, k.ID))
	})
}

// TestListAuthKeysEndsWithTheRequest: the list reads under the request's
// context, so a client that hangs up stops the read. The answer goes
// nowhere; that the read failed is what shows.
func TestListAuthKeysEndsWithTheRequest(t *testing.T) {
	_, api, auth, _, _ := authKeysAPI(t) //nolint:dogsled // the API and its key are all it needs

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	decodeProblem(t, api.GetCtx(ctx, Prefix+"/auth-keys", auth), CodeInternal)
}
