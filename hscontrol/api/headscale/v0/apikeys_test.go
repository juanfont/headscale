package apiv0

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/danielgtaylor/huma/v2/humatest"
	"github.com/stretchr/testify/require"
)

func postAPIKey(api humatest.TestAPI, auth, body string) *httptest.ResponseRecorder {
	return api.Post(Prefix+"/api-keys", auth, "Content-Type: application/json", strings.NewReader(body))
}

func decodeCreatedAPIKey(t *testing.T, rec *httptest.ResponseRecorder) CreatedApiKey {
	t.Helper()

	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())

	var k CreatedApiKey
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &k), rec.Body.String())

	return k
}

func getAPIKey(t *testing.T, api humatest.TestAPI, auth, id string) ApiKey {
	t.Helper()

	rec := api.Get(Prefix+"/api-keys/"+id, auth)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	var k ApiKey
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &k))

	return k
}

// listAllAPIKeys walks the list two at a time with query.
func listAllAPIKeys(t *testing.T, api humatest.TestAPI, auth, query string) ([]ApiKey, int) {
	t.Helper()

	var (
		all   []ApiKey
		token string
		pages int
	)

	for {
		q := "pageSize=2&" + query
		if token != "" {
			q += "&pageToken=" + url.QueryEscape(token)
		}

		rec := api.Get(Prefix+"/api-keys?"+q, auth)
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

		var l ApiKeyList
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &l))

		all = append(all, l.ApiKeys...)
		pages++

		if l.NextPageToken == "" {
			return all, pages
		}

		token = l.NextPageToken
	}
}

func TestCreateApiKey(t *testing.T) {
	b, api, auth, alice, _ := authKeysAPI(t)

	aliceID := strconv.FormatUint(uint64(alice.ID), 10)

	t.Run("a key alice owns", func(t *testing.T) {
		rec := postAPIKey(api, auth, `{"userId": "`+aliceID+`", "expiry": "`+inAnHour()+`"}`)
		k := decodeCreatedAPIKey(t, rec)

		require.Equal(t, Prefix+"/api-keys/"+k.ID, rec.Header().Get("Location"))
		require.True(t, strings.HasPrefix(k.Key, "hskey-api-"+k.Prefix+"-"))
		require.Equal(t, ApiKeyValid, k.State)
		require.Equal(t, "alice", k.Owner.User.LoginName)
		require.Equal(t, []string{}, k.Owner.Tags)
		require.Nil(t, k.LastSeen)
		require.Equal(t, k.ApiKey, getAPIKey(t, api, auth, k.ID), "the create answers what a get does")

		// The new key works, as the API key it is.
		rec = api.Get(Prefix+"/me", "Authorization: Bearer "+k.Key)
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		require.NotNil(t, getAPIKey(t, api, auth, k.ID).LastSeen, "its use is recorded")
	})

	t.Run("a key with no owner", func(t *testing.T) {
		k := decodeCreatedAPIKey(t, postAPIKey(api, auth, `{"expiry": "`+inAnHour()+`"}`))
		require.Nil(t, k.Owner)
	})

	for _, tt := range []struct {
		name, body string
		code       Code
		location   string
	}{
		{"no expiry", `{}`, CodeExpiryRequired, ""},
		{"a null expiry is no expiry", `{"expiry": null}`, CodeExpiryRequired, ""},
		{"an expiry in the past", `{"expiry": "2020-01-01T00:00:00Z"}`, CodeExpiryInPast, ""},
		{"a userId that is not an ID", `{"userId": "alice", "expiry": "` + inAnHour() + `"}`, CodeInvalidField, "body.userId"},
		{"a userId no user has", `{"userId": "999", "expiry": "` + inAnHour() + `"}`, CodeInvalidField, "body.userId"},
		{"an unknown field", `{"scopes": ["all"], "expiry": "` + inAnHour() + `"}`, CodeInvalidField, "body.scopes"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			p := decodeProblem(t, postAPIKey(api, auth, tt.body), tt.code)
			if tt.location != "" {
				require.Equal(t, tt.location, p.Errors[0].Location)
			}
		})
	}

	// No scope is enough: the rule answers before the scopes, so a token is
	// not told to get one.
	for name, scopes := range map[string][]string{"all": {"all"}, "oauth_keys": {"oauth_keys"}} {
		t.Run("a token with "+name+" makes no API key", func(t *testing.T) {
			p := decodeProblem(t, postAPIKey(api, keysToken(t, b, nil, scopes...), `{"expiry": "`+inAnHour()+`"}`), CodeForbidden)
			require.Equal(t, "token_cannot_create_api_key", p.Details["rule"])
			require.Equal(t, []any{}, p.Details["scopes"])
		})
	}
}

func TestListApiKeys(t *testing.T) {
	b, api, auth, alice, bob := authKeysAPI(t)

	aliceID := strconv.FormatUint(uint64(alice.ID), 10)

	valid := decodeCreatedAPIKey(t, postAPIKey(api, auth, `{"userId": "`+aliceID+`", "expiry": "`+inAnHour()+`"}`))
	revoked := decodeCreatedAPIKey(t, postAPIKey(api, auth, `{"userId": "`+aliceID+`", "expiry": "`+inAnHour()+`"}`))
	require.Equal(t, http.StatusNoContent, api.Delete(Prefix+"/api-keys/"+revoked.ID, auth).Code)

	_, expired, err := b.State.CreateAPIKey(new(time.Now().Add(-time.Hour)))
	require.NoError(t, err)

	all, pages := listAllAPIKeys(t, api, auth, "")
	states := map[string]ApiKeyState{}

	for _, k := range all {
		states[k.ID] = k.State
	}

	// The key of the request, bob's, comes first.
	require.Len(t, all, 4)
	require.Equal(t, 2, pages)
	require.Equal(t, map[string]ApiKeyState{
		all[0].ID:                          ApiKeyValid,
		valid.ID:                           ApiKeyValid,
		revoked.ID:                         ApiKeyRevoked,
		strconv.FormatUint(expired.ID, 10): ApiKeyExpired,
	}, states)
	require.Equal(t, "bob", all[0].Owner.User.LoginName)

	t.Run("user matches the owner", func(t *testing.T) {
		got, _ := listAllAPIKeys(t, api, auth, "user="+aliceID)
		require.Equal(t, []string{valid.ID, revoked.ID}, apiKeyIDs(got))

		got, _ = listAllAPIKeys(t, api, auth, "user="+strconv.FormatUint(uint64(bob.ID), 10))
		require.Equal(t, []string{all[0].ID}, apiKeyIDs(got))

		got, _ = listAllAPIKeys(t, api, auth, "user=999")
		require.Empty(t, got)
	})

	t.Run("user that is not an ID", func(t *testing.T) {
		p := decodeProblem(t, api.Get(Prefix+"/api-keys?user=alice", auth), CodeInvalidField)
		require.Equal(t, "query.user", p.Errors[0].Location)
	})

	t.Run("a token needs all:read", func(t *testing.T) {
		p := decodeProblem(t, api.Get(Prefix+"/api-keys", keysToken(t, b, nil, "oauth_keys")), CodeForbidden)
		require.Equal(t, []any{"all:read"}, p.Details["scopes"])

		require.Equal(t, http.StatusOK, api.Get(Prefix+"/api-keys", keysToken(t, b, nil, "all:read")).Code)
	})
}

func apiKeyIDs(ks []ApiKey) []string {
	ids := make([]string, len(ks))
	for i, k := range ks {
		ids[i] = k.ID
	}

	return ids
}

func TestDeleteApiKey(t *testing.T) {
	b, api, auth, _, _ := authKeysAPI(t)

	k := decodeCreatedAPIKey(t, postAPIKey(api, auth, `{"expiry": "`+inAnHour()+`"}`))
	require.Equal(t, http.StatusNoContent, api.Delete(Prefix+"/api-keys/"+k.ID, auth).Code)

	got := getAPIKey(t, api, auth, k.ID)
	require.Equal(t, ApiKeyRevoked, got.State)
	require.Equal(t, got.Revoked.Add(7*24*time.Hour), *got.Removal)

	t.Run("the key is refused", func(t *testing.T) {
		decodeProblem(t, api.Get(Prefix+"/me", "Authorization: Bearer "+k.Key), CodeUnauthorized)
	})

	t.Run("again is 204 and changes nothing", func(t *testing.T) {
		require.Equal(t, http.StatusNoContent, api.Delete(Prefix+"/api-keys/"+k.ID, auth).Code)
		require.Equal(t, got, getAPIKey(t, api, auth, k.ID))
	})

	t.Run("a key deletes itself", func(t *testing.T) {
		self := decodeCreatedAPIKey(t, postAPIKey(api, auth, `{"expiry": "`+inAnHour()+`"}`))
		bearer := "Authorization: Bearer " + self.Key

		rec := api.Delete(Prefix+"/api-keys/"+self.ID, bearer)
		require.Equal(t, http.StatusNoContent, rec.Code)
		require.Empty(t, rec.Body.String())
		decodeProblem(t, api.Get(Prefix+"/me", bearer), CodeUnauthorized)
		decodeProblem(t, api.Delete(Prefix+"/api-keys/"+self.ID, bearer), CodeUnauthorized)
	})

	t.Run("a token needs all", func(t *testing.T) {
		p := decodeProblem(t, api.Delete(Prefix+"/api-keys/"+k.ID, keysToken(t, b, nil, "all:read")), CodeForbidden)
		require.Equal(t, []any{"all"}, p.Details["scopes"])
	})

	for _, id := range []string{"999", "abc", "007", k.Key} {
		t.Run("not found "+id[:min(len(id), 12)], func(t *testing.T) {
			decodeProblem(t, api.Delete(Prefix+"/api-keys/"+id, auth), CodeNotFound)
		})
	}
}
