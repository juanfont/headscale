// This file replays admin API exchanges captured from Tailscale SaaS, in
// order and as the principal SaaS saw, and compares each answer with SaaS's.
//
// Test data source: servertest/testdata/steps/{oauth,policy-api,key-list}.hujson,
// loaded by name. oauth's late joins are also replayed with real clients by
// TestAPIv2OAuthClientDeleteCompat in servertest.
// Source format:    github.com/juanfont/headscale/hscontrol/types/testcapture

package hscontrol

import (
	"bytes"
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	apiv2 "github.com/juanfont/headscale/hscontrol/api/v2"
	"github.com/juanfont/headscale/hscontrol/mapper"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/types/testcapture"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tailscale/hujson"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

// apiv2CompatSkipReasons lists checks where headscale differs from SaaS, keyed
// <test_id>/<step>/<i>[/<node>]/<check>, where <i> is the action's index in
// its step, or <test_id>/<object>/[<shape>/]<check> for a field compared
// over every body that names the object (key:K, client:C, device:x), device
// fields once per read shape (default, all). Every call has a status check
// and an outcome check (allowed or refused), so a listed status still fails
// when the call flips. v1-* checks are TestAPIV1PolicyVerdictCompat's. A
// listed check that matches fails, so a fix must delete its entry.
var apiv2CompatSkipReasons = map[string]string{
	"oauth/R2/4/status":  missingScopeNotFound,
	"oauth/R3/1/status":  missingScopeNotFound,
	"oauth/R3/2/status":  missingScopeNotFound,
	"oauth/R3/3/status":  missingScopeNotFound,
	"oauth/K3/0/status":  missingScopeNotFound,
	"oauth/J2/0/status":  missingScopeNotFound,
	"oauth/K4/0/status":  missingScopeNotFound,
	"oauth/D1/0/message": missingScopeText,

	"oauth/O3/0/status": mintScopeRefusalStatus,
	"oauth/O4/0/scope":  unknownScopeGranted,

	"oauth/O4/0/tags":  mintTagsNotEchoed,
	"oauth/E1/0/tags":  mintTagsNotEchoed,
	"oauth/E9a/0/tags": mintTagsNotEchoed,
	"oauth/T1/0/tags":  mintTagsNotEchoed,
	"oauth/D0/6/tags":  mintTagsNotEchoed,
	"oauth/B1/0/tags":  mintTagsNotEchoed,
	"oauth/B3/0/tags":  mintTagsNotEchoed,
	"oauth/B11/1/tags": mintTagsNotEchoed,

	"key-list/setup-token-keys/0/tags": mintTagsNotEchoed,
	"key-list/setup-token-keys/2/tags": mintTagsNotEchoed,
	"key-list/setup-token-keys/4/tags": mintTagsNotEchoed,
	"key-list/setup-token-keys/6/tags": mintTagsNotEchoed,

	"oauth/K5/0/status": unknownKeyType,

	"oauth/E4/0/status": tagRefusalStatus,
	"oauth/E5/0/status": tagRefusalStatus,
	"oauth/T2/1/status": tagRefusalStatus,
	"oauth/T3/1/status": tagRefusalStatus,

	"oauth/T4/1/status":  retagRemovesUnownedTag,
	"oauth/T4/1/outcome": retagRemovesUnownedTag,
	"oauth/T4/2/tags":    retagRemovesUnownedTag,
	"oauth/T4/2/owner":   retagRemovesUnownedTag,
	"oauth/T5/1/status":  retagRemovesUnownedTag,
	"oauth/T5/1/outcome": retagRemovesUnownedTag,
	"oauth/T5/2/tags":    retagRemovesUnownedTag,
	"oauth/T5/2/owner":   retagRemovesUnownedTag,

	"oauth/D0/1/listed": emptyKeyListNull,

	"oauth/D7/2/status":  deletedClientGone,
	"oauth/D7/2/outcome": deletedClientGone,
	"oauth/D7/3/message": deletedClientCredentialText,
	"oauth/D7/4/message": deletedClientCredentialText,
	"oauth/B7/0/message": deletedClientCredentialText,
	"oauth/B7/1/message": deletedClientCredentialText,

	"oauth/device:before/all/device-oauth-client": deviceOAuthClientMaker,
	"oauth/device:joiner/all/device-oauth-client": deviceOAuthClientMaker,

	"policy-api/P7/0/body": hujsonFormatted,
	"policy-api/P7/1/body": hujsonFormatted,
}

// apiv2CompatNotCompared lists, by key prefix, checks left out: SaaS's
// answer there is in doubt, so it is no reference.
var apiv2CompatNotCompared = []string{
	"policy-api/P2/1/status",
	"policy-api/P2/1/outcome",
	"policy-api/P2/1/enforced",
	"policy-api/P2/1/v1-verdict",
	"policy-api/P2/1/v1-stored",
	"policy-api/P2/1/v1-enforced",
	"policy-api/P2/2/body",
	"policy-api/P2/2/etag",
}

// apiv2CompatNotReplayed lists steps left out, keyed <test_id>/<step>, with
// the objects only they create, which listings then leave out: SaaS's answer
// there is in doubt, so it is no reference.
var apiv2CompatNotReplayed = map[string][]string{
	"oauth/E7":  {"{client:C-all-2}"},
	"oauth/E9b": {"{key:K-E9b}"},
}

// notCompared reports whether key falls under one of prefixes.
func notCompared(prefixes []string, key string) bool {
	return slices.ContainsFunc(prefixes, func(p string) bool {
		return strings.HasPrefix(key, p)
	})
}

// Differences a planned change removes.
const (
	retagRemovesUnownedTag = "RETAG_REMOVES_UNOWNED_TAG: SaaS refuses a token's retag of a device holding a tag outside the token's grant with 400 cannot remove current tags; headscale replaces the tags"
)

// Differences no planned change removes yet.
const (
	mintScopeRefusalStatus      = "TOKEN_SCOPE_REFUSAL_STATUS: SaaS refuses a token scope the client lacks with 403 and a message; headscale with 400 invalid_scope"
	mintTagsNotEchoed           = "TOKEN_TAGS_NOT_ECHOED: SaaS's token answer names the token's tags; headscale's has no tags"
	unknownKeyType              = "UNKNOWN_KEY_TYPE: SaaS refuses an unknown keyType with 400 before it checks scopes; headscale checks the scope first and answers 403"
	tagRefusalStatus            = "TAG_REFUSAL_STATUS: SaaS refuses a tag outside the token's grant with 400 requested tags are invalid or not permitted; headscale with 403"
	emptyKeyListNull            = "EMPTY_KEY_LIST_NULL: SaaS answers a listing that holds no key with keys null; headscale with []"
	deletedClientGone           = "DELETED_CLIENT_GONE: SaaS keeps a deleted OAuth client readable as invalid and revoked; headscale removes it"
	deletedClientCredentialText = "DELETED_CLIENT_CREDENTIAL_TEXT: SaaS refuses a deleted client's secret and tokens with API token invalid; headscale says invalid client credentials and unauthorized"
	missingScopeText            = "MISSING_SCOPE_TEXT: SaaS refuses a delete outside the token's scopes with calling actor does not have enough permissions; headscale names the missing scope"
	hujsonFormatted             = "HUJSON_FORMATTED: SaaS stores a HuJSON policy formatted, comments kept; headscale stores the bytes as sent"
)

// SaaS behaviour recorded as it is; following it is the maintainer's call.
const (
	deviceOAuthClientMaker = "DEVICE_OAUTH_CLIENT_ID: SaaS names, in oauthClientId, the OAuth client whose token made the device's key; headscale does not record which client that was, so it leaves the field out"
	missingScopeNotFound   = "MISSING_SCOPE_NOT_FOUND: SaaS answers a call outside the token's scopes with 404 not found; headscale answers 403"
	unknownScopeGranted    = "UNKNOWN_SCOPE_GRANTED: SaaS ignores an unknown requested scope and grants the client's own; headscale grants the unknown scope alone"
)

// TestAPIv2OAuthCompat replays OAuth clients, token exchanges, auth keys,
// device reads and tag writes by principal: admin-made clients of every
// scope, scope narrowing, token-made clients and their tokens, tag writes on
// devices tagged outside the token's grant, key listing and deletes by scope,
// and a parent client deleted while its key and child client live on.
func TestAPIv2OAuthCompat(t *testing.T) {
	runAPICompat(t, "oauth", false)
}

// TestAPIv2KeyListCompat replays auth key listings, with and without
// all=true, by read-only OAuth tokens untagged and of one and two tags and
// by the tokens that made keys, over keys of tags inside, overlapping and
// outside theirs that the admin or a token made, an untagged key the admin
// made, and an admin key made after the token-made ones.
func TestAPIv2KeyListCompat(t *testing.T) {
	runAPICompat(t, "key-list", false)
}

// TestAPIv2ACLCompat replays policy writes over a fixed baseline: an
// identical write, zero-length, newline-only and empty-object bodies, a cut
// short body, a failing test, If-Match with a stale and the current ETag and
// ts-default, and HuJSON with a comment. It compares statuses, messages, the
// stored body, ETag relations and whether the enforced policy changed.
func TestAPIv2ACLCompat(t *testing.T) {
	runAPICompat(t, "policy-api", false)
}

// TestAPIV1PolicyVerdictCompat sends the same policy bodies through the v1
// API: each write through PUT /api/v1/policy and each validate through
// /api/v1/policy/check. The verdict, whether the stored policy changed and
// whether the enforced policy changed must match SaaS's.
func TestAPIV1PolicyVerdictCompat(t *testing.T) {
	runAPICompat(t, "policy-api", true)
}

func runAPICompat(t *testing.T, id string, v1 bool) {
	t.Helper()

	c, err := testcapture.Read(filepath.Join("servertest", "testdata", "steps", id+".hujson"))
	require.NoError(t, err)
	require.NotEmpty(t, c.Steps, "%s: not a step capture", id)

	r := newAPIReplay(t, c, v1)

	for _, step := range c.Steps {
		// A setup-failed step sent nothing.
		require.Contains(t, []string{"observed", "setup-failed"}, step.Result, step.Name)

		if objs, ok := apiv2CompatNotReplayed[id+"/"+step.Name]; ok {
			r.unlisted = append(r.unlisted, objs...)

			continue
		}

		r.step(t, step)
	}

	if !v1 {
		r.aggregateChecks(t)
	}

	for k := range apiv2CompatSkipReasons {
		check := k[strings.LastIndex(k, "/")+1:]
		if strings.HasPrefix(k, id+"/") && strings.HasPrefix(check, "v1-") == v1 && !r.evaluated[k] {
			t.Errorf("skip entry %q names no check", k)
		}
	}
}

// apiReplay replays one capture's actions against headscale. SaaS labels
// ({key:K}, {client:C}, {device:x}, {etag:N}) map to headscale's IDs and
// ETags as the replay creates them.
type apiReplay struct {
	c     *testcapture.Capture
	app   *Headscale
	v2    http.Handler
	v1    http.Handler
	useV1 bool

	admin string
	names map[string]string // SaaS email → capture user name

	ids     map[string]string // SaaS label → headscale ID
	labels  map[string]string // "<kind>/<headscale ID>" → SaaS label
	secrets map[string]string // key or client label → secret
	tokens  map[string]string // principal → access token
	addrs   map[string]string // SaaS node address → headscale's

	// ETag relations: where each ETag was first seen, per side.
	saasETag, hsETag map[string]string
	hsByLabel        map[string]string

	// saasCurrentETag is SaaS's last ETag, for the v1 replay.
	saasCurrentETag string

	// saasBaseline is the enforced policy every policy row starts from.
	saasBaseline map[string]string

	refusals map[string][2][]byte

	// aggregates holds per-object observations checked over the whole
	// capture: check → object label → [SaaS, headscale] values seen.
	aggregates map[string]map[string][2]map[string]bool

	// unlisted holds labels of objects made by steps left out.
	unlisted []string

	evaluated map[string]bool
}

func newAPIReplay(t *testing.T, c *testcapture.Capture, useV1 bool) *apiReplay {
	t.Helper()

	app := newAddressedTestApp(t)

	r := &apiReplay{
		c:          c,
		app:        app,
		v1:         newHumaTestHandler(app),
		useV1:      useV1,
		names:      map[string]string{},
		ids:        map[string]string{},
		labels:     map[string]string{},
		secrets:    map[string]string{},
		tokens:     map[string]string{},
		addrs:      map[string]string{},
		saasETag:   map[string]string{},
		hsETag:     map[string]string{},
		hsByLabel:  map[string]string{},
		refusals:   map[string][2][]byte{},
		aggregates: map[string]map[string][2]map[string]bool{},
		evaluated:  map[string]bool{},
	}

	users := map[string]*types.User{}
	for _, u := range c.Topology.Users {
		users[u.Name] = app.state.CreateUserForTest(u.Name)
		r.names[u.Email] = u.Name
	}

	// SaaS admin calls act as the tailnet owner.
	owner, ok := users[r.names[c.Tailnet]]
	require.True(t, ok, "%s: tailnet %q is not a capture user", c.TestID, c.Tailnet)

	admin, apiKey, err := app.state.CreateAPIKey(nil)
	require.NoError(t, err)
	require.NoError(t, app.state.SetAPIKeyUser(apiKey.ID, types.UserID(owner.ID)))

	r.admin = admin

	r.v2, _ = apiv2.Handler(apiv2.Backend{State: app.state, Change: app.Change, Cfg: app.cfg})

	return r
}

// newAddressedTestApp is [createTestApp] with address prefixes, so joined
// nodes get addresses the replayed policies can name.
func newAddressedTestApp(t *testing.T) *Headscale {
	t.Helper()

	tmpDir := t.TempDir()
	prefixV4 := netip.MustParsePrefix("100.64.0.0/10")
	prefixV6 := netip.MustParsePrefix("fd7a:115c:a1e0::/48")

	cfg := types.Config{
		ServerURL:           "http://localhost:8080",
		NoisePrivateKeyPath: tmpDir + "/noise_private.key",
		PrefixV4:            &prefixV4,
		PrefixV6:            &prefixV6,
		IPAllocation:        types.IPAllocationStrategySequential,
		Database: types.DatabaseConfig{
			Type:   "sqlite3",
			Sqlite: types.SqliteConfig{Path: tmpDir + "/headscale_test.db"},
		},
		Policy: types.PolicyConfig{Mode: types.PolicyModeDB},
		Tuning: types.Tuning{BatchChangeDelay: 100 * time.Millisecond, BatcherWorkers: 1},
	}

	app, err := NewHeadscale(&cfg)
	require.NoError(t, err)

	app.mapBatcher = mapper.NewBatcherAndMapper(&cfg, app.state)
	app.mapBatcher.Start()
	t.Cleanup(app.mapBatcher.Close)

	return app
}

// apiCheck is one rendering of an outcome: SaaS's and headscale's.
type apiCheck struct {
	name, want, got string
}

func (r *apiReplay) step(t *testing.T, step testcapture.Step) {
	t.Helper()

	var checks []apiCheck

	for i, a := range step.Actions {
		prefix := strconv.Itoa(i) + "/"

		var got []apiCheck

		switch a.Kind {
		case "join":
			got = r.join(t, step, a)
		case "token":
			got = r.token(t, a)
		case "api", "policy":
			got = r.api(t, step, i, a)
		case "cli", "wait", "retire":
			// Client settings, SaaS settle time and the run's cleanup.
		default:
			t.Fatalf("%s: no replay for action %q", step.Name, a.Kind)
		}

		for _, ch := range got {
			// The v1 replay sets up through v2, whose checks the v2 tests own.
			if strings.HasPrefix(ch.name, "v1-") == r.useV1 {
				ch.name = prefix + ch.name
				checks = append(checks, ch)
			}
		}
	}

	keyPrefix := r.c.TestID + "/" + step.Name + "/"
	checks = slices.DeleteFunc(checks, func(ch apiCheck) bool {
		return notCompared(apiv2CompatNotCompared, keyPrefix+ch.name)
	})

	if len(checks) == 0 {
		return
	}

	// Marked here, so a run filtered to other steps does not call these
	// entries stale.
	for _, ch := range checks {
		r.evaluated[keyPrefix+ch.name] = true
	}

	t.Run(step.Name, func(t *testing.T) {
		for _, ch := range checks {
			t.Run(ch.name, func(t *testing.T) {
				apiCompatCheck(t, keyPrefix+ch.name, ch.want, ch.got)
			})
		}
	})
}

func apiCompatCheck(t *testing.T, key, want, got string) {
	t.Helper()

	reason, listed := apiv2CompatSkipReasons[key]

	switch {
	case listed && want == got:
		t.Errorf("matches SaaS; delete apiv2CompatSkipReasons[%q] (%s)", key, reason)
	case listed:
		t.Skip(reason)
	default:
		assert.Equal(t, want, got)
	}
}

// join registers the node with the labelled key, as the capture's stock
// client did, and records its device ID.
func (r *apiReplay) join(t *testing.T, step testcapture.Step, a testcapture.Action) []apiCheck {
	t.Helper()

	secret, ok := r.secrets[a.Key]
	require.True(t, ok, "%s: join with unknown key %s", step.Name, a.Key)

	hi := &tailcfg.Hostinfo{Hostname: a.Hostname}
	if a.RequestTags != nil {
		hi.RequestTags = *a.RequestTags
	}

	for _, route := range a.Routes {
		hi.RoutableIPs = append(hi.RoutableIPs, netip.MustParsePrefix(route))
	}

	node, change, err := r.app.state.HandleNodeFromPreAuthKey(tailcfg.RegisterRequest{
		Auth:     &tailcfg.RegisterResponseAuth{AuthKey: secret},
		NodeKey:  key.NewNode().Public(),
		Hostinfo: hi,
		Expiry:   time.Now().Add(24 * time.Hour),
	}, key.NewMachine().Public())
	r.app.Change(change)

	got := "accepted"
	if err != nil {
		got = "refused: " + err.Error()
	} else {
		label := "{device:" + a.Node + "}"
		r.ids[label] = node.StringID()
		r.labels["device/"+node.StringID()] = label

		// Policies name SaaS's addresses for the node.
		topo := r.c.Topology.Nodes[a.Node]

		for _, ip := range node.IPs() {
			if ip.Is4() {
				r.addrs[topo.IPv4] = ip.String()
			} else {
				r.addrs[topo.IPv6] = ip.String()
			}
		}
	}

	want := "refused"
	if att := step.Register[a.Node]; len(att) > 0 && att[len(att)-1].MachineAuthorized != nil &&
		*att[len(att)-1].MachineAuthorized {
		want = "accepted"
	}

	return []apiCheck{{"join", want, got}}
}

// token runs the client-credentials exchange the action records. The form
// carries the client's secret, scope and tags as SaaS received them.
func (r *apiReplay) token(t *testing.T, a testcapture.Action) []apiCheck {
	t.Helper()

	secret, ok := r.secrets[a.Client]
	require.True(t, ok, "token for unknown client %s", a.Client)

	form := url.Values{"grant_type": {"client_credentials"}, "client_secret": {secret}}
	if a.Scope != nil {
		form.Set("scope", *a.Scope)
	}

	if a.RequestTags != nil {
		form.Set("tags", strings.Join(*a.RequestTags, " "))
	}

	status, _, body := r.serve(t, http.MethodPost, "/api/v2/oauth/token",
		map[string]string{"Content-Type": "application/x-www-form-urlencoded"}, []byte(form.Encode()), r.v2)

	checks := []apiCheck{
		{"status", strconv.Itoa(a.Status), strconv.Itoa(status)},
		{"outcome", verdict(a.Status == http.StatusOK), verdict(status == http.StatusOK)},
	}

	var want, got struct {
		AccessToken string `json:"access_token"`
		Scope       string `json:"scope"`
		Tags        string `json:"tags"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int    `json:"expires_in"`
	}

	require.NoError(t, json.Unmarshal(a.Response, &want))
	require.NoErrorf(t, json.Unmarshal(body, &got), "token body: %s", body)

	switch {
	case a.Status == http.StatusOK && status == http.StatusOK:
		r.tokens[a.Principal] = got.AccessToken

		checks = append(checks,
			apiCheck{"scope", want.Scope, got.Scope},
			apiCheck{"tags", want.Tags, got.Tags},
			apiCheck{
				"token",
				fmt.Sprintf("type %s expires_in %d", want.TokenType, want.ExpiresIn),
				fmt.Sprintf("type %s expires_in %d", got.TokenType, got.ExpiresIn),
			},
		)
	case status == http.StatusOK:
		// SaaS sent nothing with a token it refused.
		r.tokens[a.Principal] = got.AccessToken
	case a.Status == status:
		checks = append(checks, messageCheck(t, a.Response, body))
	}

	return checks
}

var labelRE = regexp.MustCompile(`\{(?:device|key|client):[^}]+\}`)

// api sends one admin API call as its principal and compares the answer.
func (r *apiReplay) api(t *testing.T, step testcapture.Step, i int, a testcapture.Action) []apiCheck {
	t.Helper()

	endpoint, _, _ := strings.Cut(a.Path, "?")
	isPolicy := endpoint == "/tailnet/-/acl" || endpoint == "/tailnet/-/acl/validate"

	if r.useV1 && isPolicy {
		return r.v1Policy(t, step, i, a)
	}

	if r.useV1 && a.Method == http.MethodGet {
		return nil
	}

	isWrite := a.Method == http.MethodPost && endpoint == "/tailnet/-/acl"
	isValidate := endpoint == "/tailnet/-/acl/validate"
	path, header, body := r.request(t, a, isPolicy)

	var before string
	if isWrite {
		before = r.enforcedNow(t)
	}

	status, respHeader, resp := r.serve(t, a.Method, path, header, body, r.v2)

	saasOK := a.Status/100 == 2
	hsOK := status/100 == 2

	// SaaS's validate answers some refusals with 200 and a message.
	saasRefused := !saasOK || isValidate && len(errorTexts(a.Response)) > 0
	hsRefused := !hsOK || isValidate && len(errorTexts(resp)) > 0

	checks := []apiCheck{
		{"status", strconv.Itoa(a.Status), strconv.Itoa(status)},
		{"outcome", verdict(!saasRefused), verdict(!hsRefused)},
	}

	if len(a.Response) > 0 && (!saasOK && a.Status == status || isValidate && saasRefused) {
		checks = append(checks, messageCheck(t, a.Response, resp))
	}

	// Labelled also when SaaS refused it, so listings name what headscale
	// made.
	if hsOK {
		r.record(t, a, resp)
	}

	if saasOK && hsOK {
		checks = append(checks, r.bodyChecks(t, a, endpoint, resp)...)
	}

	if label := a.RespHeader["ETag"]; label != "" && saasOK && hsOK {
		checks = append(checks, r.etagCheck(step, i, label, respHeader.Get("ETag")))
	}

	if a.Kind == "api" && saasRefused && (isWrite || isValidate) {
		checks = append(checks, r.refusalChecks(t, a, endpoint, body, resp)...)
	}

	if isWrite {
		if ch, ok := r.enforcedCheck(t, step, a.Kind, before); ok {
			checks = append(checks, ch)
		}
	}

	return checks
}

// request is the call a sent, with SaaS's labels, emails and addresses
// replaced by headscale's and its principal's credential.
func (r *apiReplay) request(t *testing.T, a testcapture.Action, isPolicy bool) (string, map[string]string, []byte) {
	t.Helper()

	body := []byte(a.Body)
	if isPolicy {
		body = r.policyBody(t, a.Body)
	}

	header := maps.Clone(a.Header)
	if header == nil {
		header = map[string]string{}
	}

	if hs, ok := r.hsByLabel[header["If-Match"]]; ok {
		header["If-Match"] = hs
	}

	if _, ok := header["Content-Type"]; !ok && a.Body != nil {
		header["Content-Type"] = "application/json"
	}

	switch {
	case a.Principal == "admin":
		header["Authorization"] = "Bearer " + r.admin
	case strings.HasPrefix(a.Principal, "token:"):
		// A token headscale never issued is refused like a missing one.
		header["Authorization"] = "Bearer " + r.tokens[a.Principal]
	default:
		t.Fatalf("unknown principal %q", a.Principal)
	}

	path := "/api/v2" + labelRE.ReplaceAllStringFunc(a.Path, func(l string) string {
		if id, ok := r.ids[l]; ok {
			return id
		}

		return "unknown"
	})

	return path, header, body
}

// serve sends one request to handler and returns its answer.
func (r *apiReplay) serve(
	t *testing.T,
	method, path string,
	header map[string]string,
	body []byte,
	handler http.Handler,
) (int, http.Header, []byte) {
	t.Helper()

	req := httptest.NewRequestWithContext(t.Context(), method, path, bytes.NewReader(body))
	for k, v := range header {
		req.Header.Set(k, v)
	}

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	return rec.Code, rec.Header(), rec.Body.Bytes()
}

// policyBody is a policy body as headscale must receive it: HuJSON and
// zero-length bodies are stored as JSON strings, and SaaS's user emails and
// node addresses become headscale's.
func (r *apiReplay) policyBody(t *testing.T, raw json.RawMessage) []byte {
	t.Helper()

	s := string(raw)
	if strings.HasPrefix(s, `"`) {
		require.NoError(t, json.Unmarshal(raw, &s))
	}

	for email, name := range r.names {
		s = strings.ReplaceAll(s, email, name+"@")
	}

	// Quoted, so one address cannot rewrite a longer one it prefixes.
	for saas, hs := range r.addrs {
		s = strings.ReplaceAll(s, `"`+saas+`"`, `"`+hs+`"`)
	}

	return []byte(s)
}

// apiBody is the union of the v2 bodies the checks read: keys, OAuth
// clients, devices and errors. Raw fields keep absent apart from null and [].
type apiBody struct {
	ID            string   `json:"id"`
	KeyType       string   `json:"keyType"`
	Description   string   `json:"description"`
	ExpirySeconds int64    `json:"expirySeconds"`
	Invalid       bool     `json:"invalid"`
	Revoked       *string  `json:"revoked"`
	UserID        *string  `json:"userId"`
	Scopes        []string `json:"scopes"`
	Tags          []string `json:"tags"`
	Capabilities  *struct {
		Devices struct {
			Create struct {
				Reusable      bool     `json:"reusable"`
				Ephemeral     bool     `json:"ephemeral"`
				Preauthorized bool     `json:"preauthorized"`
				Tags          []string `json:"tags"`
			} `json:"create"`
		} `json:"devices"`
	} `json:"capabilities"`

	User             string          `json:"user"`
	AdvertisedRoutes json.RawMessage `json:"advertisedRoutes"`
	EnabledRoutes    json.RawMessage `json:"enabledRoutes"`
	OAuthClientID    *string         `json:"oauthClientId"`

	Keys    json.RawMessage `json:"keys"`
	Devices []apiBody       `json:"devices"`
}

func decodeBody(t *testing.T, raw []byte) apiBody {
	t.Helper()

	var b apiBody
	if len(raw) > 0 {
		require.NoErrorf(t, json.Unmarshal(raw, &b), "body: %s", raw)
	}

	return b
}

// record learns the IDs and secrets of what a create returned.
func (r *apiReplay) record(t *testing.T, a testcapture.Action, resp []byte) {
	t.Helper()

	if a.Method != http.MethodPost || a.Path != "/tailnet/-/keys" {
		return
	}

	var created struct {
		ID      string `json:"id"`
		Key     string `json:"key"`
		KeyType string `json:"keyType"`
	}
	require.NoError(t, json.Unmarshal(resp, &created))

	name, label := a.Key, "{key:"+a.Key+"}"
	if created.KeyType == "client" {
		name, label = a.Client, "{client:"+a.Client+"}"
	}

	r.ids[label] = created.ID
	r.labels[created.KeyType+"/"+created.ID] = label
	r.secrets[name] = created.Key
}

// bodyChecks compares what a successful call returned, by endpoint.
func (r *apiReplay) bodyChecks(t *testing.T, a testcapture.Action, endpoint string, resp []byte) []apiCheck {
	t.Helper()

	switch {
	case endpoint == "/tailnet/-/acl":
		return []apiCheck{r.policyCheck(t, a, resp)}

	case endpoint == "/tailnet/-/keys" && a.Method == http.MethodGet:
		return []apiCheck{{"listed", r.listedKeys(t, a.Response), r.listedKeys(t, resp)}}

	case strings.HasPrefix(endpoint, "/tailnet/-/keys") && a.Method != http.MethodDelete:
		return r.keyChecks(decodeBody(t, a.Response), decodeBody(t, resp))

	case endpoint == "/tailnet/-/devices":
		return r.deviceListChecks(t, a, resp)

	case strings.HasSuffix(endpoint, "/routes"):
		want, got := decodeBody(t, a.Response), decodeBody(t, resp)

		return []apiCheck{{"routes", routesOf(want), routesOf(got)}}

	case strings.HasPrefix(endpoint, "/device/") && a.Method == http.MethodGet:
		alias := strings.TrimSuffix(strings.TrimPrefix(endpoint, "/device/{device:"), "}")

		return r.deviceChecks("", alias, strings.Contains(a.Path, "fields=all"), decodeBody(t, a.Response), decodeBody(t, resp))
	}

	return nil
}

// keyChecks compares an auth key or OAuth client.
func (r *apiReplay) keyChecks(want, got apiBody) []apiCheck {
	r.observe("creator-user-id", want.ID, presence(want.UserID != nil), presence(got.UserID != nil))

	state := func(b apiBody) string {
		return fmt.Sprintf("invalid %t revoked %s", b.Invalid, presence(b.Revoked != nil))
	}

	checks := []apiCheck{
		{"key-type", want.KeyType, got.KeyType},
		{"description", want.Description, got.Description},
		{"state", state(want), state(got)},
	}

	if want.KeyType == "client" {
		return append(checks,
			apiCheck{"scopes", sortedStrings(want.Scopes), sortedStrings(got.Scopes)},
			apiCheck{"tags", sortedStrings(want.Tags), sortedStrings(got.Tags)},
		)
	}

	caps := func(b apiBody) string {
		if b.Capabilities == nil {
			return "none"
		}

		c := b.Capabilities.Devices.Create

		return fmt.Sprintf("reusable %t ephemeral %t preauthorized %t tags %s",
			c.Reusable, c.Ephemeral, c.Preauthorized, sortedStrings(c.Tags))
	}

	return append(checks,
		apiCheck{"capabilities", caps(want), caps(got)},
		apiCheck{"expiry", strconv.FormatInt(want.ExpirySeconds, 10), strconv.FormatInt(got.ExpirySeconds, 10)},
	)
}

// listedKeys renders a key listing as the labels it holds.
func (r *apiReplay) listedKeys(t *testing.T, raw []byte) string {
	t.Helper()

	b := decodeBody(t, raw)
	if string(b.Keys) == "null" {
		return "null"
	}

	var keys []apiBody
	require.NoError(t, json.Unmarshal(b.Keys, &keys))

	labels := make([]string, 0, len(keys))
	for _, k := range keys {
		if l := r.label(k.KeyType, k.ID); !slices.Contains(r.unlisted, l) {
			labels = append(labels, l)
		}
	}

	return sortedStrings(labels)
}

// label maps an ID from either side to its SaaS label.
func (r *apiReplay) label(kind, id string) string {
	if strings.HasPrefix(id, "{") {
		return id
	}

	if l, ok := r.labels[kind+"/"+id]; ok {
		return l
	}

	return "{unmatched}"
}

func (r *apiReplay) deviceListChecks(t *testing.T, a testcapture.Action, resp []byte) []apiCheck {
	t.Helper()

	all := strings.Contains(a.Path, "fields=all")
	want, got := decodeBody(t, a.Response), decodeBody(t, resp)

	byLabel := func(devs []apiBody) map[string]apiBody {
		m := make(map[string]apiBody, len(devs))
		for _, d := range devs {
			m[r.label("device", d.ID)] = d
		}

		return m
	}

	wantBy, gotBy := byLabel(want.Devices), byLabel(got.Devices)
	checks := []apiCheck{{"listed", sortedStrings(slices.Collect(maps.Keys(wantBy))), sortedStrings(slices.Collect(maps.Keys(gotBy)))}}

	for _, l := range slices.Sorted(maps.Keys(wantBy)) {
		g, ok := gotBy[l]
		if !ok {
			continue
		}

		alias := strings.TrimSuffix(strings.TrimPrefix(l, "{device:"), "}")
		checks = append(checks, r.deviceChecks(alias+"/", alias, all, wantBy[l], g)...)
	}

	return checks
}

// deviceChecks compares a device's tags, owner and, with fields=all, routes.
func (r *apiReplay) deviceChecks(prefix, alias string, all bool, want, got apiBody) []apiCheck {
	label := "{device:" + alias + "}"

	// Apart per read shape, so a field fixed in one shape only shows.
	shape := "default/"
	if all {
		shape = "all/"
	}

	r.observe(shape+"device-oauth-client", label, optional(want.OAuthClientID), r.credentialLabel(got.OAuthClientID))
	r.observe(shape+"device-user", label, r.userName(want.User), got.User)

	checks := []apiCheck{
		{prefix + "tags", sortedStrings(want.Tags), sortedStrings(got.Tags)},
		{prefix + "owner", deviceOwner(want.Tags, r.userName(want.User)), deviceOwner(got.Tags, got.User)},
	}

	if all {
		checks = append(checks, apiCheck{prefix + "routes", routesOf(want), routesOf(got)})

		if routesOf(want) == routesOf(apiBody{}) {
			r.observe("empty-route-lists", label, listShape(want), listShape(got))
		}
	}

	return checks
}

func (r *apiReplay) userName(email string) string {
	if name, ok := r.names[email]; ok {
		return name
	}

	return email
}

func deviceOwner(tags []string, user string) string {
	if len(tags) > 0 {
		return "tags " + sortedStrings(tags)
	}

	return "user " + user
}

func routesOf(b apiBody) string {
	list := func(raw json.RawMessage) []string {
		var out []string
		if len(raw) > 0 {
			_ = json.Unmarshal(raw, &out)
		}

		return out
	}

	return fmt.Sprintf("advertised %s enabled %s", sortedStrings(list(b.AdvertisedRoutes)), sortedStrings(list(b.EnabledRoutes)))
}

// listShape is how a body wrote its route lists: absent, null or [].
func listShape(b apiBody) string {
	shape := func(raw json.RawMessage) string {
		if raw == nil {
			return "absent"
		}

		return string(raw)
	}

	return "advertised " + shape(b.AdvertisedRoutes) + " enabled " + shape(b.EnabledRoutes)
}

func presence(set bool) string {
	if set {
		return "set"
	}

	return "absent"
}

func optional(s *string) string {
	if s == nil {
		return "absent"
	}

	return *s
}

// credentialLabel is the SaaS label of an auth key or OAuth client ID
// headscale sent.
func (r *apiReplay) credentialLabel(id *string) string {
	if id == nil {
		return "absent"
	}

	for _, kind := range []string{"auth", "client"} {
		if l, ok := r.labels[kind+"/"+*id]; ok {
			return l
		}
	}

	return "{unmatched}"
}

// observe records one object's value on each side for a check over every
// body that names it.
func (r *apiReplay) observe(check, label, want, got string) {
	if r.aggregates[check] == nil {
		r.aggregates[check] = map[string][2]map[string]bool{}
	}

	seen, ok := r.aggregates[check][label]
	if !ok {
		seen = [2]map[string]bool{{}, {}}
		r.aggregates[check][label] = seen
	}

	seen[0][want] = true
	seen[1][got] = true
}

// aggregateChecks compares, per object and check, the values each side
// showed over the capture.
func (r *apiReplay) aggregateChecks(t *testing.T) {
	t.Helper()

	for _, check := range slices.Sorted(maps.Keys(r.aggregates)) {
		for _, label := range slices.Sorted(maps.Keys(r.aggregates[check])) {
			seen := r.aggregates[check][label]
			name := strings.Trim(label, "{}") + "/" + check
			key := r.c.TestID + "/" + name
			r.evaluated[key] = true

			t.Run(name, func(t *testing.T) {
				apiCompatCheck(t, key,
					strings.Join(slices.Sorted(maps.Keys(seen[0])), "|"),
					strings.Join(slices.Sorted(maps.Keys(seen[1])), "|"))
			})
		}
	}
}

// messageCheck passes when SaaS's error message appears in headscale's
// answer, as its message, OAuth error description or one of its details.
func messageCheck(t *testing.T, saas, hs []byte) apiCheck {
	t.Helper()

	var want struct {
		Message string `json:"message"`
	}
	require.NoError(t, json.Unmarshal(saas, &want))

	texts := errorTexts(hs)
	for _, s := range texts {
		if strings.Contains(s, want.Message) {
			return apiCheck{"message", want.Message, want.Message}
		}
	}

	return apiCheck{"message", want.Message, strings.Join(texts, " | ")}
}

func errorTexts(raw []byte) []string {
	var body struct {
		Message          string `json:"message"`
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
		Data             []struct {
			Errors []string `json:"errors"`
		} `json:"data"`
	}

	if json.Unmarshal(raw, &body) != nil {
		return []string{string(raw)}
	}

	texts := []string{body.Message, body.ErrorDescription}
	for _, d := range body.Data {
		texts = append(texts, d.Errors...)
	}

	return slices.DeleteFunc(texts, func(s string) bool { return s == "" })
}

// policyCheck compares a policy answer: the HuJSON text byte for byte when
// SaaS sent text, else the document.
func (r *apiReplay) policyCheck(t *testing.T, a testcapture.Action, resp []byte) apiCheck {
	t.Helper()

	want := string(r.policyBody(t, a.Response))
	if strings.HasPrefix(string(a.Response), `"`) {
		return apiCheck{"body", want, string(resp)}
	}

	return apiCheck{"body", canonicalPolicy(t, []byte(want)), canonicalPolicy(t, resp)}
}

func canonicalPolicy(t *testing.T, raw []byte) string {
	t.Helper()

	std, err := hujson.Standardize(bytes.Clone(raw))
	require.NoErrorf(t, err, "policy: %s", raw)

	var v any
	require.NoError(t, json.Unmarshal(std, &v))

	out, err := json.Marshal(v)
	require.NoError(t, err)

	return string(out)
}

// etagCheck compares where each side first saw the answer's ETag.
func (r *apiReplay) etagCheck(step testcapture.Step, i int, label, hs string) apiCheck {
	here := fmt.Sprintf("%s/%d", step.Name, i)

	first := func(seen map[string]string, v string) string {
		if at, ok := seen[v]; ok {
			return "same as " + at
		}

		seen[v] = here

		return "new"
	}

	if _, ok := r.hsByLabel[label]; !ok {
		r.hsByLabel[label] = hs
	}

	return apiCheck{"etag", first(r.saasETag, label), first(r.hsETag, hs)}
}

// refusalChecks compare a refused policy write or validate's detail: the
// hostnames it names that the policy does not, how many detail entries for
// which users, and whether a second principal sending the same body to the
// same endpoint got the same answer.
func (r *apiReplay) refusalChecks(t *testing.T, a testcapture.Action, endpoint string, sent, resp []byte) []apiCheck {
	t.Helper()

	var hostnames []string

	for _, n := range r.c.Topology.Nodes {
		if !bytes.Contains(sent, []byte(n.Hostname)) {
			hostnames = append(hostnames, n.Hostname)
		}
	}

	named := func(texts []string) string {
		var out []string

		for _, h := range hostnames {
			if slices.ContainsFunc(texts, func(s string) bool { return strings.Contains(s, h) }) {
				out = append(out, h)
			}
		}

		return sortedStrings(out)
	}

	var want, got struct {
		Data []struct {
			User string `json:"user"`
		} `json:"data"`
	}

	require.NoError(t, json.Unmarshal(a.Response, &want))

	require.NoErrorf(t, json.Unmarshal(resp, &got), "body: %s", resp)

	users := func(data []struct {
		User string `json:"user"`
	},
	) string {
		out := make([]string, 0, len(data))
		for _, d := range data {
			out = append(out, r.userName(d.User))
		}

		return fmt.Sprintf("%q", out)
	}

	checks := []apiCheck{
		{"hostnames", named(errorTexts(a.Response)), named(errorTexts(resp))},
		{"detail", users(want.Data), users(got.Data)},
	}

	sameBody := endpoint + " " + string(sent)
	if prev, ok := r.refusals[sameBody]; ok && bytes.Equal(prev[0], a.Response) {
		checks = append(checks, apiCheck{"same-answer", "same", map[bool]string{true: "same", false: "differs"}[bytes.Equal(prev[1], resp)]})
	}

	r.refusals[sameBody] = [2][]byte{a.Response, resp}

	return checks
}

// enforcedNow renders what every replayed node enforces: its filter rules and
// SSH rules.
func (r *apiReplay) enforcedNow(t *testing.T) string {
	t.Helper()

	var b strings.Builder

	for _, label := range slices.Sorted(maps.Keys(r.ids)) {
		if !strings.HasPrefix(label, "{device:") {
			continue
		}

		id, err := strconv.ParseUint(r.ids[label], 10, 64)
		require.NoError(t, err)

		nv, ok := r.app.state.GetNodeByID(types.NodeID(id))
		require.True(t, ok, label)

		rules, err := r.app.state.FilterForNode(nv)
		require.NoError(t, err)

		ssh, err := r.app.state.SSHPolicy(nv)
		require.NoError(t, err)

		out, err := json.Marshal([]any{rules, ssh})
		require.NoError(t, err)

		fmt.Fprintf(&b, "%s %s\n", label, out)
	}

	return b.String()
}

// enforcedCheck compares whether a policy row changed what nodes enforce.
// Every row starts from the baseline the first captured step installed, so
// SaaS's change is its nodes' rules against that step's.
func (r *apiReplay) enforcedCheck(t *testing.T, step testcapture.Step, kind, before string) (apiCheck, bool) {
	t.Helper()

	if len(step.Captures) == 0 || kind != "api" {
		return apiCheck{}, false
	}

	saas := make(map[string]string, len(step.Captures))

	for alias, n := range step.Captures {
		out, err := json.Marshal([]any{n.PacketFilterRules, n.SSHRules})
		require.NoError(t, err)

		saas[alias] = string(out)
	}

	if r.saasBaseline == nil {
		r.saasBaseline = saas

		return apiCheck{}, false
	}

	name := "enforced"
	if r.useV1 {
		name = "v1-enforced"
	}

	return apiCheck{name, changed(!maps.Equal(saas, r.saasBaseline)), changed(r.enforcedNow(t) != before)}, true
}

// v1Policy sends a policy write or validate through the v1 API. Writes
// refused by SaaS only for their If-Match have no v1 form and are not sent.
func (r *apiReplay) v1Policy(t *testing.T, step testcapture.Step, i int, a testcapture.Action) []apiCheck {
	t.Helper()

	endpoint, _, _ := strings.Cut(a.Path, "?")

	if a.Method == http.MethodGet {
		if label := a.RespHeader["ETag"]; label != "" {
			r.saasCurrentETag = label
		}

		return nil
	}

	if _, ok := a.Header["If-Match"]; ok && a.Status == http.StatusPreconditionFailed {
		return nil
	}

	body, err := json.Marshal(map[string]string{"policy": string(r.policyBody(t, a.Body))})
	require.NoError(t, err)

	if endpoint == "/tailnet/-/acl/validate" {
		res := callHandler(r.v1, http.MethodPost, "/api/v1/policy/check", body)

		// SaaS's validate answers 200 with a message for some refusals.
		var saas struct {
			Message string `json:"message"`
		}
		require.NoError(t, json.Unmarshal(a.Response, &saas))

		return []apiCheck{{"v1-verdict", verdict(a.Status == http.StatusOK && saas.Message == ""), verdict(isSuccess(res.status))}}
	}

	storedBefore := r.storedPolicy()
	before := r.enforcedNow(t)
	etagBefore := r.saasCurrentETag

	res := callHandler(r.v1, http.MethodPut, "/api/v1/policy", body)

	if label := a.RespHeader["ETag"]; label != "" {
		r.saasCurrentETag = label
	}

	if a.Kind == "policy" {
		require.Truef(t, isSuccess(res.status), "%s: setup policy: %s", step.Name, res.body)

		return nil
	}

	checks := []apiCheck{{"v1-verdict", verdict(a.Status/100 == 2), verdict(isSuccess(res.status))}}

	// SaaS's stored policy changed when the step's next read has a new ETag.
	for _, next := range step.Actions[i+1:] {
		if next.Method == http.MethodGet && next.RespHeader["ETag"] != "" {
			checks = append(checks, apiCheck{
				"v1-stored",
				changed(next.RespHeader["ETag"] != etagBefore),
				changed(r.storedPolicy() != storedBefore),
			})

			break
		}
	}

	if ch, ok := r.enforcedCheck(t, step, a.Kind, before); ok {
		checks = append(checks, ch)
	}

	return checks
}

func verdict(ok bool) string {
	if ok {
		return "accepted"
	}

	return "refused"
}

func changed(c bool) string {
	if c {
		return "changed"
	}

	return "unchanged"
}

func (r *apiReplay) storedPolicy() string {
	p, err := r.app.state.GetPolicy()
	if err != nil {
		return ""
	}

	return p.Data
}
