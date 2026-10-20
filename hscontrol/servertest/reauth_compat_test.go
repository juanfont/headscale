// This file replays re-authentication captures from Tailscale SaaS.
//
// Test data source: testdata/steps/{owner-routes,reauth,reauth-foreign,
// reauth-owner,identity,reauth-user,tag-owner-chain}.hujson, loaded by name.
// owner-routes is checked by runRouteLifecycleCompat in
// lifecycle_compat_test.go. tag-owner-chain's joins are replayed here; its
// OAuth mints and the tag owner functions are checked in ../policy/v2. The
// refused logins of ephemeral-lifecycle.hujson are rows here too.
// Source format:    github.com/juanfont/headscale/hscontrol/types/testcapture

package servertest_test

import (
	"cmp"
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/servertest"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/types/testcapture"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
	"tailscale.com/tailcfg"
	"tailscale.com/types/netmap"
	"tailscale.com/wgengine/filter"
)

// reauthSkipReasons lists checks where headscale differs from SaaS, keyed
// <test_id>/<step>[/<node>]/<check>. A listed check that matches fails, so a
// fix must delete its entry.
var reauthSkipReasons = map[string]string{
	"owner-routes/r-expired-retag/expire/served": expiredRouterUnserved,
	"owner-routes/r-expired-retag/expire/online": expiredPeerOffline,

	"owner-routes/r-expired-retag/owner/node-key": expiredKeyAccepted,

	"owner-routes/r-admin/owner/enabled":     adminRetagNoApproval,
	"owner-routes/r-admin/owner/served":      adminRetagNoApproval,
	"owner-routes/r-admin/owner/self-routes": adminRetagNoApproval,

	"owner-routes/r-retag/withdraw/enabled":         withdrawKeepsAutoApproval,
	"owner-routes/r-expired-retag/withdraw/enabled": withdrawKeepsAutoApproval,
	"owner-routes/u-convert/withdraw/enabled":       withdrawKeepsAutoApproval,

	"reauth/t-spent-relogin/t-spent/outcome":            expiredKeyNotRotated,
	"reauth/t-revoked-relogin/t-revoked/outcome":        expiredKeyNotRotated,
	"reauth/t-valid-relogin/t-valid/outcome":            expiredKeyNotRotated,
	"reauth/t-valid-relogin/t-valid/node-key":           expiredKeyAccepted,
	"reauth-user/a4-expired-spent-key/u-spent/outcome":  expiredKeyNotRotated,
	"reauth-user/a5-expired-valid-key/u-valid/outcome":  expiredKeyNotRotated,
	"reauth-user/a5-expired-valid-key/u-valid/node-key": expiredKeyAccepted,

	"reauth/t-spent-relogin/t-spent/expiry":         expiredTaggedRevived,
	"reauth/t-spent-relogin/t-spent/peer-obs":       expiredTaggedRevived,
	"reauth/t-spent-relogin-force/t-spent/expiry":   expiredTaggedRevived,
	"reauth/t-spent-relogin-force/t-spent/peer-obs": expiredTaggedRevived,
	"reauth/t-revoked-relogin/t-revoked/expiry":     expiredTaggedRevived,
	"reauth/t-revoked-relogin/t-revoked/peer-obs":   expiredTaggedRevived,

	"reauth-owner/u-renew-relogin/u-renew/expiry": sameKeyRenewsExpiry,
	"reauth-user/a1-spent-key/u-spent/expiry":     sameKeyRenewsExpiry,
	"reauth-user/a2-valid-key/u-valid/expiry":     sameKeyRenewsExpiry,

	"reauth-foreign/t-reauth-foreign-relogin/t-reauth-foreign/devices":       otherUserKeyReauthsTagged,
	"reauth-foreign/t-reauth-foreign-relogin/t-reauth-foreign/owner":         otherUserKeyReauthsTagged,
	"reauth-foreign/t-reauth-foreign-relogin/t-reauth-foreign/node-key":      otherUserKeyReauthsTagged,
	"reauth-foreign/t-reauth-foreign-relogin/t-reauth-foreign/expiry":        otherUserKeyReauthsTagged,
	"reauth-foreign/t-reauth-foreign-relogin/t-reauth-foreign/ephemeral":     otherUserKeyReauthsTagged,
	"reauth-foreign/t-reauth-foreign-relogin/t-reauth-foreign/peer-obs":      otherUserKeyReauthsTagged,
	"reauth-foreign/t-reauth-foreign-relogin/obs/filter":                     otherUserKeyReauthsTagged,
	"reauth-foreign/t-reauth-foreign-relogin/t-reauth-foreign/login-devices": loginTakesTaggedDevice,
	"reauth-foreign/t-reauth-foreign-relogin/t-reauth-foreign/login-owner":   loginTakesTaggedDevice,
	"reauth-foreign/t-exp-foreign-relogin/t-exp-foreign/devices":             otherUserKeyReauthsTagged,
	"reauth-foreign/t-exp-foreign-relogin/t-exp-foreign/owner":               otherUserKeyReauthsTagged,
	"reauth-foreign/t-exp-foreign-relogin/t-exp-foreign/node-key":            otherUserKeyReauthsTagged,
	"reauth-foreign/t-exp-foreign-relogin/t-exp-foreign/expiry":              otherUserKeyReauthsTagged,
	"reauth-foreign/t-exp-foreign-relogin/t-exp-foreign/ephemeral":           otherUserKeyReauthsTagged,
	"reauth-foreign/t-exp-foreign-relogin/t-exp-foreign/peer-obs":            otherUserKeyReauthsTagged,
	"reauth-foreign/t-exp-foreign-relogin/obs/filter":                        otherUserKeyReauthsTagged,
	"reauth-foreign/t-exp-foreign-relogin/t-exp-foreign/login-devices":       loginTakesTaggedDevice,
	"reauth-foreign/t-exp-foreign-relogin/t-exp-foreign/login-owner":         loginTakesTaggedDevice,

	"reauth-foreign/t-eph-spent-foreign-key/t-eph/ephemeral": spentKeyRebindsNode,
	"reauth-foreign/t-eph-logout/t-eph/devices":              spentKeyRebindsNode,
	"reauth-foreign/t-eph-logout/t-eph/owner":                spentKeyRebindsNode,
	"reauth-foreign/t-eph-logout/t-eph/expiry":               spentKeyRebindsNode,
	"reauth-foreign/t-eph-logout/t-eph/ephemeral":            spentKeyRebindsNode,
	"reauth-foreign/t-eph-logout/t-eph/peer-obs":             spentKeyRebindsNode,

	"reauth-foreign/t-logout-logout/t-logout/expiry":    taggedLogoutNotExpired,
	"reauth-foreign/t-logout-logout/t-logout/peer-obs":  taggedLogoutNotExpired,
	"reauth-foreign/t-logout-relogin/t-logout/expiry":   taggedLogoutNotExpired,
	"reauth-foreign/t-logout-relogin/t-logout/peer-obs": taggedLogoutNotExpired,

	"reauth-foreign/t-wake-foreign-key-tags/t-wake/outcome": wakeWithTagsRefused,
	"identity/w-tagreq-relogin-tags/w-tagreq/owner":         keyLoginTagsRefused,
	"identity/w-tagreq-relogin-tags/w-tagreq/outcome":       keyLoginTagsRefused,
	"identity/w-tagreq-relogin-tags/w-tagreq/node-key":      keyLoginTagsRefused,
	"identity/w-tagreq-relogin-tags/w-tagreq/expiry":        keyLoginTagsRefused,
	"identity/w-tagreq-relogin-tags/obs/filter":             keyLoginTagsRefused,
	"identity/w-tagreq-new-join/w-tagreq-new/devices":       keyLoginTagsRefused,
	"identity/w-tagreq-new-join/w-tagreq-new/owner":         keyLoginTagsRefused,
	"identity/w-tagreq-new-join/w-tagreq-new/outcome":       keyLoginTagsRefused,
	"identity/w-tagreq-new-join/w-tagreq-new/expiry":        keyLoginTagsRefused,
	"identity/w-tagreq-new-join/w-tagreq-new/ephemeral":     keyLoginTagsRefused,
	"identity/w-tagreq-new-join/w-tagreq-new/peer-obs":      keyLoginTagsRefused,
	"identity/w-tagreq-new-join/w-tagreq-new/peer-key-obs":  keyLoginTagsRefused,

	"tag-owner-chain/u-base-join/u-base/devices":      keyLoginTagsRefused,
	"tag-owner-chain/u-base-join/u-base/owner":        keyLoginTagsRefused,
	"tag-owner-chain/u-base-join/u-base/outcome":      keyLoginTagsRefused,
	"tag-owner-chain/u-base-join/u-base/expiry":       keyLoginTagsRefused,
	"tag-owner-chain/u-base-join/u-base/ephemeral":    keyLoginTagsRefused,
	"tag-owner-chain/u-base-join/u-base/peer-obs":     keyLoginTagsRefused,
	"tag-owner-chain/u-base-join/u-base/peer-key-obs": keyLoginTagsRefused,

	"tag-owner-chain/t-mid-join/t-mid/devices":      taggedKeyOwnedTagRefused,
	"tag-owner-chain/t-mid-join/t-mid/owner":        taggedKeyOwnedTagRefused,
	"tag-owner-chain/t-mid-join/t-mid/outcome":      taggedKeyOwnedTagRefused,
	"tag-owner-chain/t-mid-join/t-mid/expiry":       taggedKeyOwnedTagRefused,
	"tag-owner-chain/t-mid-join/t-mid/ephemeral":    taggedKeyOwnedTagRefused,
	"tag-owner-chain/t-mid-join/t-mid/peer-obs":     taggedKeyOwnedTagRefused,
	"tag-owner-chain/t-mid-join/t-mid/peer-key-obs": taggedKeyOwnedTagRefused,

	"reauth-owner/u-tagged-reauth-relogin/u-tagged-reauth/owner":  adminTagsKeptOnUserLogin,
	"reauth-owner/u-tagged-reauth-relogin/u-tagged-reauth/expiry": adminTagsKeptOnUserLogin,
	"reauth-owner/u-tagged-reauth-relogin/obs/filter":             adminTagsKeptOnUserLogin,

	"reauth/late-pak-spent-key/late-pak/text":        refusalText,
	"reauth/late-pak-spent-key/late-pak/legacy-text": refusalText,

	"ephemeral-lifecycle/late-revoked/late/text":            refusalText,
	"ephemeral-lifecycle/late-revoked/late/legacy-text":     refusalText,
	"ephemeral-lifecycle/late-expired/late-exp/text":        refusalText,
	"ephemeral-lifecycle/late-expired/late-exp/legacy-text": refusalText,
}

const (
	expiredKeyAccepted        = "EXPIRED_KEY_ACCEPTED: headscale re-registers an expired node under its old node key; SaaS answers NodeKeyExpired, so the client rotates it"
	adminRetagNoApproval      = "ADMIN_RETAG_NO_APPROVAL: an admin tag change does not auto-approve the routes the new tags may approve; SaaS approves them at once"
	withdrawKeepsAutoApproval = "WITHDRAW_KEEPS_AUTO_APPROVAL: headscale keeps an auto-approved route once it is withdrawn; SaaS drops it and keeps only admin-set approvals"
)

const (
	expiredKeyNotRotated      = "EXPIRED_KEY_NOT_ROTATED: headscale answers an expired node's key login without asking for a new node key; SaaS answers NodeKeyExpired first, so the client rotates it"
	expiredTaggedRevived      = "EXPIRED_TAGGED_REVIVED: headscale lets an expired tagged node log in again with its spent or revoked key and lifts its expiry; SaaS refuses the key and the node stays expired"
	sameKeyRenewsExpiry       = "SAME_KEY_LOGIN_RENEWS_EXPIRY: headscale renews a user node's expiry on a key login that keeps its node key; SaaS renews it only with a new node key"
	otherUserKeyReauthsTagged = "OTHER_USER_KEY_REAUTHS_TAGGED: headscale re-registers a tagged device in place when another user's key logs in anew on its machine; SaaS keeps the tagged device and adds one for that user"
	loginTakesTaggedDevice    = "LOGIN_TAKES_TAGGED_DEVICE: headscale's interactive login gives another user the tagged device on the machine; SaaS's key login keeps it and adds a device for that user"
	spentKeyRebindsNode       = "SPENT_KEY_REBINDS_NODE: headscale binds a live node to the spent key it logs in with, so an ephemeral node stops being ephemeral and survives logout; SaaS keeps the node as it was"
	taggedLogoutNotExpired    = "TAGGED_LOGOUT_NOT_EXPIRED: headscale leaves a tagged node unexpired when it logs out; SaaS expires it"
	wakeWithTagsRefused       = "WAKE_WITH_TAGS_REFUSED: headscale refuses a key login that requests tags the key does not carry even when the node keeps its node key and tags; SaaS accepts it and changes nothing"
	keyLoginTagsRefused       = "KEY_LOGIN_TAGS_REFUSED: headscale refuses a user's key login that requests tags the user owns; SaaS tags the device, converting it in place or creating it tagged"
	taggedKeyOwnedTagRefused  = "TAGGED_KEY_OWNED_TAG_REFUSED: headscale refuses a tagged key's login that requests a tag the key's tags own; SaaS gives the device the requested tags"
	adminTagsKeptOnUserLogin  = "ADMIN_TAGS_KEPT_ON_USER_LOGIN: headscale keeps an admin-tagged device tagged when its user's key logs in anew; SaaS turns it back into that user's device"
	refusalText               = "REFUSAL_TEXT: SaaS refuses a key by naming its ID; headscale says why the key is refused"
)

// reauthNotCompared lists, by key prefix, checks left out: SaaS's answer
// there is in doubt, so it is no reference.
var reauthNotCompared = []string{
	"reauth-user/a8-convert/key:A-Kp",
	"reauth-user/a8-convert/u-convert/expiry",
	"reauth-user/a9-used-tagged-key/key:A-Kp",
	"reauth-user/a9-used-tagged-key/u-loser-same/owner",
	"reauth-user/a9-used-tagged-key/u-loser-same/outcome",
	"reauth-user/a9-used-tagged-key/obs/filter",
	"reauth-user/a9-used-tagged-key/t-server/filter",
	"reauth-user/a10-used-tagged-key-force/u-loser-force/owner",
	"reauth-user/a10-used-tagged-key-force/u-loser-force/outcome",
	"reauth-user/a10-used-tagged-key-force/u-loser-force/node-key",
	"reauth-user/a10-used-tagged-key-force/u-loser-force/expiry",
	"reauth-user/a10-used-tagged-key-force/obs/filter",
	"reauth-user/a10-used-tagged-key-force/t-server/filter",
}

// reauthCompatTests are the captures [runReauthCompat] replays.
var reauthCompatTests = []string{"reauth", "reauth-foreign", "reauth-owner", "identity", "reauth-user", "tag-owner-chain"}

// reauthObservers stay up through a capture: their view of each cell and
// their own filters are checked.
var reauthObservers = []string{"obs", "t-server"}

// TestReauthCompat replays re-authentication against SaaS. owner-routes:
// owner changes on routers with approved routes. The others: expired and
// live devices logging in again with spent, revoked, valid and other users'
// keys, logout, ephemeral devices, admin tagging, conversion either way, a
// second profile, one single-use tagged key presented by several devices,
// and joins requesting tags owned through other tags. via=login replays a
// user's key logins as interactive logins that user approves.
func TestReauthCompat(t *testing.T) {
	t.Parallel()

	t.Run("owner-routes", func(t *testing.T) {
		t.Parallel()

		runRouteLifecycleCompat(t, "owner-routes", "obs", reauthSkipReasons)
	})

	for _, id := range reauthCompatTests {
		for _, via := range []string{"key", "login"} {
			t.Run(id+"/via="+via, func(t *testing.T) {
				t.Parallel()

				runReauthCompat(t, id, via == "login")
			})
		}
	}
}

// runReauthCompat replays capture id step by step and checks each cell the
// step acted on against SaaS:
//   - outcome: the login's register answers, see [registerOutcome];
//   - devices, owner, node-key, expiry, ephemeral: every device on the
//     cell's machine, in join order;
//   - peer-<observer>, peer-key, disco: how the observers see them;
//
// and, per step, each observer's filter and each key SaaS read back. With
// viaLogin, a login SaaS accepted from a user's key is replayed as an
// interactive login that user approves, and only its devices and owner, and
// its expiry when SaaS ended tagged, are checked.
func runReauthCompat(t *testing.T, id string, viaLogin bool) {
	t.Helper()

	c := readStepCapture(t, id)

	days := c.Input.Tailnet.Settings.DevicesKeyDurationDays
	require.NotNil(t, days, "%s: no key duration", id)

	run := &reauthRun{
		c:         c,
		r:         newStepReplay(t, c, servertest.WithNodeExpiry(time.Duration(*days)*24*time.Hour)),
		viaLogin:  viaLogin,
		loggedOut: map[string]bool{},
		saasFirst: map[string]deviceView{},
		hsFirst:   map[string]deviceView{},
		saasPrev:  map[string]deviceView{},
		evaluated: map[string]bool{},
	}

	if viaLogin {
		run.r.interactive = func(step testcapture.Step, a testcapture.Action) bool {
			return loginReplayable(step, a, run.r.keyTags, run.loggedOut[a.Node])
		}
	}

	for _, step := range c.Steps {
		// The replay has no OAuth client; ../policy/v2 checks the mints
		// against TagOwnedByTags, which headscale's mint asks.
		if slices.ContainsFunc(step.Actions, func(a testcapture.Action) bool { return a.Kind == "token" }) {
			break
		}

		if step.Result == "setup-failed" {
			require.False(t, slices.ContainsFunc(step.Actions, func(a testcapture.Action) bool {
				return a.Kind != "api" || a.Status < http.StatusBadRequest
			}), "%s: a failed setup is skipped only when SaaS refused all of it", step.Name)

			continue
		}

		require.Contains(t, []string{"observed", "expected-refusal"}, step.Result,
			"%s: the replay follows every step", step.Name)

		run.step(t, step)
	}

	for k := range reauthSkipReasons {
		check := k[strings.LastIndex(k, "/")+1:]
		if !strings.HasPrefix(k, id+"/") || refusalCheck(check) ||
			strings.HasPrefix(check, "login-") != viaLogin {
			continue
		}

		if !run.evaluated[k] {
			t.Errorf("skip entry %q names no check", k)
		}
	}
}

// reauthRun is one replay of a re-authentication capture and what earlier
// steps showed on each side.
type reauthRun struct {
	c        *testcapture.Capture
	r        *stepReplay
	viaLogin bool

	loggedOut map[string]bool

	// saasFirst and hsFirst hold each cell's first device; saasPrev each
	// SaaS device as last listed.
	saasFirst, hsFirst map[string]deviceView
	saasPrev           map[string]deviceView

	prevCaptures map[string]testcapture.Node
	evaluated    map[string]bool
}

// before is headscale's state for a step's cells just before it runs.
type before struct {
	attempts map[string]int
	views    map[string]deviceView
	disco    map[string]string
}

func (run *reauthRun) step(t *testing.T, step testcapture.Step) {
	t.Helper()

	r := run.r
	cells, logins := stepCells(step)

	prev := before{attempts: map[string]int{}, views: map[string]deviceView{}, disco: map[string]string{}}

	for _, cell := range cells {
		if cl, ok := r.clients[cell]; ok {
			prev.attempts[cell] = len(cl.RegisterAttempts())
		}

		for _, v := range r.hsViews(cell) {
			prev.views[v.id] = v

			for _, obs := range reauthObservers {
				if cl, ok := r.clients[obs]; ok {
					prev.disco[obs+"/"+v.id] = peerDisco(cl.Netmap(), v.nodeID)
				}
			}
		}
	}

	r.apply(t, step)

	// After apply: a step's own mints decide its keys' tags.
	replayed := map[string]bool{}
	for node, a := range logins {
		replayed[node] = loginReplayable(step, a, r.keyTags, run.loggedOut[node])
	}

	for _, a := range step.Actions {
		switch a.Kind {
		case "cli":
			run.loggedOut[a.Node] = strings.Join(a.Args, " ") == "logout"
		case "join", "relogin", "login", "switch_profile":
			run.loggedOut[a.Node] = false
		}
	}

	defer func() { run.prevCaptures = step.Captures }()

	devices, readAt, ok := stepDeviceRead(step)
	if !ok {
		return
	}

	var checks []stepCheck

	for _, cell := range cells {
		if run.viaLogin && !replayed[cell] {
			continue
		}

		login, isLogin := logins[cell]
		checks = append(checks, run.cellChecks(step, cell, saasDeviceViews(run.c, devices, cell, readAt), prev, login, isLogin)...)
	}

	if !run.viaLogin {
		checks = append(checks, r.keyChecks(step)...)
		checks = append(checks, r.filterChecks(t, step, devices)...)
	}

	prefix := run.c.TestID + "/" + step.Name + "/"
	checks = slices.DeleteFunc(checks, func(ch stepCheck) bool {
		return notCompared(reauthNotCompared, prefix+ch.name)
	})

	// Marked here, so a run filtered to other steps does not call these
	// entries stale.
	for _, ch := range checks {
		run.evaluated[prefix+ch.name] = true
	}

	if len(checks) > 0 {
		t.Run(step.Name, func(t *testing.T) {
			holdChecks(t, reauthSkipReasons, prefix, checks, run.evaluated)
		})
	}

	for _, cell := range cells {
		if want := saasDeviceViews(run.c, devices, cell, readAt); len(want) > 0 {
			if _, ok := run.saasFirst[cell]; !ok {
				run.saasFirst[cell] = want[0]
			}
		}

		if got := r.hsViews(cell); len(got) > 0 {
			if _, ok := run.hsFirst[cell]; !ok {
				run.hsFirst[cell] = got[0]
			}
		}
	}

	for _, d := range devices {
		run.saasPrev[d.ID] = saasDeviceView(run.c, d, readAt)
	}
}

// cellChecks builds one cell's checks for a step; want is SaaS's view of
// the cell's devices.
func (run *reauthRun) cellChecks(
	step testcapture.Step,
	cell string,
	want []deviceView,
	prev before,
	login testcapture.Action,
	isLogin bool,
) []stepCheck {
	r := run.r
	got := func() []deviceView { return r.hsViews(cell) }

	var checks []stepCheck

	check := func(name, want string, got func() string) {
		if run.viaLogin {
			name = "login-" + name
		}

		checks = append(checks, stepCheck{cell + "/" + name, want, got})
	}

	first, ok := run.saasFirst[cell]
	if !ok && len(want) > 0 {
		first = want[0]
	}

	check("devices", renderDevices(want, first), func() string {
		views := got()

		f, ok := run.hsFirst[cell]
		if !ok && len(views) > 0 {
			f = views[0]
		}

		return renderDevices(views, f)
	})
	check("owner", renderOwners(want), func() string { return renderOwners(got()) })

	if run.viaLogin {
		if len(want) > 0 && !slices.ContainsFunc(want, func(v deviceView) bool { return !v.tagged }) {
			check("expiry", renderExpiry(want, run.saasPrev), func() string { return renderExpiry(got(), prev.views) })
		}

		return checks
	}

	if isLogin {
		check("outcome", registerOutcome(step.Register[login.Node]), func() string {
			return registerOutcome(r.clients[cell].RegisterAttempts()[prev.attempts[cell]:])
		})
	}

	if slices.ContainsFunc(want, func(v deviceView) bool { _, ok := run.saasPrev[v.id]; return ok }) {
		check("node-key", renderNodeKeys(want, run.saasPrev), func() string { return renderNodeKeys(got(), prev.views) })
	}

	check("expiry", renderExpiry(want, run.saasPrev), func() string { return renderExpiry(got(), prev.views) })
	check("ephemeral", renderEphemeral(want), func() string { return renderEphemeral(got()) })

	self := step.Captures[cell]
	restarted := slices.ContainsFunc(step.Actions, func(a testcapture.Action) bool {
		return a.Kind == "restart" && a.Node == cell
	})

	for _, obs := range reauthObservers {
		view, captured := step.Captures[obs]
		if !captured || obs == cell {
			continue
		}

		check("peer-"+obs, renderPeers(want, view.Netmap), func() string {
			return renderPeers(got(), r.clients[obs].Netmap())
		})

		if self.Netmap == nil {
			continue
		}

		if self.BackendState == "Running" {
			check("peer-key-"+obs, peerKeyState(view.Netmap, self.Netmap), func() string {
				return peerKeyState(r.clients[obs].Netmap(), r.clients[cell].Netmap())
			})
		}

		if restarted {
			selfID := self.Netmap.SelfNode.ID()
			saas := discoChange(peerDisco(run.prevCaptures[obs].Netmap, selfID), peerDisco(view.Netmap, selfID))

			check("disco-"+obs, saas, func() string {
				views := got()
				if len(views) == 0 {
					return "no device"
				}

				v := views[len(views)-1]

				return discoChange(prev.disco[obs+"/"+v.id], peerDisco(r.clients[obs].Netmap(), v.nodeID))
			})
		}
	}

	return checks
}

// stepCells returns the nodes a step acts on, in order, and the last login
// each made. A step that names none, such as a key deletion, acts on every
// captured node that is not an observer.
func stepCells(step testcapture.Step) ([]string, map[string]testcapture.Action) {
	var cells []string

	logins := map[string]testcapture.Action{}

	add := func(node string) {
		if !slices.Contains(cells, node) {
			cells = append(cells, node)
		}
	}

	for _, a := range step.Actions {
		switch a.Kind {
		case "join", "relogin", "login", "switch_profile":
			add(a.Node)
			logins[a.Node] = a
		case "restart", "cli", "logout":
			add(a.Node)
		case "api":
			if strings.HasPrefix(a.Path, "/device/") {
				alias, _, _ := strings.Cut(strings.TrimPrefix(a.Path, "/device/{device:"), "}")
				add(alias)
			}
		}
	}

	if len(cells) == 0 {
		for _, node := range slices.Sorted(maps.Keys(step.Captures)) {
			if !slices.Contains(reauthObservers, node) {
				add(node)
			}
		}
	}

	return cells, logins
}

// loginReplayable reports whether via=login replays a as an interactive
// login: a join, a new profile, or a relogin that starts a new login (forced,
// or after a logout), made with a user's untagged key and accepted by SaaS.
// A key's refusal says nothing about who may approve a login.
func loginReplayable(step testcapture.Step, a testcapture.Action, keyTags map[string][]string, loggedOut bool) bool {
	switch a.Kind {
	case "join", "login":
	case "relogin":
		if !a.Force && !loggedOut {
			return false
		}
	default:
		return false
	}

	tags, minted := keyTags[a.Key]

	return minted && len(tags) == 0 && step.Result == "observed" &&
		strings.HasSuffix(registerOutcome(step.Register[a.Node]), "accepted")
}

// registerOutcome reads a login's register exchanges up to the answer that
// ends it: "node-key-expired" for each answer asking for a new node key,
// then "accepted", "refused" or "auth-url". Errors of a login the client
// cancelled to start another are skipped.
func registerOutcome(attempts []testcapture.RegisterAttempt) string {
	var out []string

	for _, a := range attempts {
		switch {
		case strings.Contains(a.Err, "context canceled"):
		case a.Err != "":
			return strings.Join(append(out, "refused"), ", ")
		case a.AuthURL != "":
			return strings.Join(append(out, "auth-url"), ", ")
		case a.NodeKeyExpired != nil && *a.NodeKeyExpired:
			out = append(out, "node-key-expired")
		case a.MachineAuthorized != nil && *a.MachineAuthorized:
			return strings.Join(append(out, "accepted"), ", ")
		}
	}

	return strings.Join(append(out, "unanswered"), ", ")
}

// stepDeviceRead returns the step's last device list and when SaaS read it.
func stepDeviceRead(step testcapture.Step) ([]saasDevice, time.Time, bool) {
	for _, a := range slices.Backward(step.Actions) {
		if a.Kind != "api" || a.Method != http.MethodGet || !strings.HasPrefix(a.Path, "/tailnet/-/devices") {
			continue
		}

		var out struct {
			Devices []saasDevice `json:"devices"`
		}

		if json.Unmarshal(a.Response, &out) != nil {
			return nil, time.Time{}, false
		}

		return out.Devices, step.At.Add(time.Duration(a.OffsetMS) * time.Millisecond), true
	}

	return nil, time.Time{}, false
}

// deviceView is one device as the checks read it, from a SaaS device list
// or headscale's NodeStore.
type deviceView struct {
	id        string // SaaS label or headscale node ID
	nodeID    tailcfg.NodeID
	tagged    bool
	owner     string
	expiry    string // "disabled", "past" or "future"
	expires   string // the raw expiry, to tell a renewal from no change
	ephemeral bool
	nodeKey   string
	addrs     string
	ips       []netip.Addr
}

// saasDeviceViews returns the devices on cell's machine in join order: the
// first device, then "#2" onward.
func saasDeviceViews(c *testcapture.Capture, devices []saasDevice, cell string, at time.Time) []deviceView {
	var out []deviceView

	for _, d := range devices {
		if d.MachineKey == "{machine:"+cell+"}" {
			out = append(out, saasDeviceView(c, d, at))
		}
	}

	slices.SortFunc(out, func(a, b deviceView) int {
		return cmp.Or(cmp.Compare(len(a.id), len(b.id)), strings.Compare(a.id, b.id))
	})

	return out
}

func saasDeviceView(c *testcapture.Capture, d saasDevice, at time.Time) deviceView {
	expiry := "disabled"

	exp, err := time.Parse(time.RFC3339, d.Expires)
	if err == nil && !d.KeyExpiryDisabled {
		expiry = "future"
		if exp.Before(at) {
			expiry = "past"
		}
	}

	return deviceView{
		id:        d.ID,
		nodeID:    c.NodeIDs[deviceLabelAlias(d.ID)],
		tagged:    len(d.Tags) > 0,
		owner:     saasOwner(d),
		expiry:    expiry,
		expires:   d.Expires,
		ephemeral: d.IsEphemeral,
		nodeKey:   d.NodeKey,
		addrs:     sortedStrings(d.Addresses),
	}
}

// deviceLabelAlias turns "{device:x#2}" into "x#2".
func deviceLabelAlias(label string) string {
	return strings.TrimSuffix(strings.TrimPrefix(label, "{device:"), "}")
}

// hsViews returns the nodes on alias's machine in join order.
func (r *stepReplay) hsViews(alias string) []deviceView {
	nodes := r.machineNodes(alias)
	slices.SortFunc(nodes, func(a, b types.NodeView) int { return cmp.Compare(a.ID(), b.ID()) })

	out := make([]deviceView, 0, len(nodes))

	for _, nv := range nodes {
		v := deviceView{
			id:        nv.StringID(),
			nodeID:    nv.ID().NodeID(),
			tagged:    nv.IsTagged(),
			expiry:    "disabled",
			ephemeral: nv.IsEphemeral(),
			nodeKey:   nv.NodeKey().String(),
			addrs:     sortedStrings(nv.IPsAsString()),
			ips:       nv.IPs(),
		}

		if v.tagged {
			v.owner = "tags " + sortedStrings(nv.Tags().AsSlice())
		} else {
			v.owner = "user " + nv.User().Name()
		}

		if exp := nv.Expiry(); exp.Valid() && !exp.Get().IsZero() {
			v.expires = exp.Get().String()

			v.expiry = "future"
			if exp.Get().Before(time.Now()) {
				v.expiry = "past"
			}
		}

		out = append(out, v)
	}

	return out
}

func renderDevices(views []deviceView, first deviceView) string {
	kept := slices.ContainsFunc(views, func(v deviceView) bool {
		return v.id == first.id && v.addrs == first.addrs
	})

	return fmt.Sprintf("devices %d, first kept %t", len(views), kept)
}

func renderOwners(views []deviceView) string {
	return renderEach(views, func(v deviceView) string { return v.owner })
}

func renderNodeKeys(views []deviceView, prev map[string]deviceView) string {
	return renderEach(views, func(v deviceView) string {
		p, ok := prev[v.id]

		switch {
		case !ok:
			return "new"
		case p.nodeKey == v.nodeKey:
			return "kept"
		default:
			return "rotated"
		}
	})
}

// renderExpiry gives each device's expiry class; a future expiry also says
// whether the step moved it.
func renderExpiry(views []deviceView, prev map[string]deviceView) string {
	return renderEach(views, func(v deviceView) string {
		p, ok := prev[v.id]
		if v.expiry != "future" || !ok || p.expiry != "future" {
			return v.expiry
		}

		if p.expires == v.expires {
			return "future, unchanged"
		}

		return "future, renewed"
	})
}

func renderEphemeral(views []deviceView) string {
	return renderEach(views, func(v deviceView) string { return strconv.FormatBool(v.ephemeral) })
}

// renderPeers gives how an observer sees each device: absent, expired or
// valid.
func renderPeers(views []deviceView, nm *netmap.NetworkMap) string {
	return renderEach(views, func(v deviceView) string {
		p, missing := peerByID(nm, v.nodeID)

		switch {
		case missing != "":
			return missing
		case p.Expired():
			return "expired"
		default:
			return "valid"
		}
	})
}

func renderEach(views []deviceView, f func(deviceView) string) string {
	out := make([]string, len(views))
	for i, v := range views {
		out[i] = f(v)
	}

	return strings.Join(out, "; ")
}

// peerKeyState reports whether the observer's peer entry for a node holds
// the node key the node itself uses.
func peerKeyState(observer, self *netmap.NetworkMap) string {
	if self == nil || !self.SelfNode.Valid() {
		return "no self"
	}

	p, missing := peerByID(observer, self.SelfNode.ID())
	if missing != "" {
		return missing
	}

	if p.Key() == self.SelfNode.Key() {
		return "current"
	}

	return "stale"
}

func peerDisco(nm *netmap.NetworkMap, id tailcfg.NodeID) string {
	p, missing := peerByID(nm, id)
	if missing != "" {
		return missing
	}

	return p.DiscoKey().String()
}

func discoChange(before, after string) string {
	switch {
	case strings.HasPrefix(after, "discokey:") && before == after:
		return "kept"
	case strings.HasPrefix(after, "discokey:") && strings.HasPrefix(before, "discokey:"):
		return "rotated"
	default:
		return before + " -> " + after
	}
}

// keyChecks compares each key SaaS read back in the step: valid, invalid
// (spent, revoked or expired) or absent.
func (r *stepReplay) keyChecks(step testcapture.Step) []stepCheck {
	var checks []stepCheck

	for _, a := range step.Actions {
		label, ok := strings.CutPrefix(a.Path, "/tailnet/-/keys/{key:")
		if a.Kind != "api" || a.Method != http.MethodGet || !ok {
			continue
		}

		// A member may read no keys, so his refused read says nothing about
		// the key.
		if a.Status != http.StatusOK && a.Principal != "admin" {
			continue
		}

		label = strings.TrimSuffix(label, "}")

		want := "absent"

		if a.Status == http.StatusOK {
			var k struct {
				Invalid bool `json:"invalid"`
			}

			want = "valid"
			if json.Unmarshal(a.Response, &k) == nil && k.Invalid {
				want = "invalid"
			}
		}

		checks = append(checks, stepCheck{"key:" + label, want, func() string {
			pak, err := r.srv.State().GetPreAuthKeyByID(r.keyIDs[label])

			switch {
			case err != nil:
				return "absent"
			case pak.Validate() != nil:
				return "invalid"
			default:
				return "valid"
			}
		}})
	}

	return checks
}

// filterChecks compares each captured observer's packet filter, as source
// devices and ports per rule. The observer is every rule's destination, so
// destinations are left out.
func (r *stepReplay) filterChecks(t *testing.T, step testcapture.Step, devices []saasDevice) []stepCheck {
	t.Helper()

	saasNames := map[netip.Addr]string{}

	for _, d := range devices {
		for _, s := range d.Addresses {
			addr, err := netip.ParseAddr(s)
			if err == nil {
				saasNames[addr] = deviceLabelAlias(d.ID)
			}
		}
	}

	var checks []stepCheck

	for _, obs := range reauthObservers {
		view, ok := step.Captures[obs]
		if !ok {
			continue
		}

		var want []string

		for _, rule := range view.PacketFilterRules {
			var srcs []netip.Prefix

			for _, s := range rule.SrcIPs {
				pfxs, err := parseDstPrefixes(s)
				require.NoError(t, err, "%s: %s filter source", step.Name, obs)

				srcs = append(srcs, pfxs...)
			}

			for _, dp := range rule.DstPorts {
				want = append(want, filterLine(srcs, saasNames, dp.Ports.First, dp.Ports.Last))
			}
		}

		checks = append(checks, stepCheck{obs + "/filter", filterLines(want), func() string {
			nm := r.clients[obs].Netmap()
			if nm == nil {
				return "no netmap"
			}

			names := r.addrNames()

			var got []string

			for _, m := range nm.PacketFilter {
				got = append(got, matchLines(m, names)...)
			}

			return filterLines(got)
		}})
	}

	return checks
}

func matchLines(m filter.Match, names map[netip.Addr]string) []string {
	out := make([]string, 0, len(m.Dsts))
	for _, d := range m.Dsts {
		out = append(out, filterLine(m.Srcs, names, d.Ports.First, d.Ports.Last))
	}

	return out
}

// filterLine renders one rule as "sources => first-last".
func filterLine(srcs []netip.Prefix, names map[netip.Addr]string, first, last uint16) string {
	set := map[string]bool{}

	// Headscale merges adjacent addresses into prefixes, so a Tailscale
	// prefix stands for every device inside it.
	for _, p := range srcs {
		matched := false

		if p.Bits() == 0 {
			set["*"], matched = true, true
		} else if prefixInTailscaleRange(p) {
			for addr, name := range names {
				if p.Contains(addr) {
					set[name], matched = true, true
				}
			}
		}

		if !matched {
			set[p.String()] = true
		}
	}

	return fmt.Sprintf("%s => %d-%d", strings.Join(slices.Sorted(maps.Keys(set)), ","), first, last)
}

func filterLines(lines []string) string {
	slices.Sort(lines)

	return strings.Join(slices.Compact(lines), "\n")
}

// addrNames names each headscale node by its machine's alias, with "#2"
// onward for later nodes on one machine, as SaaS labels devices.
func (r *stepReplay) addrNames() map[netip.Addr]string {
	out := map[netip.Addr]string{}

	for alias := range r.clients {
		for i, v := range r.hsViews(alias) {
			name := alias
			if i > 0 {
				name = fmt.Sprintf("%s#%d", alias, i+1)
			}

			for _, addr := range v.ips {
				out[addr] = name
			}
		}
	}

	return out
}

// authKeyRefusalRows are fresh machines logging in with a key whose state
// the capture shows: spent, revoked by a delete, expired, and a valid
// control row.
var authKeyRefusalRows = []struct {
	id, step, node string
}{
	{"reauth", "late-pak-spent-key", "late-pak"},
	{"reauth", "t-valid-join", "t-valid"},
	{"ephemeral-lifecycle", "late-revoked", "late"},
	{"ephemeral-lifecycle", "late-expired", "late-exp"},
}

// refusalCheck reports whether a check name belongs to
// [TestAuthKeyRefusalCompat].
func refusalCheck(check string) bool {
	switch strings.TrimPrefix(check, "legacy-") {
	case "refused", "nodes", "text":
		return true
	}

	return false
}

// TestAuthKeyRefusalCompat replays a fresh machine's login with a key in
// the state SaaS shows, and checks that it is refused or accepted as on
// SaaS and that a refusal leaves no node. Each row runs again with the key
// stored under a legacy hash, the path that verifies it on a slower route.
func TestAuthKeyRefusalCompat(t *testing.T) {
	t.Parallel()

	for _, row := range authKeyRefusalRows {
		for _, legacy := range []bool{false, true} {
			name := row.id + "/" + row.step
			if legacy {
				name += "/legacy_hash"
			}

			t.Run(name, func(t *testing.T) {
				t.Parallel()

				runAuthKeyRefusalCompat(t, row.id, row.step, row.node, legacy)
			})
		}
	}

	t.Run("entries", func(t *testing.T) {
		for k := range reauthSkipReasons {
			check := k[strings.LastIndex(k, "/")+1:]
			if !refusalCheck(check) {
				continue
			}

			named := slices.ContainsFunc(authKeyRefusalRows, func(row struct{ id, step, node string }) bool {
				return strings.HasPrefix(k, row.id+"/"+row.step+"/"+row.node+"/")
			})
			if !named {
				t.Errorf("skip entry %q names no check", k)
			}
		}
	})
}

func runAuthKeyRefusalCompat(t *testing.T, id, stepName, node string, legacy bool) {
	t.Helper()

	c := readStepCapture(t, id)
	r := newStepReplay(t, c)
	// Statuses are compared by the capture's own test; here a difference
	// must not stop the replay.
	r.readAPI = true

	i := slices.IndexFunc(c.Steps, func(s testcapture.Step) bool { return s.Name == stepName })
	require.GreaterOrEqual(t, i, 0, "%s: no step %s", id, stepName)

	for _, step := range c.Steps[:i] {
		r.apply(t, step)
	}

	step := c.Steps[i]

	j := slices.IndexFunc(step.Actions, func(a testcapture.Action) bool { return a.Kind == "join" && a.Node == node })
	require.GreaterOrEqual(t, j, 0, "%s: %s does not join", stepName, node)

	// Keys minted in the step exist only once their action ran.
	var refused map[string]error

	if legacy {
		label := step.Actions[j].Key
		head, tail := step, step
		head.Actions, tail.Actions = step.Actions[:j], step.Actions[j:]
		r.apply(t, head)
		r.storeLegacyHash(t, label)
		refused = r.apply(t, tail)

		// Verifying a legacy hash upgrades it, so the login took that path.
		var hash string
		require.NoError(t, r.srv.State().DB().DB.Raw(
			"SELECT hash FROM credentials WHERE id = ?", r.keyIDs[label]).Scan(&hash).Error)
		require.True(t, strings.HasPrefix(hash, "$sha256$"), "the login verified the legacy hash")
	} else {
		refused = r.apply(t, step)
	}

	devices, _, ok := stepDeviceRead(step)
	require.True(t, ok, "%s: no device list", stepName)

	saas := registerOutcome(step.Register[node])
	saasErr := ""

	for _, a := range step.Register[node] {
		if a.Err != "" && !strings.Contains(a.Err, "context canceled") {
			saasErr = a.Err

			break
		}
	}

	prefix := ""
	if legacy {
		prefix = "legacy-"
	}

	checks := make([]stepCheck, 0, 3)
	checks = append(checks,
		stepCheck{node + "/" + prefix + "refused", strconv.FormatBool(strings.HasSuffix(saas, "refused")), func() string {
			return strconv.FormatBool(refused[node] != nil)
		}},
		stepCheck{node + "/" + prefix + "nodes", strconv.Itoa(len(saasDeviceViews(c, devices, node, step.At))), func() string {
			return strconv.Itoa(len(r.machineNodes(node)))
		}},
	)

	checks = append(checks, stepCheck{node + "/" + prefix + "text", saasErr, func() string {
		if refused[node] == nil {
			return ""
		}

		// The client wraps the server's message in its own context.
		msg := refused[node].Error()
		if i := strings.LastIndex(msg, ": "); i >= 0 {
			msg = msg[i+2:]
		}

		return msg
	}})

	holdChecks(t, reauthSkipReasons, id+"/"+stepName+"/", checks, map[string]bool{})
}

// storeLegacyHash rewrites a key's stored secret as a legacy bcrypt hash,
// as keys created before the SHA-256 format hold it.
func (r *stepReplay) storeLegacyHash(t *testing.T, label string) {
	t.Helper()

	full, ok := r.keys[label]
	require.True(t, ok, "no key %s", label)

	secret := full[strings.LastIndex(full, "-")+1:]

	hash, err := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.MinCost)
	require.NoError(t, err)

	require.NoError(t, r.srv.State().DB().DB.Exec(
		"UPDATE credentials SET hash = ? WHERE id = ?", hash, r.keyIDs[label],
	).Error)
}
