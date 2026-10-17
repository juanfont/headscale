// This file replays re-authentication captures from Tailscale SaaS.
//
// Test data source: testdata/steps/owner-routes.hujson, loaded by name; the
// replay and checks are runRouteLifecycleCompat in lifecycle_compat_test.go.
// Source format:    github.com/juanfont/headscale/hscontrol/types/testcapture

package servertest_test

import "testing"

// reauthSkipReasons lists checks where headscale differs from SaaS, keyed
// <test_id>/<step>/<check>. A listed check that matches fails, so a fix must
// delete its entry.
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
}

const (
	expiredKeyAccepted        = "EXPIRED_KEY_ACCEPTED: headscale re-registers an expired node under its old node key; SaaS answers NodeKeyExpired, so the client rotates it"
	adminRetagNoApproval      = "ADMIN_RETAG_NO_APPROVAL: an admin tag change does not auto-approve the routes the new tags may approve; SaaS approves them at once"
	withdrawKeepsAutoApproval = "WITHDRAW_KEEPS_AUTO_APPROVAL: headscale keeps an auto-approved route once it is withdrawn; SaaS drops it and keeps only admin-set approvals"
)

// TestReauthCompat replays owner changes on routers with approved routes:
// re-auth with another tag's key, the same after expiry and key deletion,
// same-tag rotation, admin retag, a user router converted by a tagged key
// and same-user re-auth, each followed by a withdraw and re-advertise.
func TestReauthCompat(t *testing.T) {
	t.Parallel()

	t.Run("owner-routes", func(t *testing.T) {
		t.Parallel()

		runRouteLifecycleCompat(t, "owner-routes", "obs", reauthSkipReasons)
	})
}
