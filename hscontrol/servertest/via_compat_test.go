// This file implements data-driven via grant compatibility tests using
// golden data captured from Tailscale SaaS. These scenarios exercise via
// grant steering with peer connectivity, cross-subnet forwarding and
// exit nodes.
//
// Test data source: ../policy/v2/testdata/{grant,routes}_results/, see
// viaCompatTests and routesMapCompatTests
// Source format:    github.com/juanfont/headscale/hscontrol/types/testcapture
package servertest_test

import (
	"context"
	"fmt"
	"maps"
	"net/netip"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/servertest"
	"github.com/juanfont/headscale/hscontrol/state"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/types/testcapture"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go4.org/netipx"
	"tailscale.com/tailcfg"
	"tailscale.com/tailcfg/peercap"
	"tailscale.com/types/netmap"
	"tailscale.com/types/views"
	"tailscale.com/wgengine/filter"
)

// viaCompatTests lists golden captures that exercise via grant steering.
var viaCompatTests = []struct {
	id   string
	desc string
}{
	{"grant-v11", "tag src steers subnet via router"},
	{"grant-v12", "member src steers subnet via router"},
	{"grant-v13", "group src steers subnet via router to members only"},
	{"via-grant-v14", "tag src steers the internet via tag:exit"},
	{"via-grant-v15", "wildcard src steers the internet via tag:exit"},
	{"via-grant-v16", "tag and member srcs steer the internet via tag:exit"},
	{"via-grant-v26", "one group steers the internet via one exit tag"},
	{"via-grant-v27", "members steer the internet via tag:exit on one port"},
	{"via-grant-v28", "crossed exit steering: group-a via one exit tag, group-b via another"},
	{"via-grant-v29", "crossed subnet steering: group-a via router-a, group-b via router-b"},
	{"via-grant-v30", "crossed mixed: subnet via router-a/b, exit via exit-b/a"},
	{"via-grant-v31", "peer connectivity + via exit A/B steering"},
	{"via-grant-v32", "via exit steering plus a member grant to a tagged host port"},
	{"via-grant-v33", "single via grant + HA primary election"},
	{"via-grant-v34", "wildcard src steers the internet via two exit tags"},
	{"via-grant-v35", "via grant with unadvertised destination"},
	{"via-grant-v36", "full complex: peer connectivity + crossed subnet + crossed exit"},
	{"via-grant-v47", "via dst prefix broader than the advertised subnet"},
	{"via-grant-v48", "via dst prefix narrower than the advertised subnet"},
	{"via-grant-v49", "via dst host alias broader than the advertised subnet"},
	{"via-grant-v50", "via dst prefix disjoint from the advertised subnet"},
	{"via-grant-v52", "members reach the internet only via tag:exit, admins reach everything"},
	{"via-grant-v53", "via exit steering plus a member rule to a tagged host port"},
	{"via-grant-v54", "via exit steering plus a member rule to autogroup:self"},
	{"via-grant-v55", "via exit steering plus a member rule to a private subnet"},
	{"via-grant-v56", "via exit steering plus a plain member rule to autogroup:internet"},
	{"via-grant-v57", "via exit steering plus a member rule to a non-via exit node"},
	{"via-grant-v58", "no via grant: approved exit nodes plus a member rule to a tagged host port"},
	{"via-grant-v59", "via exit steering for tagged clients; members have an unrelated rule"},
	{"via-grant-v60", "user-owned exit node outside the via tag; members have an autogroup:self rule"},
	{"via-grant-v61", "via exit steering plus a member capability grant to a tagged host"},
	{"via-grant-v62", "via exit steering plus a member rule to autogroup:internet on one port"},
	{"via-grant-v63", "repeated and nested via destinations, and a second via grant on one port"},
	{"via-grant-v66", "a user source steers a subnet via tag:router"},
	{"via-grant-v67", "an empty group as the only via source"},
}

// routesMapCompatTests lists routes captures replayed through the mapper.
// They are shared with TestRoutesCompat* in policy/v2, which read their
// filters and route sets; this replay reads the netmaps.
var routesMapCompatTests = []struct {
	id   string
	desc string
}{
	{"routes-a1-wildcard-acl-includes-routes-in-srcips", "wildcard ACL, every router"},
	{"routes-a2-tag-based-acl-excludes-routes", "router-to-router ACL"},
	{"routes-a3-explicit-subnet-filter-to-router", "ACL to one subnet"},
	{"routes-a4-multiple-routes-same-router", "ACL to one route of a router with an exit route too"},
	{"routes-e1-ha-two-routers-same-subnet", "HA pair, ACL to the shared subnet"},
	{"routes-e2-ha-primary-in-allowedips", "HA primary in AllowedIPs"},
	{"routes-f2-subnet-as-acl-source", "subnet as ACL source"},
	{"routes-f3-wildcard-src-specific-dst", "ACL to one port of a subnet"},
	{"routes-h1-wildcard-srcips-format", "wildcard source to tagged routers"},
	{"routes-pa1-partial-route-approval", "router with an unapproved route"},
	{"routes-m1-wildcard-src-multi-range", "wildcard source to a tagged port, multi-route router"},
	{"routes-m2-member-partial-subnet", "members to one route of a multi-route router"},
	{"routes-m3-subnet-route-as-src", "one route of a multi-route router as source"},
	{"routes-m4-member-self", "members to autogroup:self beside a multi-route router"},
	{"routes-m5-wildcard-all", "allow-all with a multi-route router and an exit node"},
	{"routes-m6-subnet-to-subnet-multi-route", "subnet of a multi-route router to a subnet of an exit node"},
}

// viaCompatSkipReasons lists checks where headscale differs from SaaS, keyed
// <test_id>/<node>/<check>, or by check alone where every capture differs the
// same way. A listed check that matches fails, so a fix must delete its entry.
var viaCompatSkipReasons = map[string]string{
	"tagged-self": "TAGGED_SELF_PROFILE: SaaS gives a tagged node a profile of its own, headscale the shared tagged-devices one",

	// TestViaGrantSourceLossCompat, keyed <test_id>/rename/<node>/<check>.
	"via-grant-v67/rename/squirtle/peers":          viaSourceLossNotSent,
	"via-grant-v67/rename/squirtle/packet-filter":  viaSourceLossNotSent,
	"via-grant-v67/rename/blastoise/peers":         viaSourceLossNotSent,
	"via-grant-v67/rename/blastoise/packet-filter": viaSourceLossNotSent,
	"via-grant-v67/rename/ivysaur/peers":           viaSourceLossNotSent,

	// Adjacent member addresses merge into one prefix, and the reduced
	// filter keeps all of it; SaaS lists only the node's own address.
	"routes-f2-subnet-as-acl-source/ivysaur/packet-filter":  "FILTER_DST_MERGED: own filter names a neighbour's address",
	"routes-f2-subnet-as-acl-source/venusaur/packet-filter": "FILTER_DST_MERGED: own filter names a neighbour's address",

	// SaaS sends a router every approved route in its own AllowedIPs and
	// every route it is primary for in PrimaryRoutes.
	"grant-v11/blastoise/self-routes": selfRoutesReduced,
	"grant-v11/squirtle/self-routes":  selfRoutesReduced,
	"grant-v12/blastoise/self-routes": selfRoutesReduced,
	"grant-v12/squirtle/self-routes":  selfRoutesReduced,
	"grant-v13/blastoise/self-routes": selfRoutesReduced,
	"grant-v13/squirtle/self-routes":  selfRoutesReduced,

	"routes-a1-wildcard-acl-includes-routes-in-srcips/butterfree/self-routes": selfRoutesReduced,
	"routes-a2-tag-based-acl-excludes-routes/butterfree/self-routes":          selfRoutesReduced,
	"routes-a2-tag-based-acl-excludes-routes/caterpie/self-routes":            selfRoutesReduced,
	"routes-a2-tag-based-acl-excludes-routes/metapod/self-routes":             selfRoutesReduced,
	"routes-a2-tag-based-acl-excludes-routes/squirtle/self-routes":            selfRoutesReduced,
	"routes-a2-tag-based-acl-excludes-routes/wartortle/self-routes":           selfRoutesReduced,
	"routes-a3-explicit-subnet-filter-to-router/butterfree/self-routes":       selfRoutesReduced,
	"routes-a3-explicit-subnet-filter-to-router/metapod/self-routes":          selfRoutesReduced,
	"routes-a3-explicit-subnet-filter-to-router/wartortle/self-routes":        selfRoutesReduced,
	"routes-a4-multiple-routes-same-router/butterfree/self-routes":            selfRoutesReduced,
	"routes-a4-multiple-routes-same-router/caterpie/self-routes":              selfRoutesReduced,
	"routes-a4-multiple-routes-same-router/metapod/self-routes":               selfRoutesReduced,
	"routes-a4-multiple-routes-same-router/squirtle/self-routes":              selfRoutesReduced,
	"routes-e1-ha-two-routers-same-subnet/butterfree/self-routes":             selfRoutesReduced,
	"routes-e1-ha-two-routers-same-subnet/caterpie/self-routes":               selfRoutesReduced,
	"routes-e1-ha-two-routers-same-subnet/squirtle/self-routes":               selfRoutesReduced,
	"routes-e1-ha-two-routers-same-subnet/wartortle/self-routes":              selfRoutesReduced,
	"routes-e2-ha-primary-in-allowedips/butterfree/self-routes":               selfRoutesReduced,
	"routes-e2-ha-primary-in-allowedips/caterpie/self-routes":                 selfRoutesReduced,
	"routes-e2-ha-primary-in-allowedips/squirtle/self-routes":                 selfRoutesReduced,
	"routes-e2-ha-primary-in-allowedips/wartortle/self-routes":                selfRoutesReduced,
	"routes-f2-subnet-as-acl-source/butterfree/self-routes":                   selfRoutesReduced,
	"routes-f2-subnet-as-acl-source/caterpie/self-routes":                     selfRoutesReduced,
	"routes-f2-subnet-as-acl-source/metapod/self-routes":                      selfRoutesReduced,
	"routes-f2-subnet-as-acl-source/squirtle/self-routes":                     selfRoutesReduced,
	"routes-f2-subnet-as-acl-source/wartortle/self-routes":                    selfRoutesReduced,
	"routes-f3-wildcard-src-specific-dst/butterfree/self-routes":              selfRoutesReduced,
	"routes-f3-wildcard-src-specific-dst/metapod/self-routes":                 selfRoutesReduced,
	"routes-f3-wildcard-src-specific-dst/wartortle/self-routes":               selfRoutesReduced,
	"routes-h1-wildcard-srcips-format/butterfree/self-routes":                 selfRoutesReduced,
	"routes-h1-wildcard-srcips-format/metapod/self-routes":                    selfRoutesReduced,
	"routes-pa1-partial-route-approval/butterfree/self-routes":                selfRoutesReduced,
	"routes-m1-wildcard-src-multi-range/r-exit/self-routes":                   selfRoutesReduced,
	"routes-m1-wildcard-src-multi-range/r-multi/self-routes":                  selfRoutesReduced,
	"routes-m2-member-partial-subnet/r-exit/self-routes":                      selfRoutesReduced,
	"routes-m2-member-partial-subnet/r-multi/self-routes":                     selfRoutesReduced,
	"routes-m3-subnet-route-as-src/r-exit/self-routes":                        selfRoutesReduced,
	"routes-m3-subnet-route-as-src/r-multi/self-routes":                       selfRoutesReduced,
	"routes-m4-member-self/r-exit/self-routes":                                selfRoutesReduced,
	"routes-m4-member-self/r-multi/self-routes":                               selfRoutesReduced,
	"routes-m6-subnet-to-subnet-multi-route/r-exit/self-routes":               selfRoutesReduced,
	"routes-m6-subnet-to-subnet-multi-route/r-multi/self-routes":              selfRoutesReduced,

	"via-grant-v14/blastoise/self-routes": selfRoutesReduced,
	"via-grant-v14/fearow/self-routes":    selfRoutesReduced,
	"via-grant-v14/spearow/self-routes":   selfRoutesReduced,
	"via-grant-v14/squirtle/self-routes":  selfRoutesReduced,
	"via-grant-v15/blastoise/self-routes": selfRoutesReduced,
	"via-grant-v15/fearow/self-routes":    selfRoutesReduced,
	"via-grant-v15/spearow/self-routes":   selfRoutesReduced,
	"via-grant-v15/squirtle/self-routes":  selfRoutesReduced,
	"via-grant-v16/blastoise/self-routes": selfRoutesReduced,
	"via-grant-v16/fearow/self-routes":    selfRoutesReduced,
	"via-grant-v16/spearow/self-routes":   selfRoutesReduced,
	"via-grant-v16/squirtle/self-routes":  selfRoutesReduced,
	"via-grant-v26/blastoise/self-routes": selfRoutesReduced,
	"via-grant-v26/fearow/self-routes":    selfRoutesReduced,
	"via-grant-v26/spearow/self-routes":   selfRoutesReduced,
	"via-grant-v26/squirtle/self-routes":  selfRoutesReduced,
	"via-grant-v27/blastoise/self-routes": selfRoutesReduced,
	"via-grant-v27/fearow/self-routes":    selfRoutesReduced,
	"via-grant-v27/spearow/self-routes":   selfRoutesReduced,
	"via-grant-v27/squirtle/self-routes":  selfRoutesReduced,
	"via-grant-v28/blastoise/self-routes": selfRoutesReduced,
	"via-grant-v28/fearow/self-routes":    selfRoutesReduced,
	"via-grant-v28/spearow/self-routes":   selfRoutesReduced,
	"via-grant-v28/squirtle/self-routes":  selfRoutesReduced,
	"via-grant-v29/blastoise/self-routes": selfRoutesReduced,
	"via-grant-v29/fearow/self-routes":    selfRoutesReduced,
	"via-grant-v29/spearow/self-routes":   selfRoutesReduced,
	"via-grant-v29/squirtle/self-routes":  selfRoutesReduced,
	"via-grant-v30/blastoise/self-routes": selfRoutesReduced,
	"via-grant-v30/fearow/self-routes":    selfRoutesReduced,
	"via-grant-v30/spearow/self-routes":   selfRoutesReduced,
	"via-grant-v30/squirtle/self-routes":  selfRoutesReduced,
	"via-grant-v31/blastoise/self-routes": selfRoutesReduced,
	"via-grant-v31/fearow/self-routes":    selfRoutesReduced,
	"via-grant-v31/spearow/self-routes":   selfRoutesReduced,
	"via-grant-v31/squirtle/self-routes":  selfRoutesReduced,
	"via-grant-v32/blastoise/self-routes": selfRoutesReduced,
	"via-grant-v32/fearow/self-routes":    selfRoutesReduced,
	"via-grant-v32/spearow/self-routes":   selfRoutesReduced,
	"via-grant-v32/squirtle/self-routes":  selfRoutesReduced,
	"via-grant-v33/blastoise/self-routes": selfRoutesReduced,
	"via-grant-v33/fearow/self-routes":    selfRoutesReduced,
	"via-grant-v33/spearow/self-routes":   selfRoutesReduced,
	"via-grant-v33/squirtle/self-routes":  selfRoutesReduced,
	"via-grant-v34/blastoise/self-routes": selfRoutesReduced,
	"via-grant-v34/fearow/self-routes":    selfRoutesReduced,
	"via-grant-v34/spearow/self-routes":   selfRoutesReduced,
	"via-grant-v34/squirtle/self-routes":  selfRoutesReduced,
	"via-grant-v35/blastoise/self-routes": selfRoutesReduced,
	"via-grant-v35/fearow/self-routes":    selfRoutesReduced,
	"via-grant-v35/spearow/self-routes":   selfRoutesReduced,
	"via-grant-v35/squirtle/self-routes":  selfRoutesReduced,
	"via-grant-v36/blastoise/self-routes": selfRoutesReduced,
	"via-grant-v36/fearow/self-routes":    selfRoutesReduced,
	"via-grant-v36/spearow/self-routes":   selfRoutesReduced,
	"via-grant-v36/squirtle/self-routes":  selfRoutesReduced,
	"via-grant-v47/blastoise/self-routes": selfRoutesReduced,
	"via-grant-v47/fearow/self-routes":    selfRoutesReduced,
	"via-grant-v47/spearow/self-routes":   selfRoutesReduced,
	"via-grant-v47/squirtle/self-routes":  selfRoutesReduced,
	"via-grant-v48/blastoise/self-routes": selfRoutesReduced,
	"via-grant-v48/fearow/self-routes":    selfRoutesReduced,
	"via-grant-v48/spearow/self-routes":   selfRoutesReduced,
	"via-grant-v48/squirtle/self-routes":  selfRoutesReduced,
	"via-grant-v49/blastoise/self-routes": selfRoutesReduced,
	"via-grant-v49/fearow/self-routes":    selfRoutesReduced,
	"via-grant-v49/spearow/self-routes":   selfRoutesReduced,
	"via-grant-v49/squirtle/self-routes":  selfRoutesReduced,
	"via-grant-v50/blastoise/self-routes": selfRoutesReduced,
	"via-grant-v50/fearow/self-routes":    selfRoutesReduced,
	"via-grant-v50/spearow/self-routes":   selfRoutesReduced,
	"via-grant-v50/squirtle/self-routes":  selfRoutesReduced,
	"via-grant-v63/blastoise/self-routes": selfRoutesReduced,
	"via-grant-v63/fearow/self-routes":    selfRoutesReduced,
	"via-grant-v63/spearow/self-routes":   selfRoutesReduced,
	"via-grant-v63/squirtle/self-routes":  selfRoutesReduced,
	"via-grant-v66/blastoise/self-routes": selfRoutesReduced,
	"via-grant-v66/squirtle/self-routes":  selfRoutesReduced,
	"via-grant-v67/blastoise/self-routes": selfRoutesReduced,
	"via-grant-v67/squirtle/self-routes":  selfRoutesReduced,

	"routes-m1-wildcard-src-multi-range/srv/peer-allowed-ips":         exitRoutesOnOverlap,
	"routes-m6-subnet-to-subnet-multi-route/r-multi/peer-allowed-ips": exitRoutesOnOverlap,

	"routes-m1-wildcard-src-multi-range/m-odin1/peers":     sameUserPeers,
	"routes-m1-wildcard-src-multi-range/m-odin2/peers":     sameUserPeers,
	"routes-m2-member-partial-subnet/m-odin1/peers":        sameUserPeers,
	"routes-m2-member-partial-subnet/m-odin2/peers":        sameUserPeers,
	"routes-m3-subnet-route-as-src/m-odin1/peers":          sameUserPeers,
	"routes-m3-subnet-route-as-src/m-odin2/peers":          sameUserPeers,
	"routes-m6-subnet-to-subnet-multi-route/m-odin1/peers": sameUserPeers,
	"routes-m6-subnet-to-subnet-multi-route/m-odin2/peers": sameUserPeers,
}

const viaSourceLossNotSent = "VIA_SOURCE_LOSS_NOT_SENT: a user change that leaves a via grant without sources does not reach open streams"

const exitRoutesOnOverlap = "EXIT_ROUTES_ON_OVERLAP: headscale offers a peer's exit routes to a viewer whose rules reach only nodes or subnets; SaaS leaves them out"

const sameUserPeers = "SAME_USER_PEERS: SaaS lists a user's own devices as each other's peers with no rule linking them; headscale peers only what the policy links"

const selfRoutesReduced = "SELF_ROUTES_REDUCED: headscale sends a router only the primary routes its policy lets it reach"

// TestRoutesMapCompat replays routesMapCompatTests through
// [runViaMapCompat].
func TestRoutesMapCompat(t *testing.T) {
	t.Parallel()

	for _, tc := range routesMapCompatTests {
		t.Run(tc.id, func(t *testing.T) {
			t.Parallel()

			path := filepath.Join(
				"..", "policy", "v2", "testdata", "routes_results", tc.id+".hujson",
			)

			c, err := testcapture.Read(path)
			require.NoError(t, err, "failed to read %s", path)

			runViaMapCompat(t, c)
		})
	}
}

// TestViaGrantMapCompat loads golden captures from Tailscale SaaS and
// compares headscale's [tailcfg.MapResponse] structure against the captured [netmap.NetworkMap].
//
// The comparison is IP-independent: it validates peer visibility, route
// prefixes in AllowedIPs, and PrimaryRoutes — not literal Tailscale IP
// addresses which differ between Tailscale SaaS and headscale allocation.
//
// CROSS-DEPENDENCY WARNING:
// This test reads golden files from ../policy/v2/testdata/grant_results/
// (the ones listed in viaCompatTests). These files are shared
// with TestGrantsCompat in the policy/v2 package. Any changes to the
// file format, field structure, or naming must be coordinated with
// BOTH tests.
//
// Fields consumed by this test (but NOT by TestGrantsCompat):
//   - captures[name].netmap (Peers, AllowedIPs, PrimaryRoutes, PacketFilterRules)
//   - topology.nodes[name].tags and .user (used for servertest node creation)
//
// Fields consumed by TestGrantsCompat (but NOT by this test):
//   - captures[name].packet_filter_rules (golden filter rule comparison)
//   - input.api_response_code/body (error case handling)
func TestViaGrantMapCompat(t *testing.T) {
	t.Parallel()

	for _, tc := range viaCompatTests {
		t.Run(tc.id, func(t *testing.T) {
			t.Parallel()

			path := filepath.Join(
				"..", "policy", "v2", "testdata", "grant_results", tc.id+".hujson",
			)

			c, err := testcapture.Read(path)
			require.NoError(t, err, "failed to read %s", path)

			if c.Error {
				t.Skipf("test %s is an error case", tc.id)

				return
			}

			runViaMapCompat(t, c)
		})
	}
}

// TestViaGrantSourceLossCompat renames the only user a via grant names, so
// the grant's source resolves to nothing, and checks that the open streams
// of the routers and the user's node reach what SaaS sends for the same
// grant with an empty source, without reconnecting.
//
// Test data source: ../policy/v2/testdata/grant_results/via-grant-v66.hujson
// and via-grant-v67.hujson, shared with TestGrantsCompat and
// TestViaGrantMapCompat.
func TestViaGrantSourceLossCompat(t *testing.T) {
	t.Parallel()

	read := func(id string) *testcapture.Capture {
		c, err := testcapture.Read(filepath.Join(
			"..", "policy", "v2", "testdata", "grant_results", id+".hujson",
		))
		require.NoError(t, err, "failed to read %s", id)

		return c
	}

	before, after := read("via-grant-v66"), read("via-grant-v67")

	srv, clients := startViaMapCompat(t, before)
	compareViaMapCompat(t, before, clients)

	user, err := srv.State().GetUserByName("thor")
	require.NoError(t, err)

	_, userChange, err := srv.State().RenameUser(types.UserID(user.ID), "thor-renamed")
	require.NoError(t, err)
	srv.App.Change(userChange)

	saasAddrs := saasAddrsByNode(after, clients)

	for _, name := range []string{"squirtle", "blastoise", "ivysaur"} {
		t.Run("rename/"+name, func(t *testing.T) {
			t.Parallel()

			key := after.TestID + "/rename/" + name + "/"
			want := after.Captures[name]

			current := func(tt require.TestingT) *netmap.NetworkMap {
				nm := clients[name].Netmap()
				require.NotNil(tt, nm, "netmap is nil")

				return nm
			}

			// Profiles are left out: the rename changes the user's login
			// by construction.
			t.Run("peers", func(t *testing.T) {
				t.Parallel()

				holdsUnlessListed(t, key+"peers", func(tt require.TestingT) {
					comparePeers(tt, current(tt), want, clients, "", nil)
				})
			})

			t.Run("packet-filter", func(t *testing.T) {
				t.Parallel()

				holdsUnlessListed(t, key+"packet-filter", func(tt require.TestingT) {
					comparePacketFilter(tt, current(tt), want, clients, saasAddrs, key+"packet-filter", nil)
				})
			})
		})
	}
}

// holdsUnlessListed requires check to hold, or, for a key listed in
// viaCompatSkipReasons, to keep failing.
func holdsUnlessListed(t *testing.T, key string, check func(require.TestingT)) {
	t.Helper()

	reason, listed := viaCompatSkipReasons[key]
	if !listed {
		requireNetmapHolds(t, check)

		return
	}

	// Long enough for a change in flight to arrive.
	assert.Never(t, func() bool { return passesOnce(check) }, 5*time.Second, 100*time.Millisecond,
		"matches SaaS; delete viaCompatSkipReasons[%q]", key)
	t.Skip(reason)
}

// passesOnce runs check once and reports whether it passed. It runs in its
// own goroutine because a failing require stops the goroutine it runs in.
func passesOnce(check func(require.TestingT)) bool {
	rec := &failRecorder{CollectT: new(assert.CollectT)}
	done := make(chan struct{})

	go func() {
		defer close(done)

		check(rec)
	}()

	<-done

	return !rec.failed
}

func runViaMapCompat(t *testing.T, c *testcapture.Capture) {
	t.Helper()

	_, clients := startViaMapCompat(t, c)
	compareViaMapCompat(t, c, clients)
}

// startViaMapCompat starts a server holding the capture's policy and a
// client per captured node, with the capture's routes approved, and waits
// for every client's first netmap and the peers SaaS gave it.
func startViaMapCompat(
	t *testing.T,
	c *testcapture.Capture,
) (*servertest.TestServer, map[string]*servertest.TestClient) {
	t.Helper()

	srv, clients := startCaptureClients(t, c, true)

	// Wait for peers based on golden [netmap.NetworkMap] expected counts.
	// A viewer whose peers are a listed difference never reaches them.
	for viewerName, cl := range clients {
		capture := c.Captures[viewerName]
		if capture.Netmap == nil {
			continue
		}

		if _, listed := viaCompatSkipReasons[c.TestID+"/"+viewerName+"/peers"]; listed {
			continue
		}

		expected := 0

		for _, peer := range capture.Netmap.Peers {
			peerName := extractHostname(peer.Name())
			if _, isOurs := clients[peerName]; isOurs {
				expected++
			}
		}

		if expected > 0 {
			cl.WaitForPeers(t, expected, 30*time.Second)
		}
	}

	return srv, clients
}

// startCaptureClients starts a server holding the capture's policy and a
// client per captured node, advertises the capture's routes and waits for
// every client's first netmap. With approve set, each node's approved_routes
// are approved as an admin would; otherwise only the policy approves them.
func startCaptureClients(
	t *testing.T,
	c *testcapture.Capture,
	approve bool,
) (*servertest.TestServer, map[string]*servertest.TestClient) {
	t.Helper()

	// Setup writes land one NodeStore batch at a time, and the checks hold
	// the netmaps they reach, so the default batch wait only adds time.
	srv := servertest.NewServer(t, servertest.WithNodeStoreBatchTimeout(state.TestBatchTimeout))
	tagUser := srv.CreateUser(t, "tag-user")
	users := createCaptureUsers(t, srv)

	policyJSON := convertCapturePolicy(t, c)

	changed, err := srv.State().SetPolicy(policyJSON)
	require.NoError(t, err, "failed to set policy")

	if changed {
		changes, err := srv.State().ReloadPolicy()
		require.NoError(t, err)
		srv.App.Change(changes...)
	}

	// Create clients matching the golden topology: tagged nodes under
	// tag-user, user-owned nodes under their capture user.
	// Nodes are created in SaaS registration order so headscale assigns
	// sequential DB IDs in the same relative order. This matters for
	// PrimaryRoutes election which uses lowest-node-ID-wins — the
	// tiebreaker must pick the same node as SaaS.
	clients := map[string]*servertest.TestClient{}
	order := captureNodeOrder(t, c)

	for _, name := range order {
		topoNode, exists := c.Topology.Nodes[name]
		if !exists {
			continue
		}

		if _, inCaptures := c.Captures[name]; !inCaptures {
			continue
		}

		owner := tagUser

		if len(topoNode.Tags) == 0 {
			require.Containsf(t, users, topoNode.User,
				"node %s: owner %q is not a capture user", name, topoNode.User)

			owner = users[topoNode.User]
		}

		clients[name] = servertest.NewClient(t, srv, name,
			servertest.WithUser(owner),
			servertest.WithTags(topoNode.Tags...),
		)
	}

	require.NotEmpty(t, clients, "no relevant nodes created")

	// Determine which routes each node should advertise. If the golden
	// topology has explicit routable_ips, use those. Otherwise infer
	// from the [netmap.NetworkMap] peer AllowedIPs and packet filter dst prefixes.
	nodeRoutes := inferNodeRoutes(t, c)

	// Build approved routes from topology. The topology's approved_routes
	// field records what SaaS actually approved (which may be a subset of
	// routable_ips). Using this instead of approving all advertised routes
	// ensures exit routes are only approved when SaaS approved them.
	nodeApproved := map[string][]netip.Prefix{}

	for name, node := range c.Topology.Nodes {
		for _, r := range node.ApprovedRoutes {
			nodeApproved[name] = append(
				nodeApproved[name], netip.MustParsePrefix(r),
			)
		}
	}

	// Advertise and approve routes in SaaS registration order. Via
	// grants depend on routes being advertised for compileViaGrant to
	// produce filter rules. The order matters because PrimaryRoutes
	// election is sticky — the first node to register a prefix becomes
	// primary.
	for _, name := range order {
		cl, ok := clients[name]
		if !ok {
			continue
		}

		routes := nodeRoutes[name]
		if len(routes) == 0 {
			continue
		}

		cl.Direct().SetHostinfo(&tailcfg.Hostinfo{
			BackendLogID: "servertest-" + name,
			Hostname:     name,
			RoutableIPs:  routes,
		})

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		require.NoError(t, cl.Direct().SendUpdate(ctx),
			"route advertisement for %s should succeed", name)

		cancel()

		if !approve {
			continue
		}

		nodeID := findNodeID(t, srv, name)
		_, routeChange, err := srv.State().SetApprovedRoutes(
			nodeID, nodeApproved[name],
		)
		require.NoError(t, err)
		srv.App.Change(routeChange)
	}

	for name, cl := range clients {
		cl.WaitForCondition(t, name+" initial netmap", 15*time.Second,
			func(nm *netmap.NetworkMap) bool {
				return nm != nil
			})
	}

	return srv, clients
}

// compareViaMapCompat compares every viewer's netmap and own routes with
// the capture.
func compareViaMapCompat(
	t *testing.T,
	c *testcapture.Capture,
	clients map[string]*servertest.TestClient,
) {
	t.Helper()

	saasAddrs := saasAddrsByNode(c, clients)

	// Compare each viewer's [tailcfg.MapResponse] against the golden [netmap.NetworkMap].
	// Route approvals reach clients asynchronously, so the peer-count wait
	// above says nothing about routes, primaries or filters: retry the
	// whole comparison until the viewer's netmap has caught up. Each viewer
	// reads only its own netmap, so the holds run at once.
	var wg sync.WaitGroup

	for viewerName, cl := range clients {
		capture := c.Captures[viewerName]
		if capture.Netmap == nil {
			continue
		}

		wg.Go(func() {
			t.Run(viewerName, func(t *testing.T) {
				requireNetmapHolds(t, func(tt require.TestingT) {
					nm := cl.Netmap()
					require.NotNil(tt, nm, "netmap is nil")

					// Routes were approved on live sessions: verify that approval
					// reached SelfNode throughout the stable comparison window.
					require.Equal(tt, selfOffersExit(capture.Netmap), selfOffersExit(nm),
						"SelfNode exit routes should match SaaS")

					compareNetmap(tt, nm, capture, clients, saasAddrs, c.TestID+"/"+viewerName)
				})

				t.Run("self-routes", func(t *testing.T) {
					key := c.TestID + "/" + viewerName + "/self-routes"
					reason, listed := viaCompatSkipReasons[key]

					requireNetmapHolds(t, func(tt require.TestingT) {
						want, got := selfRoutes(capture.Netmap), selfRoutes(cl.Netmap())
						if !listed {
							assert.Equal(tt, want, got, "own routes in AllowedIPs and PrimaryRoutes")

							return
						}

						if got == want {
							tt.Errorf("own routes match SaaS; delete viaCompatSkipReasons[%q]", key)
						}
					})

					if listed {
						t.Skip(reason)
					}
				})
			})
		})
	}

	wg.Wait()
}

// selfRoutes is the node's AllowedIPs minus its own addresses, and its
// PrimaryRoutes, each sorted. Host routes inside the Tailscale range stay
// in, so serving one SaaS withholds is caught.
func selfRoutes(nm *netmap.NetworkMap) string {
	self := nm.SelfNode

	var allowed, primary []string

	for _, pfx := range self.AllowedIPs().All() {
		if !views.SliceContains(self.Addresses(), pfx) {
			allowed = append(allowed, pfx.String())
		}
	}

	for _, pfx := range self.PrimaryRoutes().All() {
		primary = append(primary, pfx.String())
	}

	slices.Sort(allowed)
	slices.Sort(primary)

	return fmt.Sprintf("allowed %v primary %v", allowed, primary)
}

func TestSelfRoutesKeepsHostRoutes(t *testing.T) {
	t.Parallel()

	self := netip.MustParsePrefix("100.64.0.1/32")
	subnet := netip.MustParsePrefix("10.9.0.0/24")
	host := netip.MustParsePrefix("100.64.0.11/32")

	nm := func(routes ...netip.Prefix) *netmap.NetworkMap {
		return &netmap.NetworkMap{SelfNode: (&tailcfg.Node{
			Addresses:     []netip.Prefix{self},
			AllowedIPs:    append([]netip.Prefix{self}, routes...),
			PrimaryRoutes: routes,
		}).View()}
	}

	assert.Equal(t, "allowed [10.9.0.0/24] primary [10.9.0.0/24]", selfRoutes(nm(subnet)))
	assert.Equal(t,
		"allowed [10.9.0.0/24 100.64.0.11/32] primary [10.9.0.0/24 100.64.0.11/32]",
		selfRoutes(nm(subnet, host)))
}

func TestFilterSourcesKeepAddressFamily(t *testing.T) {
	t.Parallel()

	addrs := map[netip.Addr]string{
		netip.MustParseAddr("100.64.0.1"):        "a",
		netip.MustParseAddr("fd7a:115c:a1e0::1"): "a",
	}

	assert.Equal(t, []string{"peer:a/ipv4", "peer:a/ipv6"},
		canonicaliseSrcStrings(t, []string{"100.64.0.1", "fd7a:115c:a1e0::1"}, addrs, 0))
	assert.Equal(t, []string{"peer:a/ipv4"},
		canonicaliseSrcStrings(t, []string{"100.64.0.1"}, addrs, 0))
}

// requireNetmapHolds retries check until it passes on several consecutive
// ticks. One passing tick is not enough: a netmap that matches and then
// drifts, such as a primary flipping away, is the bug these oracles guard.
func requireNetmapHolds(t *testing.T, check func(require.TestingT)) {
	t.Helper()

	// Long enough for a batch still in flight to land.
	const holdTicks = 5

	held := 0

	require.EventuallyWithT(t, func(collect *assert.CollectT) {
		tick := &failRecorder{CollectT: collect}

		// Deferred because FailNow exits the goroutine.
		defer func() {
			if tick.failed {
				held = 0

				return
			}

			held++
			if held < holdTicks {
				collect.Errorf("netmap held for %d of %d ticks", held, holdTicks)
			}
		}()

		check(tick)
	}, 30*time.Second, 100*time.Millisecond)
}

// failRecorder notes whether a tick failed, which [assert.CollectT] does
// not expose.
type failRecorder struct {
	*assert.CollectT

	failed bool
}

func (r *failRecorder) Errorf(format string, args ...any) {
	r.failed = true
	r.CollectT.Errorf(format, args...)
}

func (r *failRecorder) FailNow() {
	r.failed = true
	r.CollectT.FailNow()
}

// compareNetmap compares the headscale [tailcfg.MapResponse] against the
// captured [netmap.NetworkMap] data in an IP-independent way: the peers (see
// [comparePeers]), the PacketFilter (source, destination, ports) triples and
// the user profiles.
//
// key is <test_id>/<node>, the prefix of the viewer's viaCompatSkipReasons
// entries. It takes [require.TestingT] so it can run inside
// [requireNetmapHolds].
func compareNetmap(
	t require.TestingT,
	got *netmap.NetworkMap,
	want testcapture.Node,
	clients map[string]*servertest.TestClient,
	saasAddrs map[netip.Addr]string,
	key string,
) {
	if h, ok := t.(interface{ Helper() }); ok {
		h.Helper()
	}

	comparePeers(t, got, want, clients, key, viaCompatSkipReasons)
	comparePacketFilter(t, got, want, clients, saasAddrs, key+"/packet-filter", viaCompatSkipReasons)
	compareUserProfiles(t, got, want.Netmap, clients)
}

// comparePeers validates, for the peers in clients, each check apart so a
// difference listed for one leaves the others asserted:
//   - peers: visibility (which peers are present, by hostname)
//   - peer-allowed-ips: route prefixes in AllowedIPs (non-Tailscale-IP
//     entries like 10.44.0.0/16)
//   - peer-addresses: the Tailscale IPs in AllowedIPs, by count and owner
//   - peer-primary-routes: PrimaryRoutes
//
// The last three cover peers both sides list. A check listed in skips as
// <key>/<check> must differ.
func comparePeers(
	t require.TestingT,
	got *netmap.NetworkMap,
	want testcapture.Node,
	clients map[string]*servertest.TestClient,
	key string,
	skips map[string]string,
) {
	if h, ok := t.(interface{ Helper() }); ok {
		h.Helper()
	}

	require.NotNil(t, want.Netmap, "golden Netmap is nil")

	check := map[string]require.TestingT{}
	listed := map[string]*failRecorder{}

	for _, name := range []string{"peers", "peer-allowed-ips", "peer-addresses", "peer-primary-routes"} {
		check[name] = t

		if _, ok := skips[key+"/"+name]; ok {
			listed[name] = &failRecorder{CollectT: new(assert.CollectT)}
			check[name] = listed[name]
		}
	}

	defer func() {
		for name, rec := range listed {
			if !rec.failed {
				t.Errorf("%s match SaaS; delete the skip entry %q (%s)",
					name, key+"/"+name, skips[key+"/"+name])
			}
		}
	}()

	// Build golden peer map (only peers in our client set).
	wantPeers := map[string]tailcfg.NodeView{}

	for _, p := range want.Netmap.Peers {
		name := extractHostname(p.Name())
		if _, isOurs := clients[name]; isOurs {
			wantPeers[name] = p
		}
	}

	// Build headscale peer map.
	gotPeers := map[string]peerSummary{}

	for _, peer := range got.Peers {
		name := ""

		if peer.Hostinfo().Valid() {
			name = peer.Hostinfo().Hostname()
		}

		if name == "" {
			for n := range clients {
				if strings.Contains(peer.Name(), n+".") {
					name = n

					break
				}
			}
		}

		if name == "" {
			continue
		}

		// Separate AllowedIPs into Tailscale IPs (node addresses)
		// and route prefixes (subnets, exit routes).
		var tsIPs []netip.Prefix

		var routePrefixes []string

		for i := range peer.AllowedIPs().Len() {
			prefix := peer.AllowedIPs().At(i)
			if isTailscaleIP(prefix) {
				tsIPs = append(tsIPs, prefix)
			} else {
				routePrefixes = append(routePrefixes, prefix.String())
			}
		}

		slices.Sort(routePrefixes)

		var proutes []string
		for i := range peer.PrimaryRoutes().Len() {
			proutes = append(proutes, peer.PrimaryRoutes().At(i).String())
		}

		slices.Sort(proutes)

		gotPeers[name] = peerSummary{
			TailscaleIPs:  tsIPs,
			RoutePrefixes: routePrefixes,
			PrimaryRoutes: proutes,
		}
	}

	// Compare peer visibility: golden peers must be present.
	for name, wantPeer := range wantPeers {
		gotPeer, visible := gotPeers[name]
		if !visible {
			wantRoutes := extractRoutePrefixesView(wantPeer.AllowedIPs())
			check["peers"].Errorf("peer %s: visible in Tailscale SaaS (routes=%v), missing in headscale",
				name, wantRoutes)

			continue
		}

		// Compare route prefixes in AllowedIPs (IP-independent).
		wantRoutes := extractRoutePrefixesView(wantPeer.AllowedIPs())
		slices.Sort(wantRoutes)

		assert.Equalf(check["peer-allowed-ips"], wantRoutes, gotPeer.RoutePrefixes,
			"peer %s: route prefixes in AllowedIPs mismatch", name)

		// Tailscale IPs: count should match, and they must belong to
		// this peer (not some other node's IPs).
		wantTSIPCount := countTailscaleIPsView(wantPeer.AllowedIPs())

		assert.Lenf(check["peer-addresses"], gotPeer.TailscaleIPs, wantTSIPCount,
			"peer %s: Tailscale IP count mismatch", name)

		// Verify the Tailscale IPs are actually this peer's addresses.
		if peerClient, ok := clients[name]; ok {
			peerNM := peerClient.Netmap()
			if peerNM != nil && peerNM.SelfNode.Valid() {
				peerAddrs := map[netip.Prefix]bool{}

				addrs := peerNM.SelfNode.Addresses()
				for i := range addrs.Len() {
					peerAddrs[addrs.At(i)] = true
				}

				for _, tsIP := range gotPeer.TailscaleIPs {
					assert.Truef(check["peer-addresses"], peerAddrs[tsIP],
						"peer %s: AllowedIPs contains Tailscale IP %s which is NOT this peer's address (peer has %v)",
						name, tsIP, peerAddrs)
				}
			}
		}

		// Compare PrimaryRoutes.
		var wantPRoutes []string
		for i := range wantPeer.PrimaryRoutes().Len() {
			wantPRoutes = append(wantPRoutes, wantPeer.PrimaryRoutes().At(i).String())
		}

		assert.ElementsMatchf(check["peer-primary-routes"], wantPRoutes, gotPeer.PrimaryRoutes,
			"peer %s: PrimaryRoutes mismatch", name)
	}

	// Check for extra peers headscale shows that Tailscale SaaS doesn't.
	for name := range gotPeers {
		if _, expected := wantPeers[name]; !expected {
			check["peers"].Errorf("peer %s: visible in headscale but NOT in Tailscale SaaS", name)
		}
	}
}

// compareUserProfiles compares the profile the viewer holds for itself and
// for each peer in clients that both sides list; a peer on one side only is
// the peers check's. Profile IDs differ between SaaS and headscale, so a
// profile is its login, with SaaS emails mapped to user names, and its
// display name.
func compareUserProfiles(
	t require.TestingT,
	got, want *netmap.NetworkMap,
	clients map[string]*servertest.TestClient,
) {
	if h, ok := t.(interface{ Helper() }); ok {
		h.Helper()
	}

	gotProfiles := nodeProfiles(got, clients)

	for name, wantProfile := range nodeProfiles(want, clients) {
		if _, ok := gotProfiles[name]; !ok {
			continue
		}

		check := "peer"
		if name == "" {
			check = "self"
			if want.SelfNode.Tags().Len() > 0 {
				check = "tagged-self"
			}
		}

		if reason, listed := viaCompatSkipReasons[check]; listed {
			if gotProfiles[name] == wantProfile {
				t.Errorf("node %q: %s profile matches SaaS; delete viaCompatSkipReasons[%q] (%s)",
					name, check, check, reason)
			}

			continue
		}

		assert.Equalf(t, wantProfile, gotProfiles[name], "node %q: %s profile mismatch", name, check)
	}
}

// nodeProfiles maps "" (self) and each peer in clients to its user profile.
func nodeProfiles(
	nm *netmap.NetworkMap,
	clients map[string]*servertest.TestClient,
) map[string]string {
	profile := func(id tailcfg.UserID) string {
		p, ok := nm.UserProfiles[id]
		if !ok {
			return "no profile"
		}

		login := p.LoginName()
		if name, ok := captureUserNames[login]; ok {
			login = name
		}

		return login + " / " + p.DisplayName()
	}

	out := map[string]string{"": profile(nm.SelfNode.User())}

	for _, peer := range nm.Peers {
		name := extractHostname(peer.Name())
		if _, isOurs := clients[name]; isOurs {
			out[name] = profile(peer.User())
		}
	}

	return out
}

// comparePacketFilter compares PacketFilter rules as a set of (source,
// destination, ports or capability) triples. Headscale merges rules
// that share sources while SaaS keeps one rule per policy entry, so rule
// count and order differ without changing what the filter allows.
// Tailscale IPs differ between SaaS and headscale allocation, so both
// sides are re-keyed by peer identity. A key listed in skips must differ.
func comparePacketFilter(
	t require.TestingT,
	got *netmap.NetworkMap,
	want testcapture.Node,
	clients map[string]*servertest.TestClient,
	saasAddrs map[netip.Addr]string,
	key string,
	skips map[string]string,
) {
	if h, ok := t.(interface{ Helper() }); ok {
		h.Helper()
	}

	wantList := saasFilterTriples(t, want.PacketFilterRules, saasAddrs)
	gotList := hsFilterTriples(t, got.PacketFilter, hsAddrsByPeer(clients))

	if reason, listed := skips[key]; listed {
		if slices.Equal(wantList, gotList) {
			t.Errorf("PacketFilter matches SaaS; delete the skip entry %q (%s)", key, reason)
		}

		return
	}

	assert.ElementsMatchf(t, wantList, gotList,
		"PacketFilter (source, destination, ports) mismatch")
}

// saasFilterTriples renders captured PacketFilter rules as sorted (source,
// destination, ports or capability) triples, peers named by saasAddrs.
func saasFilterTriples(t require.TestingT, rules []tailcfg.FilterRule, saasAddrs map[netip.Addr]string) []string {
	if h, ok := t.(interface{ Helper() }); ok {
		h.Helper()
	}

	triples := map[string]struct{}{}

	for i, rule := range rules {
		srcs := strings.Join(canonicaliseSrcStrings(t, rule.SrcIPs, saasAddrs, i), ",")

		for _, dp := range rule.DstPorts {
			pfxs, err := parseDstPrefixes(dp.IP)
			require.NoErrorf(t, err,
				"golden DstPorts[%d].IP %q should parse as prefix, addr or range", i, dp.IP)

			for _, pfx := range pfxs {
				for _, dst := range peerIdents(t, pfx, saasAddrs, i) {
					triples[filterTriple(srcs, dst, dp.Ports.First, dp.Ports.Last)] = struct{}{}
				}
			}
		}

		for _, cg := range rule.CapGrant {
			caps := slices.Collect(maps.Keys(cg.CapMap))
			caps = append(caps, cg.Caps...)

			for _, pfx := range cg.Dsts {
				for _, dst := range peerIdents(t, pfx, saasAddrs, i) {
					for _, c := range caps {
						triples[capTriple(srcs, dst, c)] = struct{}{}
					}
				}
			}
		}
	}

	return sortedKeys(triples)
}

// hsFilterTriples renders a client's packet filter as the triples
// [saasFilterTriples] gives, peers named by hsAddrs.
func hsFilterTriples(t require.TestingT, matches []filter.Match, hsAddrs map[netip.Addr]string) []string {
	if h, ok := t.(interface{ Helper() }); ok {
		h.Helper()
	}

	triples := map[string]struct{}{}

	for i, match := range matches {
		srcs := strings.Join(canonicaliseSrcPrefixes(t, match.Srcs, hsAddrs, i), ",")

		for _, dp := range match.Dsts {
			for _, dst := range peerIdents(t, dp.Net, hsAddrs, i) {
				triples[filterTriple(srcs, dst, dp.Ports.First, dp.Ports.Last)] = struct{}{}
			}
		}

		for _, cm := range match.Caps {
			for _, dst := range peerIdents(t, cm.Dst, hsAddrs, i) {
				triples[capTriple(srcs, dst, cm.Cap)] = struct{}{}
			}
		}
	}

	return sortedKeys(triples)
}

func filterTriple(srcs, dst string, first, last uint16) string {
	return fmt.Sprintf("%s => %s:%d-%d", srcs, dst, first, last)
}

func capTriple(srcs, dst string, c peercap.Cap) string {
	return fmt.Sprintf("%s => %s cap %s", srcs, dst, c)
}

// peerIdents resolves a prefix into sorted canonical identity tokens,
// see [addIdentsForSrc].
func peerIdents(
	t require.TestingT,
	pfx netip.Prefix,
	addrToPeer map[netip.Addr]string,
	ruleIndex int,
) []string {
	if h, ok := t.(interface{ Helper() }); ok {
		h.Helper()
	}

	seen := map[string]struct{}{}
	addIdentsForSrc(t, pfx, addrToPeer, ruleIndex, seen)

	return sortedKeys(seen)
}

// saasAddrsByNode maps each SaaS Tailscale address to its node's
// hostname using every captured node's own addresses. A rule may name
// sources that are not the viewer's peers, so peer lists are not
// enough. Nodes not in clients are skipped.
func saasAddrsByNode(
	c *testcapture.Capture,
	clients map[string]*servertest.TestClient,
) map[netip.Addr]string {
	out := map[netip.Addr]string{}

	for name, node := range c.Captures {
		if _, isOurs := clients[name]; !isOurs {
			continue
		}

		if node.Netmap == nil || !node.Netmap.SelfNode.Valid() {
			continue
		}

		addrs := node.Netmap.SelfNode.Addresses()
		for i := range addrs.Len() {
			pfx := addrs.At(i)
			if isTailscaleIP(pfx) {
				out[pfx.Addr()] = name
			}
		}
	}

	return out
}

// hsAddrsByPeer builds a map from headscale Tailscale address to peer
// hostname by walking each live client's self addresses.
func hsAddrsByPeer(clients map[string]*servertest.TestClient) map[netip.Addr]string {
	out := map[netip.Addr]string{}

	for name, cl := range clients {
		nm := cl.Netmap()
		if nm == nil || !nm.SelfNode.Valid() {
			continue
		}

		addrs := nm.SelfNode.Addresses()
		for i := range addrs.Len() {
			pfx := addrs.At(i)
			if isTailscaleIP(pfx) {
				out[pfx.Addr()] = name
			}
		}
	}

	return out
}

// canonicaliseSrcStrings converts a SrcIPs slice (as produced by the
// SaaS wire format) into a sorted list of canonical identifiers: "*"
// for wildcard, "peer:<name>/ipv4" or "peer:<name>/ipv6" for each
// Tailscale address or prefix that resolves to a known peer, or the
// raw CIDR string for non-Tailscale prefixes. A Tailscale prefix or
// address range expands to the union of its contained peers.
func canonicaliseSrcStrings(
	t require.TestingT,
	srcs []string,
	addrToPeer map[netip.Addr]string,
	ruleIndex int,
) []string {
	if h, ok := t.(interface{ Helper() }); ok {
		h.Helper()
	}

	seen := map[string]struct{}{}

	for _, src := range srcs {
		if src == "*" {
			seen["*"] = struct{}{}

			continue
		}

		pfxs, err := parseDstPrefixes(src)
		require.NoErrorf(t, err,
			"PacketFilter[%d]: unparseable SrcIP %q", ruleIndex, src)

		for _, pfx := range pfxs {
			addIdentsForSrc(t, pfx, addrToPeer, ruleIndex, seen)
		}
	}

	return sortedKeys(seen)
}

// canonicaliseSrcPrefixes is the headscale-side counterpart of
// [canonicaliseSrcStrings], reading already-parsed [netip.Prefix] values
// from [tailcfg.Match.Srcs].
func canonicaliseSrcPrefixes(
	t require.TestingT,
	srcs []netip.Prefix,
	addrToPeer map[netip.Addr]string,
	ruleIndex int,
) []string {
	if h, ok := t.(interface{ Helper() }); ok {
		h.Helper()
	}

	seen := map[string]struct{}{}

	for _, pfx := range srcs {
		if pfx.Bits() == 0 && pfx.Addr().IsUnspecified() {
			seen["*"] = struct{}{}

			continue
		}

		addIdentsForSrc(t, pfx, addrToPeer, ruleIndex, seen)
	}

	return sortedKeys(seen)
}

// addIdentsForSrc resolves one source prefix into canonical identity
// tokens and inserts them into seen. A non-Tailscale prefix passes
// through literally; a Tailscale-range prefix expands to the union
// of peer names whose addresses fall within it. A single address must
// be a known peer; a wider prefix may cover none, since SaaS writes
// "*" as ranges over the whole Tailscale space.
func addIdentsForSrc(
	t require.TestingT,
	pfx netip.Prefix,
	addrToPeer map[netip.Addr]string,
	ruleIndex int,
	seen map[string]struct{},
) {
	if h, ok := t.(interface{ Helper() }); ok {
		h.Helper()
	}

	if !prefixInTailscaleRange(pfx) {
		seen[pfx.String()] = struct{}{}

		return
	}

	matched := false

	for addr, name := range addrToPeer {
		if pfx.Contains(addr) {
			// The family stays in the token so a rule that loses one
			// family of a peer's addresses still differs.
			family := "/ipv6"
			if addr.Is4() {
				family = "/ipv4"
			}

			seen["peer:"+name+family] = struct{}{}
			matched = true
		}
	}

	require.Truef(t, matched || !pfx.IsSingleIP(),
		"PacketFilter[%d]: Tailscale-range SrcIP %s does not cover any known peer; addrToPeer=%v",
		ruleIndex, pfx, addrToPeer)
}

// prefixInTailscaleRange reports whether a prefix lies entirely
// within the Tailscale CGNAT range (100.64.0.0/10) or Tailscale ULA
// range (fd7a:115c:a1e0::/48), regardless of prefix length.
func prefixInTailscaleRange(p netip.Prefix) bool {
	addr := p.Addr()

	if addr.Is4() {
		return addr.As4()[0] == 100 && (addr.As4()[1]&0xC0) == 64
	}

	if addr.Is6() {
		b := addr.As16()

		return b[0] == 0xfd && b[1] == 0x7a && b[2] == 0x11 && b[3] == 0x5c //nolint:gosec // As16 returns [16]byte, indexing [0..3] is safe
	}

	return false
}

func sortedKeys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}

	slices.Sort(out)

	return out
}

type peerSummary struct {
	TailscaleIPs  []netip.Prefix // Tailscale address entries from AllowedIPs
	RoutePrefixes []string       // non-Tailscale-IP AllowedIPs (sorted)
	PrimaryRoutes []string       // sorted
}

// parsePrefixOrAddr parses a string as a [netip.Prefix]. If the string
// is a bare IP address (no slash), it is converted to a single-host
// prefix (/32 for IPv4, /128 for IPv6). Golden data DstPorts.IP can
// contain either form.
func parsePrefixOrAddr(s string) (netip.Prefix, error) {
	pfx, err := netip.ParsePrefix(s)
	if err == nil {
		return pfx, nil
	}

	addr, addrErr := netip.ParseAddr(s)
	if addrErr != nil {
		return netip.Prefix{}, err // return original prefix error
	}

	return netip.PrefixFrom(addr, addr.BitLen()), nil
}

// parseDstPrefixes parses a golden DstPorts.IP into the prefixes a client
// derives from it. Besides a prefix or bare address, SaaS writes "*" for
// every address and an address range for autogroup:internet
// ("0.0.0.0-9.255.255.255").
func parseDstPrefixes(s string) ([]netip.Prefix, error) {
	if s == "*" {
		return []netip.Prefix{
			netip.MustParsePrefix("0.0.0.0/0"),
			netip.MustParsePrefix("::/0"),
		}, nil
	}

	if strings.Contains(s, "-") {
		r, err := netipx.ParseIPRange(s)
		if err != nil {
			return nil, err
		}

		return r.Prefixes(), nil
	}

	pfx, err := parsePrefixOrAddr(s)
	if err != nil {
		return nil, err
	}

	return []netip.Prefix{pfx}, nil
}

// isTailscaleIP returns true if the prefix is a single-host Tailscale
// address (/32 for IPv4 in CGNAT range, /128 for IPv6 in Tailscale ULA).
func isTailscaleIP(prefix netip.Prefix) bool {
	addr := prefix.Addr()

	if addr.Is4() && prefix.Bits() == 32 {
		// CGNAT range 100.64.0.0/10
		return addr.As4()[0] == 100 && (addr.As4()[1]&0xC0) == 64
	}

	if addr.Is6() && prefix.Bits() == 128 {
		// Tailscale ULA fd7a:115c:a1e0::/48
		b := addr.As16()

		return b[0] == 0xfd && b[1] == 0x7a && b[2] == 0x11 && b[3] == 0x5c //nolint:gosec // As16 returns [16]byte, indexing [0..3] is safe
	}

	return false
}

// extractRoutePrefixesView returns the non-Tailscale-IP entries from
// a typed AllowedIPs view (subnet routes, exit routes, etc.).
func extractRoutePrefixesView(allowedIPs interface {
	Len() int
	At(i int) netip.Prefix
},
) []string {
	var routes []string

	for i := range allowedIPs.Len() {
		pfx := allowedIPs.At(i)
		if !isTailscaleIP(pfx) {
			routes = append(routes, pfx.String())
		}
	}

	return routes
}

// countTailscaleIPsView returns the number of Tailscale IP entries
// in a typed AllowedIPs view.
func countTailscaleIPsView(allowedIPs interface {
	Len() int
	At(i int) netip.Prefix
},
) int {
	count := 0

	for i := range allowedIPs.Len() {
		if isTailscaleIP(allowedIPs.At(i)) {
			count++
		}
	}

	return count
}

// inferNodeRoutes determines which routes each node should advertise.
// If the topology has explicit routable_ips, those are used. Otherwise
// routes are inferred from the [netmap.NetworkMap] peer AllowedIPs and packet
// filter destination prefixes.
func inferNodeRoutes(t *testing.T, c *testcapture.Capture) map[string][]netip.Prefix {
	t.Helper()

	result := map[string][]netip.Prefix{}

	// First use explicit routable_ips from topology.
	for name, node := range c.Topology.Nodes {
		for _, r := range node.RoutableIPs {
			result[name] = append(result[name], netip.MustParsePrefix(r))
		}
	}

	// If any node already has routes, the topology is populated — use as-is.
	for _, routes := range result {
		if len(routes) > 0 {
			return result
		}
	}

	// Tier 2: infer from each capture's [netmap.NetworkMap] — scan peers with
	// route prefixes in AllowedIPs. If node X appears as a peer with
	// route prefix 10.44.0.0/16, then X should advertise that route.
	for _, node := range c.Captures {
		if node.Netmap == nil {
			continue
		}

		for _, peer := range node.Netmap.Peers {
			peerName := extractHostname(peer.Name())

			for i := range peer.AllowedIPs().Len() {
				pfx := peer.AllowedIPs().At(i)
				if isTailscaleIP(pfx) {
					continue
				}

				if !slices.Contains(result[peerName], pfx) {
					result[peerName] = append(result[peerName], pfx)
				}
			}
		}
	}

	// Tier 3: infer from packet_filter_rules DstPorts — secondary HA
	// routers whose routes don't appear in AllowedIPs (only the
	// primary gets the route in AllowedIPs) DO receive filter rules
	// for those routes.
	for nodeName, node := range c.Captures {
		for _, rule := range node.PacketFilterRules {
			for _, dp := range rule.DstPorts {
				if dp.IP == "*" {
					continue
				}

				prefix, err := parsePrefixOrAddr(dp.IP)
				require.NoErrorf(t, err,
					"golden DstPorts.IP %q for %s unparseable", dp.IP, nodeName)

				if isTailscaleIP(prefix) {
					continue
				}

				if !slices.Contains(result[nodeName], prefix) {
					result[nodeName] = append(
						result[nodeName], prefix,
					)
				}
			}
		}
	}

	return result
}

// extractHostname extracts the hostname from a Tailscale FQDN like
// "router-a.tail78f774.ts.net.".
func extractHostname(fqdn string) string {
	if before, _, ok := strings.Cut(fqdn, "."); ok {
		return before
	}

	return fqdn
}
