// This file implements data-driven via+HA compatibility tests using
// golden data captured from Tailscale SaaS (v37-v46, v64, v65). These scenarios
// exercise the interaction between via grant steering and HA primary
// route election with varying combinations of shared/unique via tags,
// regular grants, and multiple HA pairs. TestViaGrantHAFailoverCompat replays
// one such route through failover, step by step.
//
// Test data source: ../policy/v2/testdata/grant_results/via-grant-v{37..46,64,65}.hujson
// and testdata/steps/via-ha-failover.hujson, loaded by name.
// Source format:    github.com/juanfont/headscale/hscontrol/types/testcapture

package servertest_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/netip"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/servertest"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/types/testcapture"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/control/controlclient"
	"tailscale.com/tailcfg"
	"tailscale.com/types/netmap"
	"tailscale.com/types/persist"
)

// viaHACompatTests lists golden captures that exercise via+HA interactions.
var viaHACompatTests = []struct {
	id   string
	desc string
}{
	{"via-grant-v37", "crossed same prefix, different via tags"},
	{"via-grant-v38", "HA baseline, no via grants"},
	{"via-grant-v39", "crossed via same prefix, different HA members"},
	{"via-grant-v40", "one client via, one client regular"},
	{"via-grant-v41", "via HA pair + non-via router same prefix"},
	{"via-grant-v42", "crossed via+regular across two HA pairs"},
	{"via-grant-v43", "partial via, partial HA, cross pairs"},
	{"via-grant-v44", "four-way HA, mixed via steering"},
	{"via-grant-v45", "via+regular overlap, 4-way HA"},
	{"via-grant-v46", "kitchen sink: mixed via+regular+HA"},
	{"via-grant-v64", "port-limited ACL to a via prefix, non-via global primary"},
	{"via-grant-v65", "via tag whose only node advertises nothing"},
}

// TestViaGrantHACompat loads golden captures from Tailscale SaaS that
// test via grant steering combined with HA primary route election.
// Each capture uses an inline topology with 4-6 nodes (instead of the
// shared 15-node grant topology used by [TestViaGrantMapCompat]).
func TestViaGrantHACompat(t *testing.T) {
	t.Parallel()

	for _, tc := range viaHACompatTests {
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

			runViaHACompat(t, c)
		})
	}
}

func runViaHACompat(t *testing.T, c *testcapture.Capture) {
	t.Helper()

	srv := servertest.NewServer(t)
	tagUser := srv.CreateUser(t, "tag-user")
	createCaptureUsers(t, srv)

	policyJSON := convertCapturePolicy(t, c)

	changed, err := srv.State().SetPolicy(policyJSON)
	require.NoError(t, err, "failed to set policy")

	if changed {
		changes, err := srv.State().ReloadPolicy()
		require.NoError(t, err)
		srv.App.Change(changes...)
	}

	// Create nodes in SaaS node ID order so headscale assigns
	// sequential DB IDs in the same relative order.
	clients := map[string]*servertest.TestClient{}
	order := captureNodeOrder(t, c)

	for _, name := range order {
		topoNode, exists := c.Topology.Nodes[name]
		if !exists || len(topoNode.Tags) == 0 {
			continue
		}

		if _, inCaptures := c.Captures[name]; !inCaptures {
			continue
		}

		clients[name] = servertest.NewClient(t, srv, name,
			servertest.WithUser(tagUser),
			servertest.WithTags(topoNode.Tags...),
		)
	}

	require.NotEmpty(t, clients, "no relevant nodes created")

	// Advertise and approve routes in SaaS node ID order.
	for _, name := range order {
		cl, ok := clients[name]
		if !ok {
			continue
		}

		topoNode := c.Topology.Nodes[name]

		var routes []netip.Prefix
		for _, r := range topoNode.RoutableIPs {
			routes = append(routes, netip.MustParsePrefix(r))
		}

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

		var approved []netip.Prefix
		for _, r := range topoNode.ApprovedRoutes {
			approved = append(approved, netip.MustParsePrefix(r))
		}

		nodeID := findNodeID(t, srv, name)

		_, routeChange, err := srv.State().SetApprovedRoutes(nodeID, approved)
		require.NoError(t, err)
		srv.App.Change(routeChange)
	}

	// Wait for peers.
	for viewerName, cl := range clients {
		capture := c.Captures[viewerName]
		if capture.Netmap == nil {
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

	// Ensure all nodes have an initial [netmap.NetworkMap].
	for name, cl := range clients {
		cl.WaitForCondition(t, name+" initial netmap", 15*time.Second,
			func(nm *netmap.NetworkMap) bool {
				return nm != nil
			})
	}

	saasAddrs := saasAddrsByNode(c, clients)

	// Compare each viewer's [tailcfg.MapResponse] against golden [netmap.NetworkMap].
	// Route approvals reach clients asynchronously, so the peer-count wait
	// above says nothing about routes, primaries or filters: retry the
	// whole comparison until the viewer's netmap has caught up.
	for viewerName, cl := range clients {
		capture := c.Captures[viewerName]
		if capture.Netmap == nil {
			continue
		}

		t.Run(viewerName, func(t *testing.T) {
			requireNetmapHolds(t, func(tt require.TestingT) {
				compareCaptureNetmap(tt, cl, capture, clients, saasAddrs, c.TestID+"/"+viewerName)
			})
		})
	}
}

// viaHAFailoverSkipReasons lists checks where headscale differs from SaaS,
// keyed <test_id>/<step>/<viewer>/<check>. A listed check that matches
// fails, so a fix must delete its entry.
var viaHAFailoverSkipReasons = map[string]string{
	"via-ha-failover/V1/client-a/route-owner": viaOfflineRouterKept,
	"via-ha-failover/V9/client-a/route-owner": viaOfflineRouterKept,

	"via-ha-failover/V2/client-a/route-owner":  viaLowestIDAfterRestart,
	"via-ha-failover/V10/client-a/route-owner": viaLowestIDAfterRestart,

	"via-ha-failover/V5/client-a/route-owner":  viaExpiredRouterKept,
	"via-ha-failover/V5b/client-a/route-owner": viaExpiredRouterKept,

	"via-ha-failover/V12/client-a/route-owner": readvertisedRouterTakesRoute,
	"via-ha-failover/V12/client-b/route-owner": readvertisedRouterTakesRoute,
}

const (
	viaOfflineRouterKept         = "VIA_OFFLINE_ROUTER_KEPT: headscale keeps a via route on an offline router while another router of the via group is online; SaaS moves it to the online one"
	viaExpiredRouterKept         = "VIA_EXPIRED_ROUTER_KEPT: headscale keeps a via route on a router whose key expired while another router of the via group is live; SaaS moves it to the live one"
	viaLowestIDAfterRestart      = "VIA_LOWEST_ID_AFTER_RESTART: headscale serves a via route from the group's lowest-ID router once it reconnects; SaaS keeps the router that served while it was down"
	readvertisedRouterTakesRoute = "READVERTISED_ROUTER_TAKES_ROUTE: SaaS hands a route back to an HA router that withdrew and re-advertised it, taking it from the router that served it meanwhile; headscale keeps that router"
)

// viaHAFailoverViewers are the clients whose views are compared: one reaches
// the route only through the via group, the other through the global
// election. The routers' own views are stored, not compared; route-cost owns
// them.
var viaHAFailoverViewers = []string{"client-a", "client-b"}

// TestViaGrantHAFailoverCompat replays one route served by a non-via router
// and a via group of two through crashes and returns, the whole via group
// down, key expiry and restore (an expired router re-advertising included),
// approval loss, withdraw, re-advertise and delete. After each step it
// compares, per viewer, which routers carry the route and which peers it
// sees.
func TestViaGrantHAFailoverCompat(t *testing.T) {
	t.Parallel()

	t.Run("via-ha-failover", func(t *testing.T) {
		t.Parallel()

		runViaHAFailoverCompat(t, "via-ha-failover")
	})
}

func runViaHAFailoverCompat(t *testing.T, id string) {
	t.Helper()

	c := readStepCapture(t, id)
	r := newStepReplay(t, c)
	evaluated := map[string]bool{}

	for _, step := range c.Steps {
		require.Equal(t, "observed", step.Result, "%s: the replay follows every step", step.Name)

		// The probe let each action land before the next, and which router
		// wins depends on that order.
		for _, a := range step.Actions {
			one := step
			one.Actions = []testcapture.Action{a}
			require.Empty(t, r.apply(t, one), "%s: every login succeeds", step.Name)
			r.waitSession(t, step.Name, a)
		}

		checks := make([]stepCheck, 0, 2*len(viaHAFailoverViewers))

		for _, viewer := range viaHAFailoverViewers {
			saas := step.Captures[viewer].Netmap
			require.NotNil(t, saas, "%s: no capture of %s", step.Name, viewer)

			cl := r.clients[viewer]
			checks = append(checks,
				stepCheck{viewer + "/route-owner", routeOwners(saas, r.saasAlias), func() string {
					return routeOwners(cl.Netmap(), r.hsAlias)
				}},
				stepCheck{viewer + "/peers", peerAliases(saas, r.saasAlias), func() string {
					return peerAliases(cl.Netmap(), r.hsAlias)
				}},
			)
		}

		prefix := id + "/" + step.Name + "/"

		t.Run(step.Name, func(t *testing.T) {
			holdChecks(t, viaHAFailoverSkipReasons, prefix, checks, evaluated)
		})
	}

	for k := range viaHAFailoverSkipReasons {
		if strings.HasPrefix(k, id+"/") && !evaluated[k] {
			t.Errorf("skip entry %q names no check", k)
		}
	}
}

// routeOwners says, per subnet route among the peers in nm that alias
// names, which of them carry it in AllowedIPs and which in PrimaryRoutes.
func routeOwners(nm *netmap.NetworkMap, alias func(tailcfg.NodeID) (string, bool)) string {
	if nm == nil {
		return "no netmap"
	}

	allowed, primary := map[string][]string{}, map[string][]string{}

	for _, p := range nm.Peers {
		name, ok := alias(p.ID())
		if !ok {
			continue
		}

		for _, pfx := range p.AllowedIPs().All() {
			if !isTailscaleIP(pfx) {
				allowed[pfx.String()] = append(allowed[pfx.String()], name)
			}
		}

		for _, pfx := range p.PrimaryRoutes().All() {
			primary[pfx.String()] = append(primary[pfx.String()], name)
		}
	}

	routes := slices.Collect(maps.Keys(allowed))
	for pfx := range primary {
		if _, ok := allowed[pfx]; !ok {
			routes = append(routes, pfx)
		}
	}

	if len(routes) == 0 {
		return "none"
	}

	slices.Sort(routes)

	out := make([]string, 0, len(routes))
	for _, pfx := range routes {
		out = append(out, fmt.Sprintf("%s allowed %s primary %s", pfx, sortedStrings(allowed[pfx]), sortedStrings(primary[pfx])))
	}

	return strings.Join(out, "; ")
}

// compareCaptureNetmap compares headscale's [tailcfg.MapResponse] against a
// [testcapture.Node]'s [netmap.NetworkMap] data. Same logic as [compareNetmap] but
// reads from typed [testcapture] fields instead of goldenFile strings.
// It takes [require.TestingT] so it can run inside [requireNetmapHolds].
func compareCaptureNetmap(
	t require.TestingT,
	viewer *servertest.TestClient,
	want testcapture.Node,
	clients map[string]*servertest.TestClient,
	saasAddrs map[netip.Addr]string,
	key string,
) {
	if h, ok := t.(interface{ Helper() }); ok {
		h.Helper()
	}

	nm := viewer.Netmap()
	require.NotNil(t, nm, "viewer has no netmap")

	// Build peer summaries from golden data.
	wantPeers := map[string]capturePeerSummary{}

	for _, peer := range want.Netmap.Peers {
		peerName := extractHostname(peer.Name())
		if _, isOurs := clients[peerName]; !isOurs {
			continue
		}

		var (
			tsIPs         []netip.Prefix
			routePrefixes []string
		)

		for i := range peer.AllowedIPs().Len() {
			pfx := peer.AllowedIPs().At(i)
			if isTailscaleIP(pfx) {
				tsIPs = append(tsIPs, pfx)
			} else {
				routePrefixes = append(routePrefixes, pfx.String())
			}
		}

		slices.Sort(routePrefixes)

		var primaryRoutes []string

		for i := range peer.PrimaryRoutes().Len() {
			primaryRoutes = append(primaryRoutes, peer.PrimaryRoutes().At(i).String())
		}

		slices.Sort(primaryRoutes)

		wantPeers[peerName] = capturePeerSummary{
			TailscaleIPs:  tsIPs,
			RoutePrefixes: routePrefixes,
			PrimaryRoutes: primaryRoutes,
		}
	}

	// Build peer summaries from headscale [tailcfg.MapResponse].
	gotPeers := map[string]capturePeerSummary{}

	for _, peer := range nm.Peers {
		peerName := extractHostname(peer.Name())
		if _, isOurs := clients[peerName]; !isOurs {
			continue
		}

		var (
			tsIPs         []netip.Prefix
			routePrefixes []string
		)

		for i := range peer.AllowedIPs().Len() {
			pfx := peer.AllowedIPs().At(i)
			if isTailscaleIP(pfx) {
				tsIPs = append(tsIPs, pfx)
			} else {
				routePrefixes = append(routePrefixes, pfx.String())
			}
		}

		slices.Sort(routePrefixes)

		var primaryRoutes []string

		for i := range peer.PrimaryRoutes().Len() {
			primaryRoutes = append(primaryRoutes, peer.PrimaryRoutes().At(i).String())
		}

		slices.Sort(primaryRoutes)

		gotPeers[peerName] = capturePeerSummary{
			TailscaleIPs:  tsIPs,
			RoutePrefixes: routePrefixes,
			PrimaryRoutes: primaryRoutes,
		}
	}

	// Compare peer visibility.
	for name, wantPeer := range wantPeers {
		gotPeer, visible := gotPeers[name]
		if !visible {
			t.Errorf("peer %s: visible in SaaS, missing in headscale (routes=%v)",
				name, wantPeer.RoutePrefixes)

			continue
		}

		assert.Equalf(t, wantPeer.RoutePrefixes, gotPeer.RoutePrefixes,
			"peer %s: route prefixes in AllowedIPs mismatch", name)

		assert.Lenf(t, gotPeer.TailscaleIPs, len(wantPeer.TailscaleIPs),
			"peer %s: Tailscale IP count mismatch", name)

		assert.ElementsMatchf(t, wantPeer.PrimaryRoutes, gotPeer.PrimaryRoutes,
			"peer %s: PrimaryRoutes mismatch", name)
	}

	// Check for extra peers.
	for name := range gotPeers {
		if _, expected := wantPeers[name]; !expected {
			t.Errorf("peer %s: visible in headscale but NOT in SaaS", name)
		}
	}

	// The triples below drop multiplicity; the count keeps it.
	if len(want.PacketFilterRules) > 0 {
		gotLen := nm.PacketFilterRules.Len()
		assert.Equalf(t, len(want.PacketFilterRules), gotLen,
			"PacketFilter rule count mismatch (SaaS=%d, headscale=%d)",
			len(want.PacketFilterRules), gotLen,
		)
	}

	// By address: the policy layer compares wire form, which differs when
	// SaaS lists contiguous addresses one by one.
	comparePacketFilter(t, nm, want, clients, saasAddrs, key+"/packet-filter", viaCompatSkipReasons)

	compareUserProfiles(t, nm, want.Netmap, clients)
}

type capturePeerSummary struct {
	TailscaleIPs  []netip.Prefix
	RoutePrefixes []string
	PrimaryRoutes []string
}

// captureNodeOrder returns node names from a [testcapture.Capture]
// sorted by SaaS node creation time, for deterministic DB ID assignment.
// SaaS elects HA primaries by registration order (first registered wins),
// which correlates with Created timestamp, not with the random snowflake
// node ID.
func captureNodeOrder(t *testing.T, c *testcapture.Capture) []string {
	t.Helper()

	type entry struct {
		name    string
		created time.Time
	}

	var entries []entry

	for name, node := range c.Captures {
		if node.Netmap == nil {
			continue
		}

		created := node.Netmap.SelfNode.Created()
		if created.IsZero() {
			continue
		}

		entries = append(entries, entry{name: name, created: created})
	}

	require.NotEmpty(t, entries, "no captures with SelfNode.Created found")

	slices.SortFunc(entries, func(a, b entry) int {
		return a.created.Compare(b.created)
	})

	names := make([]string, len(entries))
	for i, e := range entries {
		names[i] = e.name
	}

	return names
}

// captureUserNames maps the SaaS emails in capture policies to the user
// names capture topologies give their user-owned nodes.
var captureUserNames = map[string]string{
	"odin@example.com":  "odin",
	"thor@example.org":  "thor",
	"freya@example.com": "freya",
}

// createCaptureUsers creates a headscale user for each capture identity,
// keyed by name.
func createCaptureUsers(t *testing.T, srv *servertest.TestServer) map[string]*types.User {
	t.Helper()

	users := make(map[string]*types.User, len(captureUserNames))
	for _, name := range captureUserNames {
		users[name] = srv.CreateUser(t, name)
	}

	return users
}

// convertCapturePolicy converts a [testcapture.Capture]'s policy for headscale;
// see [convertPolicyEmails].
func convertCapturePolicy(t *testing.T, c *testcapture.Capture) []byte {
	t.Helper()

	return convertPolicyEmails(t, c.TestID, c.Input.FullPolicy)
}

// convertPolicyEmails replaces each SaaS email in policy with the "<name>@"
// form that resolves to the users [createCaptureUsers] creates. Fails the
// test if the policy names a user but none of the known SaaS emails: that
// would mean the capture was regenerated with a new identity and
// captureUserNames needs updating.
func convertPolicyEmails(t *testing.T, testID, policy string) []byte {
	t.Helper()

	s := policy

	substituted := false

	for email, name := range captureUserNames {
		if strings.Contains(s, email) {
			substituted = true
			s = strings.ReplaceAll(s, email, name+"@")
		}
	}

	require.True(
		t,
		substituted || !strings.Contains(s, "@"),
		"%s: no known SaaS email found in policy; update captureUserNames",
		testID,
	)

	return []byte(s)
}

// readStepCapture loads a multi-step capture by name from testdata/steps.
// Step files are read by name, never globbed, so a consumer cannot pick up
// another family's file by accident.
func readStepCapture(t *testing.T, id string) *testcapture.Capture {
	t.Helper()

	c, err := testcapture.Read(filepath.Join("testdata", "steps", id+".hujson"))
	require.NoError(t, err)
	require.NotEmpty(t, c.Steps, "%s: not a step capture", id)

	return c
}

// requireSkipCaptures fails on a skip entry that is not
// <id>/<step>/.../<check> for one of ids, the captures the map's consumers
// replay. Each consumer checks only the entries under its own capture, so
// such an entry would never go stale.
func requireSkipCaptures(t *testing.T, skips map[string]string, ids ...string) {
	t.Helper()

	for k := range skips {
		id, rest, _ := strings.Cut(k, "/")
		assert.True(t, slices.Contains(ids, id) && strings.Contains(rest, "/"),
			"skip entry %q names no replayed capture and step", k)
	}
}

// stepReplay drives a step capture's actions against headscale: policy
// pushes, key mints and revokes, joins, relogins, profile switches,
// restarts, kills, shutdowns, route announcements, logouts, retires and admin
// calls, the last through the v2 API with the bodies SaaS received. Nothing
// is seeded from the capture's end state.
type stepReplay struct {
	c        *testcapture.Capture
	srv      *servertest.TestServer
	admin    *types.User
	users    map[string]*types.User
	apiKey   string
	http     *http.Client
	keys     map[string]string
	clients  map[string]*servertest.TestClient
	hostinfo map[string]*tailcfg.Hostinfo

	// keyIDs, keyTags and keyUsers describe each minted key by label.
	keyIDs   map[string]uint64
	keyTags  map[string][]string
	keyUsers map[string]*types.User

	// profiles holds the login a node switched away from.
	profiles map[string]persist.Persist

	// keyExpires holds each minted key's SaaS expiry until the replay has
	// expired it; see [stepReplay.expireDueKeys].
	keyExpires map[string]time.Time

	// lastIDs holds each machine's last single node, so a deleted device can
	// still be addressed.
	lastIDs map[string]string

	// memState lists the nodes whose tailscaled ran with --state=mem:.
	memState map[string]bool

	// paths, when set, gives each joining client a home DERP and an
	// endpoint, as a running tailscaled reports them.
	paths bool

	// readAPI, when set, replays reads too and keeps headscale's answer to
	// each admin exchange in answers, by action index, instead of failing on
	// a status that differs from SaaS's.
	readAPI bool
	answers map[int]apiAnswer

	// interactive, when set, picks the joins and logins replayed as a login
	// approved by the key's user instead of with the key.
	interactive func(step testcapture.Step, a testcapture.Action) bool
}

func newStepReplay(t *testing.T, c *testcapture.Capture, opts ...servertest.ServerOption) *stepReplay {
	t.Helper()

	srv := servertest.NewServer(t, opts...)
	users := createCaptureUsers(t, srv)

	// SaaS keys and admin calls act as the tailnet's admin.
	admin, ok := users[captureUserNames[c.Tailnet]]
	require.True(t, ok, "%s: tailnet %q is not a capture user", c.TestID, c.Tailnet)

	return &stepReplay{
		c:        c,
		srv:      srv,
		admin:    admin,
		users:    users,
		apiKey:   srv.CreateAPIKey(t, admin),
		http:     &http.Client{Transport: &http.Transport{DialContext: srv.MemNet().Dial}},
		keys:     map[string]string{},
		clients:  map[string]*servertest.TestClient{},
		hostinfo: map[string]*tailcfg.Hostinfo{},
		keyIDs:   map[string]uint64{},
		keyTags:  map[string][]string{},
		keyUsers: map[string]*types.User{},
		profiles: map[string]persist.Persist{},

		keyExpires: map[string]time.Time{},
		lastIDs:    map[string]string{},
		memState:   memStateNodes[c.TestID],
	}
}

// memStateNodes lists, per capture, the nodes the probe ran with
// --state=mem:, which a join action does not record.
var memStateNodes = map[string]map[string]bool{
	"ephemeral-lifecycle": {"mem": true, "mem-kill": true},
}

// apiAnswer is headscale's answer to one replayed admin exchange.
type apiAnswer struct {
	status int
	body   []byte
}

// apply runs the step's actions in order and returns the logins headscale
// refused, by node. Reads are what consumers compare, so they are skipped
// unless readAPI is set.
func (r *stepReplay) apply(t *testing.T, step testcapture.Step) map[string]error {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	refused := map[string]error{}

	r.expireDueKeys(t, step.At)

	if r.readAPI {
		r.answers = map[int]apiAnswer{}
	}

	for i, a := range step.Actions {
		switch a.Kind {
		case "policy":
			require.Equal(t, http.StatusOK, a.Status, "%s: replay of a refused policy", step.Name)

			// HuJSON bodies are stored as a JSON string.
			policy := string(a.Body)
			if strings.HasPrefix(policy, `"`) {
				require.NoError(t, json.Unmarshal(a.Body, &policy))
			}

			r.setPolicy(t, step.Name, policy)

		case "api":
			r.api(t, step.Name, i, a)

		case "join":
			// The probe joins with its routes, as `tailscale up
			// --advertise-routes` does. An update sent after the join can
			// be overtaken by the stream's first request, which has none.
			hi := &tailcfg.Hostinfo{
				BackendLogID: "servertest-" + a.Node,
				Hostname:     a.Hostname,
				RequestTags:  requestTags(a, nil),
			}
			if len(a.Routes) > 0 {
				hi.RoutableIPs = prefixes(t, a.Routes)
			}

			r.hostinfo[a.Node] = hi

			opts := []servertest.ClientOption{servertest.WithUser(r.admin)}
			if r.memState[a.Node] {
				opts = append(opts, servertest.WithLoginFlags(controlclient.LoginEphemeral))
			}

			if r.paths {
				hi.NetInfo = &tailcfg.NetInfo{PreferredDERP: 1}

				opts = append(opts, servertest.WithEndpoints(tailcfg.Endpoint{
					Addr: netip.AddrPortFrom(netip.MustParseAddr("192.0.2.1"), uint16(41641+len(r.clients))), //nolint:gosec // a handful of clients
					Type: tailcfg.EndpointExplicitConf,
				}))
			}

			opts = append(opts, servertest.WithHostinfo(hi.Clone()))

			if r.interactive != nil && r.interactive(step, a) {
				opts = append(opts, servertest.WithInteractiveLogin(r.approver(ctx, t, a.Key)))
			} else {
				require.Contains(t, r.keys, a.Key, "%s: join with unknown key", step.Name)
				opts = append(opts, servertest.WithAuthKey(r.keys[a.Key]))
			}

			cl, err := servertest.TryNewClient(t, r.srv, a.Node, opts...)
			r.clients[a.Node] = cl

			if err != nil {
				refused[a.Node] = err

				continue
			}

			r.remember(a.Node)

		case "relogin":
			// The probe restates hostname and routes on every login.
			hi := r.hostinfo[a.Node].Clone()
			hi.Hostname = a.Hostname
			hi.RoutableIPs = prefixes(t, a.Routes)
			hi.RequestTags = requestTags(a, hi.RequestTags)
			r.hostinfo[a.Node] = hi

			cl := r.clients[a.Node]

			var err error
			if r.interactive != nil && r.interactive(step, a) {
				err = cl.Login(ctx, cl.Persist(), "", controlclient.LoginInteractive, hi.Clone(), r.approver(ctx, t, a.Key))
			} else {
				require.Contains(t, r.keys, a.Key, "%s: relogin with unknown key", step.Name)
				err = cl.Relogin(ctx, r.keys[a.Key], a.Force, hi.Clone())
			}

			if err != nil {
				refused[a.Node] = err
			}

			r.remember(a.Node)

		case "switch_profile":
			cl := r.clients[a.Node]

			switch strings.Join(a.Args, " ") {
			case "new":
				r.profiles[a.Node] = cl.Persist()
			case "back":
				err := cl.Login(ctx, r.profiles[a.Node], "", controlclient.LoginDefault, r.hostinfo[a.Node].Clone(), nil)
				if err != nil {
					refused[a.Node] = err
				}
			default:
				t.Fatalf("%s: no replay for switch_profile %q", step.Name, a.Args)
			}

		case "login":
			// A login on a new profile: the machine key stays, the login
			// starts empty.
			hi := r.hostinfo[a.Node].Clone()
			hi.Hostname = a.Hostname

			cl := r.clients[a.Node]

			var err error
			if r.interactive != nil && r.interactive(step, a) {
				err = cl.Login(ctx, persist.Persist{}, "", controlclient.LoginInteractive, hi, r.approver(ctx, t, a.Key))
			} else {
				require.Contains(t, r.keys, a.Key, "%s: login with unknown key", step.Name)
				err = cl.Login(ctx, persist.Persist{}, r.keys[a.Key], controlclient.LoginDefault, hi, nil)
			}

			if err != nil {
				refused[a.Node] = err
			}

		case "restart", "start", "kill", "shutdown", "logout", "advertise", "set_hostname",
			"break_tcp_conns", "rotate_disco_key", "cli", "disconnect_control":
			r.daemon(ctx, t, step.Name, a)

		case "retire":
			// SaaS stops the daemon and deletes its devices.
			r.clients[a.Node].Disconnect(t)

			for _, nv := range r.machineNodes(a.Node) {
				changes, err := r.srv.State().DeleteNode(nv)
				require.NoError(t, err, "%s: retire %s", step.Name, a.Node)
				r.srv.App.Change(changes...)
			}

		case "wait":
			// SaaS settle time. The test server runs no scheduled tasks
			// (expiry, HA probes), so passing time alone changes nothing
			// but ephemeral collection, which its consumers shorten.

		default:
			t.Fatalf("%s: no replay for action %q", step.Name, a.Kind)
		}
	}

	return refused
}

// daemon replays what a node's tailscaled or its CLI did.
func (r *stepReplay) daemon(ctx context.Context, t *testing.T, stepName string, a testcapture.Action) {
	t.Helper()

	cl := r.clients[a.Node]
	args := strings.Join(a.Args, " ")

	switch {
	case a.Kind == "restart" || a.Kind == "start":
		// start follows a kill: the daemon comes back on its state.
		require.NoError(t, cl.Restart(ctx, r.hostinfo[a.Node].Clone()), "%s: %s", stepName, a.Kind)

	case a.Kind == "kill", a.Kind == "disconnect_control",
		a.Kind == "shutdown" && !r.memState[a.Node]:
		// disconnect_control stops a refused login's retries; the next login
		// starts a new control client, as every replayed login does.
		cl.Disconnect(t)

	case a.Kind == "shutdown", a.Kind == "logout", a.Kind == "cli" && args == "logout":
		// tailscaled logs out on shutdown only with in-memory state.
		require.NoError(t, cl.LogoutAndDisconnect(ctx), "%s: %s", stepName, a.Kind)

	case a.Kind == "advertise":
		r.announce(ctx, t, a.Node, a.Routes)

	case a.Kind == "set_hostname":
		r.hostinfo[a.Node].Hostname = a.Hostname
		r.sendHostinfo(ctx, t, a.Node)

	case a.Kind == "break_tcp_conns":
		// The client polls again under the same key.
		require.NoError(t, cl.RestartPoll(ctx), "%s: reconnect", stepName)

	case a.Kind == "rotate_disco_key":
		require.NoError(t, cl.RotateDisco(ctx), "%s: disco rotation", stepName)

	case strings.HasPrefix(args, "debug set-expire --in="):
		d, err := time.ParseDuration(strings.TrimPrefix(args, "debug set-expire --in="))
		require.NoError(t, err, "%s: set-expire duration", stepName)

		// shortcut: the replay asks for at most setExpireLifetime, so the
		// wait that follows need not be real; a check of the exact expiry
		// would need the full duration.
		// A refusal is in the client's register attempts.
		_ = cl.SetExpirySooner(ctx, time.Now().Add(min(d, setExpireLifetime)))

	case strings.HasPrefix(args, "set --hostname="):
		r.hostinfo[a.Node].Hostname = strings.TrimPrefix(args, "set --hostname=")
		r.sendHostinfo(ctx, t, a.Node)

	default:
		t.Fatalf("%s: no replay for %s %q", stepName, a.Kind, a.Args)
	}
}

// setExpireLifetime bounds the key lifetime a replayed
// `tailscale debug set-expire` asks for.
const setExpireLifetime = 5 * time.Second

// expireDueKeys expires each minted key whose SaaS expiry passed before at,
// so a step taken after a key's lifetime finds it expired, as SaaS did,
// without the replay waiting.
func (r *stepReplay) expireDueKeys(t *testing.T, at time.Time) {
	t.Helper()

	for label, exp := range r.keyExpires {
		if exp.Before(at) {
			require.NoError(t, r.srv.State().ExpirePreAuthKey(r.keyIDs[label]), "expire key %s", label)
			delete(r.keyExpires, label)
		}
	}
}

// remember records alias's node while its machine holds exactly one.
func (r *stepReplay) remember(alias string) {
	if nodes := r.machineNodes(alias); len(nodes) == 1 {
		r.lastIDs[alias] = nodes[0].StringID()
	}
}

// v2Path maps a SaaS API path onto headscale's v2 API, and its device and
// key labels onto the replay's IDs. A device is its machine's one node, or
// the last one it held. It reports false for a label the replay never
// created and for a machine holding several nodes.
func (r *stepReplay) v2Path(path string) (string, bool) {
	if rest, ok := strings.CutPrefix(path, "/device/{device:"); ok {
		alias, tail, _ := strings.Cut(rest, "}")
		if len(r.machineNodes(alias)) > 1 {
			return "", false
		}

		r.remember(alias)
		id, ok := r.lastIDs[alias]

		return "/api/v2/device/" + id + tail, ok
	}

	if rest, ok := strings.CutPrefix(path, "/tailnet/-/keys/{key:"); ok {
		label, tail, _ := strings.Cut(rest, "}")
		id, ok := r.keyIDs[label]

		return "/api/v2/tailnet/-/keys/" + strconv.FormatUint(id, 10) + tail, ok
	}

	return "/api/v2" + path, true
}

// requestTags is the Hostinfo.RequestTags a login sends: the action's when
// it set them, else the ones the node sent last.
func requestTags(a testcapture.Action, last []string) []string {
	if a.RequestTags == nil {
		return last
	}

	return *a.RequestTags
}

// approver completes an interactive login as the user who owns key.
func (r *stepReplay) approver(ctx context.Context, t *testing.T, key string) func(string) error {
	t.Helper()

	user, ok := r.keyUsers[key]
	require.True(t, ok, "interactive login for unknown key %s", key)
	require.Empty(t, r.keyTags[key], "interactive login for tagged key %s", key)

	return func(authID string) error {
		return r.srv.ApproveAuth(ctx, authID, user.Name)
	}
}

func (r *stepReplay) setPolicy(t *testing.T, stepName, policy string) {
	t.Helper()

	changed, err := r.srv.State().SetPolicy(convertPolicyEmails(t, r.c.TestID, policy))
	require.NoError(t, err, "%s: policy", stepName)

	if changed {
		changes, err := r.srv.State().ReloadPolicy()
		require.NoError(t, err)
		r.srv.App.Change(changes...)
	}
}

// api replays one admin exchange, the i-th action of its step. Device and
// key deletes go to the v2 API; key mints and expiry, which the v2 API lacks
// or would answer with secrets, go to State. Reads are replayed only with
// readAPI.
func (r *stepReplay) api(t *testing.T, stepName string, i int, a testcapture.Action) {
	t.Helper()

	switch {
	case a.Method == http.MethodGet:
		if !r.readAPI {
			return
		}

		if path, ok := r.v2Path(a.Path); ok {
			r.exchange(t, stepName, i, a, path)
		}

	case a.Method == http.MethodPost && strings.HasPrefix(a.Path, "/tailnet/-/dns/"):
		// Headscale reads DNS from its config, which a consumer sets from
		// the capture's input; it has no API to change it.

	case a.Method == http.MethodPost && a.Path == "/tailnet/-/acl":
		require.Equal(t, http.StatusOK, a.Status, "%s: replay of a refused policy", stepName)
		r.setPolicy(t, stepName, string(a.Body))

	case a.Method == http.MethodPost && a.Path == "/tailnet/-/keys":
		require.Equal(t, http.StatusOK, a.Status, "%s: replay of a refused mint %s", stepName, a.Key)

		var body struct {
			Capabilities struct {
				Devices struct {
					Create struct {
						Reusable  bool     `json:"reusable"`
						Ephemeral bool     `json:"ephemeral"`
						Tags      []string `json:"tags"`
					} `json:"create"`
				} `json:"devices"`
			} `json:"capabilities"`
			ExpirySeconds int `json:"expirySeconds"`
		}
		require.NoError(t, json.Unmarshal(a.Body, &body), "%s: key body", stepName)

		// The admin mints as the tailnet owner; a user's own key mints as
		// that user.
		user := r.admin
		if name, ok := strings.CutPrefix(a.Principal, "user:"); ok {
			user, ok = r.users[name]
			require.True(t, ok, "%s: mint as unknown %s", stepName, a.Principal)
		}

		create := body.Capabilities.Devices.Create
		expiry := time.Now().Add(time.Duration(body.ExpirySeconds) * time.Second)
		uid := types.UserID(user.ID)

		pak, err := r.srv.State().CreatePreAuthKey(&uid, create.Reusable, create.Ephemeral, &expiry, create.Tags)
		require.NoError(t, err, "%s: mint %s", stepName, a.Key)

		r.keys[a.Key] = pak.Key
		r.keyIDs[a.Key] = pak.ID
		r.keyTags[a.Key] = create.Tags
		r.keyUsers[a.Key] = user

		var minted struct {
			Expires time.Time `json:"expires"`
		}
		if json.Unmarshal(a.Response, &minted) == nil && !minted.Expires.IsZero() {
			r.keyExpires[a.Key] = minted.Expires
		}

	case a.Method == http.MethodDelete && strings.HasPrefix(a.Path, "/tailnet/-/keys/{key:"):
		path, ok := r.v2Path(a.Path)
		require.True(t, ok, "%s: delete of unknown key %q", stepName, a.Path)

		r.exchange(t, stepName, i, a, path)

	case a.Method == http.MethodPost && strings.HasSuffix(a.Path, "/role"):
		// Headscale has no user roles; a role decides only what the user's
		// own API key may call, and the replay mints for him directly.

	case a.Method == http.MethodPost && strings.HasSuffix(a.Path, "/expire"):
		now := time.Now()

		_, c, err := r.srv.State().SetNodeExpiry(r.node(t, deviceAlias(t, a.Path)).ID(), &now)
		require.NoError(t, err, "%s: expire", stepName)
		r.srv.App.Change(c)

	case strings.HasPrefix(a.Path, "/device/"):
		path, ok := r.v2Path(a.Path)
		require.True(t, ok, "%s: %s names no single device", stepName, a.Path)

		r.exchange(t, stepName, i, a, path)

	default:
		t.Fatalf("%s: no replay for %s %s", stepName, a.Method, a.Path)
	}
}

// exchange sends a's request to headscale at path. With readAPI the answer
// is kept for the consumer; otherwise its status must be SaaS's.
func (r *stepReplay) exchange(t *testing.T, stepName string, i int, a testcapture.Action, path string) {
	t.Helper()

	status, resp := r.call(t, a.Method, path, a.Body)
	if r.readAPI {
		r.answers[i] = apiAnswer{status: status, body: resp}

		return
	}

	require.Equal(t, a.Status, status, "%s: %s %s: %s", stepName, a.Method, a.Path, resp)
}

// call sends one v2 API request as the admin.
func (r *stepReplay) call(t *testing.T, method, path string, body []byte) (int, []byte) {
	t.Helper()

	req, err := http.NewRequestWithContext(context.Background(), method, r.srv.URL+path, bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+r.apiKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := r.http.Do(req)
	require.NoError(t, err)

	defer resp.Body.Close()

	out, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	return resp.StatusCode, out
}

// machineNodes lists the nodes alias's machine holds now.
func (r *stepReplay) machineNodes(alias string) []types.NodeView {
	cl, ok := r.clients[alias]
	if !ok {
		return nil
	}

	nodes := r.srv.State().GetNodesByMachineKeyAllUsers(cl.MachineKey())

	return slices.Collect(maps.Values(nodes))
}

// node is the one node alias's machine holds now.
func (r *stepReplay) node(t *testing.T, alias string) types.NodeView {
	t.Helper()

	nodes := r.machineNodes(alias)
	require.Len(t, nodes, 1, "%s: nodes on its machine", alias)

	return nodes[0]
}

// waitSession holds a kill or start until headscale shows the node's
// session gone or back, as the probe waited for the device's control
// connection.
func (r *stepReplay) waitSession(t *testing.T, stepName string, a testcapture.Action) {
	t.Helper()

	if a.Kind != "kill" && a.Kind != "start" {
		return
	}

	want := a.Kind == "start"

	require.Eventuallyf(t, func() bool {
		nodes := r.machineNodes(a.Node)
		if len(nodes) != 1 {
			return false
		}

		online := nodes[0].IsOnline()

		return online.Valid() && online.Get() == want
	}, 30*time.Second, 50*time.Millisecond, "%s: %s %s", stepName, a.Kind, a.Node)
}

// saasAlias is the capture alias of SaaS node id.
func (r *stepReplay) saasAlias(id tailcfg.NodeID) (string, bool) {
	for alias, saasID := range r.c.NodeIDs {
		if saasID == id {
			return alias, true
		}
	}

	return "", false
}

// hsAlias is the alias whose machine holds node id, or last held it: a
// deleted node a client still lists must count, as saasAlias counts it.
func (r *stepReplay) hsAlias(id tailcfg.NodeID) (string, bool) {
	for alias := range r.clients {
		for _, nv := range r.machineNodes(alias) {
			if nv.ID().NodeID() == id {
				return alias, true
			}
		}
	}

	for alias, last := range r.lastIDs {
		if last == strconv.FormatInt(int64(id), 10) {
			return alias, true
		}
	}

	return "", false
}

// peerAliases names the peers in nm that alias resolves.
func peerAliases(nm *netmap.NetworkMap, alias func(tailcfg.NodeID) (string, bool)) string {
	if nm == nil {
		return "no netmap"
	}

	var out []string

	for _, p := range nm.Peers {
		if name, ok := alias(p.ID()); ok {
			out = append(out, name)
		}
	}

	return sortedStrings(out)
}

func (r *stepReplay) announce(ctx context.Context, t *testing.T, alias string, routes []string) {
	t.Helper()

	r.hostinfo[alias].RoutableIPs = prefixes(t, routes)
	r.sendHostinfo(ctx, t, alias)
}

func (r *stepReplay) sendHostinfo(ctx context.Context, t *testing.T, alias string) {
	t.Helper()

	cl := r.clients[alias]
	cl.Direct().SetHostinfo(r.hostinfo[alias].Clone())
	require.NoError(t, cl.Direct().SendUpdate(ctx), "%s: hostinfo update", alias)
}

// deviceAlias extracts x from a "/device/{device:x}/..." path.
func deviceAlias(t *testing.T, path string) string {
	t.Helper()

	rest, ok := strings.CutPrefix(path, "/device/{device:")
	alias, _, found := strings.Cut(rest, "}")
	require.True(t, ok && found, "no device label in %q", path)

	return alias
}

func prefixes(t *testing.T, routes []string) []netip.Prefix {
	t.Helper()

	out := make([]netip.Prefix, 0, len(routes))
	for _, r := range routes {
		out = append(out, netip.MustParsePrefix(r))
	}

	return out
}
