// This file implements data-driven via+HA compatibility tests using
// golden data captured from Tailscale SaaS (v37-v46). These scenarios
// exercise the interaction between via grant steering and HA primary
// route election with varying combinations of shared/unique via tags,
// regular grants, and multiple HA pairs.
//
// Test data source: ../policy/v2/testdata/grant_results/via-grant-v{37..46}.hujson
// Source format:    github.com/juanfont/headscale/hscontrol/types/testcapture

package servertest_test

import (
	"bytes"
	"context"
	"encoding/json"
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
				compareCaptureNetmap(tt, cl, capture, clients)
			})
		})
	}
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

	// Baseline PacketFilter sanity: count rules. Full per-rule dst-prefix
	// comparison is done by the tailscale_routes_data compat test; here
	// we only catch gross drift.
	if len(want.PacketFilterRules) > 0 {
		gotLen := nm.PacketFilterRules.Len()
		assert.Equalf(t, len(want.PacketFilterRules), gotLen,
			"PacketFilter rule count mismatch (SaaS=%d, headscale=%d)",
			len(want.PacketFilterRules), gotLen,
		)
	}

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
// test if none of the known SaaS emails are present: that would mean the
// capture was regenerated with a new identity and captureUserNames needs
// updating.
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
		substituted,
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

// stepReplay drives a step capture's actions against headscale: policy
// pushes, key mints and revokes, joins, relogins, profile switches,
// restarts, route announcements, logouts, retires and admin calls, the
// last through the v2 API with the bodies SaaS received. Nothing is seeded
// from the capture's end state.
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
	}
}

// apply runs the step's actions in order and returns the logins headscale
// refused, by node. Reads are skipped: they are what consumers compare.
func (r *stepReplay) apply(t *testing.T, step testcapture.Step) map[string]error {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	refused := map[string]error{}

	for _, a := range step.Actions {
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
			r.api(t, step.Name, a)

		case "join":
			hi := &tailcfg.Hostinfo{
				BackendLogID: "servertest-" + a.Node,
				Hostname:     a.Hostname,
				RequestTags:  requestTags(a, nil),
			}
			r.hostinfo[a.Node] = hi

			opts := []servertest.ClientOption{servertest.WithUser(r.admin), servertest.WithHostinfo(hi.Clone())}
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

			if len(a.Routes) > 0 {
				r.announce(ctx, t, a.Node, a.Routes)
			}

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

		case "restart":
			require.NoError(t, r.clients[a.Node].Restart(ctx, r.hostinfo[a.Node].Clone()), "%s: restart", step.Name)

		case "advertise":
			r.announce(ctx, t, a.Node, a.Routes)

		case "cli":
			args := strings.Join(a.Args, " ")
			if args == "logout" {
				require.NoError(t, r.clients[a.Node].LogoutAndDisconnect(ctx), "%s: logout", step.Name)

				continue
			}

			hostname, ok := strings.CutPrefix(args, "set --hostname=")
			require.True(t, ok, "%s: no replay for cli %q", step.Name, a.Args)

			r.hostinfo[a.Node].Hostname = hostname
			r.sendHostinfo(ctx, t, a.Node)

		case "logout":
			require.NoError(t, r.clients[a.Node].LogoutAndDisconnect(ctx), "%s: logout", step.Name)

		case "retire":
			// SaaS stops the daemon and deletes its devices.
			r.clients[a.Node].Disconnect(t)

			for _, nv := range r.machineNodes(a.Node) {
				changes, err := r.srv.State().DeleteNode(nv)
				require.NoError(t, err, "%s: retire %s", step.Name, a.Node)
				r.srv.App.Change(changes...)
			}

		case "wait":
			// SaaS settle time.

		default:
			t.Fatalf("%s: no replay for action %q", step.Name, a.Kind)
		}
	}

	return refused
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

// api replays one admin exchange. Device and key deletes go to the v2 API;
// key mints and expiry, which the v2 API lacks or would answer with
// secrets, go to State.
func (r *stepReplay) api(t *testing.T, stepName string, a testcapture.Action) {
	t.Helper()

	switch {
	case a.Method == http.MethodGet:
		return

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

	case a.Method == http.MethodDelete && strings.HasPrefix(a.Path, "/tailnet/-/keys/{key:"):
		label := strings.TrimSuffix(strings.TrimPrefix(a.Path, "/tailnet/-/keys/{key:"), "}")
		id, ok := r.keyIDs[label]
		require.True(t, ok, "%s: delete of unknown key %q", stepName, label)

		status, resp := r.call(t, a.Method, "/api/v2/tailnet/-/keys/"+strconv.FormatUint(id, 10), nil)
		require.Equal(t, a.Status, status, "%s: %s %s: %s", stepName, a.Method, a.Path, resp)

	case a.Method == http.MethodPost && strings.HasSuffix(a.Path, "/expire"):
		now := time.Now()

		_, c, err := r.srv.State().SetNodeExpiry(r.node(t, deviceAlias(t, a.Path)).ID(), &now)
		require.NoError(t, err, "%s: expire", stepName)
		r.srv.App.Change(c)

	case strings.HasPrefix(a.Path, "/device/"):
		alias := deviceAlias(t, a.Path)
		path := "/api/v2/device/" + r.node(t, alias).StringID() +
			strings.TrimPrefix(a.Path, "/device/{device:"+alias+"}")

		status, resp := r.call(t, a.Method, path, a.Body)
		require.Equal(t, a.Status, status, "%s: %s %s: %s", stepName, a.Method, a.Path, resp)

	default:
		t.Fatalf("%s: no replay for %s %s", stepName, a.Method, a.Path)
	}
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
