// This file replays multi-step lifecycle captures from Tailscale SaaS and
// compares each step's outcome with what SaaS showed.
//
// Test data source: testdata/steps/{route-approval,owner-routes,
// ephemeral-lifecycle}.hujson, loaded by name. owner-routes is consumed by
// TestReauthCompat; the refused logins of ephemeral-lifecycle are rows of
// TestAuthKeyRefusalCompat.
// Source format:    github.com/juanfont/headscale/hscontrol/types/testcapture

package servertest_test

import (
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
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
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/types/netmap"
	"tailscale.com/types/views"
)

// lifecycleSkipReasons lists checks where headscale differs from SaaS, keyed
// <test_id>/<step>[/<node or action index>]/<check>, with "collection" for
// the step of what killed nodes leave behind. A listed check that matches
// fails, so a fix must delete its entry.
var lifecycleSkipReasons = map[string]string{
	"ephemeral-lifecycle/E3-key-delete/2/keys": deletedKeyListed,
	"ephemeral-lifecycle/E3-key-delete/3/keys": deletedKeyListed,
}

const (
	deletedKeyListed = "DELETED_KEY_LISTED: headscale lists a deleted auth key; SaaS leaves it out of both key lists, while a read by ID still answers"
)

// TestRouteApprovalCompat replays a user-owned router through admin
// approvals and revokes, same-key and forced re-auth, a hostname change,
// policy pushes, a withdraw and re-advertise, then logout and a login with
// a new key. Each step compares the routes API, the routes a tagged
// observer is served, and the router's own view with SaaS.
func TestRouteApprovalCompat(t *testing.T) {
	t.Parallel()

	t.Run("route-approval", func(t *testing.T) {
		t.Parallel()

		runRouteLifecycleCompat(t, "route-approval", "t-client", lifecycleSkipReasons)
	})
}

func TestLifecycleSkipEntriesNameCaptures(t *testing.T) {
	t.Parallel()

	requireSkipCaptures(t, lifecycleSkipReasons, "route-approval", "ephemeral-lifecycle")
	requireSkipCaptures(t, reauthSkipReasons, append([]string{"owner-routes", "ephemeral-lifecycle"}, reauthCompatTests...)...)
}

// stepCheck is one rendering of a step outcome: SaaS's, and how to read
// headscale's.
type stepCheck struct {
	name string
	want string
	got  func() string
}

// runRouteLifecycleCompat replays capture id step by step and, after each
// step that read a router's routes, checks against SaaS:
//   - advertised, enabled: the v2 routes API;
//   - owner, device, node-key: who owns the router, whether its machine
//     still holds one node with the join-time ID and addresses, and whether
//     the step rotated its node key;
//   - served, expired, online: the router as the observer's peer;
//   - self-routes: the router's own routes, while SaaS showed it running;
//   - removed, dropped: whether the observer lost the router, or any route
//     it served both before and after, during the step, when SaaS recorded
//     the observer's map stream.
func runRouteLifecycleCompat(t *testing.T, id, observer string, skips map[string]string) {
	t.Helper()

	c := readStepCapture(t, id)
	r := newStepReplay(t, c)

	type joined struct {
		saasID, saasAddrs string
		hsID              types.NodeID
		hsAddrs           string
	}

	first := map[string]joined{}
	saasKey := map[string]string{}
	hsKey := map[string]key.NodePublic{}
	evaluated := map[string]bool{}

	var prevObserved *netmap.NetworkMap

	// The probe records the observer's stream through a whole capture or not
	// at all, so a step without frames was silent.
	streamed := slices.ContainsFunc(c.Steps, func(s testcapture.Step) bool { return len(s.Frames[observer]) > 0 })

	for _, step := range c.Steps {
		require.Equal(t, "observed", step.Result, "%s: the replay follows every step", step.Name)

		// From the last netmap before the step, so a peer present then and
		// missing from the step's first netmap counts as removed.
		historyStart := 0
		if obs, ok := r.clients[observer]; ok {
			historyStart = max(len(obs.History())-1, 0)
		}

		require.Empty(t, r.apply(t, step), "%s: every login succeeds", step.Name)

		prevSaaS := prevObserved
		prevObserved = step.Captures[observer].Netmap

		router, saasRoutes, ok := lastRoutesRead(t, step)
		if !ok {
			continue
		}

		dev := saasDeviceOf(t, step, router)
		saasRouterID := c.NodeIDs[router]

		t.Run(step.Name, func(t *testing.T) {
			if _, ok := first[router]; !ok {
				nv := r.node(t, router)
				first[router] = joined{
					saasID: dev.ID, saasAddrs: sortedStrings(dev.Addresses),
					hsID: nv.ID(), hsAddrs: sortedStrings(nv.IPsAsString()),
				}
			}

			join := first[router]

			hsRoutes := func() (deviceRoutes, bool) { return r.hsDeviceRoutes(t, router) }

			// hsPeer is the router as the observer's peer in headscale.
			hsPeer := func() (tailcfg.NodeView, string) {
				nodes := r.machineNodes(router)
				if len(nodes) != 1 {
					return tailcfg.NodeView{}, fmt.Sprintf("devices %d", len(nodes))
				}

				nm := r.clients[observer].Netmap()
				if nm == nil {
					return tailcfg.NodeView{}, "no netmap"
				}

				return peerByID(nm, nodes[0].ID().NodeID())
			}

			saasPeer, saasPeerState := peerByID(step.Captures[observer].Netmap, saasRouterID)

			checks := []stepCheck{
				{"advertised", sortedStrings(saasRoutes.Advertised), func() string {
					got, ok := hsRoutes()
					if !ok {
						return "no single device"
					}

					return sortedStrings(got.Advertised)
				}},
				{"enabled", sortedStrings(saasRoutes.Enabled), func() string {
					got, ok := hsRoutes()
					if !ok {
						return "no single device"
					}

					return sortedStrings(got.Enabled)
				}},
				{"owner", saasOwner(dev), func() string {
					nodes := r.machineNodes(router)
					if len(nodes) != 1 {
						return fmt.Sprintf("devices %d", len(nodes))
					}

					if nodes[0].IsTagged() {
						return "tags " + sortedStrings(nodes[0].Tags().AsSlice())
					}

					return "user " + nodes[0].User().Name()
				}},
				{"device", deviceState(
					countDevicesOnMachine(t, step, dev.MachineKey),
					dev.ID == join.saasID, sortedStrings(dev.Addresses) == join.saasAddrs,
				), func() string {
					nodes := r.machineNodes(router)
					if len(nodes) != 1 {
						return deviceState(len(nodes), false, false)
					}

					return deviceState(1, nodes[0].ID() == join.hsID,
						sortedStrings(nodes[0].IPsAsString()) == join.hsAddrs)
				}},
				{"served", servedRoutes(saasPeer, saasPeerState), func() string {
					return servedRoutes(hsPeer())
				}},
				{"expired", peerExpired(saasPeer, saasPeerState), func() string {
					return peerExpired(hsPeer())
				}},
				{"online", peerOnline(saasPeer, saasPeerState), func() string {
					return peerOnline(hsPeer())
				}},
			}

			if prev, ok := saasKey[router]; ok {
				prevHS := hsKey[router]

				checks = append(checks, stepCheck{"node-key", keyChange(prev == dev.NodeKey), func() string {
					nodes := r.machineNodes(router)
					if len(nodes) != 1 {
						return fmt.Sprintf("devices %d", len(nodes))
					}

					return keyChange(nodes[0].NodeKey() == prevHS)
				}})
			}

			if self := step.Captures[router]; self.BackendState == "Running" && self.Netmap != nil {
				checks = append(checks, stepCheck{"self-routes", selfRoutes(self.Netmap), func() string {
					nm := r.clients[router].Netmap()
					if nm == nil {
						return "no netmap"
					}

					return selfRoutes(nm)
				}})
			}

			if streamed {
				frames := step.Frames[observer]
				hsHistory := func() ([]*netmap.NetworkMap, tailcfg.NodeID, string) {
					nodes := r.machineNodes(router)
					if len(nodes) != 1 {
						return nil, 0, fmt.Sprintf("devices %d", len(nodes))
					}

					return r.clients[observer].History()[historyStart:], nodes[0].ID().NodeID(), ""
				}

				checks = append(checks,
					stepCheck{"removed", saasRemoved(prevSaaS, frames, saasRouterID), func() string {
						history, nodeID, missing := hsHistory()
						if missing != "" {
							return missing
						}

						return hsRemoved(history, nodeID)
					}},
					stepCheck{"dropped", droppedRoutes(saasServedViews(prevSaaS, frames, step.Captures[observer].Netmap, saasRouterID)), func() string {
						history, nodeID, missing := hsHistory()
						if missing != "" {
							return missing
						}

						return droppedRoutes(hsServedViews(history, nodeID))
					}},
				)
			}

			holdChecks(t, skips, id+"/"+step.Name+"/", checks, evaluated)
		})

		saasKey[router] = dev.NodeKey
		if nodes := r.machineNodes(router); len(nodes) == 1 {
			hsKey[router] = nodes[0].NodeKey()
		}
	}

	for k := range skips {
		if strings.HasPrefix(k, id+"/") && !evaluated[k] {
			t.Errorf("skip entry %q names no check", k)
		}
	}
}

// holdChecks polls the checks until, for several ticks in a row, each one
// listed in skips differs from SaaS and every other one matches, then
// reports each as a subtest. A listed check that matches fails.
func holdChecks(
	t *testing.T,
	skips map[string]string,
	prefix string,
	checks []stepCheck,
	evaluated map[string]bool,
) {
	t.Helper()

	// Long enough for a batch still in flight to land.
	const holdTicks = 5

	got := make([]string, len(checks))
	held := 0

	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()

	for deadline := time.Now().Add(15 * time.Second); held < holdTicks && time.Now().Before(deadline); <-tick.C {
		settled := true

		for i, c := range checks {
			got[i] = c.got()
			if _, listed := skips[prefix+c.name]; (got[i] == c.want) == listed {
				settled = false
			}
		}

		if settled {
			held++
		} else {
			held = 0
		}
	}

	// A last-sample match is not a settled one.
	if held < holdTicks {
		t.Errorf("%s: checks still changing at the deadline", strings.TrimSuffix(prefix, "/"))
	}

	for i, c := range checks {
		key := prefix + c.name
		evaluated[key] = true

		t.Run(c.name, func(t *testing.T) {
			reason, listed := skips[key]

			switch {
			case listed && got[i] == c.want:
				t.Errorf("matches SaaS; delete the skip entry %q (%s)", key, reason)
			case listed:
				t.Skip(reason)
			default:
				assert.Equal(t, c.want, got[i])
			}
		})
	}
}

// deviceRoutes is the routes API body, on SaaS and on headscale's v2 API.
type deviceRoutes struct {
	Advertised []string `json:"advertisedRoutes"`
	Enabled    []string `json:"enabledRoutes"`
}

// hsDeviceRoutes reads alias's routes from headscale's v2 API, while its
// machine holds one node.
func (r *stepReplay) hsDeviceRoutes(t *testing.T, alias string) (deviceRoutes, bool) {
	t.Helper()

	nodes := r.machineNodes(alias)
	if len(nodes) != 1 {
		return deviceRoutes{}, false
	}

	status, body := r.call(t, http.MethodGet, "/api/v2/device/"+nodes[0].StringID()+"/routes", nil)
	require.Equal(t, http.StatusOK, status, "%s", body)

	var out deviceRoutes
	require.NoError(t, json.Unmarshal(body, &out))

	return out, true
}

// saasDevice is the part of a SaaS device-list entry the checks read.
// Keys and IDs are the capture's labels.
type saasDevice struct {
	ID                string   `json:"id"`
	Name              string   `json:"name"`
	Hostname          string   `json:"hostname"`
	NodeKey           string   `json:"nodeKey"`
	MachineKey        string   `json:"machineKey"`
	Addresses         []string `json:"addresses"`
	Tags              []string `json:"tags"`
	User              string   `json:"user"`
	Expires           string   `json:"expires"`
	KeyExpiryDisabled bool     `json:"keyExpiryDisabled"`
	IsEphemeral       bool     `json:"isEphemeral"`
}

// lastRoutesRead returns the step's last routes read: the device it named
// and SaaS's answer.
func lastRoutesRead(t *testing.T, step testcapture.Step) (string, deviceRoutes, bool) {
	t.Helper()

	for _, a := range slices.Backward(step.Actions) {
		if a.Kind != "api" || a.Method != http.MethodGet || !strings.HasSuffix(a.Path, "/routes") {
			continue
		}

		require.Equal(t, http.StatusOK, a.Status, "%s: %s", step.Name, a.Path)

		var out deviceRoutes
		require.NoError(t, json.Unmarshal(a.Response, &out), "%s: %s", step.Name, a.Path)

		return deviceAlias(t, a.Path), out, true
	}

	return "", deviceRoutes{}, false
}

// stepDevices decodes the step's last device-list read.
func stepDevices(t *testing.T, step testcapture.Step) []saasDevice {
	t.Helper()

	for _, a := range slices.Backward(step.Actions) {
		if a.Kind != "api" || a.Method != http.MethodGet || !strings.HasPrefix(a.Path, "/tailnet/-/devices") {
			continue
		}

		var out struct {
			Devices []saasDevice `json:"devices"`
		}
		require.NoError(t, json.Unmarshal(a.Response, &out), "%s: %s", step.Name, a.Path)

		return out.Devices
	}

	t.Fatalf("%s: no device-list read", step.Name)

	return nil
}

// saasDeviceOf finds alias's device by its machine, so a device SaaS
// re-created would still be found.
func saasDeviceOf(t *testing.T, step testcapture.Step, alias string) saasDevice {
	t.Helper()

	for _, d := range stepDevices(t, step) {
		if d.MachineKey == "{machine:"+alias+"}" {
			return d
		}
	}

	t.Fatalf("%s: no device on %s's machine", step.Name, alias)

	return saasDevice{}
}

func countDevicesOnMachine(t *testing.T, step testcapture.Step, machine string) int {
	t.Helper()

	n := 0

	for _, d := range stepDevices(t, step) {
		if d.MachineKey == machine {
			n++
		}
	}

	return n
}

func saasOwner(d saasDevice) string {
	if len(d.Tags) > 0 {
		return "tags " + sortedStrings(d.Tags)
	}

	return "user " + captureUserNames[d.User]
}

func deviceState(devices int, sameID, sameAddrs bool) string {
	return fmt.Sprintf("devices %d, id kept %t, addresses kept %t", devices, sameID, sameAddrs)
}

func keyChange(kept bool) string {
	if kept {
		return "kept"
	}

	return "rotated"
}

// peerByID finds a peer, or says why there is none.
func peerByID(nm *netmap.NetworkMap, id tailcfg.NodeID) (tailcfg.NodeView, string) {
	if nm == nil {
		return tailcfg.NodeView{}, "no netmap"
	}

	for _, p := range nm.Peers {
		if p.ID() == id {
			return p, ""
		}
	}

	return tailcfg.NodeView{}, "absent"
}

func servedRoutes(p tailcfg.NodeView, missing string) string {
	if missing != "" {
		return missing
	}

	return "allowed " + selfAllowed(p) + " primary " + prefixList(p.PrimaryRoutes())
}

func peerExpired(p tailcfg.NodeView, missing string) string {
	if missing != "" {
		return missing
	}

	return strconv.FormatBool(p.Expired())
}

func peerOnline(p tailcfg.NodeView, missing string) string {
	if missing != "" {
		return missing
	}

	if !p.Online().Valid() {
		return "unknown"
	}

	return strconv.FormatBool(p.Online().Get())
}

// saasRemoved reports whether the peer, present before the step or once a
// frame named it, was then removed or left out of a full peer list.
func saasRemoved(before *netmap.NetworkMap, frames []testcapture.Frame, id tailcfg.NodeID) string {
	_, missing := peerByID(before, id)
	seen := missing == ""

	for _, f := range frames {
		resp := f.Response
		if resp == nil {
			continue
		}

		if slices.Contains(resp.PeersRemoved, id) {
			return "removed"
		}

		listed := slices.ContainsFunc(resp.Peers, func(n *tailcfg.Node) bool { return n.ID == id })

		switch {
		case listed || slices.ContainsFunc(resp.PeersChanged, func(n *tailcfg.Node) bool { return n.ID == id }):
			seen = true
		case resp.Peers != nil && seen:
			return "removed"
		}
	}

	return "kept"
}

// hsRemoved reports whether the peer, once present, went missing from a
// later netmap.
func hsRemoved(history []*netmap.NetworkMap, id tailcfg.NodeID) string {
	seen := false

	for _, nm := range history {
		_, missing := peerByID(nm, id)

		switch {
		case missing == "":
			seen = true
		case seen:
			return "removed"
		}
	}

	return "kept"
}

// servedEntries lists a peer's subnet routes, by field; none when missing.
func servedEntries(p tailcfg.NodeView, missing string) []string {
	if missing != "" {
		return nil
	}

	var out []string

	for _, pfx := range p.AllowedIPs().All() {
		if !views.SliceContains(p.Addresses(), pfx) {
			out = append(out, "allowed "+pfx.String())
		}
	}

	for _, pfx := range p.PrimaryRoutes().All() {
		out = append(out, "primary "+pfx.String())
	}

	return out
}

// saasServedViews returns the peer's routes before the step, after each
// frame that names it, and at the step's end.
func saasServedViews(before *netmap.NetworkMap, frames []testcapture.Frame, after *netmap.NetworkMap, id tailcfg.NodeID) [][]string {
	out := [][]string{servedEntries(peerByID(before, id))}

	for _, f := range frames {
		resp := f.Response
		if resp == nil {
			continue
		}

		if slices.Contains(resp.PeersRemoved, id) {
			out = append(out, nil)

			continue
		}

		byID := func(n *tailcfg.Node) bool { return n.ID == id }

		switch changed, listed := slices.IndexFunc(resp.PeersChanged, byID), slices.IndexFunc(resp.Peers, byID); {
		case changed >= 0:
			out = append(out, servedEntries(resp.PeersChanged[changed].View(), ""))
		case listed >= 0:
			out = append(out, servedEntries(resp.Peers[listed].View(), ""))
		case resp.Peers != nil:
			out = append(out, nil)
		}
	}

	return append(out, servedEntries(peerByID(after, id)))
}

func hsServedViews(history []*netmap.NetworkMap, id tailcfg.NodeID) [][]string {
	out := make([][]string, 0, len(history))
	for _, nm := range history {
		out = append(out, servedEntries(peerByID(nm, id)))
	}

	return out
}

// droppedRoutes lists the routes served both before and after a step that
// some view in between left out, so routes cleared and restored within a
// step do not pass as kept.
func droppedRoutes(seen [][]string) string {
	if len(seen) < 2 {
		return "none"
	}

	var out []string

	for _, r := range seen[0] {
		if !slices.Contains(seen[len(seen)-1], r) {
			continue
		}

		if slices.ContainsFunc(seen[1:], func(v []string) bool { return !slices.Contains(v, r) }) {
			out = append(out, r)
		}
	}

	if len(out) == 0 {
		return "none"
	}

	return sortedStrings(out)
}

func TestDroppedRoutes(t *testing.T) {
	t.Parallel()

	a, b := "primary 10.0.0.0/24", "primary 10.1.0.0/24"

	assert.Equal(t, "none", droppedRoutes([][]string{{a, b}, {a, b}}))
	assert.Equal(t, "[primary 10.0.0.0/24]", droppedRoutes([][]string{{a, b}, {b}, {a, b}}))
	assert.Equal(t, "none", droppedRoutes([][]string{{a, b}, {b}, {b}}), "a route gone at the end is not dropped")
}

// TestEphemeralLifecycleCompat replays ephemeral devices through logout, a
// rejoin, a device deleted twice, a deleted key and a restart after it,
// re-auth with a key of the other kind, a shutdown with in-memory state and
// a kill of several devices. Each step compares with SaaS: the status of
// every admin exchange, key validity and listing, register answers, the
// devices on each machine, their ephemeral flag, node key, address and
// expiry, the observer's view and removals, and at the last read which
// devices are left once the killed ones could be collected and whether the
// observer lost them.
func TestEphemeralLifecycleCompat(t *testing.T) {
	t.Parallel()

	t.Run("ephemeral-lifecycle", func(t *testing.T) {
		t.Parallel()

		runEphemeralLifecycleCompat(t, "ephemeral-lifecycle", "observer")
	})
}

func runEphemeralLifecycleCompat(t *testing.T, id, observer string) {
	t.Helper()

	c := readStepCapture(t, id)

	// Short, so the killed devices can be collected while the last read is
	// checked; collection timing is not compared.
	r := newStepReplay(t, c, servertest.WithEphemeralTimeout(2*time.Second))
	r.readAPI = true

	lastRead := -1

	for i, step := range c.Steps {
		if _, _, ok := stepDeviceRead(step); ok {
			lastRead = i
		}
	}

	saasFirst, hsFirst := map[string]deviceView{}, map[string]deviceView{}
	saasPrev := map[string][]deviceView{}
	killed := map[string]*killedNode{}
	evaluated := map[string]bool{}
	prevObs := c.Captures[observer].Netmap

	for i, step := range c.Steps {
		require.Contains(t, []string{"observed", "expected-refusal"}, step.Result,
			"%s: the replay follows every step", step.Name)

		cells := lifecycleCells(step)

		hsPrev := map[string][]deviceView{}
		attempts := map[string]int{}

		for _, cell := range cells {
			hsPrev[cell] = r.hsViews(cell)
			if cl, ok := r.clients[cell]; ok {
				attempts[cell] = len(cl.RegisterAttempts())
			}
		}

		historyStart := 0
		if obs, ok := r.clients[observer]; ok {
			historyStart = max(len(obs.History())-1, 0)
		}

		r.apply(t, step)
		markKilled(step, killed, func(node string) *killedNode {
			return &killedNode{saas: saasPrev[node], hs: hsPrev[node], prevObs: prevObs, historyStart: historyStart}
		})

		for _, k := range killed {
			k.frames = append(k.frames, step.Frames[observer]...)
		}

		checks := r.answerChecks(step)
		checks = append(checks, r.keyChecks(step)...)
		checks = append(checks, r.keyListChecks(t, step)...)

		devices, readAt, listed := stepDeviceRead(step)

		r.firstDevices(c, step, saasFirst, hsFirst)

		for _, cell := range cells {
			// A device killed in the step is judged at the last read only:
			// when it is collected is timing.
			want, ok := saasCellDevices(c, step, cell)
			if killed[cell] != nil || !ok {
				continue
			}

			checks = append(checks, ephemeralCellChecks(r, step, cell, observer, cellState{
				want: want, saasPrev: saasPrev[cell], hsPrev: hsPrev[cell],
				saasFirst: saasFirst[cell], hsFirst: hsFirst[cell],
				attempts: attempts[cell], prevObs: prevObs, historyStart: historyStart,
				saasAll: devices, listed: listed,
			})...)
		}

		run := func(name string, checks []stepCheck) {
			prefix := id + "/" + name + "/"
			for _, ch := range checks {
				evaluated[prefix+ch.name] = true
			}

			if len(checks) > 0 {
				t.Run(name, func(t *testing.T) {
					holdChecks(t, lifecycleSkipReasons, prefix, checks, evaluated)
				})
			}
		}

		run(step.Name, checks)

		// Keyed apart from the step, so the poll that first finds a device
		// gone does not name the check.
		if i == lastRead {
			run("collection", append(r.leftChecks(c, step), r.collectionChecks(killed, observer)...))
		}

		// A device list shows every machine; a device read only its own.
		if listed {
			for alias := range r.clients {
				saasPrev[alias] = saasDeviceViews(c, devices, alias, readAt)
			}
		}

		for _, cell := range cells {
			if want, ok := saasCellDevices(c, step, cell); ok {
				saasPrev[cell] = want
			}
		}

		if obs, ok := step.Captures[observer]; ok && obs.Netmap != nil {
			prevObs = obs.Netmap
		}
	}

	for k := range lifecycleSkipReasons {
		if strings.HasPrefix(k, id+"/") && !evaluated[k] {
			t.Errorf("skip entry %q names no check", k)
		}
	}
}

// killedNode is what a killed node's collection is judged against: both
// sides' devices and SaaS's observer view before the kill, where the
// observer's headscale history stood then, and SaaS's observer frames since.
type killedNode struct {
	saas, hs     []deviceView
	prevObs      *netmap.NetworkMap
	historyStart int
	frames       []testcapture.Frame
}

// markKilled records the nodes a step killed, as before reports them, and
// forgets those it brought back.
func markKilled(step testcapture.Step, killed map[string]*killedNode, before func(node string) *killedNode) {
	for _, a := range step.Actions {
		switch a.Kind {
		case "kill":
			killed[a.Node] = before(a.Node)
		case "start", "join", "relogin", "restart":
			delete(killed, a.Node)
		}
	}
}

// collectionChecks compares, per device of each node still killed, whether
// the observer lost it since the kill and whether it is still a peer.
func (r *stepReplay) collectionChecks(killed map[string]*killedNode, observer string) []stepCheck {
	var checks []stepCheck

	for _, node := range slices.Sorted(maps.Keys(killed)) {
		k := killed[node]
		if len(k.saas) == 0 {
			continue
		}

		checks = append(checks,
			stepCheck{node + "/removed-" + observer, renderEach(k.saas, func(v deviceView) string {
				return saasRemoved(k.prevObs, k.frames, v.nodeID)
			}), func() string {
				history := r.clients[observer].History()[k.historyStart:]

				return renderEach(k.hs, func(v deviceView) string { return hsRemoved(history, v.nodeID) })
			}},
			stepCheck{node + "/present-" + observer, renderEach(k.saas, func(v deviceView) string {
				return saasPresent(k.prevObs, k.frames, v.nodeID)
			}), func() string {
				nm := r.clients[observer].Netmap()

				return renderEach(k.hs, func(v deviceView) string {
					if _, missing := peerByID(nm, v.nodeID); missing != "" {
						return missing
					}

					return "present"
				})
			}},
		)
	}

	return checks
}

// saasPresent reports whether the peer is listed once the frames apply to
// the netmap before them.
func saasPresent(before *netmap.NetworkMap, frames []testcapture.Frame, id tailcfg.NodeID) string {
	_, missing := peerByID(before, id)
	present := missing == ""
	byID := func(n *tailcfg.Node) bool { return n.ID == id }

	for _, f := range frames {
		switch resp := f.Response; {
		case resp == nil:
		case slices.Contains(resp.PeersRemoved, id):
			present = false
		case resp.Peers != nil:
			present = slices.ContainsFunc(resp.Peers, byID)
		case slices.ContainsFunc(resp.PeersChanged, byID):
			present = true
		}
	}

	if present {
		return "present"
	}

	return "absent"
}

// firstDevices records each machine's device as it first joined: on SaaS
// from the first device list that shows it.
func (r *stepReplay) firstDevices(c *testcapture.Capture, step testcapture.Step, saasFirst, hsFirst map[string]deviceView) {
	devices, at, listed := stepDeviceRead(step)

	for alias := range r.clients {
		if _, seen := saasFirst[alias]; !seen && listed {
			if views := saasDeviceViews(c, devices, alias, at); len(views) > 0 {
				saasFirst[alias] = views[0]
			}
		}

		if _, seen := hsFirst[alias]; !seen {
			if views := r.hsViews(alias); len(views) > 0 {
				hsFirst[alias] = views[0]
			}
		}
	}
}

// leftChecks compares how many devices each machine holds at the last read.
// A device the polls still saw when they gave up is not observed, not kept.
func (r *stepReplay) leftChecks(c *testcapture.Capture, step testcapture.Step) []stepCheck {
	devices, at, _ := stepDeviceRead(step)

	_, unseen, _ := strings.Cut(step.Note, "not observed: ")
	notObserved := strings.Split(unseen, ", ")

	checks := make([]stepCheck, 0, len(r.clients))

	for _, alias := range slices.Sorted(maps.Keys(r.clients)) {
		if slices.Contains(notObserved, alias) {
			continue
		}

		checks = append(checks, stepCheck{alias + "/left", strconv.Itoa(len(saasDeviceViews(c, devices, alias, at))), func() string {
			return strconv.Itoa(len(r.machineNodes(alias)))
		}})
	}

	return checks
}

// cellState is what a cell's checks compare against: SaaS's devices for the
// cell in the step and both sides' devices before it.
type cellState struct {
	want               []deviceView
	saasPrev, hsPrev   []deviceView
	saasFirst, hsFirst deviceView
	attempts           int
	prevObs            *netmap.NetworkMap
	historyStart       int
	saasAll            []saasDevice
	listed             bool
}

// ephemeralCellChecks compares one cell after a step: its devices, their
// ephemeral flag, node key, address and expiry, its register answers, and the
// observer's view of it and whether the observer lost it.
func ephemeralCellChecks(r *stepReplay, step testcapture.Step, cell, observer string, st cellState) []stepCheck {
	got := func() []deviceView { return r.hsViews(cell) }
	byID := func(views []deviceView) map[string]deviceView {
		out := make(map[string]deviceView, len(views))
		for _, v := range views {
			out[v.id] = v
		}

		return out
	}

	checks := []stepCheck{
		{cell + "/devices", renderDevices(st.want, st.saasFirst), func() string { return renderDevices(got(), st.hsFirst) }},
		{cell + "/ephemeral", renderEphemeral(st.want), func() string { return renderEphemeral(got()) }},
		{cell + "/expiry", renderExpiry(st.want, byID(st.saasPrev)), func() string { return renderExpiry(got(), byID(st.hsPrev)) }},
	}

	if len(st.saasPrev) > 0 {
		checks = append(checks, stepCheck{cell + "/node-key", renderNodeKeys(st.want, byID(st.saasPrev)), func() string {
			return renderNodeKeys(got(), byID(st.hsPrev))
		}})
	}

	if st.listed {
		saasAddrs := map[string]int{}
		for _, d := range st.saasAll {
			saasAddrs[sortedStrings(d.Addresses)]++
		}

		checks = append(checks, stepCheck{cell + "/address", renderAddresses(st.want, st.saasFirst, saasAddrs), func() string {
			hsAddrs := map[string]int{}
			for _, nv := range r.srv.State().ListNodes().All() {
				hsAddrs[sortedStrings(nv.IPsAsString())]++
			}

			return renderAddresses(got(), st.hsFirst, hsAddrs)
		}})
	}

	if saas := step.Register[cell]; len(saas) > 0 {
		checks = append(checks, stepCheck{cell + "/outcome", registerFlags(saas), func() string {
			return registerFlags(r.clients[cell].RegisterAttempts()[st.attempts:])
		}})
	}

	if view, ok := step.Captures[observer]; ok && cell != observer {
		checks = append(checks, stepCheck{cell + "/peer-" + observer, renderPeers(st.want, view.Netmap), func() string {
			return renderPeers(got(), r.clients[observer].Netmap())
		}})
	}

	if frames := step.Frames[observer]; len(frames) > 0 && cell != observer {
		saas := make([]string, 0, len(st.saasPrev))
		for _, v := range st.saasPrev {
			saas = append(saas, saasRemoved(st.prevObs, frames, v.nodeID))
		}

		checks = append(checks, stepCheck{cell + "/removed-" + observer, strings.Join(saas, "; "), func() string {
			history := r.clients[observer].History()[st.historyStart:]

			hs := make([]string, 0, len(st.hsPrev))
			for _, v := range st.hsPrev {
				hs = append(hs, hsRemoved(history, v.nodeID))
			}

			return strings.Join(hs, "; ")
		}})
	}

	return checks
}

// lifecycleCells returns the nodes a step's actions name, in order: the
// node of a client action and the device of an API path.
func lifecycleCells(step testcapture.Step) []string {
	var cells []string

	for _, a := range step.Actions {
		node := a.Node
		if rest, ok := strings.CutPrefix(a.Path, "/device/{device:"); ok {
			node, _, _ = strings.Cut(rest, "}")
		}

		if node != "" && !slices.Contains(cells, node) {
			cells = append(cells, node)
		}
	}

	return cells
}

// saasCellDevices returns SaaS's devices on cell's machine after the step:
// from its last device list, else from its last read of cell's device. It
// reports false when the step read neither.
func saasCellDevices(c *testcapture.Capture, step testcapture.Step, cell string) ([]deviceView, bool) {
	if devices, at, ok := stepDeviceRead(step); ok {
		return saasDeviceViews(c, devices, cell, at), true
	}

	for _, a := range slices.Backward(step.Actions) {
		if a.Kind != "api" || a.Method != http.MethodGet || !strings.HasPrefix(a.Path, "/device/{device:"+cell+"}?") {
			continue
		}

		if a.Status != http.StatusOK {
			return nil, true
		}

		var d saasDevice
		if json.Unmarshal(a.Response, &d) != nil {
			return nil, false
		}

		return []deviceView{saasDeviceView(c, d, step.At.Add(time.Duration(a.OffsetMS)*time.Millisecond))}, true
	}

	return nil, false
}

// renderAddresses says, per device, whether it holds the first device's
// addresses and whether no other device holds them.
func renderAddresses(views []deviceView, first deviceView, holders map[string]int) string {
	return renderEach(views, func(v deviceView) string {
		return fmt.Sprintf("first's %t, unique %t", v.addrs == first.addrs, holders[v.addrs] == 1)
	})
}

// registerFlags renders each register answer the client logged: its
// NodeKeyExpired and MachineAuthorized flags and whether it carried an auth
// URL, or "error" for a refusal and "unanswered" for a request still waiting.
// Requests the client cancelled are left out.
func registerFlags(attempts []testcapture.RegisterAttempt) string {
	out := make([]string, 0, len(attempts))

	for _, a := range attempts {
		switch {
		case strings.Contains(a.Err, "context canceled"):
		case a.Err != "":
			out = append(out, "error")
		case a.MachineAuthorized == nil || a.NodeKeyExpired == nil:
			out = append(out, "unanswered")
		default:
			out = append(out, fmt.Sprintf("expired=%t authorized=%t url=%t",
				*a.NodeKeyExpired, *a.MachineAuthorized, a.AuthURL != ""))
		}
	}

	return strings.Join(out, "; ")
}

// answerChecks compares the status of each admin exchange headscale
// answered in the step, keyed by the action's index.
func (r *stepReplay) answerChecks(step testcapture.Step) []stepCheck {
	checks := make([]stepCheck, 0, len(r.answers))

	for _, i := range slices.Sorted(maps.Keys(r.answers)) {
		got := strconv.Itoa(r.answers[i].status)
		checks = append(checks, stepCheck{strconv.Itoa(i) + "/status", strconv.Itoa(step.Actions[i].Status), func() string {
			return got
		}})
	}

	return checks
}

// keyListChecks compares which of the replay's keys each key listing in the
// step names.
func (r *stepReplay) keyListChecks(t *testing.T, step testcapture.Step) []stepCheck {
	t.Helper()

	labels := map[string]string{}
	for label, id := range r.keyIDs {
		labels[strconv.FormatUint(id, 10)] = label
	}

	listedIn := func(body []byte, label func(string) (string, bool)) string {
		var out struct {
			Keys []struct {
				ID string `json:"id"`
			} `json:"keys"`
		}
		require.NoError(t, json.Unmarshal(body, &out), "%s: key list", step.Name)

		var got []string

		for _, k := range out.Keys {
			if l, ok := label(k.ID); ok {
				got = append(got, l)
			}
		}

		return sortedStrings(got)
	}

	var checks []stepCheck

	for i, a := range step.Actions {
		ans, ok := r.answers[i]
		if !ok || a.Method != http.MethodGet || !strings.HasPrefix(a.Path, "/tailnet/-/keys") || strings.Contains(a.Path, "{key:") {
			continue
		}

		want := listedIn(a.Response, func(id string) (string, bool) {
			l, ok := strings.CutPrefix(id, "{key:")
			l = strings.TrimSuffix(l, "}")
			_, minted := r.keyIDs[l]

			return l, ok && minted
		})

		got := ""
		if ans.status == http.StatusOK {
			got = listedIn(ans.body, func(id string) (string, bool) { l, ok := labels[id]; return l, ok })
		}

		checks = append(checks, stepCheck{strconv.Itoa(i) + "/keys", want, func() string { return got }})
	}

	return checks
}
