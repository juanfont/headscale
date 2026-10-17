// This file replays multi-step lifecycle captures from Tailscale SaaS and
// compares each step's outcome with what SaaS showed.
//
// Test data source: testdata/steps/{route-approval,owner-routes}.hujson,
// loaded by name. owner-routes is consumed by TestReauthCompat.
// Source format:    github.com/juanfont/headscale/hscontrol/types/testcapture

package servertest_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/types/testcapture"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/types/netmap"
)

// lifecycleSkipReasons lists checks where headscale differs from SaaS, keyed
// <test_id>/<step>/<check>. A listed check that matches fails, so a fix must
// delete its entry.
var lifecycleSkipReasons = map[string]string{
	"route-approval/b6/enabled":     approvalOnHostinfo,
	"route-approval/b6/served":      approvalOnHostinfo,
	"route-approval/b6/self-routes": approvalOnHostinfo,

	"route-approval/b7/enabled":     approvalOnPolicy,
	"route-approval/b7/served":      approvalOnPolicy,
	"route-approval/b7/self-routes": approvalOnPolicy,
	"route-approval/b8/enabled":     approvalOnPolicy,
	"route-approval/b8/served":      approvalOnPolicy,
	"route-approval/b8/self-routes": approvalOnPolicy,

	"route-approval/b9/enabled":     approvalOnSameKeyReauth,
	"route-approval/b9/served":      approvalOnSameKeyReauth,
	"route-approval/b9/self-routes": approvalOnSameKeyReauth,

	"route-approval/r1/served": loggedOutRouterUnserved,
}

// SaaS runs auto-approval when a router's announced routes change and on a
// re-auth that rotates its node key, over every announced route.
const (
	approvalOnHostinfo      = "APPROVAL_ON_HOSTINFO: headscale auto-approves when a router with no approved routes sends a Hostinfo change that keeps its routes; SaaS does not"
	approvalOnPolicy        = "APPROVAL_ON_POLICY: headscale auto-approves announced routes when a policy is set; SaaS waits for the router's next route change or key rotation"
	approvalOnSameKeyReauth = "APPROVAL_ON_SAME_KEY_REAUTH: headscale auto-approves on a re-auth that keeps the node key; SaaS does not"
	loggedOutRouterUnserved = "LOGGED_OUT_ROUTER_UNSERVED: headscale stops serving a logged-out router's routes; SaaS keeps them on the expired, offline peer"
)

// Used by reauthSkipReasons.
const (
	expiredRouterUnserved = "EXPIRED_ROUTER_UNSERVED: headscale stops serving an expired router's routes; SaaS keeps them in the peer's AllowedIPs and PrimaryRoutes"
	expiredPeerOffline    = "EXPIRED_PEER_OFFLINE: headscale shows an expired peer offline while it is connected; SaaS shows it online"
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
//   - removed: whether the observer lost the router during the step, when
//     SaaS recorded the observer's map stream.
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

			hsRoutes := func() (deviceRoutes, bool) {
				nodes := r.machineNodes(router)
				if len(nodes) != 1 {
					return deviceRoutes{}, false
				}

				status, body := r.call(t, http.MethodGet, "/api/v2/device/"+nodes[0].StringID()+"/routes", nil)
				require.Equal(t, http.StatusOK, status, "%s", body)

				var out deviceRoutes
				require.NoError(t, json.Unmarshal(body, &out))

				return out, true
			}

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

			if frames := step.Frames[observer]; len(frames) > 0 {
				checks = append(checks, stepCheck{"removed", saasRemoved(prevSaaS, frames, saasRouterID), func() string {
					nodes := r.machineNodes(router)
					if len(nodes) != 1 {
						return fmt.Sprintf("devices %d", len(nodes))
					}

					return hsRemoved(r.clients[observer].History()[historyStart:], nodes[0].ID().NodeID())
				}})
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

// saasDevice is the part of a SaaS device-list entry the checks read.
// Keys and IDs are the capture's labels.
type saasDevice struct {
	ID                string   `json:"id"`
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
