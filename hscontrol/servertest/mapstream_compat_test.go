// This file replays map stream captures from Tailscale SaaS: what each node
// is sent when a device is retagged, when a running peer changes its DERP
// home, disco key, hostname or port, when a node goes down and up around
// policy pushes, and which Hostinfo fields peers and the node itself get;
// what a node hears of nodes it cannot see; what a router's peers hear of
// routes it announces but has no approval for; what every node is sent as
// one policy is compiled again for node changes and a group edit; and what
// every node is sent when an admin role change alters what the policy
// resolves.
//
// Test data source: testdata/steps/{map-delivery,hidden-peers,route-announce,
// policy-generation,user-role}.hujson, loaded by name. The disco rotation of
// map-delivery also pins a row of TestBuildMapRequestChangeResponse in
// ../state; policy-generation is also read by TestPolicySequenceCompat in
// ../policy/v2; user-role's setup step is also read by
// TestAPIV2TaggedDeviceUserCompat in apiv2_devices_test.go.
// Source format:    github.com/juanfont/headscale/hscontrol/types/testcapture

package servertest_test

import (
	"context"
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
	"tailscale.com/tailcfg"
	"tailscale.com/types/netmap"
)

// mapStreamSkipReasons lists checks where headscale differs from SaaS, keyed
// <test_id>/<step>/<node>/<check>. A listed check that matches fails, so a
// fix must delete its entry.
var mapStreamSkipReasons = map[string]string{
	"map-delivery/S1.1/appc/frames":   policyResponseToEveryNode,
	"map-delivery/S1.1/router/frames": policyResponseToEveryNode,
	"map-delivery/S1.1/sshd/frames":   policyResponseToEveryNode,
	"map-delivery/S1.2/appc/frames":   policyResponseToEveryNode,
	"map-delivery/S1.2/router/frames": policyResponseToEveryNode,
	"map-delivery/S1.2/sshd/frames":   policyResponseToEveryNode,
	"map-delivery/S1.3/appc/frames":   policyResponseToEveryNode,
	"map-delivery/S1.3/router/frames": policyResponseToEveryNode,
	"map-delivery/S1.3/sshd/frames":   policyResponseToEveryNode,
	"map-delivery/S1.4/appc/frames":   policyResponseToEveryNode,
	"map-delivery/S1.4/router/frames": policyResponseToEveryNode,
	"map-delivery/S1.4/sshd/frames":   policyResponseToEveryNode,

	"map-delivery/S3.5-remove/db1/frames":  policyResponseToEveryNode,
	"map-delivery/S3.5-restore/db1/frames": policyResponseToEveryNode,

	"map-delivery/S2.5/laptop/endpoints-gap-bystander": restartEndpointsKept,
	"map-delivery/S2.5/laptop/endpoints-gap-svc":       restartEndpointsKept,

	"map-delivery/S3.6/bystander/peers": sameUserPeers,
	"map-delivery/S3.6/laptop/peers":    sameUserPeers,

	"hidden-peers/S2/witness/presence":   policyResponseToEveryNode,
	"hidden-peers/S8/observer/presence":  policyResponseToEveryNode,
	"hidden-peers/S9/observer/presence":  policyResponseToEveryNode,
	"hidden-peers/S10/observer/presence": policyResponseToEveryNode,
	"hidden-peers/S13/observer/presence": policyResponseToEveryNode,
	"route-announce/RA3/srv/presence":    policyResponseToEveryNode,
	"route-announce/RA3/wit/presence":    policyResponseToEveryNode,
	"route-announce/RA4/srv/presence":    policyResponseToEveryNode,
	"route-announce/RA4/wit/presence":    policyResponseToEveryNode,
	"route-announce/RA6/rtr/presence":    policyResponseToEveryNode,
	"route-announce/RA6/srv/presence":    policyResponseToEveryNode,
	"route-announce/RA6/wit/presence":    policyResponseToEveryNode,
	"route-announce/RA9/rtr/presence":    policyResponseToEveryNode,
	"route-announce/RA9/srv/presence":    policyResponseToEveryNode,
	"route-announce/RA9/wit/presence":    policyResponseToEveryNode,

	"route-announce/RA2/observer/presence":  announcePeerResent,
	"route-announce/RA2/srv/presence":       announcePeerResent,
	"route-announce/RA2/witness/presence":   announcePeerResent,
	"route-announce/RA5/observer/presence":  announcePeerResent,
	"route-announce/RA5/witness/presence":   announcePeerResent,
	"route-announce/RA8/observer/presence":  announcePeerResent,
	"route-announce/RA8/srv/presence":       announcePeerResent,
	"route-announce/RA8/witness/presence":   announcePeerResent,
	"route-announce/RA11/observer/presence": announcePeerResent,
	"route-announce/RA11/srv/presence":      announcePeerResent,
	"route-announce/RA11/witness/presence":  announcePeerResent,

	"policy-generation/G2/thor-1/peers":       sameUserPeers,
	"policy-generation/G2/thor-2/peers":       sameUserPeers,
	"policy-generation/G3/thor-1/peers":       sameUserPeers,
	"policy-generation/G3/thor-2/peers":       sameUserPeers,
	"policy-generation/G4/thor-1/peers":       sameUserPeers,
	"policy-generation/G4/thor-2/peers":       sameUserPeers,
	"policy-generation/G2/thor-1/peer-owners": sameUserPeers,
	"policy-generation/G2/thor-2/peer-owners": sameUserPeers,
	"policy-generation/G3/thor-1/peer-owners": sameUserPeers,
	"policy-generation/G3/thor-2/peer-owners": sameUserPeers,
	"policy-generation/G4/thor-1/peer-owners": sameUserPeers,
	"policy-generation/G4/thor-2/peer-owners": sameUserPeers,

	"policy-generation/G7/rt-b/filter":     deletedDeviceInRules,
	"policy-generation/G7/rt-plain/filter": deletedDeviceInRules,
	"policy-generation/G7/srv/filter":      deletedDeviceInRules,
	"policy-generation/G7/srv/ssh":         deletedDeviceInRules,

	"user-role/S1/own-a/frames": userChangePushed,
	"user-role/S1/own-b/frames": userChangePushed,
	"user-role/S1/own-b/peers":  userChangePushed,
	"user-role/S1/tag-a/frames": userChangePushed,
	"user-role/S1/tag-a/peers":  userChangePushed,
	"user-role/S1/tag-a/filter": userChangePushed,
	"user-role/S1/tag-b/frames": userChangePushed,
	"user-role/S1/tag-b/peers":  userChangePushed,
	"user-role/S1/tag-b/filter": userChangePushed,

	"user-role/S1-reconnect/own-b/peers":  userChangePushed,
	"user-role/S1-reconnect/tag-b/peers":  userChangePushed,
	"user-role/S1-reconnect/tag-b/filter": userChangePushed,

	"user-role/S2/own-a/frames": userChangePushed,
	"user-role/S2/own-b/frames": userChangePushed,
	"user-role/S2/tag-a/frames": userChangePushed,
	"user-role/S2/tag-a/peers":  userChangePushed,
	"user-role/S2/tag-a/filter": userChangePushed,
	"user-role/S2/tag-b/frames": userChangePushed,
}

const (
	policyResponseToEveryNode = "POLICY_RESPONSE_TO_EVERY_NODE: headscale sends every connected node a policy response when the policy, a node's tags or approved routes, or the set of nodes change; SaaS sends only the nodes whose peers or filter change"
	restartEndpointsKept      = "RESTART_ENDPOINTS_KEPT: headscale keeps a restarted node's last endpoints at its peers until it reports new ones; SaaS sends peers the node without endpoints until then"
	announcePeerResent        = "ANNOUNCE_PEER_RESENT: headscale sends a router's peers its entry again whenever its announced routes change; SaaS sends the unchanged entry only after some announcements"
	deletedDeviceInRules      = "DELETED_DEVICE_IN_RULES: SaaS keeps a deleted device's addresses in other nodes' filter and SSH rules until the next policy change; headscale drops them with the device"
	userChangePushed          = "USER_CHANGE_PUSHED: headscale sends every connected node a policy response as soon as a user change alters what the policy resolves; SaaS sends an admin role change to no open stream, so a node gets it only on its next new stream"
)

// TestMapDeliveryCompat replays a device retagged through the API, a running
// peer that picks new DERP homes, rotates its disco key, renames itself and
// restarts on another port, down and up gaps of a node and a router, a rule
// removed and restored around a reconnect, and a policy with no rules. After
// each scenario step it compares, per captured node, its peers, packet
// filter, tags and own endpoints; per viewer, how it sees the step's subject;
// and, per node, whether it was sent anything at all.
func TestMapDeliveryCompat(t *testing.T) {
	t.Parallel()

	t.Run("map-delivery", func(t *testing.T) {
		t.Parallel()

		replayMapDelivery(t, "map-delivery", "", deliveryChecks, func(key string) bool {
			return !strings.Contains(key, "hostinfo")
		})
	})
}

// TestPeerHostinfoCompat replays the same capture up to its quiet step, with
// sshd running Tailscale SSH and appc advertising an app connector, and
// compares the Hostinfo fields and values each captured node gets for its
// peers and for itself.
func TestPeerHostinfoCompat(t *testing.T) {
	t.Parallel()

	t.Run("map-delivery", func(t *testing.T) {
		t.Parallel()

		replayMapDelivery(t, "map-delivery", hostinfoStep, hostinfoChecks, func(key string) bool {
			return strings.Contains(key, "hostinfo")
		})
	})
}

// hostinfoStep is the quiet step whose captures hold the Hostinfo snapshots.
const hostinfoStep = "S2.0"

// settledGap is how far apart two actions must be sent for SaaS to have
// handled them one after the other rather than in one batch.
const settledGap = time.Second

// replayMapDelivery replays capture id step by step, through the step named
// last (every step when empty), and holds the checks of each scenario step
// against [mapStreamSkipReasons]. Setup steps (policy, keys, joins, the steady
// wait) are replayed, not compared: their join bursts and SaaS's own stream
// restarts are not what the scenarios ask about. owns picks the skip entries
// this caller's checks evaluate.
func replayMapDelivery(
	t *testing.T,
	id, last string,
	checks func(d *deliveryStep) []stepCheck,
	owns func(key string) bool,
) {
	t.Helper()

	c := readStepCapture(t, id)
	r := newStepReplay(t, c)
	evaluated := map[string]bool{}

	saasLast := map[string]*netmap.NetworkMap{}
	for alias, n := range c.Captures {
		saasLast[alias] = n.Netmap
	}

	for _, step := range c.Steps {
		require.Equal(t, "observed", step.Result, "%s: the replay follows every step", step.Name)

		r.settle(t)

		d := &deliveryStep{
			r: r, step: step, caps: step.Captures, saasBefore: maps.Clone(saasLast),
			hsBefore: map[string]*netmap.NetworkMap{}, updates: map[string]int{},
		}
		// The start check has no captures of its own: it is the baseline.
		if len(d.caps) == 0 {
			d.caps = c.Captures
		}

		for alias, cl := range r.clients {
			d.hsBefore[alias] = cl.Netmap()
			d.updates[alias] = cl.UpdateCount()
		}

		r.replayDelivery(t, step)

		if strings.HasPrefix(step.Name, "S") {
			cs := checks(d)
			prefix := id + "/" + step.Name + "/"

			if len(cs) > 0 {
				t.Run(step.Name, func(t *testing.T) {
					holdChecks(t, mapStreamSkipReasons, prefix, cs, evaluated)
				})
			}
		}

		for alias, n := range step.Captures {
			saasLast[alias] = n.Netmap
		}

		if step.Name == last {
			break
		}
	}

	for k := range mapStreamSkipReasons {
		if strings.HasPrefix(k, id+"/") && owns(k) && !evaluated[k] {
			t.Errorf("skip entry %q names no check", k)
		}
	}
}

// replayDelivery applies the step's actions one at a time. What a node
// reported is replayed from its captured map requests, so the CLI lever SaaS
// was driven with does not decide what headscale sees. Headscale settles
// where SaaS waited or sent the next action a while later; actions sent
// together stay together.
func (r *stepReplay) replayDelivery(t *testing.T, step testcapture.Step) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	reports := stepReports(t, step)

	for i, a := range step.Actions {
		switch a.Kind {
		case "wait":
			r.settle(t)
		case "cli", "restart":
			r.deliveryDaemon(ctx, t, step, a)
		default:
			one := step
			one.Actions = []testcapture.Action{a}
			require.Empty(t, r.apply(t, one), "%s: every login succeeds", step.Name)
		}

		if reqs, ok := reports[i]; ok {
			r.report(ctx, t, a.Node, reqs)
		}

		// A wait on either side settles anyway.
		if i+1 < len(step.Actions) {
			next := step.Actions[i+1]
			if a.Kind != "wait" && next.Kind != "wait" &&
				time.Duration(next.OffsetMS-a.OffsetMS)*time.Millisecond >= settledGap {
				r.settle(t)
			}
		}
	}
}

// deliveryDaemon replays what a node's tailscaled did around its reports: a
// restart, a disco key rotation, or its stream going down and coming back.
func (r *stepReplay) deliveryDaemon(ctx context.Context, t *testing.T, step testcapture.Step, a testcapture.Action) {
	t.Helper()

	cl := r.clients[a.Node]

	switch args := strings.Join(a.Args, " "); {
	case a.Kind == "restart":
		// The daemon starts again on the Hostinfo of its first request, with
		// no endpoints or DERP home until it reports them.
		var hi *tailcfg.Hostinfo

		for _, f := range step.Frames[a.Node] {
			if f.Request != nil && f.Request.Hostinfo != nil {
				hi = f.Request.Hostinfo.Clone()

				break
			}
		}

		require.NotNil(t, hi, "%s: no request from restarted %s", step.Name, a.Node)
		require.NoError(t, cl.Restart(ctx, hi), "%s: restart", step.Name)

	case args == "debug rotate-disco-key":
		require.NoError(t, cl.RotateDisco(ctx), "%s: disco rotation", step.Name)

		// SaaS got the node's next report after the new stream's first map.
		// Sent sooner, it can reach the server ahead of the stream request,
		// whose older Hostinfo then overwrites it.
		require.Eventually(t, func() bool {
			_, maps := cl.Stream()

			return maps > 0
		}, 10*time.Second, 10*time.Millisecond, "%s: new stream answered", step.Name)

	case args == "debug pick-new-derp", args == "set --ssh", args == "set --advertise-connector",
		strings.HasPrefix(args, "set --hostname="):
		// Only what the node reports changes.

	default:
		r.daemon(ctx, t, step.Name, a)
	}
}

// stepReports hands each node's captured map requests, other than stream
// starts, to the actions after which it reported, by action index: a node's
// only reporting action takes them all, and several take one each.
func stepReports(t *testing.T, step testcapture.Step) map[int][]*tailcfg.MapRequest {
	t.Helper()

	actions := map[string][]int{}

	for i, a := range step.Actions {
		switch {
		case a.Kind == "join", a.Kind == "restart", a.Kind == "cli" && strings.Join(a.Args, " ") != "down":
			actions[a.Node] = append(actions[a.Node], i)
		}
	}

	out := map[int][]*tailcfg.MapRequest{}

	for node, idx := range actions {
		var reqs []*tailcfg.MapRequest

		for _, f := range step.Frames[node] {
			if f.Request != nil && !f.Request.Stream {
				reqs = append(reqs, f.Request)
			}
		}

		switch {
		case len(idx) == 1:
			out[idx[0]] = reqs
		case len(idx) == len(reqs):
			for k, i := range idx {
				out[i] = reqs[k : k+1]
			}
		default:
			t.Fatalf("%s: %d reporting actions on %s, %d requests", step.Name, len(idx), node, len(reqs))
		}
	}

	return out
}

// report sends what the node told SaaS, request by request: its Hostinfo, and
// its DERP home and endpoints where the request carried them. A request that
// changes nothing is not sent.
func (r *stepReplay) report(ctx context.Context, t *testing.T, alias string, reqs []*tailcfg.MapRequest) {
	t.Helper()

	d := r.clients[alias].Direct()

	for _, req := range reqs {
		changed := false

		if hi := req.Hostinfo; hi != nil {
			changed = d.SetHostinfo(hi)
			if hi.NetInfo != nil {
				changed = d.SetNetInfo(hi.NetInfo) || changed
			}
		}

		if len(req.Endpoints) > 0 {
			eps := make([]tailcfg.Endpoint, len(req.Endpoints))
			for i, ap := range req.Endpoints {
				eps[i].Addr = ap
				if i < len(req.EndpointTypes) {
					eps[i].Type = req.EndpointTypes[i]
				}
			}

			changed = d.SetEndpoints(eps) || changed
		}

		if changed {
			require.NoError(t, d.SendUpdate(ctx), "%s: report", alias)
		}
	}
}

// settle waits until no client has been sent a map response for a while, so
// a batch in flight lands before the next action.
func (r *stepReplay) settle(t *testing.T) {
	t.Helper()

	const quiet = 300 * time.Millisecond

	counts := func() map[string]int {
		out := make(map[string]int, len(r.clients))
		for alias, cl := range r.clients {
			out[alias] = cl.Frames()
		}

		return out
	}

	last, since := counts(), time.Now()

	tick := time.NewTicker(25 * time.Millisecond)
	defer tick.Stop()

	for deadline := time.Now().Add(15 * time.Second); time.Now().Before(deadline); <-tick.C {
		now := counts()
		if !maps.Equal(now, last) {
			last, since = now, time.Now()

			continue
		}

		if time.Since(since) >= quiet {
			return
		}
	}

	t.Fatalf("map streams did not settle: %v", last)
}

// deliveryStep is one replayed step, what SaaS showed after it and what both
// sides showed before it.
type deliveryStep struct {
	r    *stepReplay
	step testcapture.Step

	// caps is SaaS's end state; saasBefore each node's last capture before
	// the step.
	caps       map[string]testcapture.Node
	saasBefore map[string]*netmap.NetworkMap

	// hsBefore and updates are each client's netmap and update count, which
	// is its history's length, when the step began.
	hsBefore map[string]*netmap.NetworkMap
	updates  map[string]int
}

// deliveryChecks compares, per captured node, its peers, filter, tags and
// own endpoints; per captured viewer, how it sees each node the step acted
// on; and, per node, whether it was sent anything.
func deliveryChecks(d *deliveryStep) []stepCheck {
	r := d.r
	saasNames := topologyAddrNames(r.c)

	var checks []stepCheck

	for _, x := range slices.Sorted(maps.Keys(r.c.NodeIDs)) {
		cl, ok := r.clients[x]
		if !ok {
			continue
		}

		// A client without delta handling rebuilds its netmap, so its update
		// count moves, on every map response but a keep-alive.
		checks = append(checks, stepCheck{x + "/frames", saasDelivered(d.step.Frames[x]), func() string {
			if cl.UpdateCount() > d.updates[x] {
				return "frame"
			}

			return "silent"
		}})
	}

	captured := slices.Sorted(maps.Keys(d.caps))

	for _, x := range captured {
		saas, cl := d.caps[x].Netmap, r.clients[x]
		if saas == nil || cl == nil {
			continue
		}

		checks = append(checks,
			stepCheck{x + "/peers", peerAliases(saas, r.saasAlias), func() string { return peerAliases(cl.Netmap(), r.hsAlias) }},
			stepCheck{x + "/filter", renderMatches(saas, saasNames), func() string { return renderMatches(cl.Netmap(), r.addrNames()) }},
			stepCheck{x + "/tags", selfTags(saas), func() string { return selfTags(cl.Netmap()) }},
			stepCheck{x + "/self-endpoints", selfEndpoints(saas), func() string { return selfEndpoints(cl.Netmap()) }},
		)
	}

	for _, x := range stepSubjects(d.step) {
		for _, v := range captured {
			if v != x && d.caps[v].Netmap != nil && r.clients[v] != nil {
				checks = append(checks, d.subjectChecks(x, v)...)
			}
		}
	}

	return checks
}

// subjectChecks compares how v sees x: online, its DERP home, endpoints,
// name, routes, whether its disco key changed during the step and whether
// its endpoints were cleared on the way.
func (d *deliveryStep) subjectChecks(x, v string) []stepCheck {
	r := d.r
	saasID := r.c.NodeIDs[x]
	saasPeer, saasMissing := peerByID(d.caps[v].Netmap, saasID)

	hsID := func() (tailcfg.NodeID, string) {
		nodes := r.machineNodes(x)
		if len(nodes) != 1 {
			return 0, fmt.Sprintf("devices %d", len(nodes))
		}

		return nodes[0].ID().NodeID(), ""
	}
	hsPeer := func() (tailcfg.NodeView, string) {
		id, missing := hsID()
		if missing != "" {
			return tailcfg.NodeView{}, missing
		}

		return peerByID(r.clients[v].Netmap(), id)
	}

	hsBefore := ""
	if id, missing := hsID(); missing == "" {
		hsBefore = peerDisco(d.hsBefore[v], id)
	}

	return []stepCheck{
		{x + "/online-" + v, peerOnline(saasPeer, saasMissing), func() string { return peerOnline(hsPeer()) }},
		{x + "/derp-" + v, peerDERP(saasPeer, saasMissing), func() string { return peerDERP(hsPeer()) }},
		{x + "/endpoints-" + v, peerEndpoints(saasPeer, saasMissing), func() string { return peerEndpoints(hsPeer()) }},
		{x + "/name-" + v, peerLabel(saasPeer, saasMissing), func() string { return peerLabel(hsPeer()) }},
		{x + "/routes-" + v, servedRoutes(saasPeer, saasMissing), func() string { return servedRoutes(hsPeer()) }},
		{
			x + "/disco-" + v,
			discoState(peerDisco(d.saasBefore[v], saasID), peerDisco(d.caps[v].Netmap, saasID)),
			func() string {
				p, missing := hsPeer()
				if missing != "" {
					return discoState(hsBefore, missing)
				}

				return discoState(hsBefore, p.DiscoKey().String())
			},
		},
		{x + "/endpoints-gap-" + v, saasEndpointsCleared(d.step.Frames[v], saasID), func() string {
			id, missing := hsID()
			if missing != "" {
				return missing
			}

			return hsEndpointsCleared(r.clients[v].History()[d.updates[v]:], id)
		}},
	}
}

// topologyAddrNames names each SaaS address in c's topology by alias, so a
// rule naming a device that has since left still reads by name.
func topologyAddrNames(c *testcapture.Capture) map[netip.Addr]string {
	out := map[netip.Addr]string{}

	for alias, n := range c.Topology.Nodes {
		for _, s := range []string{n.IPv4, n.IPv6} {
			addr, err := netip.ParseAddr(s)
			if err == nil {
				out[addr] = alias
			}
		}
	}

	return out
}

// stepSubjects names the nodes the step acted on, by action or device path.
func stepSubjects(step testcapture.Step) []string {
	set := map[string]bool{}

	for _, a := range step.Actions {
		switch {
		case a.Node != "":
			set[a.Node] = true
		case strings.HasPrefix(a.Path, "/device/{device:"):
			alias, _, _ := strings.Cut(strings.TrimPrefix(a.Path, "/device/{device:"), "}")
			set[alias] = true
		}
	}

	return slices.Sorted(maps.Keys(set))
}

// saasDelivered says whether a node's stream carried any map response but a
// keep-alive during the step.
func saasDelivered(frames []testcapture.Frame) string {
	for _, f := range frames {
		if f.Response != nil && !f.Response.KeepAlive {
			return "frame"
		}
	}

	return "silent"
}

// saasEndpointsCleared says whether a frame left the viewer holding peer id
// without endpoints: a whole node with none, or a patch that empties them.
func saasEndpointsCleared(frames []testcapture.Frame, id tailcfg.NodeID) string {
	for _, f := range frames {
		resp := f.Response
		if resp == nil {
			continue
		}

		for _, n := range slices.Concat(resp.Peers, resp.PeersChanged) {
			if n.ID == id && len(n.Endpoints) == 0 {
				return "cleared"
			}
		}

		for i, p := range resp.PeersChangedPatch {
			if p.NodeID == id && f.Empty[fmt.Sprintf("PeersChangedPatch[%d].Endpoints", i)] != "" {
				return "cleared"
			}
		}
	}

	return "kept"
}

// hsEndpointsCleared says whether any of the netmaps held peer id without
// endpoints.
func hsEndpointsCleared(history []*netmap.NetworkMap, id tailcfg.NodeID) string {
	for _, nm := range history {
		if p, missing := peerByID(nm, id); missing == "" && p.Endpoints().Len() == 0 {
			return "cleared"
		}
	}

	return "kept"
}

func peerDERP(p tailcfg.NodeView, missing string) string {
	if missing != "" {
		return missing
	}

	return strconv.FormatInt(int64(p.HomeDERP()), 10)
}

func peerEndpoints(p tailcfg.NodeView, missing string) string {
	if missing != "" {
		return missing
	}

	return addrPorts(p)
}

// peerLabel is the first label of the peer's MagicDNS name and its hostname.
func peerLabel(p tailcfg.NodeView, missing string) string {
	if missing != "" {
		return missing
	}

	return peerName(p, "") + " " + p.Hostinfo().Hostname()
}

func selfTags(nm *netmap.NetworkMap) string {
	if nm == nil || !nm.SelfNode.Valid() {
		return "no netmap"
	}

	return sortedStrings(nm.SelfNode.Tags().AsSlice())
}

func selfEndpoints(nm *netmap.NetworkMap) string {
	if nm == nil || !nm.SelfNode.Valid() {
		return "no netmap"
	}

	return addrPorts(nm.SelfNode)
}

func addrPorts(n tailcfg.NodeView) string {
	out := make([]string, 0, n.Endpoints().Len())
	for _, ap := range n.Endpoints().All() {
		out = append(out, ap.String())
	}

	return sortedStrings(out)
}

// renderMatches lists nm's packet filter as "sources => ports to
// destination" lines, devices named by names.
func renderMatches(nm *netmap.NetworkMap, names map[netip.Addr]string) string {
	if nm == nil {
		return "no netmap"
	}

	var out []string

	for _, m := range nm.PacketFilter {
		for _, d := range m.Dsts {
			dst := d.Net.String()
			if name, ok := names[d.Net.Addr()]; ok && d.Net.IsSingleIP() {
				dst = name
			}

			out = append(out, filterLine(m.Srcs, names, d.Ports.First, d.Ports.Last)+" to "+dst)
		}
	}

	return filterLines(out)
}

// hostinfoChecks compares, at the quiet step, each captured node's Hostinfo
// for itself and for each peer: which fields it holds, and the values of the
// fields SaaS sent.
func hostinfoChecks(d *deliveryStep) []stepCheck {
	if d.step.Name != hostinfoStep {
		return nil
	}

	r := d.r

	var checks []stepCheck

	for _, v := range slices.Sorted(maps.Keys(d.caps)) {
		saas, cl := d.caps[v].Netmap, r.clients[v]
		if saas == nil || cl == nil {
			continue
		}

		saasSelf := hostinfoFields(saas.SelfNode.Hostinfo())
		saasPeers := peerHostinfos(saas, r.saasAlias)

		checks = append(checks,
			stepCheck{v + "/self-hostinfo-keys", fieldNames(saasSelf), func() string {
				nm := cl.Netmap()
				if nm == nil {
					return "no netmap"
				}

				return fieldNames(hostinfoFields(nm.SelfNode.Hostinfo()))
			}},
			stepCheck{v + "/self-hostinfo", fieldValues(saasSelf, saasSelf), func() string {
				nm := cl.Netmap()
				if nm == nil {
					return "no netmap"
				}

				return fieldValues(hostinfoFields(nm.SelfNode.Hostinfo()), saasSelf)
			}},
			stepCheck{v + "/peer-hostinfo-keys", renderPeerFields(saasPeers, nil), func() string {
				return renderPeerFields(peerHostinfos(cl.Netmap(), r.hsAlias), nil)
			}},
			stepCheck{v + "/peer-hostinfo", renderPeerFields(saasPeers, saasPeers), func() string {
				return renderPeerFields(peerHostinfos(cl.Netmap(), r.hsAlias), saasPeers)
			}},
		)
	}

	return checks
}

// hostinfoFields is hi's JSON object, field by field.
func hostinfoFields(hi tailcfg.HostinfoView) map[string]json.RawMessage {
	out := map[string]json.RawMessage{}
	if !hi.Valid() {
		return out
	}

	b, err := json.Marshal(hi)
	if err == nil {
		_ = json.Unmarshal(b, &out)
	}

	return out
}

// peerHostinfos holds the Hostinfo fields of each peer alias names.
func peerHostinfos(nm *netmap.NetworkMap, alias func(tailcfg.NodeID) (string, bool)) map[string]map[string]json.RawMessage {
	out := map[string]map[string]json.RawMessage{}
	if nm == nil {
		return out
	}

	for _, p := range nm.Peers {
		if name, ok := alias(p.ID()); ok {
			out[name] = hostinfoFields(p.Hostinfo())
		}
	}

	return out
}

func fieldNames(fields map[string]json.RawMessage) string {
	return strings.Join(slices.Sorted(maps.Keys(fields)), ",")
}

// fieldValues renders the fields named in want, as fields holds them.
func fieldValues(fields, want map[string]json.RawMessage) string {
	out := make([]string, 0, len(want))

	for _, k := range slices.Sorted(maps.Keys(want)) {
		v, ok := fields[k]
		if !ok {
			v = json.RawMessage("absent")
		}

		out = append(out, k+"="+string(v))
	}

	return strings.Join(out, " ")
}

// renderPeerFields lists each peer's field names or, with want, the values
// of the fields want holds for it.
func renderPeerFields(peers, want map[string]map[string]json.RawMessage) string {
	out := make([]string, 0, len(peers))

	for _, name := range slices.Sorted(maps.Keys(peers)) {
		line := fieldNames(peers[name])
		if want != nil {
			line = fieldValues(peers[name], want[name])
		}

		out = append(out, name+": "+line)
	}

	return strings.Join(out, "\n")
}

// TestHiddenPeerEventsCompat replays two users' nodes under a policy that
// lets each reach only its own: nodes the observer cannot see go down, come
// up, rename, join, are deleted and log out, then a one-way rule shows them
// to it and is taken back. After each step it compares, per captured node,
// whether it was sent anything, which nodes it was told were removed, and
// its peers.
func TestHiddenPeerEventsCompat(t *testing.T) {
	t.Parallel()

	t.Run("hidden-peers", func(t *testing.T) {
		t.Parallel()

		replayVisibility(t, "hidden-peers")
	})
}

// TestRouteAnnouncementCompat replays a tagged router that renames itself
// and announces and drops a route no auto-approver covers, which the admin
// approves and revokes once, under a global, an autogroup:self and a via
// policy. After each step it compares what [TestHiddenPeerEventsCompat]
// does, plus the routes API, the router's own routes and how each captured
// node is served by it.
func TestRouteAnnouncementCompat(t *testing.T) {
	t.Parallel()

	t.Run("route-announce", func(t *testing.T) {
		t.Parallel()

		replayVisibility(t, "route-announce")
	})
}

func TestMapStreamSkipEntriesNameCaptures(t *testing.T) {
	t.Parallel()

	requireSkipCaptures(t, mapStreamSkipReasons, "map-delivery", "hidden-peers", "route-announce", "policy-generation", userRoleID)
}

// visibilityMark is what a client had been sent when a step began.
type visibilityMark struct {
	frames, removed int

	// history indexes the client's last netmap before the step, so a peer
	// held then and missing from the step's first netmap counts as removed.
	history int
}

// replayVisibility replays capture id step by step, each action landing
// before the next, and holds each step's [visibilityChecks] against
// [mapStreamSkipReasons].
func replayVisibility(t *testing.T, id string) {
	t.Helper()

	c := readStepCapture(t, id)
	r := newStepReplay(t, c)
	r.deltaUpdates = true
	evaluated := map[string]bool{}

	// Nodes kept from an earlier capture joined under the policy the tailnet
	// held when this one began, before the step's own push.
	r.setPolicy(t, "setup", c.Input.FullPolicy)

	for _, step := range c.Steps {
		require.Equal(t, "observed", step.Result, "%s: the replay follows every step", step.Name)

		r.settle(t)

		before := make(map[string]visibilityMark, len(r.clients))
		for alias, cl := range r.clients {
			before[alias] = visibilityMark{
				frames:  cl.Frames(),
				removed: len(cl.DeltaRemovedPeers()),
				history: max(cl.UpdateCount()-1, 0),
			}
		}

		for _, a := range step.Actions {
			one := step
			one.Actions = []testcapture.Action{a}
			require.Empty(t, r.apply(t, one), "%s: every login succeeds", step.Name)
			r.waitSession(t, step.Name, a)
		}

		t.Run(step.Name, func(t *testing.T) {
			holdChecks(t, mapStreamSkipReasons, id+"/"+step.Name+"/", visibilityChecks(t, r, step, before), evaluated)
		})
	}

	for k := range mapStreamSkipReasons {
		if strings.HasPrefix(k, id+"/") && !evaluated[k] {
			t.Errorf("skip entry %q names no check", k)
		}
	}
}

// visibilityChecks compares, per node SaaS captured in the step (the nodes
// whose streams it followed), whether it was sent anything, which nodes it
// was told were removed and its peers.
// After a step that read a router's routes, it also compares the routes
// API, the router's own routes and how each captured node is served by it.
func visibilityChecks(t *testing.T, r *stepReplay, step testcapture.Step, before map[string]visibilityMark) []stepCheck {
	t.Helper()

	subjects := stepSubjects(step)
	captured := slices.Sorted(maps.Keys(step.Captures))

	var checks []stepCheck

	for _, x := range captured {
		saas, cl := step.Captures[x].Netmap, r.clients[x]
		if saas == nil || cl == nil {
			continue
		}

		mark := before[x]

		checks = append(checks,
			stepCheck{x + "/presence", saasPresence(step.Frames[x], slices.Contains(subjects, x)), func() string {
				if cl.Frames() > mark.frames {
					return "frame"
				}

				return "silent"
			}},
			stepCheck{x + "/removed", saasRemovedPeers(step.Frames[x], r.saasAlias), func() string {
				return r.hsRemovedPeers(cl, mark)
			}},
			stepCheck{x + "/peers", peerAliases(saas, r.saasAlias), func() string {
				return peerAliases(cl.Netmap(), r.hsAlias)
			}},
		)
	}

	router, saasRoutes, ok := lastRoutesRead(t, step)
	if !ok {
		return checks
	}

	checks = append(checks,
		stepCheck{router + "/advertised", sortedStrings(saasRoutes.Advertised), func() string {
			got, ok := r.hsDeviceRoutes(t, router)
			if !ok {
				return "no single device"
			}

			return sortedStrings(got.Advertised)
		}},
		stepCheck{router + "/enabled", sortedStrings(saasRoutes.Enabled), func() string {
			got, ok := r.hsDeviceRoutes(t, router)
			if !ok {
				return "no single device"
			}

			return sortedStrings(got.Enabled)
		}},
	)

	if self := step.Captures[router].Netmap; self != nil && r.clients[router] != nil {
		checks = append(checks, stepCheck{router + "/self-routes", selfRoutes(self), func() string {
			nm := r.clients[router].Netmap()
			if nm == nil {
				return "no netmap"
			}

			return selfRoutes(nm)
		}})
	}

	for _, v := range captured {
		saas := step.Captures[v].Netmap
		if v == router || saas == nil || r.clients[v] == nil {
			continue
		}

		checks = append(checks, stepCheck{router + "/routes-" + v, servedRoutes(peerByID(saas, r.c.NodeIDs[router])), func() string {
			nodes := r.machineNodes(router)
			if len(nodes) != 1 {
				return fmt.Sprintf("devices %d", len(nodes))
			}

			return servedRoutes(peerByID(r.clients[v].Netmap(), nodes[0].ID().NodeID()))
		}})
	}

	return checks
}

// saasPresence says whether SaaS sent a node anything but keep-alives during
// the step. A frame holding only the node's own Node counts only for a node
// the step acted on: SaaS can send a node its own Node, with what the node
// reported earlier, when another node's change reaches the tailnet, so to a
// node the step left alone such a frame says nothing about the step.
func saasPresence(frames []testcapture.Frame, actedOn bool) string {
	for _, f := range frames {
		resp := f.Response
		if resp == nil || resp.KeepAlive || (!actedOn && selfOnly(f)) {
			continue
		}

		return "frame"
	}

	return "silent"
}

// selfOnly reports whether a frame carries the node's own Node and nothing
// else but ControlTime.
func selfOnly(f testcapture.Frame) bool {
	if f.Response.Node == nil || len(f.Empty) > 0 || len(f.Dropped) > 0 {
		return false
	}

	rest := *f.Response
	rest.Node, rest.ControlTime = nil, nil

	b, err := json.Marshal(rest)

	return err == nil && string(b) == "{}"
}

// saasRemovedPeers names the nodes the step's frames removed.
func saasRemovedPeers(frames []testcapture.Frame, alias func(tailcfg.NodeID) (string, bool)) string {
	set := map[string]bool{}

	for _, f := range frames {
		if f.Response == nil {
			continue
		}

		for _, id := range f.Response.PeersRemoved {
			if name, ok := alias(id); ok {
				set[name] = true
			}
		}
	}

	return sortedStrings(slices.Collect(maps.Keys(set)))
}

// hsRemovedPeers names the nodes headscale told cl were removed since mark:
// removals it applied as a delta, and peers its netmaps dropped.
//
// shortcut: a removal of a peer cl never held, sent with fields a delta
// cannot carry (a policy response holds the self node and SSH policy), shows
// in neither; record raw responses in the test client if a step needs it.
func (r *stepReplay) hsRemovedPeers(cl *servertest.TestClient, mark visibilityMark) string {
	set := map[string]bool{}

	for _, id := range cl.DeltaRemovedPeers()[mark.removed:] {
		if name, ok := r.hsAlias(id); ok {
			set[name] = true
		}
	}

	history := cl.History()[mark.history:]
	for i := 1; i < len(history); i++ {
		for _, p := range history[i-1].Peers {
			if _, missing := peerByID(history[i], p.ID()); missing != "" {
				if name, ok := r.hsAlias(p.ID()); ok {
					set[name] = true
				}
			}
		}
	}

	return sortedStrings(slices.Collect(maps.Keys(set)))
}

// TestPolicySequenceMapCompat replays one policy while members join, a
// second via router joins and the first withdraws its routes, the admin tags
// one member's device and deletes another, then the group the policy names
// in ACLs, a via grant, SSH and autoApprovers is edited. After each step it
// compares, per captured node, its peers, whom it sees each owned by, which
// peers serve each route, and its filter and SSH rules by device; and per
// device, its owner and routes. TestPolicySequenceCompat in ../policy/v2
// compares the same steps at the policy layer.
func TestPolicySequenceMapCompat(t *testing.T) {
	t.Parallel()

	t.Run("policy-generation", func(t *testing.T) {
		t.Parallel()

		replayPolicySequence(t, "policy-generation")
	})
}

func replayPolicySequence(t *testing.T, id string) {
	t.Helper()

	c := readStepCapture(t, id)
	r := newStepReplay(t, c)
	saasNames := topologyAddrNames(c)
	evaluated := map[string]bool{}

	// Kept past a deletion, as saasNames are, so a deleted device's
	// addresses still read as that device in rules that keep them.
	hsNames := map[netip.Addr]string{}
	names := func() map[netip.Addr]string {
		maps.Copy(hsNames, r.addrNames())

		return hsNames
	}

	for _, step := range c.Steps {
		require.Equal(t, "observed", step.Result, "%s: the replay follows every step", step.Name)

		// The probe let each action land before the next, and which router
		// serves a route depends on join order.
		for _, a := range step.Actions {
			one := step
			one.Actions = []testcapture.Action{a}
			require.Empty(t, r.apply(t, one), "%s: every login succeeds", step.Name)
			r.waitSession(t, step.Name, a)
		}

		t.Run(step.Name, func(t *testing.T) {
			holdChecks(t, mapStreamSkipReasons, id+"/"+step.Name+"/", sequenceChecks(t, r, step, saasNames, names), evaluated)
		})
	}

	for k := range mapStreamSkipReasons {
		if strings.HasPrefix(k, id+"/") && !evaluated[k] {
			t.Errorf("skip entry %q names no check", k)
		}
	}
}

// sequenceChecks compares, per node SaaS captured in the step, its peers,
// their owners and routes, and its filter and SSH rules with devices named
// by saasNames and hsNames; per device in the step's device list, its owner;
// and per device whose routes the step read, the routes API.
func sequenceChecks(
	t *testing.T,
	r *stepReplay,
	step testcapture.Step,
	saasNames map[netip.Addr]string,
	hsNames func() map[netip.Addr]string,
) []stepCheck {
	t.Helper()

	var checks []stepCheck

	for _, x := range slices.Sorted(maps.Keys(step.Captures)) {
		saas, cl := step.Captures[x].Netmap, r.clients[x]
		require.NotNil(t, saas, "%s: no netmap of %s", step.Name, x)
		require.NotNil(t, cl, "%s: %s never joined", step.Name, x)

		checks = append(checks,
			stepCheck{x + "/peers", peerAliases(saas, r.saasAlias), func() string { return peerAliases(cl.Netmap(), r.hsAlias) }},
			stepCheck{x + "/peer-owners", peerOwners(saas, r.saasAlias), func() string { return peerOwners(cl.Netmap(), r.hsAlias) }},
			stepCheck{x + "/route-owner", routeOwners(saas, r.saasAlias), func() string { return routeOwners(cl.Netmap(), r.hsAlias) }},
			stepCheck{x + "/filter", renderMatches(saas, saasNames), func() string { return renderMatches(cl.Netmap(), hsNames()) }},
			stepCheck{x + "/ssh", renderSSHRules(saas, saasNames), func() string { return renderSSHRules(cl.Netmap(), hsNames()) }},
		)
	}

	for _, d := range stepDevices(t, step) {
		x := deviceLabelAlias(d.ID)
		checks = append(checks, stepCheck{x + "/owner", saasOwner(d), func() string { return renderOwners(r.hsViews(x)) }})
	}

	for _, a := range step.Actions {
		if a.Kind != "api" || a.Method != http.MethodGet || !strings.HasSuffix(a.Path, "/routes") {
			continue
		}

		x := deviceAlias(t, a.Path)

		var want deviceRoutes
		require.NoError(t, json.Unmarshal(a.Response, &want), "%s: %s", step.Name, a.Path)

		hs := func(pick func(deviceRoutes) []string) func() string {
			return func() string {
				got, ok := r.hsDeviceRoutes(t, x)
				if !ok {
					return "no single device"
				}

				return sortedStrings(pick(got))
			}
		}

		checks = append(checks,
			stepCheck{x + "/advertised", sortedStrings(want.Advertised), hs(func(d deviceRoutes) []string { return d.Advertised })},
			stepCheck{x + "/enabled", sortedStrings(want.Enabled), hs(func(d deviceRoutes) []string { return d.Enabled })},
		)
	}

	return checks
}

// peerOwners gives, per peer in nm that alias names, its tags and the login
// of the user it is shown under, SaaS emails mapped to user names.
func peerOwners(nm *netmap.NetworkMap, alias func(tailcfg.NodeID) (string, bool)) string {
	if nm == nil {
		return "no netmap"
	}

	var out []string

	for _, p := range nm.Peers {
		name, ok := alias(p.ID())
		if !ok {
			continue
		}

		login := "no profile"
		if prof, ok := nm.UserProfiles[p.User()]; ok {
			login = prof.LoginName()
			if user, ok := captureUserNames[login]; ok {
				login = user
			}
		}

		out = append(out, fmt.Sprintf("%s %s as %s", name, sortedStrings(p.Tags().AsSlice()), login))
	}

	slices.Sort(out)

	return strings.Join(out, "; ")
}

// userRoleID is the capture of an admin role change that
// [TestUserChangeDispatchCompat] and [TestAPIV2TaggedDeviceUserCompat] replay.
const userRoleID = "user-role"

// userRoleSetup is the step that pushes the policy and joins the nodes; its
// frames are join traffic, not the role change's.
const userRoleSetup = "S0"

// adminSuffix marks a user's name while the replay stands in for its admin
// role; see [stepReplay.applyUserRole].
const adminSuffix = "-admin"

// TestUserChangeDispatchCompat replays an admin role change under a fixed
// policy whose autogroup:admin rule reaches two tag:server nodes: freya
// raised to admin, one tagged node's stream restarted, freya back to member
// and that stream restarted again. After each step it compares, per node,
// its peers and filter and, past the setup step, whether it was sent
// anything.
func TestUserChangeDispatchCompat(t *testing.T) {
	t.Parallel()

	t.Run(userRoleID, func(t *testing.T) {
		t.Parallel()

		c := readStepCapture(t, userRoleID)
		r := newStepReplay(t, c)
		saasNames := topologyAddrNames(c)
		evaluated := map[string]bool{}

		for _, step := range c.Steps {
			requireUserRoleResult(t, step)

			r.settle(t)

			updates := make(map[string]int, len(r.clients))
			for alias, cl := range r.clients {
				updates[alias] = cl.UpdateCount()
			}

			r.applyUserRole(t, step)

			t.Run(step.Name, func(t *testing.T) {
				holdChecks(t, mapStreamSkipReasons, userRoleID+"/"+step.Name+"/",
					userRoleChecks(t, r, step, saasNames, updates), evaluated)
			})
		}

		for k := range mapStreamSkipReasons {
			if strings.HasPrefix(k, userRoleID+"/") && !deviceListCheck(k) && !evaluated[k] {
				t.Errorf("skip entry %q names no check", k)
			}
		}
	})
}

// requireUserRoleResult admits observed steps and barrier timeouts. The
// probe's barrier waits for the role change to reach the streams; a timeout
// whose note lists the links that never held is that observation, and its
// captures and frames are what SaaS showed by the barrier's end.
func requireUserRoleResult(t *testing.T, step testcapture.Step) {
	t.Helper()

	if step.Result == "timeout" {
		require.True(t, strings.HasPrefix(step.Note, "never held:"), "%s: timeout without the links that never held: %q", step.Name, step.Note)

		return
	}

	require.Equal(t, "observed", step.Result, "%s: the replay follows every step", step.Name)
}

// applyUserRole applies one user-role step, each action landing before the
// next. Headscale has no user roles, so a name stands in for the admin role:
// autogroup:admin becomes the tailnet owner, whom SaaS counts as an admin,
// plus each user's name with adminSuffix, and a role call renames its user
// to or from that name through the v1 API. Like the role call, the rename is
// a user change the policy resolves while its text stays the same, sent by
// headscale's own admin path. Roles held before the capture's first role
// call are not mirrored, so the setup step's checks fail if one decides
// what a node reaches.
func (r *stepReplay) applyUserRole(t *testing.T, step testcapture.Step) {
	t.Helper()

	for _, a := range step.Actions {
		switch a.Kind {
		case "policy":
			require.Equal(t, http.StatusOK, a.Status, "%s: replay of a refused policy", step.Name)
			r.setPolicy(t, step.Name, adminPolicy(r.c.Tailnet, string(a.Body)))

		case "role":
			r.roleRename(t, step.Name, a)

		default:
			one := step
			one.Actions = []testcapture.Action{a}
			require.Empty(t, r.apply(t, one), "%s: every login succeeds", step.Name)
			r.waitSession(t, step.Name, a)
		}
	}
}

// adminPolicy replaces autogroup:admin in policy with the owner and the
// names [stepReplay.roleRename] gives admins.
func adminPolicy(owner, policy string) string {
	admins := make([]string, 0, len(captureUserNames)+1)

	admins = append(admins, strconv.Quote(owner))
	for _, name := range slices.Sorted(maps.Values(captureUserNames)) {
		admins = append(admins, strconv.Quote(name+adminSuffix+"@"))
	}

	return strings.ReplaceAll(policy, strconv.Quote("autogroup:admin"), strings.Join(admins, ", "))
}

// roleRename mirrors a role call on "/users/{user:x}/role": admin renames x
// to x with adminSuffix, member back to x.
func (r *stepReplay) roleRename(t *testing.T, stepName string, a testcapture.Action) {
	t.Helper()

	require.Equal(t, http.StatusOK, a.Status, "%s: replay of a refused role call", stepName)

	rest, ok := strings.CutPrefix(a.Path, "/users/{user:")
	alias, _, found := strings.Cut(rest, "}")
	require.True(t, ok && found, "%s: no user label in %q", stepName, a.Path)

	user, ok := r.users[alias]
	require.True(t, ok, "%s: role of unknown user %s", stepName, alias)

	var body struct {
		Role string `json:"role"`
	}
	require.NoError(t, json.Unmarshal(a.Body, &body), "%s: role body", stepName)

	name := alias

	switch body.Role {
	case "admin":
		name += adminSuffix
	case "member":
	default:
		t.Fatalf("%s: no replay for role %q", stepName, body.Role)
	}

	current, err := r.srv.State().GetUserByID(types.UserID(user.ID))
	require.NoError(t, err)

	if current.Name == name {
		return
	}

	status, resp := r.call(t, http.MethodPost, fmt.Sprintf("/api/v1/user/%d/rename/%s", user.ID, name), nil)
	require.Equal(t, http.StatusOK, status, "%s: rename %s: %s", stepName, alias, resp)
}

// userRoleChecks compares, per node SaaS captured, its peers and filter and,
// past the setup step, whether it was sent anything but a keep-alive since
// updates, each client's update count when the step began.
func userRoleChecks(
	t *testing.T,
	r *stepReplay,
	step testcapture.Step,
	saasNames map[netip.Addr]string,
	updates map[string]int,
) []stepCheck {
	t.Helper()

	var checks []stepCheck

	for _, x := range slices.Sorted(maps.Keys(step.Captures)) {
		saas, cl := step.Captures[x].Netmap, r.clients[x]
		require.NotNil(t, saas, "%s: no netmap of %s", step.Name, x)
		require.NotNil(t, cl, "%s: %s never joined", step.Name, x)

		if step.Name != userRoleSetup {
			checks = append(checks, stepCheck{x + "/frames", saasDelivered(step.Frames[x]), func() string {
				if cl.UpdateCount() > updates[x] {
					return "frame"
				}

				return "silent"
			}})
		}

		checks = append(checks,
			stepCheck{x + "/peers", peerAliases(saas, r.saasAlias), func() string { return peerAliases(cl.Netmap(), r.hsAlias) }},
			stepCheck{x + "/filter", renderMatches(saas, saasNames), func() string { return renderMatches(cl.Netmap(), r.addrNames()) }},
		)
	}

	return checks
}

// deviceListCheck reports whether a user-role skip key names one of
// [TestAPIV2TaggedDeviceUserCompat]'s checks.
func deviceListCheck(key string) bool {
	return strings.HasSuffix(key, "/device-user") || strings.HasSuffix(key, "/device-tags")
}
