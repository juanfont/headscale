// This file replays map stream captures from Tailscale SaaS: what each node
// is sent when a device is retagged, when a running peer changes its DERP
// home, disco key, hostname or port, when a node goes down and up around
// policy pushes, and which Hostinfo fields peers and the node itself get.
//
// Test data source: testdata/steps/map-delivery.hujson, loaded by name. Its
// disco rotation also pins a row of TestBuildMapRequestChangeResponse in
// ../state.
// Source format:    github.com/juanfont/headscale/hscontrol/types/testcapture

package servertest_test

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

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

	"map-delivery/S3.5-remove/db1/frames":   policyResponseToEveryNode,
	"map-delivery/S3.5-restore/appc/frames": policyResponseToEveryNode,
	"map-delivery/S3.5-restore/db1/frames":  policyResponseToEveryNode,
	"map-delivery/S3.5-restore/sshd/frames": policyResponseToEveryNode,

	"map-delivery/S2.1/laptop/frames":         ownReportEchoed,
	"map-delivery/S2.3/laptop/frames":         ownReportEchoed,
	"map-delivery/S2.5/laptop/self-endpoints": ownReportEchoed,

	"map-delivery/S2.5/laptop/endpoints-gap-bystander": restartEndpointsKept,
	"map-delivery/S2.5/laptop/endpoints-gap-svc":       restartEndpointsKept,

	"map-delivery/S3.1/appc/frames":      reconnectAnnounced,
	"map-delivery/S3.1/bystander/frames": reconnectAnnounced,
	"map-delivery/S3.1/router/frames":    reconnectAnnounced,
	"map-delivery/S3.1/sshd/frames":      reconnectAnnounced,
	"map-delivery/S3.1/svc/frames":       reconnectAnnounced,

	"map-delivery/S3.4/appc/frames":      routerReconnectRecompute,
	"map-delivery/S3.4/bystander/frames": routerReconnectRecompute,
	"map-delivery/S3.4/db1/frames":       routerReconnectRecompute,
	"map-delivery/S3.4/laptop/frames":    routerReconnectRecompute,
	"map-delivery/S3.4/sshd/frames":      routerReconnectRecompute,
	"map-delivery/S3.4/svc/frames":       routerReconnectRecompute,

	"map-delivery/S3.6/bystander/peers": sameUserPeers,
	"map-delivery/S3.6/laptop/peers":    sameUserPeers,

	"map-delivery/S2.0/appc/self-hostinfo-keys":      selfHostinfoWhole,
	"map-delivery/S2.0/bystander/self-hostinfo-keys": selfHostinfoWhole,
	"map-delivery/S2.0/sshd/self-hostinfo-keys":      selfHostinfoWhole,

	"map-delivery/S2.0/appc/peer-hostinfo-keys":      peerHostinfoWhole,
	"map-delivery/S2.0/bystander/peer-hostinfo-keys": peerHostinfoWhole,
	"map-delivery/S2.0/sshd/peer-hostinfo-keys":      peerHostinfoWhole,

	"map-delivery/S2.0/appc/peer-hostinfo":      peerServicesWhole,
	"map-delivery/S2.0/bystander/peer-hostinfo": peerServicesWhole,
	"map-delivery/S2.0/sshd/peer-hostinfo":      peerServicesWhole,
}

const (
	policyResponseToEveryNode = "POLICY_RESPONSE_TO_EVERY_NODE: headscale sends every connected node a policy response when tags or the policy change; SaaS sends only the nodes whose peers or filter change"
	ownReportEchoed           = "OWN_REPORT_ECHOED: headscale sends a node its own endpoint or DERP report back; SaaS sends it nothing, so its own entry keeps the endpoints of its last full map"
	restartEndpointsKept      = "RESTART_ENDPOINTS_KEPT: headscale keeps a restarted node's last endpoints at its peers until it reports new ones; SaaS sends peers the node without endpoints until then"
	reconnectAnnounced        = "RECONNECT_ANNOUNCED: headscale tells peers a node is online after a stream gap of a few seconds; SaaS sends them nothing"
	routerReconnectRecompute  = "ROUTER_RECONNECT_RECOMPUTE: headscale sends every node a policy response when a subnet router's stream comes back after a few seconds; SaaS sends nothing"
	selfHostinfoWhole         = "SELF_HOSTINFO_WHOLE: headscale sends a node its whole reported Hostinfo; SaaS sends only Hostname, RequestTags and Services"
	peerHostinfoWhole         = "PEER_HOSTINFO_WHOLE: headscale sends peers a node's whole reported Hostinfo; SaaS sends only Hostname, OS, Services, the SSH host keys and AppConnector"
	peerServicesWhole         = "PEER_SERVICES_WHOLE: headscale sends peers every service a node reports; SaaS leaves out peerapi-dns-proxy"
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

	case args == "down":
		cl.Disconnect(t)

	case args == "up":
		// tailscaled registers again on its node key, then polls.
		require.NoError(t, cl.ReloginAndPoll(ctx), "%s: up", step.Name)

	case args == "debug rotate-disco-key":
		require.NoError(t, cl.RotateDisco(ctx), "%s: disco rotation", step.Name)

	case args == "debug pick-new-derp", args == "set --ssh", args == "set --advertise-connector",
		strings.HasPrefix(args, "set --hostname="):
		// Only what the node reports changes.

	default:
		t.Fatalf("%s: no replay for %s %q", step.Name, a.Kind, a.Args)
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
			out[alias] = cl.UpdateCount()
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
	saasNames := map[netip.Addr]string{}

	for alias, n := range r.c.Topology.Nodes {
		for _, s := range []string{n.IPv4, n.IPv6} {
			addr, err := netip.ParseAddr(s)
			if err == nil {
				saasNames[addr] = alias
			}
		}
	}

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
