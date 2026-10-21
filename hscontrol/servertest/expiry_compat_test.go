// This file replays key expiry captures from Tailscale SaaS: a router whose
// key expires beside a standby, a client's own expiry request and logout,
// and an expired node that keeps its control session while its peers,
// routes, DNS, policy and SSH change.
//
// Test data source: testdata/steps/expiry.hujson, loaded by name.
// Source format:    github.com/juanfont/headscale/hscontrol/types/testcapture

package servertest_test

import (
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/servertest"
	"github.com/juanfont/headscale/hscontrol/types/testcapture"
	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
	"tailscale.com/types/netmap"
)

// expirySkipReasons lists checks where headscale differs from SaaS, keyed
// <test_id>/<step>/<node>/<check>. A listed check that matches fails, so a
// fix must delete its entry.
var expirySkipReasons = map[string]string{
	"expiry/C2-expire-r1/r1/online-observer": expiredPeerOffline,
	"expiry/C2-expire-r1/r1/online-r2":       expiredPeerOffline,
	"expiry/C2-expire-r1/r1/paths-observer":  expiredPeerPaths,
	"expiry/C2-expire-r1/r1/paths-r2":        expiredPeerPaths,

	"expiry/C4-expire-r2/r2/online-observer": expiredPeerOffline,
	"expiry/C4-expire-r2/r2/online-r1":       expiredPeerOffline,
	"expiry/C4-expire-r2/r2/paths-observer":  expiredPeerPaths,
	"expiry/C4-expire-r2/r2/paths-r1":        expiredPeerPaths,

	// A client asked for this expiry; once it passes the node is expired
	// like any other.
	"expiry/D3-past-expiry/subject/online-observer": expiredPeerOffline,
	"expiry/D3-past-expiry/subject/paths-observer":  expiredPeerPaths,

	"expiry/A2-expire/laptop/online-observer": expiredPeerOffline,
	"expiry/A2-expire/laptop/online-peer1":    expiredPeerOffline,
	"expiry/A2-expire/laptop/paths-observer":  expiredPeerPaths,
	"expiry/A2-expire/laptop/paths-peer1":     expiredPeerPaths,

	"expiry/A3-peer-change/laptop/online-observer": expiredPeerOffline,
	"expiry/A3-peer-change/laptop/online-peer1":    expiredPeerOffline,
	"expiry/A3-peer-change/laptop/online-peer3":    expiredPeerOffline,
	"expiry/A3-peer-change/laptop/paths-observer":  expiredPeerPaths,
	"expiry/A3-peer-change/laptop/paths-peer1":     expiredPeerPaths,
	"expiry/A3-peer-change/laptop/paths-peer3":     expiredPeerPaths,

	"expiry/A4-rename/laptop/online-observer": expiredPeerOffline,
	"expiry/A4-rename/laptop/paths-observer":  expiredPeerPaths,

	"expiry/A5-advertise/laptop/online-observer": expiredPeerOffline,
	"expiry/A5-advertise/laptop/paths-observer":  expiredPeerPaths,

	"expiry/A7-dns/laptop/dns":             nameserversFromConfig,
	"expiry/A7-dns/laptop/online-observer": expiredPeerOffline,
	"expiry/A7-dns/laptop/paths-observer":  expiredPeerPaths,
	"expiry/A7-dns/observer/dns":           nameserversFromConfig,

	"expiry/A8-policy/laptop/online-observer": expiredPeerOffline,
	"expiry/A8-policy/laptop/paths-observer":  expiredPeerPaths,

	"expiry/A9-ssh/laptop/online-observer": expiredPeerOffline,
	"expiry/A9-ssh/laptop/paths-observer":  expiredPeerPaths,

	"expiry/A10-reconnect/laptop/online-observer": expiredPeerOffline,
	"expiry/A10-reconnect/laptop/paths-observer":  expiredPeerPaths,

	"expiry/A6a-expire-again/laptop/online-observer": expiredPeerOffline,
	"expiry/A6a-expire-again/laptop/online-peer1":    expiredPeerOffline,
	"expiry/A6a-expire-again/laptop/paths-observer":  expiredPeerPaths,
	"expiry/A6a-expire-again/laptop/paths-peer1":     expiredPeerPaths,

	"expiry/A6b-rotate-disco/laptop/online-observer": expiredPeerOffline,
	"expiry/A6b-rotate-disco/laptop/online-peer1":    expiredPeerOffline,
	"expiry/A6b-rotate-disco/laptop/online-peer3":    expiredPeerOffline,
	"expiry/A6b-rotate-disco/laptop/paths-observer":  expiredPeerPaths,
	"expiry/A6b-rotate-disco/laptop/paths-peer1":     expiredPeerPaths,
	"expiry/A6b-rotate-disco/laptop/paths-peer3":     expiredPeerPaths,
}

const (
	expiredPeerPaths      = "EXPIRED_PEER_PATHS: headscale sends peers an expired node's endpoints and home DERP; SaaS leaves both out"
	nameserversFromConfig = "NAMESERVERS_FROM_CONFIG: headscale reads nameservers from its config and cannot change them while running; SaaS pushes a change to every node, an expired one too"
)

// TestNodeExpiryCompat replays key expiry against SaaS: an expired router
// beside a standby, restored, then the standby expired; a client asking for
// an earlier expiry, waiting past it and logging out, and a tagged node
// logging out; an expired node whose peers rename and join, which renames
// itself, advertises a route, and keeps its stream while DNS, the policy and
// SSH change, reconnects, is restored, expired again and rotates its disco
// key. Each step compares every captured node's own view, every captured
// node's view of the others, its register answers, the routes API and the
// device's key expiry.
func TestNodeExpiryCompat(t *testing.T) {
	t.Parallel()

	t.Run("expiry", func(t *testing.T) {
		t.Parallel()

		runNodeExpiryCompat(t, "expiry", "observer")
	})
}

func runNodeExpiryCompat(t *testing.T, id, observer string) {
	t.Helper()

	c := readStepCapture(t, id)

	base, ok := c.Captures[observer]
	require.True(t, ok && base.Netmap != nil, "%s: no baseline for %s", id, observer)

	opts := []servertest.ServerOption{
		servertest.WithNodeExpiry(captureKeyDuration(t, c)),
		servertest.WithDNSResolvers(c.Input.Tailnet.DNS.Nameservers...),
	}
	if c.Input.Tailnet.DNS.MagicDNS && len(base.Netmap.DNS.Domains) > 0 {
		opts = append(opts, servertest.WithMagicDNS(base.Netmap.DNS.Domains[0]))
	}

	r := newStepReplay(t, c, opts...)
	r.paths = true

	// The test server runs no scheduled tasks. Run headscale's expiry pass on
	// a short timer, so peers learn when an expiry a client asked for passes.
	go func() {
		tick := time.NewTicker(250 * time.Millisecond)
		defer tick.Stop()

		last := time.Unix(0, 0)

		for {
			select {
			case <-t.Context().Done():
				return
			case <-tick.C:
				next, changes, _ := r.srv.State().ExpireExpiredNodes(last)
				last = next

				r.srv.App.Change(changes...)
			}
		}
	}()

	// A change is judged against the step before only, so both sides
	// compare the same span.
	prevCaps := c.Captures
	saasPrev, hsPrev := map[string]deviceView{}, map[string]deviceView{}
	evaluated := map[string]bool{}

	for _, step := range c.Steps {
		require.Equal(t, "observed", step.Result, "%s: the replay follows every step", step.Name)

		start := map[string]*netmap.NetworkMap{}
		historyStart, attempts, streams := map[string]int{}, map[string]int{}, map[string]int{}

		for alias, cl := range r.clients {
			start[alias] = cl.Netmap()
			historyStart[alias] = max(len(cl.History())-1, 0)
			attempts[alias] = len(cl.RegisterAttempts())
			streams[alias], _ = cl.Stream()

			if v := r.hsViews(alias); len(v) == 1 {
				hsPrev[alias] = v[0]
			}
		}

		r.apply(t, step)

		e := &expiryStep{
			r: r, c: c, step: step, at: stepCaptureTime(step), saasNames: r.saasAddrNames(step),
			prevCaps: prevCaps, start: start, historyStart: historyStart, streams: streams,
		}

		var checks []stepCheck

		captured := slices.Sorted(maps.Keys(step.Captures))
		for _, x := range captured {
			if step.Captures[x].Netmap == nil || r.clients[x] == nil {
				continue
			}

			checks = append(checks, e.selfChecks(t, x)...)

			for _, v := range captured {
				if v != x && step.Captures[v].Netmap != nil && r.clients[v] != nil {
					checks = append(checks, e.viewChecks(x, v)...)
				}
			}
		}

		for _, node := range slices.Sorted(maps.Keys(step.Register)) {
			if cl, ok := r.clients[node]; ok {
				checks = append(checks, stepCheck{node + "/outcome", registerFlags(step.Register[node]), func() string {
					return registerFlags(cl.RegisterAttempts()[attempts[node]:])
				}})
			}
		}

		checks = append(checks, e.apiChecks(t, saasPrev, hsPrev)...)

		prefix := id + "/" + step.Name + "/"
		for _, ch := range checks {
			evaluated[prefix+ch.name] = true
		}

		if len(checks) > 0 {
			t.Run(step.Name, func(t *testing.T) {
				holdChecks(t, expirySkipReasons, prefix, checks, evaluated)
			})
		}

		prevCaps = step.Captures
	}

	// The map serves this capture alone, so every entry must name a check.
	for k := range expirySkipReasons {
		if !evaluated[k] {
			t.Errorf("skip entry %q names no check", k)
		}
	}
}

// expiryStep is one replayed step and what both sides showed before it.
type expiryStep struct {
	r    *stepReplay
	c    *testcapture.Capture
	step testcapture.Step

	// at is when SaaS's captures were taken.
	at time.Time

	// saasNames names the capture's nodes the step's netmaps show by their
	// SaaS addresses.
	saasNames map[netip.Addr]string

	// prevCaps holds SaaS's captures of the step before; start, historyStart
	// and streams headscale's netmaps and map streams when the step began.
	prevCaps     map[string]testcapture.Node
	start        map[string]*netmap.NetworkMap
	historyStart map[string]int
	streams      map[string]int
}

// selfChecks compares x's own view: its key expiry flags, its peers among
// the capture's nodes, its packet filter and SSH rules, whether a map stream
// the step opened was answered and, when the step before captured x too,
// whether it lost any peer during the step and whether its DNS, packet
// filter and SSH policy changed.
func (e *expiryStep) selfChecks(t *testing.T, x string) []stepCheck {
	t.Helper()

	saas := e.step.Captures[x].Netmap
	cl := e.r.clients[x]

	checks := []stepCheck{
		{x + "/self", renderSelfExpiry(saas, e.at), func() string { return renderSelfExpiry(cl.Netmap(), time.Now()) }},
		{x + "/peers", peerAliases(saas, e.r.saasAlias), func() string { return peerAliases(cl.Netmap(), e.r.hsAlias) }},
		{x + "/filter-rules", strings.Join(saasFilterTriples(t, e.step.Captures[x].PacketFilterRules, e.saasNames), "\n"), func() string {
			nm := cl.Netmap()
			if nm == nil {
				return "no netmap"
			}

			// Polled outside the test's own flow, so failures become text.
			var errs errText

			return strings.Join(append(hsFilterTriples(&errs, nm.PacketFilter, e.r.addrNames()), errs...), "\n")
		}},
		{x + "/ssh-rules", renderSSHRules(saas, e.saasNames), func() string { return renderSSHRules(cl.Netmap(), e.r.addrNames()) }},
	}

	// Only nodes whose stream SaaS recorded; opening one logs its request.
	if opensStream(e.step, x) && len(e.step.Frames[x]) > 0 {
		checks = append(checks, stepCheck{x + "/stream", saasStreamAnswer(e.step.Frames[x]), func() string {
			switch opened, maps := cl.Stream(); {
			case opened == e.streams[x]:
				return "not opened"
			case maps == 0:
				return "unanswered"
			default:
				return "answered"
			}
		}})
	}

	prev := e.prevCaps[x].Netmap
	if prev == nil || e.start[x] == nil {
		return checks
	}

	if frames := e.step.Frames[x]; len(frames) > 0 {
		checks = append(checks, stepCheck{x + "/removed", e.saasRemovedPeers(prev, frames), func() string {
			return e.hsRemovedPeers(x)
		}})
	}

	for _, part := range []struct {
		name   string
		render func(*netmap.NetworkMap) string
	}{
		{"dns", renderResolvers},
		{"filter", renderFilterRules},
		{"ssh", renderSSHPolicy},
	} {
		checks = append(checks, stepCheck{x + "/" + part.name, changed(part.render(prev), part.render(saas)), func() string {
			return changed(part.render(e.start[x]), part.render(cl.Netmap()))
		}})
	}

	return checks
}

// viewChecks compares how v sees x: expired, online, whether it has paths
// to it, the routes it is served through it, its name and, when the step
// before captured v too, whether its disco key changed.
func (e *expiryStep) viewChecks(x, v string) []stepCheck {
	saasView := e.step.Captures[v].Netmap
	saasID := e.c.NodeIDs[x]
	saasPeer, saasMissing := peerByID(saasView, saasID)

	hsPeer := func() (tailcfg.NodeView, string) {
		nodes := e.r.machineNodes(x)
		if len(nodes) != 1 {
			return tailcfg.NodeView{}, fmt.Sprintf("devices %d", len(nodes))
		}

		return peerByID(e.r.clients[v].Netmap(), nodes[0].ID().NodeID())
	}

	checks := make([]stepCheck, 0, 6)
	checks = append(checks,
		stepCheck{x + "/expired-" + v, peerExpired(saasPeer, saasMissing), func() string { return peerExpired(hsPeer()) }},
		stepCheck{x + "/online-" + v, peerOnline(saasPeer, saasMissing), func() string { return peerOnline(hsPeer()) }},
		stepCheck{x + "/paths-" + v, peerPaths(saasPeer, saasMissing), func() string { return peerPaths(hsPeer()) }},
		stepCheck{x + "/routes-" + v, servedRoutes(saasPeer, saasMissing), func() string { return servedRoutes(hsPeer()) }},
		stepCheck{x + "/name-" + v, peerName(saasPeer, saasMissing), func() string { return peerName(hsPeer()) }},
	)

	prev := e.prevCaps[v].Netmap
	nodes := e.r.machineNodes(x)

	if prev == nil || e.start[v] == nil || len(nodes) != 1 {
		return checks
	}

	hsBefore := peerDisco(e.start[v], nodes[0].ID().NodeID())

	return append(checks, stepCheck{x + "/disco-" + v, discoState(peerDisco(prev, saasID), peerDisco(saasView, saasID)), func() string {
		p, missing := hsPeer()
		if missing != "" {
			return discoState(hsBefore, missing)
		}

		return discoState(hsBefore, p.DiscoKey().String())
	}})
}

// apiChecks compares the step's last routes read and last device read of
// each device: advertised and enabled routes, and the key expiry, which for
// a future expiry also says whether the step moved it.
func (e *expiryStep) apiChecks(t *testing.T, saasPrev, hsPrev map[string]deviceView) []stepCheck {
	t.Helper()

	routes := map[string]testcapture.Action{}
	device := map[string]testcapture.Action{}

	for _, a := range e.step.Actions {
		if a.Kind != "api" || a.Method != http.MethodGet || !strings.HasPrefix(a.Path, "/device/{device:") {
			continue
		}

		alias := deviceAlias(t, a.Path)

		switch {
		case strings.HasSuffix(a.Path, "/routes"):
			routes[alias] = a
		case strings.HasSuffix(a.Path, "?fields=all"):
			device[alias] = a
		}
	}

	var checks []stepCheck

	for _, alias := range slices.Sorted(maps.Keys(routes)) {
		a := routes[alias]
		require.Equal(t, http.StatusOK, a.Status, "%s: %s", e.step.Name, a.Path)

		var want deviceRoutes
		require.NoError(t, json.Unmarshal(a.Response, &want), "%s: %s", e.step.Name, a.Path)

		got := func() (deviceRoutes, bool) {
			path, ok := e.r.v2Path(a.Path)
			if !ok {
				return deviceRoutes{}, false
			}

			status, body := e.r.call(t, http.MethodGet, path, nil)

			var out deviceRoutes

			return out, status == http.StatusOK && json.Unmarshal(body, &out) == nil
		}

		checks = append(checks,
			stepCheck{alias + "/advertised", sortedStrings(want.Advertised), func() string {
				out, ok := got()
				if !ok {
					return "no device"
				}

				return sortedStrings(out.Advertised)
			}},
			stepCheck{alias + "/enabled", sortedStrings(want.Enabled), func() string {
				out, ok := got()
				if !ok {
					return "no device"
				}

				return sortedStrings(out.Enabled)
			}},
		)
	}

	for _, alias := range slices.Sorted(maps.Keys(device)) {
		a := device[alias]
		require.Equal(t, http.StatusOK, a.Status, "%s: %s", e.step.Name, a.Path)

		var d saasDevice
		require.NoError(t, json.Unmarshal(a.Response, &d), "%s: %s", e.step.Name, a.Path)

		want := saasDeviceView(e.c, d, e.step.At.Add(time.Duration(a.OffsetMS)*time.Millisecond))
		prevWant, hadWant := saasPrev[alias]
		prevGot, hadGot := hsPrev[alias]
		saasPrev[alias] = want

		checks = append(checks, stepCheck{alias + "/key-expiry", renderKeyExpiry(want, prevWant, hadWant), func() string {
			views := e.r.hsViews(alias)
			if len(views) != 1 {
				return fmt.Sprintf("devices %d", len(views))
			}

			return renderKeyExpiry(views[0], prevGot, hadGot)
		}})
	}

	return checks
}

// saasRemovedPeers lists the capture's nodes x had as peers before the step
// and lost during it, or "none".
func (e *expiryStep) saasRemovedPeers(prev *netmap.NetworkMap, frames []testcapture.Frame) string {
	var out []string

	for alias, id := range e.c.NodeIDs {
		if _, missing := peerByID(prev, id); missing == "" && saasRemoved(prev, frames, id) == "removed" {
			out = append(out, alias)
		}
	}

	return removedList(out)
}

func (e *expiryStep) hsRemovedPeers(x string) string {
	cl := e.r.clients[x]
	history := cl.History()[e.historyStart[x]:]

	var out []string

	if before := e.start[x]; before != nil {
		for _, p := range before.Peers {
			if alias, ok := e.r.hsAlias(p.ID()); ok && hsRemoved(history, p.ID()) == "removed" {
				out = append(out, alias)
			}
		}
	}

	return removedList(out)
}

func removedList(aliases []string) string {
	if len(aliases) == 0 {
		return "none"
	}

	return sortedStrings(aliases)
}

// stepCaptureTime is when the probe took the step's captures: after its last
// action, a wait counted to its end.
func stepCaptureTime(step testcapture.Step) time.Time {
	end := step.At

	for _, a := range step.Actions {
		at := step.At.Add(time.Duration(a.OffsetMS) * time.Millisecond)

		if a.Kind == "wait" && len(a.Args) == 1 {
			d, err := time.ParseDuration(a.Args[0])
			if err == nil {
				at = at.Add(d)
			}
		}

		if at.After(end) {
			end = at
		}
	}

	return end
}

// captureKeyDuration is the tailnet's key lifetime, read off the first
// device that holds its key expiry.
func captureKeyDuration(t *testing.T, c *testcapture.Capture) time.Duration {
	t.Helper()

	for _, step := range c.Steps {
		for _, a := range step.Actions {
			if a.Kind != "api" || a.Method != http.MethodGet || !strings.HasSuffix(a.Path, "?fields=all") || a.Status != http.StatusOK {
				continue
			}

			var d struct {
				Created           time.Time `json:"created"`
				Expires           time.Time `json:"expires"`
				KeyExpiryDisabled bool      `json:"keyExpiryDisabled"`
				Tags              []string  `json:"tags"`
			}
			if json.Unmarshal(a.Response, &d) == nil && !d.KeyExpiryDisabled && len(d.Tags) == 0 {
				return d.Expires.Sub(d.Created)
			}
		}
	}

	t.Fatalf("%s: no device shows the key lifetime", c.TestID)

	return 0
}

// renderSelfExpiry gives a node's own entry: its key expiry relative to now,
// and its MachineAuthorized and Expired flags.
func renderSelfExpiry(nm *netmap.NetworkMap, now time.Time) string {
	if nm == nil || !nm.SelfNode.Valid() {
		return "no netmap"
	}

	self := nm.SelfNode

	expiry := "zero"
	if ke := self.KeyExpiry(); !ke.IsZero() {
		expiry = "future"
		if ke.Before(now) {
			expiry = "past"
		}
	}

	return fmt.Sprintf("key expiry %s, authorized %t, expired %t", expiry, self.MachineAuthorized(), self.Expired())
}

// renderKeyExpiry gives a device's key expiry class; a future expiry also
// says whether it moved since prev.
func renderKeyExpiry(v, prev deviceView, hadPrev bool) string {
	switch {
	case v.expiry != "future" || !hadPrev || prev.expiry != "future":
		return v.expiry
	case prev.expires == v.expires:
		return "future, unchanged"
	default:
		return "future, moved"
	}
}

func peerPaths(p tailcfg.NodeView, missing string) string {
	if missing != "" {
		return missing
	}

	return fmt.Sprintf("endpoints %t, derp %t", p.Endpoints().Len() > 0, p.HomeDERP() != 0)
}

// peerName is the first label of the peer's MagicDNS name.
func peerName(p tailcfg.NodeView, missing string) string {
	if missing != "" {
		return missing
	}

	label, _, _ := strings.Cut(p.Name(), ".")

	return label
}

// discoState says whether a peer's disco key was kept or rotated, or that
// the peer appeared or is missing.
func discoState(before, after string) string {
	switch {
	case !strings.HasPrefix(after, "discokey:"):
		return after
	case !strings.HasPrefix(before, "discokey:"):
		return "appeared"
	case before == after:
		return "kept"
	default:
		return "rotated"
	}
}

// saasAddrNames names by alias each SaaS address of the capture's nodes that
// a netmap of step shows, itself or as a peer: the devices then present.
func (r *stepReplay) saasAddrNames(step testcapture.Step) map[netip.Addr]string {
	out := map[netip.Addr]string{}

	add := func(n tailcfg.NodeView) {
		if alias, ok := r.saasAlias(n.ID()); ok {
			for _, p := range n.Addresses().All() {
				out[p.Addr()] = alias
			}
		}
	}

	for _, node := range step.Captures {
		if nm := node.Netmap; nm != nil {
			add(nm.SelfNode)

			for _, p := range nm.Peers {
				add(p)
			}
		}
	}

	return out
}

// errText is a [require.TestingT] that keeps failures as text.
type errText []string

func (e *errText) Errorf(format string, args ...any) { *e = append(*e, fmt.Sprintf(format, args...)) }

func (e *errText) FailNow() {}

// renderSSHRules gives a node's SSH rules in order: principals by name and
// address family, local user mappings and the action. Addresses of nodes
// outside the capture are left out, and so is a rule left with no
// principal. SaaS's login "0" to no user mapping is left out too:
// TestSSHDataCompat checks it apart.
func renderSSHRules(nm *netmap.NetworkMap, names map[netip.Addr]string) string {
	if nm == nil {
		return "no netmap"
	}

	if nm.SSHPolicy == nil {
		return "none"
	}

	var out []string

	for _, rule := range nm.SSHPolicy.Rules {
		var who []string

		for _, p := range rule.Principals {
			addr, err := netip.ParseAddr(p.NodeIP)

			switch {
			case err != nil:
				who = append(who, fmt.Sprintf("%+v", *p))
			case names[addr] != "":
				family := "/ipv6"
				if addr.Is4() {
					family = "/ipv4"
				}

				who = append(who, names[addr]+family)
			case !prefixInTailscaleRange(netip.PrefixFrom(addr, addr.BitLen())):
				who = append(who, p.NodeIP)
			}
		}

		if len(who) == 0 {
			continue
		}

		users := make([]string, 0, len(rule.SSHUsers))
		for from, to := range rule.SSHUsers {
			if from != "0" || to != "" {
				users = append(users, from+"="+to)
			}
		}

		action := "no action"
		if a := rule.Action; a != nil {
			action = fmt.Sprintf("accept %t, reject %t, check %t", a.Accept, a.Reject, a.HoldAndDelegate != "")
		}

		out = append(out, fmt.Sprintf("%s as %s: %s", sortedStrings(who), sortedStrings(users), action))
	}

	if len(out) == 0 {
		return "none"
	}

	return strings.Join(out, "\n")
}

// opensStream reports whether the step's actions open a new map stream for
// x: a login, a restart or a reconnect.
func opensStream(step testcapture.Step, x string) bool {
	return slices.ContainsFunc(step.Actions, func(a testcapture.Action) bool {
		return a.Node == x && slices.Contains([]string{
			"join", "relogin", "login", "restart", "start", "break_tcp_conns", "rotate_disco_key",
		}, a.Kind)
	})
}

// saasStreamAnswer says whether SaaS answered the last map stream the frames
// show opening with a full map.
func saasStreamAnswer(frames []testcapture.Frame) string {
	answer := "not opened"

	for _, f := range frames {
		switch {
		case f.Request != nil && f.Request.Stream:
			answer = "unanswered"
		case answer == "unanswered" && f.Response != nil && f.Response.Node != nil:
			answer = "answered"
		}
	}

	return answer
}

func changed(before, after string) string {
	if before == after {
		return "unchanged"
	}

	return "changed"
}

func renderResolvers(nm *netmap.NetworkMap) string {
	if nm == nil {
		return "no netmap"
	}

	out := make([]string, 0, len(nm.DNS.Resolvers))
	for _, r := range nm.DNS.Resolvers {
		out = append(out, r.Addr)
	}

	return sortedStrings(out)
}

func renderFilterRules(nm *netmap.NetworkMap) string {
	if nm == nil {
		return "no netmap"
	}

	b, err := json.Marshal(nm.PacketFilterRules)
	if err != nil {
		return err.Error()
	}

	return string(b)
}

func renderSSHPolicy(nm *netmap.NetworkMap) string {
	if nm == nil {
		return "no netmap"
	}

	b, err := json.Marshal(nm.SSHPolicy)
	if err != nil {
		return err.Error()
	}

	return string(b)
}
