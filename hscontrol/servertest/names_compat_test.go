// This file replays node name captures from Tailscale SaaS and compares each
// device's MagicDNS label with what SaaS showed.
//
// Test data source: testdata/steps/{names,names-svc}.hujson, loaded by name.
// names-svc ran on names' tailnet right after it, reusing its viewer and
// keys, so the two replay in one server. TestNodeNameReplayCompat in
// ../state replays names through State.
// Source format:    github.com/juanfont/headscale/hscontrol/types/testcapture

package servertest_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/juanfont/headscale/hscontrol/servertest"
	"github.com/juanfont/headscale/hscontrol/types/testcapture"
	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
	"tailscale.com/types/netmap"
)

// nameSkipReasons lists checks where headscale differs from SaaS, keyed
// <test_id>/<step>/<node or action index>/<check>. A listed check that
// matches fails, so a fix must delete its entry.
var nameSkipReasons = map[string]string{
	"names/N1/domain":     v2NameBare,
	"names/N2/domain":     v2NameBare,
	"names/N3/domain":     v2NameBare,
	"names/N4/domain":     v2NameBare,
	"names/N5/domain":     v2NameBare,
	"names/N6/domain":     v2NameBare,
	"names/N7/domain":     v2NameBare,
	"names/N8/domain":     v2NameBare,
	"names/N9a/domain":    v2NameBare,
	"names/N9b/domain":    v2NameBare,
	"names/N10/domain":    v2NameBare,
	"names/N11/domain":    v2NameBare,
	"names/N11b/domain":   v2NameBare,
	"names/N12a/domain":   v2NameBare,
	"names/N12b/domain":   v2NameBare,
	"names/N13/domain":    v2NameBare,
	"names-svc/S1/domain": v2NameBare,
	"names-svc/S2/domain": v2NameBare,
	"names-svc/S3/domain": v2NameBare,
	"names-svc/S4/domain": v2NameBare,
	"names-svc/S5/domain": v2NameBare,
	"names-svc/S6/domain": v2NameBare,
	"names-svc/S7/domain": v2NameBare,

	"names/N11/pdb/label":  adminNameFollowsHostname,
	"names/N11b/pdb/label": adminNameFollowsHostname,
	"names/N12a/pdb/label": adminNameFollowsHostname,
	"names/N12b/pdb/label": adminNameFollowsHostname,
	"names/N13/pdb/label":  adminNameFollowsHostname,
}

const (
	adminNameFollowsHostname = "ADMIN_NAME_FOLLOWS_HOSTNAME: an admin name equal to the hostname's label counts as derived from it, so a hostname change replaces it; SaaS keeps an admin name across hostname changes"
	v2NameBare               = "V2_NAME_BARE: headscale's v2 device name is the bare label; SaaS's is the FQDN under the tailnet domain"
)

// nameViewer is the node whose netmap every step captured.
const nameViewer = "viewer"

// TestNodeNameCompat replays devices joining under taken hostnames, a
// restart, the holder's deletion, hostnames that sanitise to nothing, admin
// renames that differ in case, hostname changes after a rename and the
// longest hostnames a stock client sends; then a Tailscale Service holding
// a label, replayed as the extra DNS record it publishes. After each step
// it compares, per device, its label in the v2 API, in the viewer's netmap
// and in its own, and its hostname in the v2 API and the viewer's netmap;
// the v2 name's domain; which devices exist; each captured node's extra
// records; and each rename and delete answer.
func TestNodeNameCompat(t *testing.T) {
	t.Parallel()

	// One subtest owns the clients, so both captures replay before its
	// cleanup stops them.
	t.Run("replay", func(t *testing.T) {
		t.Parallel()

		names := readStepCapture(t, "names")
		svc := readStepCapture(t, "names-svc")

		self := names.Captures[nameViewer].Netmap
		require.NotNil(t, self, "names: no baseline netmap of %s", nameViewer)

		_, domain, _ := strings.Cut(strings.TrimSuffix(self.SelfNode.Name(), "."), ".")

		n := &nameReplay{
			stepReplay: newStepReplay(t, names, servertest.WithMagicDNS(domain)),
			domain:     domain,
			services:   map[string][]string{},
		}
		n.readAPI = true
		evaluated := map[string]bool{}

		for _, c := range []*testcapture.Capture{names, svc} {
			n.replay(t, c, evaluated)
		}

		for k := range nameSkipReasons {
			if !evaluated[k] {
				t.Errorf("skip entry %q names no check", k)
			}
		}
	})
}

type nameReplay struct {
	*stepReplay

	domain string

	// services holds each live Service's addresses by name.
	services map[string][]string
}

func (n *nameReplay) replay(t *testing.T, c *testcapture.Capture, evaluated map[string]bool) {
	t.Helper()

	n.c = c

	for _, step := range c.Steps {
		require.Contains(t, []string{"observed", "expected-refusal"}, step.Result,
			"%s: the replay follows every step", step.Name)

		answers := n.applyStep(t, step)

		devices, _, ok := stepDeviceRead(step)
		if !ok {
			continue
		}

		t.Run(c.TestID+"/"+step.Name, func(t *testing.T) {
			holdChecks(t, nameSkipReasons, c.TestID+"/"+step.Name+"/", n.checks(t, step, devices, answers), evaluated)
		})
	}
}

// applyStep runs the step's actions one at a time, as the probe let each land
// before the next, and returns headscale's answer to each admin exchange by
// its index in the step.
func (n *nameReplay) applyStep(t *testing.T, step testcapture.Step) map[int]apiAnswer {
	t.Helper()

	answers := map[int]apiAnswer{}

	for i, a := range step.Actions {
		if n.service(t, step.Name, a) {
			continue
		}

		one := step
		one.Actions = []testcapture.Action{a}
		require.Empty(t, n.apply(t, one), "%s: every login succeeds", step.Name)
		n.waitSession(t, step.Name, a)

		if ans, ok := n.answers[0]; ok {
			answers[i] = ans
		}
	}

	return answers
}

// service replays what headscale has no Services for, and reports whether a
// was such an action. A Service publishes its name as an extra DNS record,
// so creating and deleting one sets the records. Serving it, the grants and
// approvers that name it, and the client's own DNS answers have no headscale
// side.
func (n *nameReplay) service(t *testing.T, stepName string, a testcapture.Action) bool {
	t.Helper()

	switch {
	case a.Kind == "dns_query",
		a.Kind == "cli" && len(a.Args) > 0 && a.Args[0] == "serve",
		a.Kind == "policy" && bytes.Contains(a.Body, []byte(`"svc:`)):
		return true
	case a.Kind != "api" || !strings.HasPrefix(a.Path, "/tailnet/-/vip-services"):
		return false
	}

	// A refused create has no address to publish.
	name, one := strings.CutPrefix(a.Path, "/tailnet/-/vip-services/svc:")
	if !one || a.Status != http.StatusOK {
		return true
	}

	switch a.Method {
	case http.MethodPut:
		var body struct {
			Addrs []string `json:"addrs"`
		}
		require.NoError(t, json.Unmarshal(a.Response, &body), "%s: %s", stepName, a.Path)

		n.services[name] = body.Addrs
	case http.MethodDelete:
		delete(n.services, name)
	default:
		return true
	}

	var records []tailcfg.DNSRecord

	for _, name := range slices.Sorted(maps.Keys(n.services)) {
		for _, addr := range n.services[name] {
			records = append(records, tailcfg.DNSRecord{Name: name + "." + n.domain + ".", Value: addr})
		}
	}

	n.srv.SetExtraRecords(records)

	return true
}

// checks compares, per device of the capture's topology in the step's device
// list, its label and hostname; per step, the viewer's peers, the v2 name's
// domain and which devices exist; per node SaaS captured, its extra records;
// and per rename or delete, its status and, for a refusal, its message.
func (n *nameReplay) checks(t *testing.T, step testcapture.Step, devices []saasDevice, answers map[int]apiAnswer) []stepCheck {
	t.Helper()

	saasViewer := step.Captures[nameViewer].Netmap
	require.NotNil(t, saasViewer, "%s: no netmap of %s", step.Name, nameViewer)

	var (
		checks  []stepCheck
		listed  []string
		domains []string
	)

	for _, d := range devices {
		x := deviceLabelAlias(d.ID)
		// Devices left from the capture before this one are not in its
		// topology.
		if _, ok := n.c.Topology.Nodes[x]; !ok {
			continue
		}

		listed = append(listed, x)

		label, _, _ := strings.Cut(d.Name, ".")
		domains = append(domains, nameDomain(d.Name))

		saasSeen, saasMissing := nodeIn(saasViewer, n.c.NodeIDs[x])

		saasSelf, captured := step.Captures[x]

		checks = append(checks,
			stepCheck{x + "/label", agreed(label, peerName(saasSeen, saasMissing), selfLabel(saasSelf.Netmap, captured)), func() string {
				dev, missing := n.hsDevice(t, x)
				if missing != "" {
					return missing
				}

				hsLabel, _, _ := strings.Cut(dev.Name, ".")
				seen, seenMissing := n.hsSeen(x)

				return agreed(hsLabel, peerName(seen, seenMissing), selfLabel(n.clients[x].Netmap(), captured))
			}},
			stepCheck{x + "/hostname", agreed(d.Hostname, peerHostname(saasSeen, saasMissing), ""), func() string {
				dev, missing := n.hsDevice(t, x)
				if missing != "" {
					return missing
				}

				return agreed(dev.Hostname, peerHostname(n.hsSeen(x)), "")
			}},
		)
	}

	// Only this capture's devices: the one before left its own behind.
	inTopology := func(alias func(tailcfg.NodeID) (string, bool)) func(tailcfg.NodeID) (string, bool) {
		return func(id tailcfg.NodeID) (string, bool) {
			x, ok := alias(id)
			_, mine := n.c.Topology.Nodes[x]

			return x, ok && mine
		}
	}

	checks = append(checks,
		stepCheck{nameViewer + "/peers", peerAliases(saasViewer, inTopology(n.saasAlias)), func() string {
			return peerAliases(n.clients[nameViewer].Netmap(), inTopology(n.hsAlias))
		}},
		stepCheck{"devices", sortedStrings(listed), func() string {
			var live []string

			for x := range n.c.Topology.Nodes {
				if len(n.machineNodes(x)) > 0 {
					live = append(live, x)
				}
			}

			return sortedStrings(live)
		}},
		stepCheck{"domain", distinct(domains), func() string {
			var got []string

			for _, x := range listed {
				dev, missing := n.hsDevice(t, x)
				if missing != "" {
					return missing
				}

				got = append(got, nameDomain(dev.Name))
			}

			return distinct(got)
		}},
	)

	for _, x := range slices.Sorted(maps.Keys(step.Captures)) {
		saas := step.Captures[x].Netmap
		require.NotNil(t, saas, "%s: no netmap of %s", step.Name, x)

		checks = append(checks, stepCheck{x + "/records", renderRecords(saas), func() string {
			return renderRecords(n.clients[x].Netmap())
		}})
	}

	for i, a := range step.Actions {
		if a.Kind != "api" || a.Method == http.MethodGet || !strings.HasPrefix(a.Path, "/device/") {
			continue
		}

		got, ok := answers[i]
		require.True(t, ok, "%s: %s %s not replayed", step.Name, a.Method, a.Path)

		idx := strconv.Itoa(i)
		checks = append(checks, stepCheck{idx + "/status", strconv.Itoa(a.Status), func() string { return strconv.Itoa(got.status) }})

		if a.Status >= http.StatusBadRequest {
			want := errorMessage(a.Response)
			checks = append(checks, stepCheck{idx + "/message", want, func() string {
				hs := errorMessage(got.body)
				if strings.Contains(hs, want) {
					return want
				}

				return hs
			}})
		}
	}

	return checks
}

// hsDevice reads alias's device from headscale's v2 API, while its machine
// holds one node.
func (n *nameReplay) hsDevice(t *testing.T, alias string) (saasDevice, string) {
	t.Helper()

	nodes := n.machineNodes(alias)
	if len(nodes) != 1 {
		return saasDevice{}, fmt.Sprintf("devices %d", len(nodes))
	}

	status, body := n.call(t, http.MethodGet, "/api/v2/device/"+nodes[0].StringID(), nil)
	require.Equal(t, http.StatusOK, status, "%s", body)

	var dev saasDevice
	require.NoError(t, json.Unmarshal(body, &dev))

	return dev, ""
}

// hsSeen is alias's node as headscale's viewer sees it.
func (n *nameReplay) hsSeen(alias string) (tailcfg.NodeView, string) {
	nodes := n.machineNodes(alias)
	if len(nodes) != 1 {
		return tailcfg.NodeView{}, fmt.Sprintf("devices %d", len(nodes))
	}

	return nodeIn(n.clients[nameViewer].Netmap(), nodes[0].ID().NodeID())
}

// nodeIn finds node id in nm, itself or as a peer.
func nodeIn(nm *netmap.NetworkMap, id tailcfg.NodeID) (tailcfg.NodeView, string) {
	if nm != nil && nm.SelfNode.Valid() && nm.SelfNode.ID() == id {
		return nm.SelfNode, ""
	}

	return peerByID(nm, id)
}

// agreed is the one value the API, the viewer and the node itself show, or
// all three when they differ. self is empty when not compared.
func agreed(api, viewer, self string) string {
	if api == viewer && (self == "" || self == api) {
		return api
	}

	return fmt.Sprintf("api %q, viewer %q, self %q", api, viewer, self)
}

// selfLabel is the first label of nm's own name, when SaaS captured it.
func selfLabel(nm *netmap.NetworkMap, captured bool) string {
	if !captured {
		return ""
	}

	if nm == nil || !nm.SelfNode.Valid() {
		return "no netmap"
	}

	label, _, _ := strings.Cut(nm.SelfNode.Name(), ".")

	return label
}

func peerHostname(p tailcfg.NodeView, missing string) string {
	if missing != "" {
		return missing
	}

	return p.Hostinfo().Hostname()
}

// nameDomain is what follows a device name's first label.
func nameDomain(name string) string {
	if _, domain, ok := strings.Cut(name, "."); ok {
		return domain
	}

	return "none"
}

func distinct(s []string) string {
	return fmt.Sprint(slices.Compact(slices.Sorted(slices.Values(s))))
}

// renderRecords lists nm's extra DNS records.
func renderRecords(nm *netmap.NetworkMap) string {
	if nm == nil {
		return "no netmap"
	}

	out := make([]string, 0, len(nm.DNS.ExtraRecords))
	for _, r := range nm.DNS.ExtraRecords {
		out = append(out, r.Name+" "+r.Type+" "+r.Value)
	}

	return sortedStrings(out)
}

// errorMessage is an error body's text: SaaS's message, or headscale's
// detail and error messages.
func errorMessage(body []byte) string {
	var e struct {
		Message string `json:"message"`
		Detail  string `json:"detail"`
		Errors  []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}

	if json.Unmarshal(body, &e) != nil {
		return string(body)
	}

	texts := []string{e.Message, e.Detail}
	for _, x := range e.Errors {
		texts = append(texts, x.Message)
	}

	return strings.Join(slices.DeleteFunc(texts, func(s string) bool { return s == "" }), " | ")
}
