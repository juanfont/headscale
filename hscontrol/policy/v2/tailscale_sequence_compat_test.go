// Compatibility tests for one policy compiled again and again as the nodes
// under it change: members join, a second via router joins and the first
// withdraws its routes, the admin tags one member's device and deletes
// another, then the group the policy names everywhere is edited. Each step
// is compared with what Tailscale SaaS sent every live node.
//
// Test data source: ../../servertest/testdata/steps/policy-generation.hujson,
// loaded by name; TestPolicySequenceMapCompat in ../../servertest replays it
// through real clients.
// Source format:    github.com/juanfont/headscale/hscontrol/types/testcapture

package v2

import (
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"net/netip"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/types/testcapture"
	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
)

// policySequenceSkipReasons lists checks where headscale differs from SaaS,
// keyed <test_id>/<step>/<node>/<check>. A listed check that matches fails,
// so a fix must delete its entry.
var policySequenceSkipReasons = map[string]string{
	"policy-generation/G0/rt/filter":   viaRuleMerged,
	"policy-generation/G1/rt/filter":   viaRuleMerged,
	"policy-generation/G2/rt/filter":   viaRuleMerged,
	"policy-generation/G3/rt/filter":   viaRuleMerged,
	"policy-generation/G3/rt-b/filter": viaRuleMerged,
	"policy-generation/G4/rt-b/filter": viaRuleMerged,
	"policy-generation/G5/rt-b/filter": viaRuleMerged,

	"policy-generation/G7/rt-plain/filter": deletedDeviceInRules,
	"policy-generation/G7/srv/ssh-rules":   deletedDeviceInRules,
	"policy-generation/G7/srv/uid-zero":    deletedDeviceInRules,
	"policy-generation/G7/srv/filter":      deletedDeviceInRules,
	"policy-generation/G7/rt-b/filter":     "VIA_RULE_MERGED+DELETED_DEVICE_IN_RULES: the via grant's rule apart from the ACL rule, and the deleted device's addresses kept",
}

const (
	viaRuleMerged        = "VIA_RULE_MERGED: on a via router headscale merges the via grant's filter rule with an ACL rule of the same sources; SaaS sends the two apart"
	deletedDeviceInRules = "DELETED_DEVICE_IN_RULES: SaaS keeps a deleted device's addresses in other nodes' filter and SSH rules until the next policy change; headscale drops them with the device"
)

// TestPolicySequenceCompat follows the capture with one PolicyManager, as
// headscale does: SetNodes after each node change, SetPolicy for the edit,
// with nodes rebuilt from the step's device list and route reads. After each
// step it compares, per node SaaS captured, the filter and SSH rules, and
// the auto-approval of routes the step advertised. At every step the manager
// must also answer as one built from that step's inputs alone, so a cache
// that outlives its inputs shows without SaaS.
func TestPolicySequenceCompat(t *testing.T) {
	t.Parallel()

	t.Run("policy-generation", func(t *testing.T) {
		t.Parallel()

		runPolicySequenceCompat(t, "policy-generation")
	})
}

// runPolicySequenceCompat replays capture id step by step. Steps run in
// order, since the one manager carries each into the next.
func runPolicySequenceCompat(t *testing.T, id string) {
	t.Helper()

	c, err := testcapture.Read(filepath.Join("..", "..", "servertest", "testdata", "steps", id+".hujson"))
	require.NoError(t, err)
	require.NotEmpty(t, c.Steps, "%s: not a step capture", id)

	users := setupGrantsCompatUsers()

	// Node IDs follow join order, as headscale would assign them.
	ids := map[string]types.NodeID{}

	var (
		pm     *PolicyManager
		policy []byte
	)

	evaluated := map[string]bool{}

	for _, step := range c.Steps {
		require.Equal(t, "observed", step.Result, "%s: the replay follows every step", step.Name)

		for _, a := range step.Actions {
			if _, ok := ids[a.Node]; a.Kind == "join" && !ok {
				ids[a.Node] = types.NodeID(len(ids) + 1) //nolint:gosec // a handful of nodes
			}
		}

		nodes, approved := sequenceNodes(t, users, step, ids)
		pushed := stepPolicy(t, step)

		if pm == nil {
			require.NotNil(t, pushed, "%s: the first step sets the policy", step.Name)

			policy = pushed
			pm, err = NewPolicyManager(policy, users, nodes.ViewSlice())
			require.NoError(t, err, "%s: policy", step.Name)
		} else {
			_, err = pm.SetNodes(nodes.ViewSlice())
			require.NoError(t, err, "%s: nodes", step.Name)

			if pushed != nil {
				policy = pushed
				_, err = pm.SetPolicy(policy)
				require.NoError(t, err, "%s: policy", step.Name)
			}
		}

		pol, err := unmarshalPolicy(policy)
		require.NoError(t, err, "%s: policy", step.Name)

		fresh, err := NewPolicyManager(policy, users, nodes.ViewSlice())
		require.NoError(t, err, "%s: policy", step.Name)

		t.Run(step.Name, func(t *testing.T) {
			t.Run("fresh", func(t *testing.T) {
				if diff := freshMismatch(pm, fresh, nodes); diff != "" {
					t.Error(diff)
				}
			})

			for _, alias := range slices.Sorted(maps.Keys(step.Captures)) {
				capture := step.Captures[alias]
				node := findGrantsNode(nodes, alias)
				require.NotNil(t, node, "%s: %s is not in the device list", step.Name, alias)

				key := id + "/" + step.Name + "/" + alias + "/"

				t.Run(alias, func(t *testing.T) {
					check := func(name string, mismatch func() string) {
						evaluated[key+name] = true
						compatCheck(t, policySequenceSkipReasons, key+name, mismatch)
					}

					check("filter", func() string {
						got, err := pm.FilterForNode(node.View())
						if err != nil {
							return err.Error()
						}

						return cmp.Diff(capture.PacketFilterRules, got, append(cmpOptions(), cmpopts.EquateEmpty())...)
					})

					check("ssh-rules", func() string {
						return sshRulesMismatch(pol, pm, users, nodes, node, capture, withoutUIDZero)
					})

					check("uid-zero", func() string {
						return uidZeroMismatch(pm, node, capture)
					})

					// Approval is judged only where the step advertised:
					// approvals that outlive eligibility are not asked here.
					if advertised := joinRoutes(step, alias); len(advertised) > 0 {
						check("auto-approval", func() string {
							var want, got []string

							for _, p := range advertised {
								want = append(want, fmt.Sprintf("%s %t", p, slices.Contains(approved[alias], p)))
								got = append(got, fmt.Sprintf("%s %t", p, pm.NodeCanApproveRoute(node.View(), p)))
							}

							return cmp.Diff(want, got)
						})
					}
				})
			}
		})
	}

	// The map serves this one capture, so a key naming another fails too.
	for k := range policySequenceSkipReasons {
		if !evaluated[k] {
			t.Errorf("skip entry %q names no check", k)
		}
	}
}

// freshMismatch compares the manager that followed every step with one built
// from the step's inputs alone: per node its filter, SSH policy and via
// routes towards every peer, and the peer map; "" is a match.
func freshMismatch(pm, fresh *PolicyManager, nodes types.Nodes) string {
	opts := cmpopts.EquateComparable(netip.Prefix{}, netip.Addr{})

	var diffs []string

	add := func(what string, want, got any, errs ...error) {
		for _, err := range errs {
			if err != nil {
				diffs = append(diffs, what+": "+err.Error())

				return
			}
		}

		if diff := cmp.Diff(want, got, opts); diff != "" {
			diffs = append(diffs, fmt.Sprintf("%s (-fresh +incremental):\n%s", what, diff))
		}
	}

	for _, n := range nodes {
		nv := n.View()

		wantFilter, errW := fresh.FilterForNode(nv)
		gotFilter, errG := pm.FilterForNode(nv)
		add(n.GivenName+" filter", wantFilter, gotFilter, errW, errG)

		wantSSH, errW := fresh.SSHPolicy("https://unused", nv)
		gotSSH, errG := pm.SSHPolicy("https://unused", nv)
		add(n.GivenName+" SSH policy", wantSSH, gotSSH, errW, errG)

		for _, p := range nodes {
			if p.ID != n.ID {
				add(n.GivenName+" via routes of "+p.GivenName,
					fresh.ViaRoutesForPeer(nv, p.View()), pm.ViaRoutesForPeer(nv, p.View()))
			}
		}
	}

	add("peer map", fresh.BuildPeerMap(nodes.ViewSlice()), pm.BuildPeerMap(nodes.ViewSlice()))

	return strings.Join(diffs, "\n")
}

// sequenceDevice is the part of a SaaS device-list entry a node is built
// from. The ID is the capture's "{device:<alias>}" label.
type sequenceDevice struct {
	ID        string   `json:"id"`
	Addresses []string `json:"addresses"`
	Tags      []string `json:"tags"`
	User      string   `json:"user"`
}

// sequenceNodes builds the nodes SaaS listed after step: addresses, tags and,
// for untagged devices, the owner from the device list; advertised and
// approved routes from the step's route reads. It also returns each node's
// approved routes. A tagged node has no user, as headscale stores it.
func sequenceNodes(
	t *testing.T,
	users types.Users,
	step testcapture.Step,
	ids map[string]types.NodeID,
) (types.Nodes, map[string][]netip.Prefix) {
	t.Helper()

	var (
		devices    []sequenceDevice
		listed     bool
		advertised = map[string][]netip.Prefix{}
		approved   = map[string][]netip.Prefix{}
	)

	for _, a := range step.Actions {
		if a.Kind != "api" || a.Method != http.MethodGet {
			continue
		}

		switch {
		case a.Path == "/tailnet/-/devices":
			var out struct {
				Devices []sequenceDevice `json:"devices"`
			}
			require.NoError(t, json.Unmarshal(a.Response, &out), "%s: device list", step.Name)

			devices, listed = out.Devices, true

		case strings.HasPrefix(a.Path, "/device/{device:") && strings.HasSuffix(a.Path, "}/routes"):
			alias := strings.TrimSuffix(strings.TrimPrefix(a.Path, "/device/{device:"), "}/routes")

			var out struct {
				Advertised []netip.Prefix `json:"advertisedRoutes"`
				Enabled    []netip.Prefix `json:"enabledRoutes"`
			}
			require.NoError(t, json.Unmarshal(a.Response, &out), "%s: routes of %s", step.Name, alias)

			advertised[alias], approved[alias] = out.Advertised, out.Enabled
		}
	}

	require.True(t, listed, "%s: no device list", step.Name)

	nodes := make(types.Nodes, 0, len(devices))

	for _, d := range devices {
		alias := strings.TrimSuffix(strings.TrimPrefix(d.ID, "{device:"), "}")

		id, ok := ids[alias]
		require.True(t, ok, "%s: %s never joined", step.Name, alias)

		_, read := approved[alias]
		require.True(t, read, "%s: no route read for %s", step.Name, alias)

		node := &types.Node{
			ID:             id,
			Hostname:       alias,
			GivenName:      alias,
			Tags:           d.Tags,
			Hostinfo:       &tailcfg.Hostinfo{RoutableIPs: advertised[alias]},
			ApprovedRoutes: approved[alias],
		}

		for _, s := range d.Addresses {
			addr := netip.MustParseAddr(s)
			if addr.Is4() {
				node.IPv4 = &addr
			} else {
				node.IPv6 = &addr
			}
		}

		if len(d.Tags) == 0 {
			i := slices.IndexFunc(users, func(u types.User) bool { return u.Email == d.User })
			require.GreaterOrEqual(t, i, 0, "%s: %s owned by unknown %q", step.Name, alias, d.User)

			node.User = &users[i]
			node.UserID = &users[i].ID
		}

		nodes = append(nodes, node)
	}

	return nodes, approved
}

// stepPolicy returns the policy the step pushed, or nil.
func stepPolicy(t *testing.T, step testcapture.Step) []byte {
	t.Helper()

	var out []byte

	for _, a := range step.Actions {
		if a.Kind != "policy" {
			continue
		}

		require.Equal(t, http.StatusOK, a.Status, "%s: refused policy", step.Name)

		// HuJSON bodies are stored as a JSON string.
		out = a.Body
		if strings.HasPrefix(string(a.Body), `"`) {
			var s string
			require.NoError(t, json.Unmarshal(a.Body, &s), "%s: policy body", step.Name)

			out = []byte(s)
		}
	}

	return out
}

// joinRoutes returns the routes alias advertised when it joined in step.
func joinRoutes(step testcapture.Step, alias string) []netip.Prefix {
	var out []netip.Prefix

	for _, a := range step.Actions {
		if a.Kind == "join" && a.Node == alias {
			for _, r := range a.Routes {
				out = append(out, netip.MustParsePrefix(r))
			}
		}
	}

	return out
}
