// Compatibility tests for tags owned by tags: which tags a user, a tagged
// auth key and an OAuth client may apply when tagOwners chain tags, as
// Tailscale SaaS answered joins, relogins and key mints.
//
// Test data source: ../../servertest/testdata/steps/tag-owner-chain.hujson,
// loaded by name; the servertest step captures live there.
// Source format:    github.com/juanfont/headscale/hscontrol/types/testcapture

package v2

import (
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/types/testcapture"
	"github.com/stretchr/testify/require"
)

// tagOwnerSkipReasons lists checks where headscale differs from SaaS, keyed
// <test_id>/<step>/<function>. A listed check that matches fails, so a fix
// must delete its entry.
var tagOwnerSkipReasons = map[string]string{
	"tag-owner-chain/C-two-mint-subset/TagOwnedByTags": clientTagSubset,
}

const clientTagSubset = "CLIENT_TAG_SUBSET: headscale lets an OAuth client mint a key with a subset of its tags; SaaS needs that subset owned by the client's tags"

// TestTagOwnerChainCompat compares each SaaS verdict on a tag request with
// the policy function headscale asks for that request:
//   - a join with a user's untagged key and requested tags: UserCanHaveTag,
//     and NodeCanHaveTag for a node the policy does not know yet;
//   - a relogin of the user's existing node with requested tags:
//     NodeCanHaveTag for that node;
//   - an OAuth client's key mint: TagOwnedByTags with the client's tags.
//
// Only a login without a key asks the first two: a key login never asks the
// policy about requested tags. So TestReauthCompat in ../../servertest also
// replays the joins through registration, and checks a tagged key's joins
// only there. The user's own mints have no verdict: as a member his API key
// could not mint at all.
func TestTagOwnerChainCompat(t *testing.T) {
	t.Parallel()

	const id = "tag-owner-chain"

	c, err := testcapture.Read(filepath.Join("..", "..", "servertest", "testdata", "steps", id+".hujson"))
	require.NoError(t, err)
	require.NotEmpty(t, c.Steps, "%s: not a step capture", id)

	users := setupGrantsCompatUsers()
	nodes := buildGrantsNodesFromCapture(users, c)

	pm, err := NewPolicyManager([]byte(c.Input.FullPolicy), users, nodes.ViewSlice())
	require.NoError(t, err)

	byName := func(name string) *types.User {
		i := slices.IndexFunc(users, func(u types.User) bool { return u.Name == name })
		require.GreaterOrEqual(t, i, 0, "no user %s", name)

		return &users[i]
	}

	// credentialTags holds the tags of each tagged key and OAuth client, and
	// keyUsers the owner of each untagged key, by label.
	credentialTags := map[string][]string{}
	keyUsers := map[string]*types.User{}

	// One verdict per step and function, read in order: a mint's tags are
	// known only once its step has been read.
	type row struct {
		step, function string
		want           bool
		got            func() bool
	}

	var rows []row

	for _, step := range c.Steps {
		if step.Result != "observed" {
			continue
		}

		for _, a := range step.Actions {
			switch {
			case a.Kind == "api" && a.Method == http.MethodPost && a.Path == "/tailnet/-/keys":
				var body struct {
					Tags         []string `json:"tags"`
					Capabilities struct {
						Devices struct {
							Create struct {
								Tags []string `json:"tags"`
							} `json:"create"`
						} `json:"devices"`
					} `json:"capabilities"`
				}
				require.NoError(t, json.Unmarshal(a.Body, &body), "%s: mint body", step.Name)

				tags := body.Capabilities.Devices.Create.Tags
				client, byToken := strings.CutPrefix(a.Principal, "token:")

				switch {
				case a.Client != "":
					credentialTags[a.Client] = body.Tags
				case byToken:
					owners := credentialTags[client]

					rows = append(rows, row{step.Name, "TagOwnedByTags", a.Status == http.StatusOK, func() bool {
						return ownedByTags(pm, tags, owners)
					}})
				case len(tags) > 0:
					credentialTags[a.Key] = tags
				default:
					owner := byName("odin")
					if name, ok := strings.CutPrefix(a.Principal, "user:"); ok {
						owner = byName(name)
					}

					keyUsers[a.Key] = owner
				}

			case a.Kind == "join" && a.RequestTags != nil:
				if _, tagged := credentialTags[a.Key]; tagged {
					continue
				}

				tags := *a.RequestTags
				want := tagsGranted(t, step, a.Node, tags)

				user := keyUsers[a.Key]
				require.NotNil(t, user, "%s: join with unknown key %s", step.Name, a.Key)

				// Outside the policy's node set, as a node that is only now
				// registering.
				fresh := (&types.Node{
					ID:     types.NodeID(len(nodes) + 1), //nolint:gosec
					User:   user,
					UserID: &user.ID,
					IPv4:   ptrAddr("100.64.255.254"),
				}).View()

				rows = append(rows,
					row{step.Name, "UserCanHaveTag", want, func() bool {
						return allTags(tags, func(tag string) bool { return pm.UserCanHaveTag(user.View(), tag) })
					}},
					row{step.Name, "NodeCanHaveTag", want, func() bool {
						return allTags(tags, func(tag string) bool { return pm.NodeCanHaveTag(fresh, tag) })
					}},
				)

			case a.Kind == "relogin" && a.RequestTags != nil:
				tags := *a.RequestTags
				want := tagsGranted(t, step, a.Node, tags)

				node := findGrantsNode(nodes, a.Node)
				require.NotNil(t, node, "%s: %s is not in the topology", step.Name, a.Node)

				rows = append(rows, row{step.Name, "NodeCanHaveTag", want, func() bool {
					return allTags(tags, func(tag string) bool { return pm.NodeCanHaveTag(node.View(), tag) })
				}})
			}
		}
	}

	evaluated := map[string]bool{}

	for _, step := range c.Steps {
		stepRows := slices.DeleteFunc(slices.Clone(rows), func(r row) bool { return r.step != step.Name })
		if len(stepRows) == 0 {
			continue
		}

		for _, r := range stepRows {
			evaluated[id+"/"+r.step+"/"+r.function] = true
		}

		t.Run(step.Name, func(t *testing.T) {
			t.Parallel()

			for _, r := range stepRows {
				compatCheck(t, tagOwnerSkipReasons, id+"/"+r.step+"/"+r.function, func() string {
					if got := r.got(); got != r.want {
						return fmt.Sprintf("SaaS allowed %t, headscale %t", r.want, got)
					}

					return ""
				})
			}
		})
	}

	for k := range tagOwnerSkipReasons {
		if !evaluated[k] {
			t.Errorf("skip entry %q names no check", k)
		}
	}
}

// tagsGranted reports whether SaaS gave node's device every requested tag:
// the step's device list holds a device on node's machine carrying them.
func tagsGranted(t *testing.T, step testcapture.Step, node string, tags []string) bool {
	t.Helper()

	for _, a := range slices.Backward(step.Actions) {
		if a.Kind != "api" || a.Method != http.MethodGet || !strings.HasPrefix(a.Path, "/tailnet/-/devices") {
			continue
		}

		var out struct {
			Devices []struct {
				MachineKey string   `json:"machineKey"`
				Tags       []string `json:"tags"`
			} `json:"devices"`
		}
		require.NoError(t, json.Unmarshal(a.Response, &out), "%s: device list", step.Name)

		return slices.ContainsFunc(out.Devices, func(d struct {
			MachineKey string   `json:"machineKey"`
			Tags       []string `json:"tags"`
		},
		) bool {
			return d.MachineKey == "{machine:"+node+"}" &&
				allTags(tags, func(tag string) bool { return slices.Contains(d.Tags, tag) })
		})
	}

	t.Fatalf("%s: no device list", step.Name)

	return false
}

func ownedByTags(pm *PolicyManager, tags, ownerTags []string) bool {
	return allTags(tags, func(tag string) bool { return pm.TagOwnedByTags(tag, ownerTags) })
}

func allTags(tags []string, ok func(string) bool) bool {
	return len(tags) > 0 && !slices.ContainsFunc(tags, func(tag string) bool { return !ok(tag) })
}
