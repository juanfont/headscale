// This file replays pending interactive logins captured from Tailscale SaaS
// through the register handler, one client exchange at a time.
//
// Test data source: servertest/testdata/steps/pending-login.hujson, loaded
// by name.
// Source format:    github.com/juanfont/headscale/hscontrol/types/testcapture

package hscontrol

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/types/testcapture"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

// pendingLoginSkipReasons lists checks where headscale differs from SaaS,
// keyed <test_id>/<step>/<node>/<check>. A listed check that matches fails,
// so a fix must delete its entry.
var pendingLoginSkipReasons = map[string]string{
	"pending-login/PL-E2-expire-restart/pl-laptop/exchange-0": expiredRestartUnauthorized,
	"pending-login/PL-E3-restart/pl-laptop/exchange-1":        expiredRestartUnauthorized,

	"pending-login/PL-E4-restore/pl-laptop/exchange-0": loginCompletedByRestore,
	"pending-login/PL-E4-restore/pl-laptop/devices":    loginCompletedByRestore,
}

const expiredRestartUnauthorized = "EXPIRED_RESTART_UNAUTHORIZED: headscale answers an expired node's restart with MachineAuthorized false; SaaS answers true, and both say the node key expired"

// SaaS behaviour recorded as it is, not followed.
const loginCompletedByRestore = "LOGIN_COMPLETED_BY_RESTORE: SaaS completes a waiting login when the device's key expiry is turned off, giving it the client's newest node key without a login; headscale keeps the login waiting"

// TestPendingLoginCompat replays a fresh machine's interactive login across
// a restart and a stop, and an expired device restarted twice while its
// login waits, then restored. Each exchange the client logged is sent as the
// client sent it: same machine and node keys, follow-ups to the URL the
// server gave. It compares each answer's flags, whether an auth URL is new or
// repeats an earlier one, and the devices on each machine with their node
// key. The replay approves no login itself, so a waiting login that SaaS
// completed on restore shows in the follow-up's answer and the node key.
func TestPendingLoginCompat(t *testing.T) {
	t.Parallel()

	runPendingLoginCompat(t, "pending-login")
}

func runPendingLoginCompat(t *testing.T, id string) {
	t.Helper()

	c, err := testcapture.Read(filepath.Join("servertest", "testdata", "steps", id+".hujson"))
	require.NoError(t, err)
	require.NotEmpty(t, c.Steps, "%s: not a step capture", id)

	r := newPendingReplay(t, c)

	for _, step := range c.Steps {
		require.Equal(t, "observed", step.Result, "%s: the replay follows every step", step.Name)

		r.step(t, step)
	}

	// The map serves this capture alone, so every entry must name a check.
	for k := range pendingLoginSkipReasons {
		if !r.evaluated[k] {
			t.Errorf("skip entry %q names no check", k)
		}
	}
}

// pendingReplay drives the register handler as the capture's clients did.
// SaaS labels for node keys and auth URLs map to the keys the replay makes
// and the auth IDs headscale returns.
type pendingReplay struct {
	c     *testcapture.Capture
	app   *Headscale
	users map[string]*types.User
	owner *types.User

	machines  map[string]key.MachinePrivate
	nodeKeys  map[string]key.NodePrivate
	keyLabels map[key.NodePublic]string
	authKeys  map[string]string

	// urls holds each auth URL in the order it was given: SaaS's label
	// and headscale's auth ID.
	urls []pendingURL

	// held is the auth key each client still holds in memory, lastURL the
	// auth URL label it was last given, waiting its follow-up in flight.
	held     map[string]string
	hostname map[string]string
	lastURL  map[string]types.AuthID
	waiting  map[string]*pendingFollowup

	evaluated map[string]bool
}

type pendingURL struct {
	label  string
	authID types.AuthID
}

// pendingFollowup is a follow-up parked in the register handler.
type pendingFollowup struct {
	nodeKey string
	cancel  context.CancelFunc
	done    chan struct{}
	answer  string
}

func newPendingReplay(t *testing.T, c *testcapture.Capture) *pendingReplay {
	t.Helper()

	r := &pendingReplay{
		c:         c,
		app:       createTestApp(t),
		users:     map[string]*types.User{},
		machines:  map[string]key.MachinePrivate{},
		nodeKeys:  map[string]key.NodePrivate{},
		keyLabels: map[key.NodePublic]string{},
		authKeys:  map[string]string{},
		held:      map[string]string{},
		hostname:  map[string]string{},
		lastURL:   map[string]types.AuthID{},
		waiting:   map[string]*pendingFollowup{},
		evaluated: map[string]bool{},
	}

	for _, u := range c.Topology.Users {
		r.users[u.Name] = r.app.state.CreateUserForTest(u.Name)
		if u.Email == c.Tailnet {
			r.owner = r.users[u.Name]
		}
	}

	require.NotNil(t, r.owner, "%s: tailnet %q is not a capture user", c.TestID, c.Tailnet)

	t.Cleanup(func() {
		for _, f := range r.waiting {
			f.cancel()
			<-f.done
		}
	})

	return r
}

// pendingCheck is one rendering of an outcome: SaaS's, and how to read
// headscale's.
type pendingCheck struct {
	name string
	want string
	got  func() string
}

// step applies the step's actions, then sends its register exchanges, then
// compares the outcome.
func (r *pendingReplay) step(t *testing.T, step testcapture.Step) {
	t.Helper()

	r.apply(t, step)

	var checks []pendingCheck

	for _, node := range slices.Sorted(maps.Keys(step.Register)) {
		for i, a := range step.Register[node] {
			name := fmt.Sprintf("%s/exchange-%d", node, i)

			switch {
			case strings.Contains(a.Err, "context canceled"):
				// The client gave up on a request when it restarted.
				continue

			case a.Err != "":
				t.Fatalf("%s: %s: no replay for a refusal: %s", step.Name, name, a.Err)

			case a.Followup && a.OffsetMS < 0:
				// Sent in an earlier step and answered in this one.
				f := r.waiting[node]
				require.NotNil(t, f, "%s: %s answers no follow-up", step.Name, name)
				require.Equal(t, a.NodeKey, f.nodeKey, "%s: %s", step.Name, name)

				checks = append(checks, pendingCheck{name, registerFlags(a), f.state})

			case a.Followup:
				f := r.followup(t, step, node, a)
				checks = append(checks, pendingCheck{name, registerFlags(a), f.state})

			default:
				got := r.register(t, step, node, a)
				checks = append(checks, pendingCheck{name, registerFlags(a), func() string { return got }})

				if a.AuthURL != "" {
					checks = append(checks, r.authURLCheck(name))
				}
			}
		}
	}

	checks = append(checks, r.deviceChecks(t, step)...)

	r.hold(t, r.c.TestID+"/"+step.Name+"/", checks)
}

// apply runs the step's actions.
func (r *pendingReplay) apply(t *testing.T, step testcapture.Step) {
	t.Helper()

	for _, a := range step.Actions {
		switch a.Kind {
		case "join", "relogin":
			r.held[a.Node] = a.Key
			r.hostname[a.Node] = a.Hostname

		case "restart", "kill":
			// A new process: the follow-up dies and the key held in memory
			// is gone.
			r.stopWaiting(a.Node)
			r.held[a.Node] = ""

		case "retire":
			r.stopWaiting(a.Node)

			for _, nv := range r.nodes(a.Node) {
				changes, err := r.app.state.DeleteNode(nv)
				require.NoError(t, err, "%s: retire %s", step.Name, a.Node)
				r.app.Change(changes...)
			}

		case "wait":

		case "api":
			r.api(t, step, a)

		default:
			t.Fatalf("%s: no replay for action %q", step.Name, a.Kind)
		}
	}
}

// api replays one admin exchange: key mints, expiry and the key expiry
// setting. Reads are what the checks compare.
func (r *pendingReplay) api(t *testing.T, step testcapture.Step, a testcapture.Action) {
	t.Helper()

	switch {
	case a.Method == http.MethodGet:

	case a.Method == http.MethodPost && a.Path == "/tailnet/-/keys":
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
		require.NoError(t, json.Unmarshal(a.Body, &body), "%s: key body", step.Name)

		create := body.Capabilities.Devices.Create
		expiry := time.Now().Add(time.Duration(body.ExpirySeconds) * time.Second)
		uid := types.UserID(r.owner.ID)

		pak, err := r.app.state.CreatePreAuthKey(&uid, create.Reusable, create.Ephemeral, &expiry, create.Tags)
		require.NoError(t, err, "%s: mint %s", step.Name, a.Key)

		r.authKeys[a.Key] = pak.Key

	case a.Method == http.MethodPost && strings.HasSuffix(a.Path, "/expire"):
		now := time.Now()
		r.setExpiry(t, step, a, &now)

	case a.Method == http.MethodPost && strings.HasSuffix(a.Path, "/key"):
		var body struct {
			KeyExpiryDisabled bool `json:"keyExpiryDisabled"`
		}
		require.NoError(t, json.Unmarshal(a.Body, &body), "%s: key body", step.Name)

		// As the v2 API: only turning expiry off maps onto headscale.
		if body.KeyExpiryDisabled {
			r.setExpiry(t, step, a, nil)
		}

	default:
		t.Fatalf("%s: no replay for %s %s", step.Name, a.Method, a.Path)
	}
}

func (r *pendingReplay) setExpiry(t *testing.T, step testcapture.Step, a testcapture.Action, expiry *time.Time) {
	t.Helper()

	alias, _, _ := strings.Cut(strings.TrimPrefix(a.Path, "/device/{device:"), "}")
	nodes := r.nodes(alias)
	require.Len(t, nodes, 1, "%s: %s", step.Name, a.Path)

	_, changes, err := r.app.state.SetNodeExpiry(nodes[0].ID(), expiry)
	require.NoError(t, err, "%s: %s", step.Name, a.Path)
	r.app.Change(changes)
}

// request builds the register request a client sent: its node keys, the
// key it holds, and its hostname.
func (r *pendingReplay) request(node string, a testcapture.RegisterAttempt) tailcfg.RegisterRequest {
	req := tailcfg.RegisterRequest{
		NodeKey:  r.nodeKey(a.NodeKey).Public(),
		Hostinfo: &tailcfg.Hostinfo{Hostname: r.hostname[node]},
	}

	if a.OldNodeKey != "" {
		req.OldNodeKey = r.nodeKey(a.OldNodeKey).Public()
	}

	if label := r.held[node]; label != "" {
		req.Auth = &tailcfg.RegisterResponseAuth{AuthKey: r.authKeys[label]}
	}

	return req
}

// register sends one exchange and returns its answer's flags. An auth URL
// is mapped to SaaS's label, so a follow-up can go to it.
func (r *pendingReplay) register(t *testing.T, step testcapture.Step, node string, a testcapture.RegisterAttempt) string {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	resp, err := r.app.handleRegister(ctx, r.request(node, a), r.machine(node).Public())

	got := responseFlags(resp, err)

	if a.AuthURL != "" && resp != nil && resp.AuthURL != "" {
		authID, err := extractRegistrationIDFromAuthURL(resp.AuthURL)
		require.NoError(t, err, "%s: %s's auth URL", step.Name, node)

		r.urls = append(r.urls, pendingURL{label: a.AuthURL, authID: authID})
		r.lastURL[node] = authID
	}

	return got
}

// followup parks a follow-up to the auth URL node was last given, as
// tailscaled does while the login waits.
func (r *pendingReplay) followup(t *testing.T, step testcapture.Step, node string, a testcapture.RegisterAttempt) *pendingFollowup {
	t.Helper()

	authID, ok := r.lastURL[node]
	require.True(t, ok, "%s: %s follows up on no auth URL", step.Name, node)

	r.stopWaiting(node)

	req := r.request(node, a)
	req.Followup = r.app.authProvider.RegisterURL(authID)

	ctx, cancel := context.WithCancel(context.Background())
	f := &pendingFollowup{nodeKey: a.NodeKey, cancel: cancel, done: make(chan struct{})}
	machine := r.machine(node).Public()

	go func() {
		defer close(f.done)

		resp, err := r.app.handleRegister(ctx, req, machine)
		if ctx.Err() == nil {
			f.answer = responseFlags(resp, err)
		}
	}()

	r.waiting[node] = f

	return f
}

// state is the follow-up's answer, or "unanswered" while it waits.
func (f *pendingFollowup) state() string {
	select {
	case <-f.done:
		if f.answer == "" {
			return "cancelled"
		}

		return f.answer
	default:
		return "unanswered"
	}
}

func (r *pendingReplay) stopWaiting(node string) {
	if f, ok := r.waiting[node]; ok {
		f.cancel()
		<-f.done
		delete(r.waiting, node)
	}
}

// authURLCheck says whether the last auth URL given is new or repeats an
// earlier one, on SaaS by label and on headscale by auth ID.
func (r *pendingReplay) authURLCheck(name string) pendingCheck {
	last := r.urls[len(r.urls)-1]
	want, got := "new", "new"

	for _, earlier := range r.urls[:len(r.urls)-1] {
		if earlier.label == last.label {
			want = "same as " + earlier.label
		}

		if earlier.authID == last.authID {
			got = "same as " + earlier.label
		}
	}

	return pendingCheck{name + "-auth-url", want, func() string { return got }}
}

// deviceChecks compares the devices on each machine after the step and
// their node keys, when SaaS read them.
func (r *pendingReplay) deviceChecks(t *testing.T, step testcapture.Step) []pendingCheck {
	t.Helper()

	type device struct {
		MachineKey string `json:"machineKey"`
		NodeKey    string `json:"nodeKey"`
	}

	var (
		devices []device
		read    bool
		single  = map[string]*device{}
	)

	for _, a := range step.Actions {
		if a.Kind != "api" || a.Method != http.MethodGet {
			continue
		}

		switch {
		case strings.HasPrefix(a.Path, "/tailnet/-/devices"):
			var out struct {
				Devices []device `json:"devices"`
			}
			require.NoError(t, json.Unmarshal(a.Response, &out), "%s: %s", step.Name, a.Path)

			devices, read = out.Devices, true

		case strings.HasPrefix(a.Path, "/device/{device:"):
			// The last read of each device.
			alias, _, _ := strings.Cut(strings.TrimPrefix(a.Path, "/device/{device:"), "}")
			single[alias] = nil

			if a.Status == http.StatusOK {
				var d device
				require.NoError(t, json.Unmarshal(a.Response, &d), "%s: %s", step.Name, a.Path)

				single[alias] = &d
			}
		}
	}

	if !read {
		for _, d := range single {
			if d != nil {
				devices = append(devices, *d)
			}
		}
	}

	var aliases []string

	for alias := range r.machines {
		if _, ok := single[alias]; read || ok {
			aliases = append(aliases, alias)
		}
	}

	slices.Sort(aliases)

	checks := make([]pendingCheck, 0, len(aliases))

	for _, alias := range aliases {
		var keys []string

		for _, d := range devices {
			if d.MachineKey == "{machine:"+alias+"}" {
				keys = append(keys, d.NodeKey)
			}
		}

		checks = append(checks, pendingCheck{alias + "/devices", renderNodeKeys(keys), func() string {
			var got []string

			for _, nv := range r.nodes(alias) {
				label, ok := r.keyLabels[nv.NodeKey()]
				if !ok {
					label = "unknown node key"
				}

				got = append(got, label)
			}

			return renderNodeKeys(got)
		}})
	}

	return checks
}

func renderNodeKeys(keys []string) string {
	slices.Sort(keys)

	return fmt.Sprintf("devices %d %v", len(keys), keys)
}

// hold polls the checks until, for several ticks in a row, each one listed
// in pendingLoginSkipReasons differs from SaaS and every other one matches,
// then reports each as a subtest. A listed check that matches fails.
func (r *pendingReplay) hold(t *testing.T, prefix string, checks []pendingCheck) {
	t.Helper()

	const holdTicks = 5

	got := make([]string, len(checks))
	held := 0

	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()

	for deadline := time.Now().Add(10 * time.Second); held < holdTicks && time.Now().Before(deadline); <-tick.C {
		settled := true

		for i, c := range checks {
			got[i] = c.got()
			if _, listed := pendingLoginSkipReasons[prefix+c.name]; (got[i] == c.want) == listed {
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
		k := prefix + c.name
		r.evaluated[k] = true

		t.Run(strings.TrimPrefix(k, r.c.TestID+"/"), func(t *testing.T) {
			reason, listed := pendingLoginSkipReasons[k]

			switch {
			case listed && got[i] == c.want:
				t.Errorf("matches SaaS; delete the skip entry %q (%s)", k, reason)
			case listed:
				t.Skip(reason)
			default:
				assert.Equal(t, c.want, got[i])
			}
		})
	}
}

func (r *pendingReplay) machine(node string) key.MachinePrivate {
	mk, ok := r.machines[node]
	if !ok {
		mk = key.NewMachine()
		r.machines[node] = mk
	}

	return mk
}

func (r *pendingReplay) nodeKey(label string) key.NodePrivate {
	nk, ok := r.nodeKeys[label]
	if !ok {
		nk = key.NewNode()
		r.nodeKeys[label] = nk
		r.keyLabels[nk.Public()] = label
	}

	return nk
}

func (r *pendingReplay) nodes(alias string) []types.NodeView {
	mk, ok := r.machines[alias]
	if !ok {
		return nil
	}

	return slices.Collect(maps.Values(r.app.state.GetNodesByMachineKeyAllUsers(mk.Public())))
}

// registerFlags renders an answer as the client logged it: its
// NodeKeyExpired and MachineAuthorized flags and whether it carried an auth
// URL, or "unanswered" for a request still waiting.
func registerFlags(a testcapture.RegisterAttempt) string {
	if a.NodeKeyExpired == nil || a.MachineAuthorized == nil {
		return "unanswered"
	}

	return fmt.Sprintf("expired=%t authorized=%t url=%t", *a.NodeKeyExpired, *a.MachineAuthorized, a.AuthURL != "")
}

// responseFlags renders headscale's answer the way [registerFlags] renders
// SaaS's; a refusal is "error".
func responseFlags(resp *tailcfg.RegisterResponse, err error) string {
	if err != nil || resp == nil || resp.Error != "" {
		return "error"
	}

	return fmt.Sprintf("expired=%t authorized=%t url=%t", resp.NodeKeyExpired, resp.MachineAuthorized, resp.AuthURL != "")
}
