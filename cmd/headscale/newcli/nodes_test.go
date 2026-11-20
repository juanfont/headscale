package newcli

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/juanfont/headscale/cmd/headscale/newcli/table"
	"github.com/juanfont/headscale/hscontrol/servertest"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

const nodesPolicy = `{
	"tagOwners": {"tag:ci": [], "tag:build": [], "tag:infra": [], "tag:server": [], "tag:test": [], "tag:example": []},
	"acls": [{"action": "accept", "src": ["*"], "dst": ["*:*"]}]
}`

// fleet is the tailnet of the proposal's examples: alice (3) owns mynode
// (12), carol (5) owns web-1 (27), bob (4) owns nothing, and builder (13),
// gateway (14) and web (21) are tagged. web's hostname is ubuntu, web-1's
// is web, so "web" names two nodes. web has a tag the policy dropped, and
// a stored expiry no API answer can carry, which its problems name. Five
// nodes are three pages of the fixture's walk.
func fleet(tb testing.TB, f *fixture) {
	tb.Helper()

	st := f.srv.State()
	day := 24 * time.Hour

	_, err := st.SetPolicy([]byte(nodesPolicy))
	require.NoError(tb, err)

	users := map[uint]*types.User{}

	for _, u := range []types.User{
		{ID: 3, Name: "alice", DisplayName: "Alice"},
		{ID: 4, Name: "bob"},
		{ID: 5, Name: "carol", Email: "carol@example.com"},
	} {
		created, _, err := st.CreateUser(u)
		require.NoError(tb, err)

		users[u.ID] = created
	}

	at := func(d time.Duration) *time.Time { return new(f.now.Add(d)) }
	prefixes := func(ps ...string) []netip.Prefix {
		out := make([]netip.Prefix, 0, len(ps))
		for _, p := range ps {
			out = append(out, netip.MustParsePrefix(p))
		}

		return out
	}
	exit := []string{"0.0.0.0/0", "::/0"}

	for _, n := range []struct {
		id                uint64
		name, host        string
		user              uint
		tags              []string
		version, os       string
		online            bool
		lastSeen, expiry  *time.Time
		created           time.Duration
		approved, offered []netip.Prefix
		method            string
		public            string
	}{
		{
			id: 12, name: "mynode", host: "ubuntu-vm", user: 3, version: "1.82.0-t0f1e2d3c4", os: "linux", online: true,
			expiry: at(89 * day), created: -120 * day, method: "cli", public: "203.0.113.7",
			approved: prefixes("10.0.0.0/8"), offered: prefixes("10.0.0.0/8", "192.168.0.0/24"),
		},
		{
			id: 13, name: "builder", host: "builder", user: 3, tags: []string{"tag:ci", "tag:build"}, version: "1.80.2", os: "linux",
			lastSeen: at(-3 * day), created: -30 * day, method: "authkey",
		},
		{
			id: 14, name: "gateway", host: "gateway", user: 3, tags: []string{"tag:infra"}, version: "1.84.0", os: "linux",
			lastSeen: at(-time.Hour), created: -20 * day, method: "authkey",
			approved: prefixes(exit...), offered: prefixes(exit...),
		},
		{
			id: 21, name: "web", host: "ubuntu", user: 5, tags: []string{"tag:infra", "tag:old"}, version: "1.78.1", os: "linux",
			lastSeen: at(-40 * day), created: -60 * day, method: "authkey",
		},
		{
			id: 27, name: "web-1", host: "web", user: 5, version: "1.82.1", os: "macOS",
			lastSeen: at(-2 * day), expiry: at(-2 * day), created: -10 * day, method: "oidc",
		},
	} {
		v4 := netip.AddrFrom4([4]byte{100, 64, 0, uint8(n.id)}) //nolint:gosec // IDs of the fleet are below 256
		v6 := netip.MustParseAddr("fd7a:115c:a1e0::" + strconv.FormatUint(n.id, 16))

		node := types.Node{
			ID:             types.NodeID(n.id),
			MachineKey:     key.NewMachine().Public(),
			NodeKey:        key.NewNode().Public(),
			DiscoKey:       key.NewDisco().Public(),
			Hostname:       n.host,
			GivenName:      n.name,
			UserID:         &n.user,
			User:           users[n.user],
			Tags:           n.tags,
			IPv4:           &v4,
			IPv6:           &v6,
			RegisterMethod: n.method,
			LastSeen:       n.lastSeen,
			Expiry:         n.expiry,
			ApprovedRoutes: n.approved,
			CreatedAt:      f.now.Add(n.created),
			Hostinfo:       &tailcfg.Hostinfo{Hostname: n.host, OS: n.os, IPNVersion: n.version, RoutableIPs: n.offered},
			IsOnline:       new(n.online),
		}

		// v0 reads a held poll session as connected.
		if n.online {
			node.ActiveSessions = 1
		}

		if n.public != "" {
			node.LastControlAddress = new(netip.MustParseAddr(n.public))
		}

		require.NoError(tb, st.DB().DB.Create(&node).Error)

		if n.id == 21 {
			node.Expiry = new(time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC))
		}

		st.PutNodeInStoreForTest(node)

		if n.id == 12 {
			f.vars["mkey"], f.vars["nodekey"], f.vars["discokey"] = node.MachineKey.String(), node.NodeKey.String(), node.DiscoKey.String()
		}
	}

	for name, t := range map[string]time.Time{"now": f.now, "in89d": f.now.Add(89 * day), "ago120d": f.now.Add(-120 * day), "ago60d": f.now.Add(-60 * day), "ago40d": f.now.Add(-40 * day)} {
		f.vars[name] = t.UTC().Format("2006-01-02 15:04 UTC")
	}
}

// renamed is mynode changing between the CLI's lookup and its write: it is
// renamed after each of the first times answers of a read of nodes.
func renamed(times int) func(testing.TB, *fixture, string) {
	return func(tb testing.TB, f *fixture, req string) {
		tb.Helper()

		if !strings.HasPrefix(req, "GET "+nodesPath) || f.changes >= times {
			return
		}

		f.changes++

		_, _, err := f.srv.State().RenameNode(12, "renamed-"+strconv.Itoa(f.changes))
		require.NoError(tb, err)
	}
}

const nodesPath = "/api/headscale/v0/nodes"

var nodes = listAt{nodesPath, "nodes"}

const nodesTable = `ID  NAME     OWNER               IP                               VERSION  ONLINE  LAST SEEN  EXPIRY
12  mynode   alice               100.64.0.12, fd7a:115c:a1e0::c   1.82.0   yes     now        in 89d
13  builder  tag:ci, tag:build   100.64.0.13, fd7a:115c:a1e0::d   1.80.2   no      3d ago     never
14  gateway  tag:infra           100.64.0.14, fd7a:115c:a1e0::e   1.84.0   no      1h ago     never
21  web      tag:infra, tag:old  100.64.0.21, fd7a:115c:a1e0::15  1.78.1   no      40d ago    invalid
27  web-1    carol@example.com   100.64.0.27, fd7a:115c:a1e0::1b  1.82.1   no      2d ago     2d ago
`

const mynodeSheet = `ID:                 12
Name:               mynode
Owner:              User 3 (alice)
IP:                 100.64.0.12, fd7a:115c:a1e0::c
Version:            1.82.0
Online:             yes
Last seen:          now ({now})
Expiry:             in 89d ({in89d})
Hostname:           ubuntu-vm
OS:                 linux
Enabled routes:     10.0.0.0/8
Advertised routes:  10.0.0.0/8, 192.168.0.0/24
Serving routes:     10.0.0.0/8
Public IP:          203.0.113.7
Ephemeral:          no
Update available:   no
Register method:    cli
Auth key:           -
Machine key:        {mkey}
Node key:           {nodekey}
Disco key:          {discokey}
Created:            120d ago ({ago120d})
Problems:           -

Attributes:
  ip:publicAddress   203.0.113.7
`

func onlyID(ids ...string) func(map[string]any) bool {
	return func(row map[string]any) bool {
		id, _ := row["id"].(string)

		return slices.Contains(ids, id)
	}
}

var nodesListCases = []cliCase{
	{
		name: "the table, walked over three pages", args: "nodes list", stdout: nodesTable,
		check: func(tb testing.TB, _ *fixture, r result) {
			tb.Helper()
			require.Len(tb, r.asked, 3, "three pages of two")
			require.Equal(tb, "GET "+nodesPath+"?pageSize=2", r.asked[0])
		},
	},
	{
		name: "the CLI's own page is the most v0 gives", args: "nodes list", pageSize: cliPages, stdout: nodesTable,
		check: func(tb testing.TB, _ *fixture, r result) {
			tb.Helper()
			require.Equal(tb, []string{"GET " + nodesPath + "?pageSize=1000"}, r.asked)
		},
	},
	{name: "-o json is every page's rows as they came", args: "nodes list -o json", want: nodes.rows(all)},
	{
		name: "columns added and a reverse sort", args: "nodes list --columns +os,+hostname --sort -last-seen",
		stdout: `ID  NAME     OWNER               IP                               VERSION  ONLINE  LAST SEEN  EXPIRY   OS     HOSTNAME
12  mynode   alice               100.64.0.12, fd7a:115c:a1e0::c   1.82.0   yes     now        in 89d   linux  ubuntu-vm
14  gateway  tag:infra           100.64.0.14, fd7a:115c:a1e0::e   1.84.0   no      1h ago     never    linux  gateway
27  web-1    carol@example.com   100.64.0.27, fd7a:115c:a1e0::1b  1.82.1   no      2d ago     2d ago   macOS  web
13  builder  tag:ci, tag:build   100.64.0.13, fd7a:115c:a1e0::d   1.80.2   no      3d ago     never    linux  builder
21  web      tag:infra, tag:old  100.64.0.21, fd7a:115c:a1e0::15  1.78.1   no      40d ago    invalid  linux  ubuntu
`,
	},
	{name: "the nodes of a user as JSON", args: "nodes list --filter owner=alice -o json", want: nodes.rows(onlyID("12"))},
	{name: "a user by ID finds the same rows", args: "nodes list --filter owner=3 --columns id", stdout: "ID\n12\n"},
	{name: "a user by email", args: "nodes list --filter owner=carol@example.com --columns id", stdout: "ID\n27\n"},
	{name: "a tag", args: "nodes list --filter owner=tag:infra --columns id,owner", stdout: "ID  OWNER\n14  tag:infra\n21  tag:infra, tag:old\n"},
	{name: "a user who is no one", args: "nodes list --filter owner=alcie", stderr: "Error: no user matches \"alcie\".\n", code: 1},
	{name: "a user who owns nothing, on a terminal", args: "nodes list --filter owner=bob", terminal: true, stdout: "No nodes.\n"},
	{name: "a user who owns nothing, in a pipe", args: "nodes list --filter owner=bob --columns id,name", stdout: "ID  NAME\n"},
	{name: "not seen for 30 days", args: "nodes ls --filter 'last-seen>30d'", stdout: "ID  NAME  OWNER               IP                               VERSION  ONLINE  LAST SEEN  EXPIRY\n21  web   tag:infra, tag:old  100.64.0.21, fd7a:115c:a1e0::15  1.78.1   no      40d ago    invalid\n"},
	{name: "expires within a week, or has", args: "nodes list --filter 'expiry<7d' --columns id,expiry", stdout: "ID  EXPIRY\n27  2d ago\n"},
	{name: "no expiry; an invalid one is not never", args: "nodes list --filter expiry=never --columns id", stdout: "ID\n13\n14\n"},
	{name: "the next expiry first, no expiry last", args: "nodes list --sort expiry --columns id,expiry", stdout: "ID  EXPIRY\n27  2d ago\n12  in 89d\n13  never\n14  never\n21  invalid\n"},
	{name: "a client older than 1.80", args: "nodes list --filter 'version<1.80'", stdout: "ID  NAME  OWNER               IP                               VERSION  ONLINE  LAST SEEN  EXPIRY\n21  web   tag:infra, tag:old  100.64.0.21, fd7a:115c:a1e0::15  1.78.1   no      40d ago    invalid\n"},
	{name: "version sorts by its numbers", args: "nodes list --sort version --columns id,version", stdout: "ID  VERSION\n21  1.78.1\n13  1.80.2\n12  1.82.0\n27  1.82.1\n14  1.84.0\n"},
	{name: "an IP", args: "nodes list --filter ip=100.64.0.12 --columns id", stdout: "ID\n12\n"},
	{name: "the public IP from the attributes", args: "nodes list --filter public-ip=203.0.113.7 --columns id,public-ip", stdout: "ID  PUBLIC IP\n12  203.0.113.7\n"},
	{name: "exit in a filter", args: "nodes list --filter enabled-routes=exit --columns id,enabled-routes", stdout: "ID  ENABLED\n14  exit\n"},
	{name: "a node with a problem", args: "nodes list --filter problems=node_expiry_invalid", stdout: "ID  NAME  OWNER               IP                               VERSION  ONLINE  LAST SEEN  EXPIRY\n21  web   tag:infra, tag:old  100.64.0.21, fd7a:115c:a1e0::15  1.78.1   no      40d ago    invalid\n"},
	{name: "a contains filter on problems", args: "nodes list --filter problems:expiry --columns id,problems", stdout: "ID  PROBLEMS\n21  node_expiry_invalid\n"},
	{
		name: "a credential that may not read nodes", args: "nodes list",
		setup: func(tb testing.TB, f *fixture) {
			tb.Helper()
			f.vars["token"] = f.token(tb, "users:read")
		},
		env:    []string{"HEADSCALE_CLI_ADDRESS={url}", "HEADSCALE_CLI_API_KEY={token}"},
		stderr: "Error: this credential may not do that.\nIt lacks the scope devices:core:read.\n", code: 1,
	},
	{name: "--force is no flag of a list", args: "nodes list --force", stderr: "Error: --force does not apply to `nodes list`.\nRun `headscale nodes list --help`.\n", code: 1},
	{
		name: "a name of the server cannot forge a line",
		setup: func(tb testing.TB, f *fixture) {
			tb.Helper()

			n := *nodeOf(tb, f, 12).AsStruct()
			n.GivenName = "x\x1b[31mred\nfake line"
			f.srv.State().PutNodeInStoreForTest(n)
		},
		args: "nodes list --filter id=12 --columns id,name", stdout: "ID  NAME\n12  x\\x1b[31mred\\x0afake line\n",
	},
	{
		name: "a terminal cuts to its width: whole IPs give way first", args: "nodes list", terminal: true, width: 95, env: []string{"NO_COLOR=1"},
		stdout: `ID  NAME     OWNER               IP                  VERSION  ONLINE  LAST SEEN  EXPIRY
12  mynode   alice               100.64.0.12 … (+1)  1.82.0   yes     now        in 89d
13  builder  tag:ci, tag:build   100.64.0.13 … (+1)  1.80.2   no      3d ago     never
14  gateway  tag:infra           100.64.0.14 … (+1)  1.84.0   no      1h ago     never
21  web      tag:infra, tag:old  100.64.0.21 … (+1)  1.78.1   no      40d ago    invalid
27  web-1    carol@example.com   100.64.0.27 … (+1)  1.82.1   no      2d ago     2d ago
`,
	},
	{
		name: "past every floor the line runs over", args: "nodes list --columns id,name,owner,ip,expiry", terminal: true, width: 50, env: []string{"NO_COLOR=1"},
		stdout: `ID  NAME  OWNER             IP                  EXPIRY
12  myn…  alice             100.64.0.12 … (+1)  in 89d
13  bui…  tag:ci … (+1)     100.64.0.13 … (+1)  never
14  gat…  tag:infra         100.64.0.14 … (+1)  never
21  web   tag:infra … (+1)  100.64.0.21 … (+1)  invalid
27  web…  carol@example.c…  100.64.0.27 … (+1)  2d ago
`,
	},
	{
		name: "a terminal colours the header, an empty cell and a time that passed", args: "nodes list --columns id,expiry,public-ip --filter id>20", terminal: true, width: 80,
		stdout: "\x1b[1mID\x1b[0m  \x1b[1mEXPIRY\x1b[0m   \x1b[1mPUBLIC IP\x1b[0m\n21  invalid  \x1b[2m-\x1b[0m\n27  \x1b[31m2d ago\x1b[0m   \x1b[2m-\x1b[0m\n",
	},
}

func TestNodesList(t *testing.T) {
	t.Parallel()

	runCases(t, fleet, nodesListCases)
}

var nodesGetCases = []cliCase{
	{name: "by name, a sheet with the attributes", args: "nodes get mynode", stdout: mynodeSheet},
	{name: "by ID as JSON", args: "nodes get 12 -o json", want: nodes.row(onlyID("12"))},
	{name: "by tailnet IP", args: "nodes get 100.64.0.12", stdout: mynodeSheet},
	{name: "an IP is compared as an address", args: "nodes get fd7a:115c:a1e0:0:0::c", stdout: mynodeSheet},
	{name: "by hostname", args: "nodes get ubuntu-vm -o json", want: nodes.row(onlyID("12"))},
	{
		name: "a word that names two nodes", args: "nodes get web",
		stderr: "Error: \"web\" matches 2 nodes. Use the ID to select one:\n\n  ID  NAME   HOSTNAME  OWNER\n  21  web    ubuntu    tag:infra, tag:old\n  27  web-1  web       carol@example.com\n",
		code:   1,
	},
	{name: "no node", args: "nodes get nope", stderr: "Error: no node matches \"nope\".\n", code: 1},
	{
		name: "an empty word is no node", args: "nodes get ''", stderr: "Error: an empty word names no node.\n", code: 1,
		check: func(tb testing.TB, _ *fixture, r result) {
			tb.Helper()
			require.Empty(tb, r.asked)
		},
	},
	{
		name: "a tagged node with a problem", args: "nodes get 21",
		stdout: `ID:                 21
Name:               web
Owner:              tag:infra, tag:old
IP:                 100.64.0.21, fd7a:115c:a1e0::15
Version:            1.78.1
Online:             no
Last seen:          40d ago ({ago40d})
Expiry:             invalid
Hostname:           ubuntu
OS:                 linux
Enabled routes:     -
Advertised routes:  -
Serving routes:     -
Public IP:          -
Ephemeral:          no
Update available:   no
Register method:    authKey
Auth key:           -
Machine key:        {mkey21}
Node key:           {nodekey21}
Disco key:          {discokey21}
Created:            60d ago ({ago60d})
Problems:           node_expiry_invalid
`,
		setup: func(tb testing.TB, f *fixture) {
			tb.Helper()

			n := nodeOf(tb, f, 21)
			f.vars["mkey21"], f.vars["nodekey21"], f.vars["discokey21"] = n.MachineKey().String(), n.NodeKey().String(), n.DiscoKey().String()
		},
	},
}

func TestNodesGet(t *testing.T) {
	t.Parallel()

	runCases(t, fleet, nodesGetCases)
}

// nodeOf reads a node back from the server.
func nodeOf(tb testing.TB, f *fixture, id types.NodeID) types.NodeView {
	tb.Helper()

	n, ok := f.srv.State().GetNodeByID(id)
	require.True(tb, ok, "node %d", id)

	return n
}

// freeWeb1 gives node 27 another name, so mynode can take web-1.
func freeWeb1(tb testing.TB, f *fixture) {
	tb.Helper()

	_, _, err := f.srv.State().RenameNode(27, "web-2")
	require.NoError(tb, err)
}

// expires is the sentence of a set expiry, from what the server stored.
func expires(tb testing.TB, f *fixture, _ result) string {
	tb.Helper()

	exp, ok := nodeOf(tb, f, 12).Expiry().GetOk()
	require.True(tb, ok)

	return "Node 12 (mynode) expires " + table.When(exp, f.now) + ".\n"
}

var nodesSetCases = []cliCase{
	{
		name: "a name", args: "nodes set mynode --name web-1", setup: freeWeb1, stdout: "Node 12 (web-1) was mynode.\n",
		check: func(tb testing.TB, f *fixture, r result) {
			tb.Helper()
			require.Equal(tb, "web-1", nodeOf(tb, f, 12).GivenName())
			require.Equal(tb, "PATCH "+nodesPath+"/12", r.asked[len(r.asked)-1], "one call for the change")
		},
	},
	{name: "a name that another node has", args: "nodes set mynode --name web-1", stderr: "Error: the name \"web-1\" belongs to Node 27 (web-1).\n", code: 1},
	{
		name: "a name that is no DNS label names the flag", args: "nodes set mynode --name -x",
		stderr: "Error: the server refused a value:\n  --name: is not a DNS label: letters, digits and '-', not at either end, at most 63\n", code: 1,
	},
	{
		name: "the name made from the hostname again", args: "nodes set web-9 --name ''",
		setup: func(tb testing.TB, f *fixture) {
			tb.Helper()

			_, _, err := f.srv.State().RenameNode(12, "web-9")
			require.NoError(tb, err)
		},
		stdout: "Node 12 (ubuntu-vm) was web-9. The name is made from its hostname again.\n",
	},
	{
		name: "a timestamp", args: "nodes set mynode --expiry 2999-08-27T10:00:00Z", want: expires,
		check: func(tb testing.TB, f *fixture, _ result) {
			tb.Helper()
			require.Equal(tb, time.Date(2999, 8, 27, 10, 0, 0, 0, time.UTC), nodeOf(tb, f, 12).Expiry().Get().UTC())
		},
	},
	{
		name: "a date is midnight UTC", args: "nodes set mynode --expiry 2999-08-27", want: expires,
		check: func(tb testing.TB, f *fixture, _ result) {
			tb.Helper()
			require.Equal(tb, time.Date(2999, 8, 27, 0, 0, 0, 0, time.UTC), nodeOf(tb, f, 12).Expiry().Get().UTC())
		},
	},
	{
		name: "a duration is from now", args: "nodes set mynode --expiry 90d", want: expires,
		check: func(tb testing.TB, f *fixture, _ result) {
			tb.Helper()
			require.Equal(tb, f.now.Add(90*24*time.Hour), nodeOf(tb, f, 12).Expiry().Get().UTC())
		},
	},
	{
		name: "now expires the node at the server's clock", args: "nodes set mynode --expiry now", stdout: "Node 12 (mynode) is now expired. It must log in again.\n",
		check: func(tb testing.TB, f *fixture, _ result) {
			tb.Helper()
			require.True(tb, nodeOf(tb, f, 12).IsExpired())
		},
	},
	{
		name: "never", args: "nodes set mynode --expiry never", stdout: "Node 12 (mynode) does not expire.\n",
		check: func(tb testing.TB, f *fixture, _ result) {
			tb.Helper()
			_, ok := nodeOf(tb, f, 12).KeyExpiry()
			require.False(tb, ok)
		},
	},
	{name: "-e is --expiry", args: "nodes set 12 -e never", stdout: "Node 12 (mynode) does not expire.\n"},
	{
		name: "both in one call", args: "nodes set mynode --name web-1 --expiry never", setup: freeWeb1,
		stdout: "Node 12 (web-1) was mynode. It does not expire.\n",
		check: func(tb testing.TB, f *fixture, r result) {
			tb.Helper()
			require.Equal(tb, "PATCH "+nodesPath+"/12", r.asked[len(r.asked)-1])
			require.Equal(tb, "GET "+nodesPath+"?pageSize=2", r.asked[0])
			require.Len(tb, r.asked, 4, "the walk and one write")
		},
	},
	{name: "-o json is the node after the change", args: "nodes set 12 --name web-1 -o json", setup: freeWeb1, want: answer(nodesPath + "/12")},
	{name: "nothing to change", args: "nodes set mynode", stderr: "Error: nothing to change. Give at least one of\n  --name, --expiry\n", code: 1},
	{
		name: "a time in the past", args: "nodes set 12 --expiry 2024-01-01",
		stderr: "Error: 2024-01-01 00:00 UTC is in the past.\nTo expire the node now: headscale nodes expire 12\n", code: 1,
	},
	{
		name: "a duration of zero is no time ahead, before any call", args: "nodes set 12 --expiry 0s",
		stderr: "Error: \"0s\" is not a valid --expiry: a duration from now is longer than 0.\n", code: 1,
		check: func(tb testing.TB, _ *fixture, r result) {
			tb.Helper()
			require.Empty(tb, r.asked)
		},
	},
	{
		name: "a time that does not read", args: "nodes set 12 --expiry soon",
		stderr: "Error: \"soon\" is not a valid --expiry: it is a time, a date, a duration such as 90d, now or never.\n", code: 1,
	},
	{
		name: "the node changed after the lookup: read again, written once more", args: "nodes set mynode --name web-1", setup: freeWeb1,
		answered: renamed(1), stdout: "Node 12 (web-1) was renamed-1.\n",
		check: func(tb testing.TB, f *fixture, r result) {
			tb.Helper()
			require.Equal(tb, "web-1", nodeOf(tb, f, 12).GivenName())
			require.Equal(tb, []string{"PATCH " + nodesPath + "/12", "GET " + nodesPath + "/12", "PATCH " + nodesPath + "/12"}, r.asked[3:])
		},
	},
	{
		name: "the node keeps changing", args: "nodes set mynode --name web-1", setup: freeWeb1, answered: renamed(2), pageSize: cliPages,
		stderr: "Error: Node 12 (renamed-2) changed while the command ran. Run it again.\n", code: 1,
		check: func(tb testing.TB, f *fixture, _ result) {
			tb.Helper()
			require.Equal(tb, "renamed-2", nodeOf(tb, f, 12).GivenName(), "nothing written")
		},
	},
	{
		name: "a credential that may only read", args: "nodes set mynode --name web-1",
		setup: func(tb testing.TB, f *fixture) {
			tb.Helper()
			f.vars["token"] = f.token(tb, "devices:core:read")
		},
		env:    []string{"HEADSCALE_CLI_ADDRESS={url}", "HEADSCALE_CLI_API_KEY={token}"},
		stderr: "Error: this credential may not do that.\nIt lacks the scope devices:core.\n", code: 1,
	},
	{
		name: "a capital letter in a name is refused, not lowered", args: "nodes set mynode --name Web",
		stderr: "Error: the server refused a value:\n  --name: has a capital letter; a name is lower case\n", code: 1,
	},
}

func TestNodesSet(t *testing.T) {
	t.Parallel()

	runCases(t, fleet, nodesSetCases)
}

var nodesExpireDeleteCases = []cliCase{
	{
		name: "expire", args: "nodes expire mynode", stdout: "Node 12 (mynode) is now expired. It must log in again.\n",
		check: func(tb testing.TB, f *fixture, r result) {
			tb.Helper()
			require.True(tb, nodeOf(tb, f, 12).IsExpired())
			require.Equal(tb, "POST "+nodesPath+"/12/expire", r.asked[len(r.asked)-1])
		},
	},
	{name: "expire -o json", args: "nodes expire 12 -o json", want: answer(nodesPath + "/12/expire")},
	{
		name: "expire a node that changed", args: "nodes expire mynode", answered: renamed(1),
		stdout: "Node 12 (renamed-1) is now expired. It must log in again.\n",
	},
	{
		name: "delete asks, about the owner", args: "nodes delete mynode", terminal: true, stdin: "y\n",
		stderr: "Delete Node 12 (mynode), owned by User 3 (alice)? [y/N] ", stdout: "Node 12 (mynode) deleted.\n",
		check: func(tb testing.TB, f *fixture, _ result) {
			tb.Helper()

			_, ok := f.srv.State().GetNodeByID(12)
			require.False(tb, ok)
		},
	},
	{
		name: "delete a tagged node asks about its tags", args: "nodes rm builder", terminal: true, stdin: "yes\n",
		stderr: "Delete Node 13 (builder), tagged tag:ci, tag:build? [y/N] ", stdout: "Node 13 (builder) deleted.\n",
	},
	{
		name: "no is not done", args: "nodes delete 12", terminal: true, stdin: "n\n",
		stderr: "Delete Node 12 (mynode), owned by User 3 (alice)? [y/N] Aborted.\n", code: 1,
		check: func(tb testing.TB, f *fixture, _ result) {
			tb.Helper()

			_, ok := f.srv.State().GetNodeByID(12)
			require.True(tb, ok)
		},
	},
	{
		name: "no terminal to ask", args: "nodes delete 12",
		stderr: "Error: confirmation needed, but there is no terminal.\nRun again with --force to delete Node 12 (mynode).\n", code: 1,
	},
	{
		name: "a terminal, but stdin is a pipe", args: "nodes delete 12", terminal: true, piped: true, stdin: "\n",
		stderr: "Error: confirmation needed, but there is no terminal.\nRun again with --force to delete Node 12 (mynode).\n", code: 1,
	},
	{name: "--force does not ask", args: "nodes delete 12 --force", stdout: "Node 12 (mynode) deleted.\n"},
	{name: "-o json prints nothing", args: "nodes delete 12 --force -o json"},
	{name: "two arguments", args: "nodes delete 12 13", stderr: "Error: `nodes delete` needs 1 argument, got 2.\n\n  headscale nodes delete <node>\n", code: 1},
	{
		name: "the node changed while the question was open: asked again", args: "nodes delete mynode", terminal: true, stdin: "y\nyes\n",
		answered: renamed(1),
		stderr:   "Delete Node 12 (mynode), owned by User 3 (alice)? [y/N] Node 12 (mynode) changed while the question was open.\nDelete Node 12 (renamed-1), owned by User 3 (alice)? [y/N] ",
		stdout:   "Node 12 (renamed-1) deleted.\n",
	},
	{
		name: "the node changed with --force: read again, not asked", args: "nodes delete 12 --force", answered: renamed(1),
		stdout: "Node 12 (renamed-1) deleted.\n",
		check: func(tb testing.TB, _ *fixture, r result) {
			tb.Helper()
			require.Equal(tb, []string{"DELETE " + nodesPath + "/12", "GET " + nodesPath + "/12", "DELETE " + nodesPath + "/12"}, r.asked[3:])
		},
	},
	{
		name: "the node keeps changing", args: "nodes delete 12 --force", answered: renamed(2), pageSize: cliPages,
		stderr: "Error: Node 12 (renamed-2) changed while the command ran. Run it again.\n", code: 1,
	},
	{
		name: "the node is gone after the lookup", args: "nodes delete 12 --force",
		answered: func(tb testing.TB, f *fixture, req string) {
			tb.Helper()

			if strings.HasPrefix(req, "GET ") && f.changes == 0 {
				f.changes++

				_, err := f.srv.State().DeleteNode(nodeOf(tb, f, 12))
				require.NoError(tb, err)
			}
		},
		stderr: "Error: Node 12 (mynode) no longer exists.\n", code: 1,
	},
	{
		name: "a credential that may only read", args: "nodes delete 12 --force",
		setup: func(tb testing.TB, f *fixture) {
			tb.Helper()
			f.vars["token"] = f.token(tb, "devices:core:read")
		},
		env:    []string{"HEADSCALE_CLI_ADDRESS={url}", "HEADSCALE_CLI_API_KEY={token}"},
		stderr: "Error: this credential may not do that.\nIt lacks the scope devices:core.\n", code: 1,
	},
}

func TestNodesExpireDelete(t *testing.T) {
	t.Parallel()

	runCases(t, fleet, nodesExpireDeleteCases)
}

// updater answers a client update over C2N as a Tailscale client does.
type updater tailcfg.C2NUpdateResponse

func (u updater) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || r.URL.Path != "/update" {
		http.NotFound(w, r)

		return
	}

	_ = json.NewEncoder(w).Encode(tailcfg.C2NUpdateResponse(u)) //nolint:errchkjson // a test client
}

// connected is a connected client named mynode that answers an update
// with res.
func connected(res tailcfg.C2NUpdateResponse) func(testing.TB, *fixture) {
	return func(tb testing.TB, f *fixture) {
		tb.Helper()

		servertest.NewClient(tb, f.srv, "mynode",
			servertest.WithHostinfo(&tailcfg.Hostinfo{BackendLogID: "newcli-mynode", Hostname: "mynode", AllowsUpdate: true, IPNVersion: "1.80.0"}),
			servertest.WithC2NHandler(updater(res)))
		f.vars["id"] = nodeIDOf(tb, f, "mynode")
	}
}

func nodeIDOf(tb testing.TB, f *fixture, name string) string {
	tb.Helper()

	for _, n := range f.srv.State().ListNodes().All() {
		if n.GivenName() == name {
			return n.StringID()
		}
	}

	tb.Fatalf("no node %s", name)

	return ""
}

var updateClientCases = []cliCase{
	{
		name: "started", args: "nodes update-client mynode", clients: true, setup: connected(tailcfg.C2NUpdateResponse{Enabled: true, Started: true}),
		stdout: "Client update started on Node {id} (mynode).\n",
	},
	{
		name: "-o json is the node", args: "nodes update-client mynode -o json", clients: true, setup: connected(tailcfg.C2NUpdateResponse{Enabled: true, Started: true}),
		want: func(tb testing.TB, f *fixture, r result) string {
			tb.Helper()

			return answer(nodesPath+"/"+f.vars["id"]+"/update-client")(tb, f, r)
		},
	},
	{
		name: "the client refuses, with its text", args: "nodes update-client mynode", clients: true, setup: connected(tailcfg.C2NUpdateResponse{Enabled: true, Err: "not supported"}),
		stderr: "Error: Node {id} (mynode) refused the update: not supported\n", code: 1,
	},
	{
		name: "not connected", args: "nodes update-client builder",
		setup: func(tb testing.TB, f *fixture) {
			tb.Helper()
			fleet(tb, f)

			n := *nodeOf(tb, f, 13).AsStruct()
			n.Hostinfo.AllowsUpdate = true
			f.srv.State().PutNodeInStoreForTest(n)
		},
		stderr: "Error: Node 13 (builder) is not connected.\n", code: 1,
	},
	{
		name: "updates not allowed", args: "nodes update-client builder", setup: fleet,
		stderr: "Error: Node 13 (builder) does not allow remote updates. Run \"tailscale set --auto-update\" on it.\n", code: 1,
	},
}

func TestNodesUpdateClient(t *testing.T) {
	t.Parallel()

	runCases(t, nil, updateClientCases)
}

var routesCases = []cliCase{
	{
		name: "only nodes with routes, exit as a word", args: "nodes routes list",
		stdout: "ID  NAME     ENABLED     ADVERTISED                  SERVING\n12  mynode   10.0.0.0/8  10.0.0.0/8, 192.168.0.0/24  10.0.0.0/8\n14  gateway  exit        exit                        exit\n", //nolint:dupword // exit in three columns
	},
	{
		name: "a terminal stacks the routes", args: "nodes routes list", terminal: true, width: 80, env: []string{"NO_COLOR=1"},
		stdout: "ID  NAME     ENABLED     ADVERTISED      SERVING\n12  mynode   10.0.0.0/8  10.0.0.0/8      10.0.0.0/8\n                         192.168.0.0/24\n14  gateway  exit        exit            exit\n", //nolint:dupword // exit in three columns
	},
	{name: "one node", args: "nodes routes list mynode", stdout: "ID  NAME    ENABLED     ADVERTISED                  SERVING\n12  mynode  10.0.0.0/8  10.0.0.0/8, 192.168.0.0/24  10.0.0.0/8\n"},
	{name: "one node as JSON", args: "nodes routes list mynode -o json", want: nodes.rows(onlyID("12"))},
	{name: "JSON is the nodes with routes", args: "nodes routes list -o json", want: nodes.rows(onlyID("12", "14"))},
	{name: "an unknown node is an error", args: "nodes routes list nope", stderr: "Error: no node matches \"nope\".\n", code: 1},
	{name: "a filter on exit", args: "nodes routes ls --filter enabled-routes=exit", stdout: "ID  NAME     ENABLED  ADVERTISED  SERVING\n14  gateway  exit     exit        exit\n"}, //nolint:dupword // exit in three columns
	{name: "the real prefix in a filter", args: "nodes routes list --filter enabled-routes=::/0 --columns id", stdout: "ID\n14\n"},
	{name: "two arguments", args: "nodes routes list 12 13", stderr: "Error: `nodes routes list` takes at most 1 argument, got 2.\n\n  headscale nodes routes list [node]\n", code: 1},
	{
		name: "set replaces", args: "nodes routes set 12 10.0.0.0/8,192.168.0.0/24", stdout: "Node 12 (mynode) enabled routes: 10.0.0.0/8, 192.168.0.0/24.\n",
		check: func(tb testing.TB, f *fixture, _ result) {
			tb.Helper()
			require.Equal(tb, "[10.0.0.0/8 192.168.0.0/24]", fmt.Sprint(nodeOf(tb, f, 12).ApprovedRoutes().AsSlice()))
		},
	},
	{name: "approve is set", args: "nodes routes approve 12 10.0.0.0/8,192.168.0.0/24", stdout: "Node 12 (mynode) enabled routes: 10.0.0.0/8, 192.168.0.0/24.\n"},
	{name: "exit is both exit routes", args: "nodes routes set 14 exit", stdout: "Node 14 (gateway) enabled routes: exit.\n"},
	{name: "exit mixes with subnet routes, and comes after them", args: "nodes routes set 14 10.0.0.0/8,exit", stdout: "Node 14 (gateway) enabled routes: 10.0.0.0/8, exit.\n"},
	{name: "one exit route is both", args: "nodes routes set 14 0.0.0.0/0", stdout: "Node 14 (gateway) enabled routes: exit.\n"},
	{name: "routes set -o json", args: "nodes routes set 14 exit -o json", want: answer(nodesPath + "/14/routes")},
	{
		name: "an empty list points to clear", args: "nodes routes set 12 ''",
		stderr: "Error: the route list is empty.\nTo remove all routes: headscale nodes routes clear 12\n", code: 1,
	},
	{
		name: "no routes points to clear", args: "nodes routes set 12",
		stderr: "Error: `nodes routes set` needs 2 arguments, got 1.\n\n  headscale nodes routes set <node> <routes>\n\nTo remove all routes: headscale nodes routes clear 12\n", code: 1,
	},
	{
		name: "a prefix with host bits, before any call", args: "nodes routes set 12 10.0.0.1/8",
		stderr: "Error: \"10.0.0.1/8\" is not a route: a route is an IP prefix with no host bits, such as 10.0.0.0/8, or exit.\n", code: 1,
		check: func(tb testing.TB, _ *fixture, r result) {
			tb.Helper()
			require.Empty(tb, r.asked)
		},
	},
	{
		name: "a bad route is named before a node that does not exist", args: "nodes routes set nope 10.0.0.1/8",
		stderr: "Error: \"10.0.0.1/8\" is not a route: a route is an IP prefix with no host bits, such as 10.0.0.0/8, or exit.\n", code: 1,
	},
	{
		name: "the node changed after the lookup", args: "nodes routes set mynode 10.0.0.0/8", answered: renamed(1),
		stdout: "Node 12 (renamed-1) enabled routes: 10.0.0.0/8.\n",
	},
	{
		name: "clear", args: "nodes routes clear 12", stdout: "Node 12 (mynode) has no enabled routes now.\n",
		check: func(tb testing.TB, f *fixture, _ result) {
			tb.Helper()
			require.Zero(tb, nodeOf(tb, f, 12).ApprovedRoutes().Len())
		},
	},
	{name: "clear a node that changed", args: "nodes routes clear mynode", answered: renamed(1), stdout: "Node 12 (renamed-1) has no enabled routes now.\n"},
	{
		name: "a credential that may only read", args: "nodes routes clear 12",
		setup: func(tb testing.TB, f *fixture) {
			tb.Helper()
			f.vars["token"] = f.token(tb, "devices:core:read")
		},
		env:    []string{"HEADSCALE_CLI_ADDRESS={url}", "HEADSCALE_CLI_API_KEY={token}"},
		stderr: "Error: this credential may not do that.\nIt lacks the scope devices:routes.\n", code: 1,
	},
}

func TestNodesRoutes(t *testing.T) {
	t.Parallel()

	runCases(t, fleet, routesCases)
}

var tags = listAt{"/api/headscale/v0/tags", "tags"}

// untagged is builder logging in again as alice's node after the CLI read
// it as tagged: a write on the tags it read is refused, and the tag write
// that follows takes alice's ownership.
func untagged(tb testing.TB, f *fixture, req string) {
	tb.Helper()

	if !strings.HasPrefix(req, "GET "+nodesPath) || f.changes > 0 {
		return
	}

	f.changes++

	n := *nodeOf(tb, f, 13).AsStruct()
	n.Tags = nil
	f.srv.State().PutNodeInStoreForTest(n)
}

var tagsCases = []cliCase{
	{
		name: "every tag of the policy and of a node", args: "nodes tags list",
		stdout: `TAG          COUNT  IN POLICY  NODES
tag:build    1      yes        builder
tag:ci       1      yes        builder
tag:example  0      yes
tag:infra    2      yes        gateway, web
tag:old      1      no         web
tag:server   0      yes
tag:test     0      yes
`,
	},
	{name: "the tags of one node", args: "nodes tags list builder", stdout: "TAG        COUNT  IN POLICY  NODES\ntag:build  1      yes        builder\ntag:ci     1      yes        builder\n"},
	{
		name: "the tags of one node as JSON", args: "nodes tags list builder -o json", want: tags.rows(all),
		check: func(tb testing.TB, _ *fixture, r result) {
			tb.Helper()
			require.Contains(tb, r.asked, "GET /api/headscale/v0/tags?pageSize=2&node=13")
		},
	},
	{name: "a tag gone from the policy", args: "nodes tags ls --filter in-policy=no", stdout: "TAG      COUNT  IN POLICY  NODES\ntag:old  1      no         web\n"},
	{name: "an unknown node", args: "nodes tags list nope", stderr: "Error: no node matches \"nope\".\n", code: 1},
	{name: "a tagged node does not ask", args: "nodes tags set 13 tag:ci,tag:build,tag:test", stdout: "Node 13 (builder) tags: tag:build, tag:ci, tag:test.\n"},
	{
		name: "a user's node asks", args: "nodes tags set mynode tag:server", terminal: true, stdin: "y\n",
		stderr: "Node 12 (mynode) is owned by User 3 (alice).\nTagging removes that ownership and cannot be undone.\nContinue? [y/N] ",
		stdout: "Node 12 (mynode) tags: tag:server.\n",
		check: func(tb testing.TB, f *fixture, _ result) {
			tb.Helper()
			require.True(tb, nodeOf(tb, f, 12).IsTagged())
		},
	},
	{name: "--force does not ask", args: "nodes tags set mynode tag:server --force", stdout: "Node 12 (mynode) tags: tag:server.\n"},
	{
		name: "no is not done", args: "nodes tags set mynode tag:server", terminal: true, stdin: "no\n",
		stderr: "Node 12 (mynode) is owned by User 3 (alice).\nTagging removes that ownership and cannot be undone.\nContinue? [y/N] Aborted.\n", code: 1,
		check: func(tb testing.TB, f *fixture, _ result) {
			tb.Helper()
			require.False(tb, nodeOf(tb, f, 12).IsTagged())
		},
	},
	{
		name: "no terminal to ask", args: "nodes tags set 12 tag:server",
		stderr: "Error: confirmation needed, but there is no terminal.\nRun again with --force to tag Node 12 (mynode).\n", code: 1,
	},
	{name: "--force on a tagged node too", args: "nodes tags set 13 tag:ci --force", stdout: "Node 13 (builder) tags: tag:ci.\n"},
	{
		name: "an empty list", args: "nodes tags set 13 ''",
		stderr: "Error: the tag list is empty. A tagged node needs at least one tag.\n", code: 1,
	},
	{name: "a tag the policy does not name", args: "nodes tags set 13 tag:serverr", stderr: "Error: these tags are not in the policy: tag:serverr\n", code: 1},
	{name: "-o json", args: "nodes tags set 13 tag:ci -o json", want: answer(nodesPath + "/13/tags")},
	{
		name: "a tagged node that became a user's while the CLI read it: asked on the new state", args: "nodes tags set builder tag:ci", terminal: true, stdin: "y\n",
		answered: untagged,
		stderr:   "Node 13 (builder) is owned by User 3 (alice).\nTagging removes that ownership and cannot be undone.\nContinue? [y/N] ",
		stdout:   "Node 13 (builder) tags: tag:ci.\n",
		check: func(tb testing.TB, _ *fixture, r result) {
			tb.Helper()
			require.Equal(tb, []string{"PUT " + nodesPath + "/13/tags", "GET " + nodesPath + "/13", "PUT " + nodesPath + "/13/tags"}, r.asked[3:])
		},
	},
	{
		name: "the same with no terminal is not done", args: "nodes tags set builder tag:ci", answered: untagged,
		stderr: "Error: confirmation needed, but there is no terminal.\nRun again with --force to tag Node 13 (builder).\n", code: 1,
		check: func(tb testing.TB, f *fixture, _ result) {
			tb.Helper()
			require.False(tb, nodeOf(tb, f, 13).IsTagged(), "alice keeps the node")
		},
	},
	{
		name: "a token gives only tags it holds", args: "nodes tags set 13 tag:test",
		setup: func(tb testing.TB, f *fixture) {
			tb.Helper()
			f.vars["token"] = f.taggedToken(tb, []string{"tag:ci"}, "devices:core")
		},
		env: []string{"HEADSCALE_CLI_ADDRESS={url}", "HEADSCALE_CLI_API_KEY={token}"},
		stderr: "Error: this credential may not do that.\nAn OAuth access token gives and takes only tags it holds or owns, " +
			"and only on a node whose tags are all its own; an API key may give any tag of the policy.\n", code: 1,
	},
}

func TestNodesTags(t *testing.T) {
	t.Parallel()

	runCases(t, fleet, tagsCases)
}
