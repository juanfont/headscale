package offline

import (
	"database/sql"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/juanfont/headscale/hscontrol/config"
	hsdb "github.com/juanfont/headscale/hscontrol/db"
	policyv2 "github.com/juanfont/headscale/hscontrol/policy/v2"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/stretchr/testify/require"
)

// env is the environment the CLI would give a new server in dir, whose
// config file is empty, so no file of the machine is read.
func env(dir string, more ...string) []string {
	return append([]string{
		"HEADSCALE_CONFIG=" + filepath.Join(dir, "config.yaml"),
		"HEADSCALE_DATABASE_SQLITE_PATH=" + filepath.Join(dir, "db.sqlite"),
		"HEADSCALE_NOISE_PRIVATE_KEY_PATH=" + filepath.Join(dir, "noise.key"),
		"HEADSCALE_UNIX_SOCKET=" + filepath.Join(dir, "headscale.sock"),
		"HEADSCALE_POLICY_MODE=database",
		"HEADSCALE_SERVER_URL=https://hs.example.com",
	}, more...)
}

// open is the database of a new server in a directory of its own, as a
// stopped server leaves it, opened to write.
func open(t *testing.T, more ...string) *DB {
	t.Helper()

	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "config.yaml"), nil, 0o600))
	created(t, dir)

	d, err := Open(t.Context(), filepath.Join(dir, "config.yaml"), env(dir, more...), true)
	require.NoError(t, err)
	t.Cleanup(func() { _ = d.Close() })

	return d
}

// created makes the database of a server in dir, as its first start does.
func created(t *testing.T, dir string) {
	t.Helper()

	l, err := config.Load(filepath.Join(dir, "config.yaml"), true, env(dir))
	require.NoError(t, err)

	d, err := hsdb.NewHeadscaleDatabase(l.Config)
	require.NoError(t, err)
	require.NoError(t, d.Close())
}

// TestOpen: a server that answers on the socket keeps its database to
// itself, a socket file it left does not; a database that is not there is
// not made, and one of another schema is refused; a read cannot write.
func TestOpen(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "config.yaml"), nil, 0o600))

	_, err := Open(t.Context(), filepath.Join(dir, "config.yaml"), env(dir), false)
	require.EqualError(t, err, "the database "+filepath.Join(dir, "db.sqlite")+" does not exist.")
	require.NoFileExists(t, filepath.Join(dir, "db.sqlite"))

	created(t, dir)

	socket := filepath.Join(dir, "headscale.sock")

	l, err := (&net.ListenConfig{}).Listen(t.Context(), "unix", socket)
	require.NoError(t, err)

	_, err = Open(t.Context(), filepath.Join(dir, "config.yaml"), env(dir), false)
	require.Equal(t, &RunningError{Socket: socket}, err)

	unix, ok := l.(*net.UnixListener)
	require.True(t, ok)
	unix.SetUnlinkOnClose(false)
	require.NoError(t, l.Close())
	require.FileExists(t, socket)

	d, err := Open(t.Context(), filepath.Join(dir, "config.yaml"), env(dir), false)
	require.NoError(t, err, "a socket file with no listener")

	_, err = d.SetPolicy([]byte("{}"))
	require.Error(t, err, "a read wrote")
	require.NoError(t, d.Close())

	d, err = Open(t.Context(), filepath.Join(dir, "config.yaml"), env(dir), true)
	require.NoError(t, err)
	require.NoError(t, d.db.DB.Exec("INSERT INTO migrations (id) VALUES ('999912312359-from-the-future')").Error)
	require.NoError(t, d.Close())

	_, err = Open(t.Context(), filepath.Join(dir, "config.yaml"), env(dir), false)
	require.EqualError(t, err, "the database has a migration that this headscale does not know: 999912312359-from-the-future. Run the CLI of the server's version.")
}

// TestOpenSocket: only no file and a refused connection say that nobody
// is there; a socket the user may not open is a refusal that names it. A
// relative socket is asked beside the config file too.
func TestOpenSocket(t *testing.T) {
	t.Parallel()

	// A unix socket path is short: the test's own directory is too long.
	dir, err := os.MkdirTemp("", "hs") //nolint:usetesting // t.TempDir is named after the test
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })

	require.NoError(t, os.WriteFile(filepath.Join(dir, "config.yaml"), nil, 0o600))
	created(t, dir)

	socket := filepath.Join(dir, "headscale.sock")

	l, err := (&net.ListenConfig{}).Listen(t.Context(), "unix", socket)
	require.NoError(t, err)
	t.Cleanup(func() { _ = l.Close() })

	_, err = Open(t.Context(), filepath.Join(dir, "config.yaml"), env(dir, "HEADSCALE_UNIX_SOCKET=headscale.sock"), false)
	require.Equal(t, &RunningError{Socket: socket}, err, "a relative socket beside the config file")

	if os.Geteuid() == 0 {
		return
	}

	require.NoError(t, os.Chmod(socket, 0o000))

	_, err = Open(t.Context(), filepath.Join(dir, "config.yaml"), env(dir), false)
	require.Equal(t, &SocketError{Socket: socket, Err: syscall.EACCES}, err)
}

// TestOpenNotHeadscale: a file that is not a Headscale database says so.
func TestOpenNotHeadscale(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "config.yaml"), nil, 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "db.sqlite"), nil, 0o600))

	_, err := Open(t.Context(), filepath.Join(dir, "config.yaml"), env(dir), false)
	require.EqualError(t, err, filepath.Join(dir, "db.sqlite")+" is not a Headscale database: it has no migrations table.")
}

// TestPolicy: what is stored comes back byte for byte; a policy the server
// would refuse is refused with its problems placed, and stores nothing.
func TestPolicy(t *testing.T) {
	t.Parallel()

	d := open(t)

	doc, err := d.Policy()
	require.NoError(t, err)
	require.Empty(t, doc.Data, "nothing is stored")
	require.Nil(t, doc.Updated)

	pol := "// hskey-api-abcdefghijkl-x\r\n{\t\"acls\": []}" //nolint:gosec // a made-up key
	set, err := d.SetPolicy([]byte(pol))
	require.NoError(t, err)
	require.Equal(t, pol, set.Data)

	doc, err = d.Policy()
	require.NoError(t, err)
	require.Equal(t, pol, doc.Data)
	require.Equal(t, types.PolicyModeDB, doc.Mode)
	require.NotNil(t, doc.Updated)

	_, err = d.SetPolicy([]byte(`{"acls": [{"action": "accept", "src": ["tag:nope"], "dst": ["*:*"]}]}`))

	refused, ok := err.(*RefusedError) //nolint:errorlint // the type itself
	require.True(t, ok, "%v", err)
	require.Equal(t, []policyv2.PolicyError{{Message: `unknown tag "tag:nope"`, Line: 1, Column: 40}}, policyv2.Explain(refused.Policy, refused.Err).Errors)

	for _, text := range []string{"", " \n", "null"} {
		err := d.CheckPolicy([]byte(text))
		require.ErrorAs(t, err, &refused, "%q", text)
	}

	doc, err = d.Policy()
	require.NoError(t, err)
	require.Equal(t, pol, doc.Data, "a refused policy stores nothing")
}

// TestPolicyUsers: the check is made against the users of the database: a
// name two users have matches neither.
func TestPolicyUsers(t *testing.T) {
	t.Parallel()

	d := open(t)

	pol := []byte(`{"acls": [{"action": "accept", "src": ["alice@"], "dst": ["*:*"]}]}`)

	_, err := d.db.CreateUser(types.User{Name: "alice"})
	require.NoError(t, err)
	require.NoError(t, d.CheckPolicy(pol))

	_, err = d.db.CreateUser(types.User{
		Name: "alice", Provider: util.RegisterMethodOIDC,
		ProviderIdentifier: sql.NullString{String: "https://idp.example.com/alice", Valid: true},
	})
	require.NoError(t, err)

	var refused *RefusedError

	require.ErrorAs(t, d.CheckPolicy(pol), &refused)

	ex := policyv2.Explain(refused.Policy, refused.Err)
	require.Len(t, ex.Errors, 1)
	require.Contains(t, ex.Errors[0].Message, `"alice@" matches more than one user`)
}

// TestPolicyFile: in file mode the policy is the file, and a write is
// refused with its path, or with none when no file is set.
func TestPolicyFile(t *testing.T) {
	t.Parallel()

	none := open(t, "HEADSCALE_POLICY_MODE=file")

	doc, err := none.Policy()
	require.NoError(t, err)
	require.Equal(t, types.PolicyModeFile, doc.Mode)
	require.Empty(t, doc.Path)

	_, err = none.SetPolicy([]byte("{}"))
	require.Equal(t, &ReadOnlyError{}, err)

	path := filepath.Join(t.TempDir(), "policy.hujson")
	require.NoError(t, os.WriteFile(path, []byte("{}\n"), 0o600))

	d := open(t, "HEADSCALE_POLICY_MODE=file", "HEADSCALE_POLICY_PATH="+path)

	doc, err = d.Policy()
	require.NoError(t, err)
	require.Equal(t, "{}\n", doc.Data)
	require.Equal(t, path, doc.Path)

	_, err = d.SetPolicy([]byte("{}"))
	require.Equal(t, &ReadOnlyError{Path: path}, err)
	require.NoError(t, d.CheckPolicy([]byte("{}")), "a check works in file mode")
}
