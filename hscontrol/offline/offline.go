// Package offline works on the database of a server that is not running:
// the CLI's database bypass, the rescue path for the day a policy in the
// database stops the server from starting. It runs the server's own checks
// of a policy, so what it refuses and why reads as API v0 answers it.
package offline

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/juanfont/headscale/hscontrol/config"
	hsdb "github.com/juanfont/headscale/hscontrol/db"
	"github.com/juanfont/headscale/hscontrol/policy"
	policyv2 "github.com/juanfont/headscale/hscontrol/policy/v2"
	"github.com/juanfont/headscale/hscontrol/state"
	"github.com/juanfont/headscale/hscontrol/types"
)

// DB is the database of a stopped server, with its configuration.
type DB struct {
	db  *hsdb.HSDatabase
	cfg *types.Config
	// Warnings are what loading the configuration found that does not stop
	// it, as serve would log them.
	Warnings []string
}

// Open loads the configuration from file and environ as serve does,
// validates it, and opens its database as it is (see [hsdb.OpenAsIs]):
// read-only unless write. A server that answers on the configured socket
// is a *RunningError, and a socket that cannot be asked is a
// *SocketError: the database may be in a server's hands.
func Open(ctx context.Context, file string, environ []string, write bool) (*DB, error) {
	cfg, warnings, err := load(file, environ)
	if err != nil {
		return nil, err
	}

	err = askSocket(ctx, cfg)
	if err != nil {
		return nil, err
	}

	d, err := hsdb.OpenAsIs(cfg, !write)
	if err != nil {
		return nil, openError(cfg, err)
	}

	return &DB{db: d, cfg: cfg, Warnings: warnings}, nil
}

// Sessions is [DB.OtherSessions] of the database that file and environ
// name, for the question before a write: 0 on SQLite, which it does not
// open.
func Sessions(ctx context.Context, file string, environ []string) (int, error) {
	cfg, _, err := load(file, environ)
	if err != nil || cfg.Database.Type != types.DatabasePostgres {
		return 0, err
	}

	d, err := Open(ctx, file, environ, false)
	if err != nil {
		return 0, err
	}
	defer d.Close()

	return d.OtherSessions()
}

// load is the configuration as serve loads and validates it, with the
// warnings serve would log.
func load(file string, environ []string) (*types.Config, []string, error) {
	l, err := config.Load(file, file != "", environ)

	switch {
	case err != nil && l.File != "":
		return nil, nil, fmt.Errorf("the config file %s cannot be read: %w", l.File, err)
	case err != nil:
		return nil, nil, fmt.Errorf("the configuration cannot be read: %w", err)
	}

	cfg := l.Config
	// The server never uses the CLI's key, which may name a file that
	// cannot be read here.
	cfg.CLI.APIKey = ""

	err = config.Validate(cfg)
	if err != nil {
		// A config error ends in a line break, which the caller's does too.
		return nil, nil, fmt.Errorf("the configuration is not valid: %s", strings.TrimRight(err.Error(), "\n")) //nolint:err113 // the text of a config error is the sentence
	}

	return cfg, append(l.Warnings, config.Warnings(cfg)...), nil
}

// askSocket asks the server's socket whether it listens. Only no file and
// a refused connection, what a stopped server leaves, say that nobody is
// there. A relative path is where the server stood, which is not known
// here: as written and beside the config file are both asked, and not
// finding them proves nothing; the lock of a write is the guard then.
func askSocket(ctx context.Context, cfg *types.Config) error {
	paths := []string{cfg.UnixSocket}
	if !filepath.IsAbs(cfg.UnixSocket) {
		paths = append(paths, cfg.AbsPath(cfg.UnixSocket))
	}

	for _, socket := range paths {
		conn, err := (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "unix", socket)

		switch {
		case err == nil:
			_ = conn.Close()

			return &RunningError{Socket: socket}
		case errors.Is(err, fs.ErrNotExist), errors.Is(err, syscall.ECONNREFUSED):
		default:
			// The cause alone: the error of the dial repeats the path.
			if errno, ok := errors.AsType[syscall.Errno](err); ok {
				err = errno
			}

			return &SocketError{Socket: socket, Err: err}
		}
	}

	return nil
}

// Where names the database: its file, or its PostgreSQL database.
func (d *DB) Where() string { return where(d.cfg) }

func where(cfg *types.Config) string {
	if cfg.Database.IsSQLite() {
		return cfg.SQLitePath()
	}

	return "the PostgreSQL database " + cfg.Database.Postgres.Name
}

// openError says why the database of cfg cannot be opened as it is.
func openError(cfg *types.Config, err error) error {
	w := where(cfg)

	var version *hsdb.VersionError

	switch {
	case errors.Is(err, hsdb.ErrDatabaseMissing):
		return fmt.Errorf("the database %s does not exist.", w) //nolint:err113,staticcheck // a sentence of the CLI
	case errors.Is(err, hsdb.ErrInUse):
		return fmt.Errorf("another program has the database %s open, such as a server that is starting or running. Stop it, then run the command again.", w) //nolint:err113,staticcheck // a sentence of the CLI
	case errors.Is(err, hsdb.ErrNeedsRecovery):
		return fmt.Errorf("the database %s holds a write that was not finished, which a read cannot recover without writing. Start the server once so it recovers the database, or run the command on a copy of the database files in a directory you may write.", w) //nolint:err113,staticcheck // a sentence of the CLI
	case errors.Is(err, hsdb.ErrNotHeadscale):
		return fmt.Errorf("%s is not a Headscale database: %s.", w, reason(err, hsdb.ErrNotHeadscale)) //nolint:err113,staticcheck // a sentence of the CLI
	case errors.Is(err, hsdb.ErrSchemaOlder), errors.Is(err, hsdb.ErrSchemaUnknown):
		return fmt.Errorf("%w. Run the CLI of the server's version.", err) //nolint:staticcheck // a sentence of the CLI
	case errors.As(err, &version):
		return fmt.Errorf("the database was last opened by headscale %s, and this CLI is %s. Run the CLI of headscale %s.", version.Stored, version.Current, version.Stored) //nolint:err113,staticcheck // a sentence of the CLI
	}

	return fmt.Errorf("the database cannot be opened: %w", err)
}

// reason is the text err adds to its sentinel.
func reason(err, sentinel error) string {
	return strings.TrimPrefix(err.Error(), sentinel.Error()+": ")
}

// RunningError is a server that answers on Socket.
type RunningError struct{ Socket string }

func (e *RunningError) Error() string { return "a server answers on " + e.Socket }

// SocketError is a socket that cannot be asked whether a server listens,
// such as one the user may not open.
type SocketError struct {
	Socket string
	Err    error
}

func (e *SocketError) Error() string {
	return "the socket " + e.Socket + " cannot be asked: " + e.Err.Error()
}

func (e *SocketError) Unwrap() error { return e.Err }

// OthersOpen reports whether another program had the database open when
// a read opened it, such as a server: see [hsdb.HSDatabase.OthersOpen].
func (d *DB) OthersOpen() bool { return d.db.OthersOpen() }

// OtherSessions is how many other sessions have the database open: on
// PostgreSQL a server on another host is one, and cannot be told from
// another client; 0 on SQLite, whose write holds the database itself.
func (d *DB) OtherSessions() (int, error) { return d.db.OtherSessions() }

// Close closes the database.
func (d *DB) Close() error { return d.db.Close() }

// Policy is the policy the server would start with: the policy file in
// file mode, the stored one otherwise. Data is "" for none.
func (d *DB) Policy() (state.PolicyDocument, error) {
	doc := state.PolicyDocument{Mode: d.cfg.Policy.Mode}

	if doc.Mode != types.PolicyModeDB {
		if d.cfg.Policy.Path == "" {
			return doc, nil
		}

		doc.Path = d.cfg.AbsPath(d.cfg.Policy.Path)

		b, err := os.ReadFile(doc.Path)
		if err != nil {
			return doc, fmt.Errorf("the policy file %s cannot be read: %w", doc.Path, err)
		}

		doc.Data = string(b)

		return doc, nil
	}

	p, err := d.db.GetPolicy()

	switch {
	case errors.Is(err, types.ErrPolicyNotFound):
		return doc, nil
	case err != nil:
		return doc, fmt.Errorf("the stored policy cannot be read: %w", err)
	case strings.TrimSpace(p.Data) == "":
		// The server refuses an empty row as it does an empty file: it is
		// not a policy that allows all.
		return doc, fmt.Errorf("the stored policy is empty, which the server refuses: %w. Store one with policy set.", policyv2.ErrPolicyEmpty) //nolint:staticcheck // a sentence of the CLI
	}

	doc.Data, doc.Updated = p.Data, &p.UpdatedAt

	return doc, nil
}

// RefusedError is a policy that a write would refuse: the text and why,
// as the server keeps them for policy_invalid.
type RefusedError struct {
	Policy []byte
	Err    error
}

func (e *RefusedError) Error() string { return e.Err.Error() }

func (e *RefusedError) Unwrap() error { return e.Err }

// ReadOnlyError is a write of the policy in file mode. Path is the policy
// file, "" when none is set.
type ReadOnlyError struct{ Path string }

func (e *ReadOnlyError) Error() string { return "the policy is read from a file" }

// CheckPolicy runs every check of a policy write of API v0 on pol against
// the users and nodes of the database, its tests included; a refusal is a
// *RefusedError. It writes nothing.
func (d *DB) CheckPolicy(pol []byte) error {
	refused := func(err error) error {
		return &RefusedError{Policy: pol, Err: err}
	}

	err := policyv2.CheckPolicyText(pol)
	if err != nil {
		return refused(err)
	}

	users, err := d.db.ListUsers(nil)
	if err != nil {
		return fmt.Errorf("the users cannot be read: %w", err)
	}

	nodes, err := d.db.ListNodes()
	if err != nil {
		return fmt.Errorf("the nodes cannot be read: %w", err)
	}

	_, err = policy.PreparePolicy(pol, users, nodes.ViewSlice())
	if err != nil {
		return refused(err)
	}

	return nil
}

// SetPolicy stores pol after [DB.CheckPolicy], as a write of API v0 does;
// in file mode it is a *ReadOnlyError.
func (d *DB) SetPolicy(pol []byte) (state.PolicyDocument, error) {
	if d.cfg.Policy.Mode != types.PolicyModeDB {
		path := ""
		if d.cfg.Policy.Path != "" {
			path = d.cfg.AbsPath(d.cfg.Policy.Path)
		}

		return state.PolicyDocument{}, &ReadOnlyError{Path: path}
	}

	err := d.CheckPolicy(pol)
	if err != nil {
		return state.PolicyDocument{}, err
	}

	p, err := d.db.SetPolicy(string(pol))
	if err != nil {
		return state.PolicyDocument{}, fmt.Errorf("the policy cannot be stored: %w", err)
	}

	return state.PolicyDocument{Data: p.Data, Updated: &p.UpdatedAt, Mode: types.PolicyModeDB}, nil
}
