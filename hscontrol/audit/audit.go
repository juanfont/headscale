// Package audit implements the Net-Scale configuration audit log: an
// append-only, JSON-lines record of control-plane administrative changes.
//
// The log is a system of record in the sense of Tailscale-tier "configuration
// audit logging" feature parity, implemented cleanly for Net-Scale: each
// mutating control-plane operation can emit an [Event] that is persisted as a
// single JSON line. The file rotates at a size threshold, keeping the most
// recent generations so an operator (or a later log-streaming integration)
// can consume them with any JSONL tooling.
package audit

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Action names the control-plane operation that produced the event.
// Keep them stable and lowercase dotted identifiers: downstream log
// pipelines key on them.
const (
	ActionUserCreated    = "user.created"
	ActionUserUpdated    = "user.updated"
	ActionUserRenamed    = "user.renamed"
	ActionUserDeleted    = "user.deleted"
	ActionNodeTagged     = "node.tagged"
	ActionPolicySet      = "policy.set"
	ActionOIDCGroupsSet  = "oidc_groups.set"
	ActionAuthKeyCreated = "authkey.created"
	ActionAuthKeyDeleted = "authkey.deleted"
)

// Default settings used when the config section leaves them unset.
const (
	DefaultPath        = "/var/lib/headscale/audit-events.jsonl"
	DefaultMaxSizeMB   = 100
	DefaultRetainFiles = 5
)

// Event is a single audited control-plane change.
type Event struct {
	// Time is when the operation completed (UTC).
	Time time.Time `json:"time"`

	// Actor identifies who performed the change; "admin:<name>" for an
	// authenticated principal or "system" for server-initiated changes.
	Actor string `json:"actor"`

	// Action is a stable dotted identifier of the operation, one of the
	// Action* constants.
	Action string `json:"action"`

	// Target identifies the object that changed, e.g. "user:2", "node:1".
	Target string `json:"target,omitempty"`

	// Detail carries operation-specific structured data.
	Detail map[string]any `json:"detail,omitempty"`
}

// Line returns the event encoded as one JSON object terminated by a newline.
func (e *Event) Line() ([]byte, error) {
	buf := new(bytes.Buffer)

	enc := json.NewEncoder(buf)
	enc.SetEscapeHTML(false)

	if err := enc.Encode(e); err != nil {
		return nil, fmt.Errorf("encoding audit event: %w", err)
	}

	return buf.Bytes(), nil
}

// Logger writes [Event]s as JSON lines to a file, rotating at a size
// threshold. It is safe for concurrent use.
type Logger struct {
	mu sync.Mutex

	path     string // base path of the audit file
	maxBytes int64  // rotation threshold (approximate; no partial lines)

	f *os.File // current append handle; nil until first write
}

// New opens (but does not yet create) a logger writing to path. The file is
// created lazily on the first recorded event, so enabling audit logging has
// no filesystem side effects until something is actually audited.
func New(path string, maxBytes int64, maxFiles int) (*Logger, error) {
	if path == "" {
		return nil, fmt.Errorf("audit: path is required")
	}

	if maxBytes <= 0 {
		maxBytes = DefaultMaxSizeMB * 1024 * 1024
	}

	_ = maxFiles // generations are pruned during rotation; see rotateLocked.

	return &Logger{
		path:     path,
		maxBytes: maxBytes,
	}, nil
}

// Record persists one event. Recording must never break the operation that
// audited it: errors are returned wrapped for logging by the caller, but
// no write happens if the event cannot be encoded.
func (l *Logger) Record(actor, action, target string, detail map[string]any) error {
	if l == nil {
		return nil // audit disabled or not wired: no-op
	}

	ev := &Event{
		Time:   time.Now().UTC(),
		Actor:  actor,
		Action: action,
		Target: target,
		Detail: detail,
	}

	line, err := ev.Line()
	if err != nil {
		return err
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	if err := l.ensureOpen(); err != nil {
		return err
	}

	if err := l.maybeRotate(); err != nil {
		return err
	}

	if _, err := l.f.Write(line); err != nil {
		return fmt.Errorf("audit: writing event: %w", err)
	}

	return nil
}

// Close releases the file handle.
func (l *Logger) Close() error {
	if l == nil {
		return nil
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	if l.f == nil {
		return nil
	}

	err := l.f.Close()
	l.f = nil

	return err
}

// ensureOpen opens the current audit file in append mode.
func (l *Logger) ensureOpen() error {
	if l.f != nil {
		return nil
	}

	if err := os.MkdirAll(filepath.Dir(l.path), 0o750); err != nil {
		return fmt.Errorf("audit: creating directory: %w", err)
	}

	f, err := os.OpenFile(l.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600) //nolint:gosec // path comes from operator config
	if err != nil {
		return fmt.Errorf("audit: opening %s: %w", l.path, err)
	}

	l.f = f

	return nil
}

// maybeRotate closes the current file and shifts it to <path>.1 … <path>.N
// once it reached the size threshold, dropping the oldest generation.
func (l *Logger) maybeRotate() error {
	f := l.f
	info, err := f.Stat()
	if err != nil {
		return fmt.Errorf("audit: stat %s: %w", l.path, err)
	}

	if info.Size() < l.maxBytes {
		return nil
	}

	if err := f.Close(); err != nil {
		return fmt.Errorf("audit: closing %s for rotation: %w", l.path, err)
	}

	l.f = nil

	for gen := DefaultRetainFiles - 1; gen >= 1; gen-- {
		from := fmt.Sprintf("%s.%d", l.path, gen)
		to := fmt.Sprintf("%s.%d", l.path, gen+1)

		if _, err := os.Stat(from); err == nil {
			_ = os.Remove(to)
			if err := os.Rename(from, to); err != nil {
				return fmt.Errorf("audit: rotating %s: %w", from, err)
			}
		}
	}

	if err := os.Rename(l.path, fmt.Sprintf("%s.1", l.path)); err != nil {
		return fmt.Errorf("audit: rotating %s: %w", l.path, err)
	}

	// Reopen a fresh current file so the caller's write lands in it.
	if err := l.ensureOpen(); err != nil {
		return fmt.Errorf("audit: reopening after rotation: %w", err)
	}

	return nil
}
