package audit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoggerRecordWritesJSONL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l, err := New(path, 1024, 3)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("file created before first Record, want lazy open")
	}

	err = l.Record("admin:alice", ActionUserCreated, "user:2", map[string]any{"name": "svc"})
	if err != nil {
		t.Fatalf("Record: %v", err)
	}

	if err := l.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}

	if !strings.Contains(string(raw), `"action":"user.created"`) ||
		!strings.Contains(string(raw), `"actor":"admin:alice"`) ||
		!strings.Contains(string(raw), `"target":"user:2"`) {
		t.Fatalf("unexpected line: %s", raw)
	}
}

func TestLoggerRotation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l, err := New(path, 1, DefaultRetainFiles)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// One byte threshold: every write rotates.
	for range DefaultRetainFiles + 2 {
		if err := l.Record("system", ActionPolicySet, "policy", nil); err != nil {
			t.Fatalf("Record: %v", err)
		}
	}

	if err := l.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}

	// base + at most RetainFiles generations
	if len(entries) > DefaultRetainFiles+1 {
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}

		t.Fatalf("too many files retained: %+v", names)
	}

	live, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read live log: %v", err)
	}

	if !strings.Contains(string(live), "policy.set") {
		t.Fatalf("live log unexpectedly empty or wrong: %s", live)
	}
}

func TestEventLineShape(t *testing.T) {
	ev := &Event{Time: time.Date(2026, 10, 18, 0, 0, 0, 0, time.UTC), Actor: "system", Action: ActionUserDeleted, Target: "user:7"}
	line, err := ev.Line()
	if err != nil {
		t.Fatalf("Line: %v", err)
	}

	want := `{"time":"2026-10-18T00:00:00Z","actor":"system","action":"user.deleted","target":"user:7"}` + "\n"
	if string(line) != want {
		t.Fatalf("got %q want %q", line, want)
	}
}

func TestNilLoggerIsNoop(t *testing.T) {
	if err := (*Logger)(nil).Record("system", ActionUserDeleted, "user:1", nil); err != nil {
		t.Fatalf("nil logger must be a no-op, got %v", err)
	}
}
