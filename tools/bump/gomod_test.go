package main

import (
	"testing"

	"golang.org/x/mod/modfile"
)

// The lockstep notes in go.mod are load-bearing prose: they are the only record
// of why the pairs exist. `go mod tidy` re-sorts requires and can leave a note
// stranded above the wrong line, which reads fine in a diff and is wrong.
func TestNoteAttached(t *testing.T) {
	const attached = `module example.com/x

go 1.27.0

require (
	// NOTE: modernc sqlite has a fragile dependency chain:
	// https://github.com/juanfont/headscale/issues/2188
	modernc.org/sqlite v1.52.0
	pgregory.net/rapid v1.3.0
)
`

	// The note is still in the file, but now documents the wrong module.
	const detached = `module example.com/x

go 1.27.0

require (
	// NOTE: modernc sqlite has a fragile dependency chain:
	// https://github.com/juanfont/headscale/issues/2188
	pgregory.net/rapid v1.3.0

	modernc.org/sqlite v1.52.0
)
`

	tests := []struct {
		name    string
		content string
		want    bool
	}{
		{name: "attached", content: attached, want: true},
		{name: "detached", content: detached, want: false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			f, err := modfile.Parse("go.mod", []byte(test.content), nil)
			if err != nil {
				t.Fatalf("parsing fixture: %v", err)
			}

			if got := noteAttached(f, "modernc.org/sqlite", "issues/2188"); got != test.want {
				t.Errorf("noteAttached = %v, want %v", got, test.want)
			}
		})
	}
}

func TestRequiredVersion(t *testing.T) {
	const goMod = `module modernc.org/sqlite

go 1.25.0

require (
	modernc.org/libc v1.75.6
	modernc.org/mathutil v1.7.1
)
`

	f, err := modfile.Parse("go.mod", []byte(goMod), nil)
	if err != nil {
		t.Fatalf("parsing fixture: %v", err)
	}

	tests := []struct {
		name  string
		dep   string
		want  string
		found bool
	}{
		{name: "present", dep: "modernc.org/libc", want: "v1.75.6", found: true},
		{name: "absent", dep: "gvisor.dev/gvisor", found: false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, ok := requiredVersion(f, test.dep)
			if ok != test.found {
				t.Fatalf("requiredVersion found = %v, want %v", ok, test.found)
			}

			if got != test.want {
				t.Errorf("requiredVersion = %q, want %q", got, test.want)
			}
		})
	}
}

// The repository's own go.mod is the case that actually matters: the notes must
// survive whatever the last tidy did to the require blocks.
func TestRepoLockstepNotesAttached(t *testing.T) {
	b, err := modfile.Parse("../../go.mod", mustRead(t, "../../go.mod"), nil)
	if err != nil {
		t.Fatalf("parsing go.mod: %v", err)
	}

	for _, note := range lockstepNotes {
		if !noteAttached(b, note.module, note.needle) {
			t.Errorf("go.mod: note %q is not attached to %s", note.needle, note.module)
		}
	}

	if len(b.Tool) == 0 {
		t.Error("go.mod: tool block is missing")
	}
}
