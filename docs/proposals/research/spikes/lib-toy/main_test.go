package main

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"

	"spike/cmdline"
)

// How a user of cmdline tests a CLI: run it in-process with argv and
// buffers, and ask Complete the same questions the shell would.
func TestRun(t *testing.T) {
	db := filepath.Join(t.TempDir(), "kv.json")
	t.Setenv("KV_DB", db)
	for _, tc := range []struct {
		argv, out string
		code      int
	}{
		{"set a 1", "", 0},
		{"get a", "1\n", 0},
		{"-d /nope --db " + db + " get a", "1\n", 0}, // last-wins
		{"get a -d /nope --db " + db, "1\n", 0},      // after the command too
		{"incr a", "2\n", 0},
		{"incr a 5 -v -v", "7\n", 0}, // -v counts
		{"rm a", "", 0},
		{"get a", "\n", 0},
		{"", "usage: kv [-d db] [-v] get|set|del|incr|completion ...\n", 0},
		{"get -h", "usage: kv [-d db] [-v] get|set|del|incr|completion ...\n", 0},
		{"gte a", "", 2},
		{"get", "", 2},
		{"get a --bogus", "", 2},
		{"set n 1 --verbose=false", "", 0},
		{"incr n -- -1", "0\n", 0},
		// Gaps: what this CLI would want and cmdline does not do.
		{"incr n -1", "", 2},  // a negative number is read as a flag (-1 unknown)
		{"incr n -vv", "", 2}, // grouped shorts are unknown flags
	} {
		var out, errb bytes.Buffer
		argv := strings.Fields(tc.argv)
		if code := run(argv, &out, &errb); code != tc.code || out.String() != tc.out {
			t.Errorf("kv %s: code %d out %q err %q; want %d %q", tc.argv, code, out.String(), errb.String(), tc.code, tc.out)
		}
	}
}

func TestComplete(t *testing.T) {
	db := filepath.Join(t.TempDir(), "kv.json")
	t.Setenv("KV_DB", db)
	if err := save(db, map[string]string{"alpha": "1", "beta": "2"}); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ line, want string }{
		{"", "get set del incr completion"},
		{"r", "rm"},
		{"get ", "alpha beta"},
		{"get a", "alpha"},
		{"-d x get b", "beta"},
		{"set alpha ", ""},
		{"get --", "--db --verbose --help"},
		{"completion f", "fish"},
		// Gap: del takes many keys, but Args completes by position only.
		{"del alpha ", ""},
	} {
		words := strings.Split(tc.line, " ")
		got, _ := cmdline.Complete(tree(), words[:len(words)-1], words[len(words)-1])
		if strings.Join(got, " ") != tc.want {
			t.Errorf("kv %s<Tab>: got %q, want %q", tc.line, got, tc.want)
		}
	}
}
