package newcli

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/juanfont/headscale/cmd/headscale/newcli/command"
	"github.com/juanfont/headscale/cmdline/argtest"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
)

var errModelMismatch = errors.New("CLI model mismatch")

// Bound: candidates are compared as a set, and against the CLI's own
// declaration, not the specification.
func TestRapidFilterCatalogue(t *testing.T) {
	tree := Tree()
	env := []string{"HOME=" + t.TempDir()}
	run := func(argv []string) (string, error) {
		var out, stderr bytes.Buffer

		rc := command.Run(
			tree,
			argv,
			command.Env{Stdout: &out, Stderr: &stderr, Environ: env},
		)
		if rc != 0 || stderr.Len() != 0 {
			return "", fmt.Errorf(
				"%w: %q: status=%d stderr=%q",
				errModelMismatch,
				argv,
				rc,
				stderr.String(),
			)
		}

		return out.String(), nil
	}

	// Proposal 001 defines the operators and operands independently of the completion callback.
	type condition struct{ accepted, badOperator, badValue string }

	conditions := map[string]condition{
		"id":      {"=1", ":1", "<many"},
		"text":    {":one", ">one", ":"},
		"list":    {":one", ">one", ":"},
		"owner":   {":team", ">team", ":"},
		"number":  {">1", ":1", "=many"},
		"bool":    {"=yes", ">yes", "=maybe"},
		"time":    {"<1h", ":1h", "<soon"},
		"version": {">1.2", ":1.2", "=later"},
	}

	type list struct{ words, columns, sealed, invalid []string }

	resources := []string{
		"users list",
		"nodes list",
		"nodes routes list",
		"nodes tags list",
		"auth keys list",
		"api keys list",
		"api oauth-clients list",
	}

	lists := make([]list, 0, len(resources))
	for _, resource := range resources {
		words := strings.Fields(resource)

		raw, err := run(slices.Concat(words, []string{"--list-columns", "-o", "json"}))
		if err != nil {
			t.Fatal(err)
		}

		var info []struct{ Name, Kind string }

		err = json.Unmarshal([]byte(raw), &info)
		if err != nil || len(info) == 0 {
			t.Fatalf("%s public column list: %v", resource, err)
		}

		cols := make([]string, 0, len(info))

		seals := make([]string, 0, len(info))

		invalid := make([]string, 0, 2*len(info))
		for _, c := range info {
			shape, ok := conditions[c.Kind]
			if !ok {
				t.Fatalf("no filter model for kind %q", c.Kind)
			}

			cols = append(cols, c.Name)
			seals = append(seals, c.Name+shape.accepted)

			invalid = append(invalid, c.Name+shape.badOperator, c.Name+shape.badValue)
			if c.Kind == "number" || c.Kind == "text" {
				seals = append(seals, c.Name+"=1")
			}
		}

		for _, seal := range seals {
			_, err := run(
				slices.Concat(words, []string{"--list-columns", "--filter", seal}),
			)
			if err != nil {
				t.Fatal(err)
			}
		}

		lists = append(lists, list{words, cols, seals, invalid})
	}

	rapid.Check(t, func(rt *rapid.T) {
		ls := rapid.SampledFrom(lists).Draw(rt, "list")
		col := rapid.SampledFrom(ls.columns).Draw(rt, "column")

		prefix := col[:rapid.IntRange(0, len(col)).Draw(rt, "prefix length")]
		if rapid.Bool().Draw(rt, "unmatched prefix") {
			prefix = "zz" + rapid.StringOfN(rapid.RuneFrom([]rune("abcxyz0-αé")), 0, 10, 32).
				Draw(rt, "unknown suffix")
		}

		sealed := rapid.SliceOfN(rapid.SampledFrom(ls.sealed), 0, 2).
			Draw(rt, "sealed filters")

		valid := rapid.Bool().Draw(rt, "valid sealed filters")
		if !valid {
			invalid := rapid.SampledFrom(slices.Concat([]string{"", col, "zz-unknown=1"}, ls.invalid)).
				Draw(rt, "invalid filter")
			at := rapid.IntRange(0, len(sealed)).Draw(rt, "invalid position")
			sealed = slices.Insert(sealed, at, invalid)
		}

		prior := ""
		if len(sealed) > 0 {
			prior = strings.Join(sealed, ",") + ","
		}

		space := rapid.SampledFrom([]string{"", " ", "\u00a0", "\u2003", " \u00a0"}).
			Draw(rt, "cursor spacing")
		cursor := prior + space + prefix

		path := slices.Clone(ls.words)
		if rapid.Bool().Draw(rt, "list alias") {
			path[len(path)-1] = "ls"
		}

		protocol := rapid.SampledFrom([]string{"__complete", "__completeNoDesc"}).
			Draw(rt, "protocol")
		argv := slices.Concat([]string{protocol}, path)
		argv = append(argv, argtest.Option(rt, "--filter", cursor)...)

		output, err := run(argv)
		if err != nil {
			fatalf(rt, "%v", err)
		}

		lines := strings.Split(strings.TrimSuffix(output, "\n"), "\n")
		directive := lines[len(lines)-1]
		bits, err := strconv.Atoi(strings.TrimPrefix(directive, ":"))
		candidates := lines[:len(lines)-1]
		// A suppressed list must also disable shell filename fallback.
		if err != nil || !strings.HasPrefix(directive, ":") || bits&4 == 0 ||
			bits&1 != 0 ||
			len(candidates) > 0 && bits&2 == 0 {
			fatalf(rt, "%q: unexpected directive %s", argv, directive)
		}

		var want []string

		for _, name := range ls.columns {
			if valid && strings.HasPrefix(name, prefix) {
				want = append(want, prior+space+name)
			}
		}

		slices.Sort(want)
		slices.Sort(candidates)

		if !slices.Equal(want, candidates) {
			fatalf(
				rt,
				"%q: candidates=%q want public columns=%q",
				argv,
				candidates,
				want,
			)
		}
	})
}

func TestInvalidFilterNoFiles(t *testing.T) {
	tree := Tree()

	for _, resource := range []string{"nodes", "users"} {
		for _, cursor := range []string{",na", "0,na", ",zzunknown", "0,zzunknown"} {
			var out, stderr bytes.Buffer

			argv := []string{"__complete", resource, "list", "--filter=" + cursor}
			code := command.Run(tree, argv, command.Env{Stdout: &out, Stderr: &stderr})
			lines := strings.Split(strings.TrimSuffix(out.String(), "\n"), "\n")
			directive := lines[len(lines)-1]

			bits, err := strconv.Atoi(strings.TrimPrefix(directive, ":"))
			if code != 0 || stderr.Len() != 0 || err != nil ||
				!strings.HasPrefix(directive, ":") ||
				bits&4 == 0 ||
				bits&1 != 0 {
				t.Errorf(
					"%q: status=%d reply=%q stderr=%q; filter completion must disable file fallback",
					argv,
					code,
					out.String(),
					stderr.String(),
				)
			}
		}
	}
}

type helpLeaf struct {
	words, aliases []string
	help           string
	config, output bool
}

type helpReply struct {
	code, answers  int
	stdout, stderr string
}

func helpCatalogue(t *testing.T) ([]helpLeaf, func([]string) helpReply) {
	t.Helper()

	tree := Tree()
	env := []string{"HOME=" + t.TempDir()}
	run := func(argv []string) helpReply {
		var (
			out, diagnostic bytes.Buffer
			reply           helpReply
		)

		reply.code = command.Run(
			tree,
			argv,
			command.Env{
				Stdout:   &out,
				Stderr:   &diagnostic,
				Environ:  env,
				Answered: func(*http.Request, []byte) { reply.answers++ },
			},
		)
		reply.stdout, reply.stderr = out.String(), diagnostic.String()

		return reply
	}

	commands := tree.Commands()

	leaves := make([]helpLeaf, 0, len(commands))
	for _, cmd := range commands {
		words := strings.Fields(cmd.Path)
		reply := run(append(slices.Clone(words), "--help"))

		_, flags, found := strings.Cut(reply.stdout, "\nFlags:\n")
		if reply.code != 0 || reply.stderr != "" || !found ||
			!strings.Contains(flags, "--help ") {
			t.Fatalf(
				"%s help: code=%d stderr=%q flags found=%t",
				cmd.Path,
				reply.code,
				reply.stderr,
				found,
			)
		}

		leaves = append(
			leaves,
			helpLeaf{
				words,
				cmd.Aliases,
				reply.stdout,
				strings.Contains(flags, "--config "),
				strings.Contains(flags, "--output "),
			},
		)
	}

	return leaves, run
}

func (l helpLeaf) check(r helpReply, chunks [][]string) error {
	if r.answers != 0 {
		return fmt.Errorf(
			"%w: help received %d API answers",
			errModelMismatch,
			r.answers,
		)
	}

	for _, chunk := range chunks {
		spelling, _, _ := strings.Cut(chunk[0], "=")

		var wrong string

		switch {
		case !l.config && (spelling == "-c" || spelling == "--config"):
			wrong = "--config"
		case !l.output && (spelling == "-o" || spelling == "--output"):
			wrong = "--output"
		default:
			continue
		}

		if r.code != 1 || r.stdout != "" ||
			!strings.HasPrefix(r.stderr, "Error: "+wrong+" does not apply to ") {
			return fmt.Errorf(
				"%w: unsupported option: exit=%d stdout=%q stderr=%q",
				errModelMismatch,
				r.code,
				r.stdout,
				r.stderr,
			)
		}

		return nil
	}

	if r.code != 0 || r.stderr != "" || r.stdout != l.help {
		return fmt.Errorf(
			"%w: exit=%d stderr=%q canonical help matches=%t",
			errModelMismatch,
			r.code,
			r.stderr,
			r.stdout == l.help,
		)
	}

	return nil
}

// Public help declares which global flags can reach each leaf.
//
// Bound: help comes from the same tree, so a leaf removed from both passes.
func TestRapidLeafOptionPlacement(t *testing.T) {
	leaves, run := helpCatalogue(t)
	hit := map[string]bool{}

	var accepted, unsupported, withAlias, interleaved int

	rapid.Check(t, func(rt *rapid.T) {
		leaf := leaves[rapid.IntRange(0, len(leaves)-1).Draw(rt, "command index")]

		path := slices.Clone(leaf.words)
		if len(leaf.aliases) > 0 && rapid.Bool().Draw(rt, "alias") {
			path[len(path)-1] = rapid.SampledFrom(leaf.aliases).Draw(rt, "leaf alias")
			withAlias++
		}

		options := [][]string{
			{rapid.SampledFrom([]string{"-h", "--help"}).Draw(rt, "help spelling")},
		}
		config := rapid.Bool().Draw(rt, "config")

		output := rapid.Bool().Draw(rt, "output")
		if config {
			flag := rapid.SampledFrom([]string{"-c", "--config"}).
				Draw(rt, "config spelling")
			value := rapid.SampledFrom([]string{"unused.yaml", "with space.yaml", "--help", "--output"}).
				Draw(rt, "config value")

				// "" is a mistake that -h does not hide (003 X8, 001 V6-16)
			options = append(options, argtest.Option(rt, flag, value))
		}

		if output {
			flag := rapid.SampledFrom([]string{"-o", "--output"}).
				Draw(rt, "output spelling")
			options = append(options, argtest.Option(rt, flag, "json"))
		}

		chunks := argtest.InterleaveChunks(rt, path, options...)

		argv := slices.Concat(chunks...)
		if len(options) > 1 && slices.Index(argv, path[len(path)-1]) > len(path)-1 {
			interleaved++
		}

		err := leaf.check(run(argv), chunks)
		if err != nil {
			fatalf(rt, "argv=%q: %v", argv, err)
		}

		hit[strings.Join(leaf.words, " ")] = true
		if config && !leaf.config || output && !leaf.output {
			unsupported++
		} else {
			accepted++
		}
	})
	t.Logf(
		"model classes accepted-placements=%d refused-placements=%d leaf-aliases=%d help-or-option-before-leaf=%d",
		accepted,
		unsupported,
		withAlias,
		interleaved,
	)
	t.Logf("reached %d of %d canonical leaves", len(hit), len(leaves))
}

func TestAllLeafGlobalOptionPositions(t *testing.T) {
	leaves, run := helpCatalogue(t)

	var forms, refusals int

	for _, leaf := range leaves {
		for _, last := range append([]string{leaf.words[len(leaf.words)-1]}, leaf.aliases...) {
			path := slices.Clone(leaf.words)
			path[len(path)-1] = last

			for _, option := range []struct {
				spell, value string
				config       bool
			}{{"-c", "unused.yaml", true}, {"--config", "unused.yaml", true}, {"-o", "json", false}, {"--output", "json", false}} {
				for _, words := range [][]string{{option.spell, option.value}, {option.spell + "=" + option.value}} {
					for _, help := range []string{"-h", "--help"} {
						for argv := range argtest.Placements(path, []string{help}, words) {
							err := leaf.check(run(argv), [][]string{words})
							if err != nil {
								t.Fatalf("argv=%q: %v", argv, err)
							}

							forms++

							if option.config && !leaf.config ||
								!option.config && !leaf.output {
								refusals++
							}
						}
					}
				}
			}
		}
	}

	t.Logf(
		"all %d two-option positions/spellings, %d refused, %d canonical leaves",
		forms,
		refusals,
		len(leaves),
	)
}

// TestRapidChecks: the count a run asks for, by the flag or by the
// environment, 0 included, is the count the package's properties make; ten
// when it asks for none. It counts the checks of a probe property in a
// child run of this binary, for each way of asking.
func TestRapidChecks(t *testing.T) {
	if os.Getenv(checksProbe) != "" {
		var n int

		rapid.Check(t, func(*rapid.T) { n++ })
		fmt.Printf("checks=%d\n", n) //nolint:forbidigo // read by the parent run

		return
	}

	t.Parallel()

	exe, err := os.Executable()
	require.NoError(t, err)

	for _, tt := range []struct {
		env  []string
		args []string
		want string
	}{
		{want: "checks=10"},
		{env: []string{"RAPID_CHECKS=3"}, want: "checks=3"},
		{env: []string{"RAPID_CHECKS=0"}, want: "checks=0"},
		{args: []string{"-rapid.checks=2"}, want: "checks=2"},
		{env: []string{"RAPID_CHECKS=3"}, args: []string{"-rapid.checks=2"}, want: "checks=2"},
	} {
		// The child sees nothing of the parent's run but the count under
		// test: no other RAPID_ setting, no flag, and a directory with no
		// failfile, which Rapid would replay first.
		//nolint:gosec // this test binary
		cmd := exec.CommandContext(
			t.Context(),
			exe,
			append([]string{"-test.run=^TestRapidChecks$", "-test.v"}, tt.args...)...)
		cmd.Dir = t.TempDir()

		cmd.Env = append(
			slices.DeleteFunc(
				os.Environ(),
				func(e string) bool { return strings.HasPrefix(e, "RAPID_") || strings.HasPrefix(e, "GOFLAGS=") },
			),
			append(tt.env, checksProbe+"=1")...)

		out, err := cmd.CombinedOutput()
		require.NoError(t, err, "%s", out)
		require.Contains(
			t,
			string(out),
			tt.want+"\n",
			"env %q args %q",
			tt.env,
			tt.args,
		)
	}
}

// TestDefaultChecks: the package's ten checks only when neither the flag
// nor the environment gives a count.
func TestDefaultChecks(t *testing.T) {
	t.Parallel()

	none := func(string) (string, bool) { return "", false }
	zero := func(k string) (string, bool) { return "0", k == "RAPID_CHECKS" }

	n, ok := defaultChecks(false, none)
	require.Equal(t, []any{"10", true}, []any{n, ok})

	for _, tt := range []struct {
		flag bool
		env  func(string) (string, bool)
	}{{true, none}, {false, zero}, {true, zero}} {
		_, ok := defaultChecks(tt.flag, tt.env)
		require.False(t, ok)
	}
}

// checksProbe makes TestRapidChecks the probe that a child run counts.
const checksProbe = "HEADSCALE_TEST_RAPID_CHECKS_PROBE"

// fatal fails a draw with its format alone and logs the values: Rapid
// shrinks a failure only while it reads the same on replay, and a value
// the fixture makes, such as a fresh ID or a time, changes between
// replays.
func fatalf(rt rapid.TB, format string, args ...any) {
	rt.Helper()
	rt.Logf(format, args...)
	rt.Fatal(format)
}
