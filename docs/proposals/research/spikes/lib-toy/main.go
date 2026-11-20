// Command kv is a toy key-value store in a JSON file: a second user of
// cmdline, unrelated to Headscale. Its conventions differ on purpose:
//
//   - a repeated value flag is last-wins (--db a --db b uses b);
//   - -v counts (-v -v is more verbose);
//   - --db and -v work on every command, before or after it, without each
//     command naming them;
//   - no groups: four commands under the root;
//   - usage errors exit 2 and print "did you mean";
//   - keys complete from the store at Tab time;
//   - kv completion <shell> prints the script.
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strconv"
	"strings"

	"spike/cmdline"
	"spike/cmdline/script"
)

func tree() *cmdline.Command {
	common := []cmdline.Flag{
		{Name: "db", Short: 'd', Complete: cmdline.Files},
		{Name: "verbose", Short: 'v', Bool: true},
		{Name: "help", Short: 'h', Bool: true},
	}
	root := &cmdline.Command{Name: "kv", Flags: common, Commands: []*cmdline.Command{
		{Name: "get", Args: []cmdline.Completer{keys}},
		{Name: "set", Args: []cmdline.Completer{keys, nil}},
		{Name: "del", Aliases: []string{"rm"}, Args: []cmdline.Completer{keys}}, // takes many keys
		{Name: "incr", Args: []cmdline.Completer{keys}},                         // <key> [delta]
		{Name: "completion", Args: []cmdline.Completer{cmdline.Words("bash", "zsh", "fish")}},
	}}
	for _, c := range root.Commands { // "inherited" flags are a loop over plain data
		c.Flags = append(c.Flags, common...)
	}
	return root
}

// keys completes from the default store: a Completer sees only the word
// being typed, not a --db given earlier on the line.
func keys(prefix string) ([]string, cmdline.Directive) {
	var out []string
	store, _ := load(dbPath("")) // Tab shows no error; a broken store offers nothing
	for k := range store {
		if strings.HasPrefix(k, prefix) {
			out = append(out, k)
		}
	}
	slices.Sort(out)
	return out, cmdline.NoFiles
}

func main() {
	if cmdline.Serve(os.Stdout, tree(), os.Args[1:]) {
		return
	}
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(argv []string, stdout, stderr io.Writer) int {
	root := tree()
	m, err := cmdline.Parse(root, argv)
	if e := (*cmdline.Error)(nil); errors.As(err, &e) {
		fmt.Fprintf(stderr, "kv: %v\n", e)
		if e.Kind == cmdline.UnknownCommand {
			for _, c := range root.Commands {
				if e.Word != "" && strings.HasPrefix(c.Name, e.Word[:1]) {
					fmt.Fprintf(stderr, "did you mean %q?\n", c.Name)
				}
			}
		}
		return 2
	}
	last := func(name string) string { // last-wins
		if v := m.Flags[name]; len(v) > 0 {
			return v[len(v)-1]
		}
		return ""
	}
	verbose := 0
	for _, v := range m.Flags["verbose"] {
		if b, err := strconv.ParseBool(v); err == nil && b {
			verbose++
		}
	}
	if m.Command == root || last("help") == "true" {
		fmt.Fprintln(stdout, "usage: kv [-d db] [-v] get|set|del|incr|completion ...")
		return 0
	}
	db := dbPath(last("db"))
	if verbose > 1 {
		fmt.Fprintf(stderr, "kv: %s %q on %s\n", m.Path[0], m.Args, db)
	}
	store, err := load(db)
	if err != nil {
		fmt.Fprintf(stderr, "kv: %v\n", err)
		return 1
	}
	a := m.Args
	need := map[string][2]int{"get": {1, 1}, "set": {2, 2}, "del": {1, 1 << 30}, "incr": {1, 2}, "completion": {1, 1}}[m.Path[0]]
	if len(a) < need[0] || len(a) > need[1] {
		fmt.Fprintf(stderr, "kv %s: wrong number of arguments\n", m.Path[0])
		return 2
	}
	switch m.Path[0] {
	case "get":
		fmt.Fprintln(stdout, store[a[0]])
		return 0
	case "set":
		store[a[0]] = a[1]
	case "del":
		for _, k := range a {
			delete(store, k)
		}
	case "incr":
		by, cur := "1", store[a[0]]
		if len(a) == 2 {
			by = a[1]
		}
		if cur == "" {
			cur = "0"
		}
		d, err1 := strconv.Atoi(by)
		n, err2 := strconv.Atoi(cur)
		if err := errors.Join(err1, err2); err != nil {
			fmt.Fprintf(stderr, "kv incr: %v\n", err)
			return 1
		}
		store[a[0]] = strconv.Itoa(n + d)
		fmt.Fprintln(stdout, store[a[0]])
	case "completion":
		if err := script.Write(stdout, a[0], "kv"); err != nil {
			fmt.Fprintf(stderr, "kv: %v\n", err)
			return 2
		}
		return 0
	}
	if err := save(db, store); err != nil {
		fmt.Fprintf(stderr, "kv: %v\n", err)
		return 1
	}
	return 0
}

func dbPath(flag string) string {
	if flag != "" {
		return flag
	}
	if env := os.Getenv("KV_DB"); env != "" {
		return env
	}
	return "kv.json"
}

// load reads the store; a missing file is an empty store.
func load(path string) (map[string]string, error) {
	m := map[string]string{}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return m, nil
	}
	if err != nil {
		return nil, err
	}
	return m, json.Unmarshal(b, &m)
}

func save(path string, m map[string]string) error {
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o644)
}
