# The parser as a library: where the edge runs, what it costs

Date: 2026-11-17. Question from the maintainer: "Can we keep our parser and structure separate from
the Headscale layer so it can be reused elsewhere as a library?" Answered with code:

| Path                    | What                                                                                                                                                                                        |
| ----------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `spikes/lib/`           | the library, module `spike/cmdline` (working name), package `cmdline` + subpackage `script`                                                                                                 |
| `spikes/lib-headscale/` | kit adapter using only the library's public API; `cmd/headscale` shell-test binary; `protodiff.sh`, `protolines.txt`; `shell/run.sh` (drives the referee's harness read-only), `shell/out/` |
| `spikes/lib-toy/`       | `kv`, a second, unrelated CLI on the same API, with tests                                                                                                                                   |

All runs: Go 1.27.3 from `nix develop` in the worktree; zsh/pwsh via `nix shell` as in `v2/run-kits.sh`.

## Verdict

1. **Yes, and the edge is where 001 already put it.** Everything the kit's `Exec` (= 001's builder) did
   stays Headscale's; the library is own-grammar's `parse`/`walk`/`Complete`/`Serve` with its own
   types. Headscale's adapter shrinks to 86 lines: tree conversion, an error map, and Headscale's
   comma-list Tab convention.
1. **Proof:** kit v2 155/155 MUST · 12/12 STRETCH, kit v1 112/112 · 4/4, **every one of the 181 v2
   rows and 132 v1 rows has the same `Got` as own-grammar**, `-race -count=3` ok. `__complete`
   answers are byte-identical on 208 lines but one (a bug the refactor found, below). Real shells:
   bash, zsh, pwsh identical; fish differs on 2 lines, caused by D23 (cobra's own fish script), not
   the library.
1. **Size:** library core 246 lines (parse 133, complete 113), `script` 20, tests 144 incl. a fuzz
   target. own-grammar's adapter was 228 + 1,054 copied script lines. "Reusable" costs about +100
   lines over "written for Headscale", plus an exported API of 21 names that becomes a contract.
1. **The toy needed four things the library lacks** (grouped short bools, negative numbers as
   positionals, Tab for variadic positionals, a Completer that sees the line) and wanted a fifth
   (descriptions on Tab). Everything else it did with plain data and a few lines of its own: last-wins,
   counted `-v`, flags inherited by every command, "did you mean", exit code 2, its own help.
1. **Nothing out there does this exact job.** Each candidate lacks two of: tree as data, GNU-style
   grammar with interspersed flags, typed errors, a cobra-protocol answerer. New library, small;
   contributing upstream is not a fit for any of them (reasons in "Prior art").
1. **Where:** a package inside the Headscale module now, guarded by a `go list -deps` test; move to
   its own repository the day a second real user exists. Moving later is cheap because only one
   Headscale file imports it.

## 1. The edge

Own-grammar taken apart, piece by piece, and where each piece went in the refactor.

| Piece of the spike                                                                                                                                                     | Went to                                               | Why                                                        |
| ---------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------- | ---------------------------------------------------------- |
| Tree as data: name, aliases, group or leaf, flags per command                                                                                                          | library (`Command`, `Flag`)                           | any user needs it; Headscale's builder fills it from specs |
| Flag grammar: `--x`, `--x=v`, `--x v`, `-x`, `-x=v`, `-x v`; `--`; interspersed; value taken verbatim (D20)                                                            | library (`parse`)                                     | grammar                                                    |
| Walk: group words, aliases, flags typed before the leaf re-read with the leaf's flags (D3)                                                                             | library (`Parse`)                                     | grammar, see "global flags" below                          |
| Typed error: unknown command / unknown flag / missing value, with path and word (D4)                                                                                   | library (`Error`)                                     | only the parser knows these                                |
| Tab answerer: which word is under the cursor, flag names, `--x=` form, D16 alias rule, no flags after `--`                                                             | library (`Complete`)                                  | grammar of the line, same tokenizer as `Parse`             |
| `__complete`/`__completeNoDesc` protocol, directive bits                                                                                                               | library (`Serve`, `Directive`)                        | protocol                                                   |
| Scripts (D23: cobra's generators)                                                                                                                                      | library subpackage `script` (imports cobra)           | protocol partner of `Serve`; kept out of the core          |
| Repeat rule (D6/D15), bool value check (D9), argument count, help, `--version`, D10, error text, "did you mean", old-name table (D5), input structs, resolvers, output | Headscale (they already lived in the kit's `Exec`)    | policy                                                     |
| Comma lists with `+`/`-` items, NoSpace after `--filter`                                                                                                               | Headscale (`values` in the adapter, as a `Completer`) | Headscale's convention                                     |

The edge items, one by one:

| Item                                    | Class                     | Where it is now                                                                                                                                                                                             | Would a second user need a knob?                                                                                                                                                   |
| --------------------------------------- | ------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Every flag but `--filter` once (D15)    | policy                    | caller: the library returns every occurrence in order; the kit's `Exec` refuses repeats                                                                                                                     | No knob. The toy did last-wins in 4 lines and counted `-v -v` from the same data. Recording every occurrence is what makes both free                                               |
| Bool value forms (`--force=false`, D9)  | grammar half, policy half | library: a bool never takes the next word, `--x=v` returns `v` verbatim. Caller: `strconv.ParseBool` (the kit's `BadValue`)                                                                                 | No. One line per caller                                                                                                                                                            |
| Which flags a command takes             | data                      | `Command.Flags`                                                                                                                                                                                             | No                                                                                                                                                                                 |
| Global flags (D3)                       | grammar                   | a flag declared on a group may be typed at that group or below it before the leaf; it counts only if the command reached declares it too. "Global" = declared on the root and on each command that takes it | No knob. cobra-style inheritance is a loop over plain data (toy: 3 lines). The other policy (git-style `-C` that the leaf does not declare) is not supported; nobody here needs it |
| Comma lists with `+`/`-`                | Headscale                 | adapter's `values` Completer                                                                                                                                                                                | No. A plain comma helper would be speculation                                                                                                                                      |
| Script generation, cobra import         | protocol                  | `script.Write`, 20 lines, cobra v1.10.2                                                                                                                                                                     | No                                                                                                                                                                                 |
| `--version`, `-h`                       | policy                    | ordinary bool flags on the commands that take them; D19 (error wins over `-h`) falls out of parse order                                                                                                     | No. A user who wants "`-h` wins over everything" pre-scans argv (5 lines)                                                                                                          |
| `-ojson`, grouped shorts, abbreviations | grammar                   | refused (D11 allows either)                                                                                                                                                                                 | Grouped bools: yes (toy wanted `-vv`), see open question 3                                                                                                                         |
| D16 aliases on Tab                      | Tab policy                | fixed in the library: aliases only when no name fits (cobra's rule too)                                                                                                                                     | No evidence anyone wants another rule                                                                                                                                              |

My reading of the brief's split holds with two corrections: (1) "which flags a command takes" and
"global flags" are not options at all, they are data plus one walk rule; (2) the comma/`+`/`-`
completion moved out of the library into Headscale as a `Completer`, so the library carries no
list convention.

## 2. The API

`go doc -all` of the library, verbatim:

```text
package cmdline // import "spike/cmdline"

Package cmdline reads a command line against a tree of commands that the caller
describes as plain data, and answers shell completion for that tree over cobra's
__complete protocol.

It does the grammar and nothing else: no help, no conversion of values,
no argument counts, no error wording beyond a default, no os.Exit, no package
state. Every value comes back as the string that was typed, and every occurrence
of a flag is kept, so the caller decides what a repeat or "--force=maybe" means.

The grammar: --name, --name=value, --name value, -x, -x=value, -x value.
A bool flag never takes the next word. The word after a value flag is its value,
whatever it looks like. Flags and positionals mix in any order; "--" ends the
flags. Attached short values (-ovalue), grouped shorts (-ab) and abbreviations
are unknown flags.

func Serve(w io.Writer, root *Command, args []string) bool

type Command struct {
	Name     string
	Aliases  []string
	Flags    []Flag
	Args     []Completer // Tab for the n-th positional; nil entries offer nothing
	Commands []*Command
}
type Completer func(prefix string) ([]string, Directive)
    func Words(words ...string) Completer
type Directive int
    const Failed, NoSpace, NoFiles, FilterExt, FilterDirs, KeepOrder  (cobra's bits)
    func Complete(root *Command, words []string, cur string) ([]string, Directive)
    func Files(string) ([]string, Directive)
type Error struct {
	Kind ErrorKind
	Path []string // the command reached, as in Match.Path
	Word string
}
    func (e *Error) Error() string
type ErrorKind int
    const UnknownCommand, UnknownFlag, MissingValue
type Flag struct {
	Name     string    // long name, without dashes
	Short    rune      // one letter, or 0
	Bool     bool      // takes no value: "--x" reads "true", "--x=v" reads "v"
	Complete Completer // Tab for the value; nil offers nothing
}
type Match struct {
	Command *Command
	Path    []string            // names from the root (not aliases), root excluded
	Flags   map[string][]string // by long name: every value given, in order
	Args    []string            // positionals, in order
}
    func Parse(root *Command, argv []string) (*Match, error)

package script // import "spike/cmdline/script"
func Write(w io.Writer, shell, program string) error
```

(The full doc comments are in `spikes/lib/*.go`; the shortened `const` lines above list the same names.)
21 exported names. Core imports only the standard library (`go list -deps` checked).

### What a stranger writes

Declare, parse, handle the error (from `lib-toy/main.go`, shortened):

```go
common := []cmdline.Flag{{Name: "db", Short: 'd', Complete: cmdline.Files}, {Name: "verbose", Short: 'v', Bool: true}}
root := &cmdline.Command{Name: "kv", Flags: common, Commands: []*cmdline.Command{
	{Name: "get", Args: []cmdline.Completer{keys}},
	{Name: "del", Aliases: []string{"rm"}, Args: []cmdline.Completer{keys}},
}}
for _, c := range root.Commands {
	c.Flags = append(c.Flags, common...) // inherited flags: a loop, not an option
}

m, err := cmdline.Parse(root, os.Args[1:])
if e := (*cmdline.Error)(nil); errors.As(err, &e) {
	// e.Kind, e.Path, e.Word: write your own text, suggest from root.Commands
}
switch m.Path[0] { case "get": ...; }    // m.Flags["db"] has every value given, in order
```

Tab, the hidden entry point and the scripts (the whole `main` of `lib-headscale/cmd/headscale`):

```go
if cmdline.Serve(os.Stdout, root, os.Args[1:]) { // answers "prog __complete …"
	return
}
// "prog completion bash": the scripts, from cobra's generators (D23)
script.Write(os.Stdout, "bash", "prog")
```

Testing a CLI built on it: `Parse` and `Complete` are pure functions of (tree, argv), so a table
test is the whole harness (`lib-toy/main_test.go`: 17 run rows, 9 Tab rows, 64 lines). `Serve`
writes to an `io.Writer`. Real-shell behaviour needs a built binary and a shell; the referee's pty
harness drove both `headscale` and `kv` unchanged.

### Plain data or a builder?

Plain data. Headscale generates the tree from specs, so a builder adds a second way to say the same
thing; a small hand-written CLI reads fine as a literal (the toy's tree is 15 lines); "inherited"
flags and per-command defaults are loops the caller writes once. What a builder would give and plain
data does not: checks at construction (duplicate names, a short letter with two meanings). Headscale
does those in `command.New` already (001 "Validation"); the library does none. A `Check(root) error`
could be added if a second user asks; nobody did.

### Strings only?

Yes. Headscale converts every value itself (time parser, lists, resolvers), and the toy needed two
`strconv` calls. A typed layer (bind to struct fields, `flag.Value`) belongs in a separate package
on top, as flax sits on creachadair/command; adding it to the core would make the library a
framework.

## 3. The proof

### Scores

| Run                                                                        | own-grammar (referee, fixed) | lib-headscale                                                                     |
| -------------------------------------------------------------------------- | ---------------------------- | --------------------------------------------------------------------------------- |
| kit v2 (MUST · STRETCH · OBSERVE)                                          | 155/155 · 12/12 · 14         | **155/155 · 12/12 · 14**; all 181 `Got` cells identical (`diff` of columns 2,7,8) |
| kit v1                                                                     | 112/112 · 4/4 · 13           | **112/112 · 4/4 · 13**; all 132 identical                                         |
| `-race -count=3`                                                           | ok                           | ok (adapter and library)                                                          |
| `__complete` answers, 208 lines (`lines.txt`, every kit run argv, 9 extra) | —                            | identical but 1 (`nodes delete o <Tab>`, the bug below)                           |
| pty bash, zsh (23 lines each)                                              | —                            | identical `FINAL` buffers                                                         |
| pty fish, fish `complete -C`                                               | —                            | 2 lines differ: `--columns=id,na`, `--filter=ow`                                  |
| pwsh `TabExpansion2`                                                       | —                            | identical (including the same `THROWS`)                                           |

The two fish lines: own-grammar used a copy of cobra's scripts with one line patched
(`string split --max 1 -- …`); D23 says ask cobra's generators instead, so `lib-headscale` gets
cobra v1.10.2's fish script and prints `string split: --columns=id,name: unknown option` into the
terminal, exactly as the referee reproduced on stock cobra. This is the price of D23, now measured
on the real candidate. The bash colon+comma corruption (`tag:ci,tag:p`) is in both builds.

Library's own tests (`lib/cmdline_test.go`): 34 parse rows, 20 Tab rows on its own small tree,
no kit; `FuzzParse` (no panic; positionals are argv words in order) ran 20 s, 18.6 M execs, clean.

### Sizes (non-blank, non-comment lines, the kit's method)

| Part                                             | Lines                                                                    |
| ------------------------------------------------ | ------------------------------------------------------------------------ |
| Library core (`parse.go` 133, `complete.go` 113) | 246                                                                      |
| `script` (cobra generators)                      | 20 (replaces 1,011 copied + 43 shim)                                     |
| Library tests + fuzz                             | 144                                                                      |
| Headscale adapter (`lib-headscale/adapter.go`)   | 86 (tree conversion ~28, error map ~10, three methods ~20, `values` ~22) |
| own-grammar adapter, for comparison              | 228                                                                      |
| Toy `kv` + tests                                 | 159 + 64                                                                 |
| Binary (shell-test `headscale`)                  | 3.72 MB vs 3.45 MB: cobra + pflag linked for the scripts                 |

Where the ~100 extra lines go: types the kit used to provide (`Command`, `Flag`, `Match`, `Error`,
`Directive`, ~50), a default `Error()` text (12), `Words`/`Files` (12), `__completeNoDesc` stripping
(3), the error map in the adapter (10), the flat→nested conversion (28; in Headscale the spec builder
would fill `cmdline.Command` directly, as the kit's `build` fills `kit.Command` today).

### What changed against the spike

1. **Bug found and fixed:** own-grammar's `byTyped` matched a bare word against short letters, so
   `headscale nodes delete o <Tab>` offered `json` (the positional `o` read as `-o`). No kit row covers
   it; the library's own test table did. `lookup` now requires a leading `-`.
1. Tree is nested (`Commands []*Command`), root `Name` is the program name (the scripts use it).
1. Flag kinds Bool/String/Strings became `Bool bool`. "May repeat" is not the parser's business: it
   returns every occurrence; the once-rule stayed in `Exec`.
1. `Flag.Global` is gone: flags readable before the leaf are the union of the groups' flags on the
   path (own-grammar: the root's only; same result on the kit tree).
1. `Values []string`/`File bool` became `Completer` funcs; Headscale's comma/`+`/`-` logic moved into
   its adapter. This also opens the "live names later" hook (R62).
1. A group with nothing after it now carries the flags of every level (own-grammar kept only the last
   level's). No kit row changed.
1. Scripts from cobra's generators (D23) instead of the patched copy.
1. `Serve` checks the entry name itself and strips descriptions for `__completeNoDesc`.

### What the toy needed (the measure of "reusable")

`kv`: `get`, `set`, `del` (alias `rm`, many keys), `incr <key> [delta]`, `completion`; no groups;
last-wins flags; `-v` counts; `--db` on every command before or after it; exit 2 on usage errors;
"did you mean"; keys completed from the store at Tab time. Tested in-process and in fish.

| Need                                                         | Library had it?                             | Cost to add                                                       | Second user really needs it?                                                                        |
| ------------------------------------------------------------ | ------------------------------------------- | ----------------------------------------------------------------- | --------------------------------------------------------------------------------------------------- |
| Last-wins repeats, counted `-v -v`                           | yes (every occurrence kept)                 | 0                                                                 | —                                                                                                   |
| Flags on every command                                       | yes (loop over data, 3 lines)               | 0                                                                 | —                                                                                                   |
| Did you mean, help, exit codes, dispatch                     | yes (caller, from the tree)                 | 0                                                                 | —                                                                                                   |
| `kv --db=k<Tab>` files, keys from the store                  | yes (`Completer`)                           | 0                                                                 | —                                                                                                   |
| **Grouped short bools `-vv`**                                | no: unknown flag `-vv`                      | ~8 lines, no option needed now that D11 lets a parser accept them | **yes**, common Unix habit                                                                          |
| **Negative number positional `incr n -1`**                   | no: unknown flag `-1`; `incr n -- -1` works | ~3 lines ("`-<digit>…` that is no flag is a positional")          | maybe: calculators, offsets; git uses `-3` as a flag                                                |
| **Tab for variadic positionals `del alpha <Tab>`**           | no: `Args` is by position                   | 1 field (`Rest Completer`) + 2 lines                              | **yes**: every `<file>...` command                                                                  |
| **Completer that sees the line (`kv --db other get <Tab>`)** | no: it gets only the prefix                 | signature change `func(m *Match, prefix string)`, ~6 lines        | **yes**, and Headscale's own R62 (live node names need `-c` from the line). Breaking if added later |
| Descriptions on Tab for commands and flags                   | no (values can carry `"\t"desc`)            | `Help string` on `Command`, `Flag`, ~4 lines                      | likely: zsh and fish show them; Headscale has `Short` texts already                                 |
| Optional-value flag `--color[=when]`                         | no                                          | ~10 lines + a field                                               | speculation; GNU-ism, skip                                                                          |

Not added, per the brief. The two "yes" items that change a signature (Completer, variadic) are the
ones to settle before anyone else imports it.

## 4. Prior art: is this library already out there?

| Project                       | Tree as data       | GNU grammar, interspersed, `--` strict                                                                                     | Typed errors                                                    | cobra-protocol answerer                                                        | Fit                                                                      |
| ----------------------------- | ------------------ | -------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------- | ------------------------------------------------------------------------------ | ------------------------------------------------------------------------ |
| `creachadair/command` (+flax) | yes                | no: stdlib `flag`, `--` stops only as first free word, unknown flag after a positional becomes a positional                | no (stdlib strings; `UsageError` never returned by the library) | no                                                                             | dispatcher only                                                          |
| `peterbourgon/ff` v4          | yes (`ff.Command`) | short/long and `-ab` yes; **flags after positionals no** (#124, maintainer objects to the premise); beta tag since 2025-08 | sentinel errors                                                 | no (Tailscale asked in #132, 2024-03; "show me a strawman PR"; nothing landed) | close, but D3/R20 fail by design                                         |
| Tailscale `ffcomplete`        | on ffcli v3        | stdlib `flag`                                                                                                              | —                                                               | yes (cobra protocol, tempfork scripts)                                         | an app's internals in `tailscale.com`, not a library; package-level maps |
| `coder/serpent`               | yes                | pflag                                                                                                                      | pflag's                                                         | own minimal scripts, no NoSpace/directives                                     | a framework (options, YAML, env, help)                                   |
| go-task #2897                 | —                  | pflag                                                                                                                      | —                                                               | yes, `task __complete`                                                         | inside go-task, not importable                                           |
| cobra                         | builder            | pflag                                                                                                                      | partly typed                                                    | yes                                                                            | the framework we would leave                                             |
| pflag                         | no tree            | yes                                                                                                                        | typed since v1.0.7                                              | no                                                                             | flag set only                                                            |
| posener/complete              | own tree           | —                                                                                                                          | —                                                               | own protocol, rc-file install                                                  | unmaintained per OpenTofu RFC                                            |
| carapace                      | —                  | —                                                                                                                          | —                                                               | own                                                                            | needs cobra                                                              |

(Sources: `screen-ff-command-mitchellh-gocmd.md`, `deep-creachadair.md`, `deep-own.md`. A GitHub code
search for `__completeNoDesc` in Go found only cobra users; a wider search was not done, UNVERIFIED
that no other small library exists.)

- **Contribute to creachadair/command?** We would ask for aliases, strict `--`, typed errors (all
  small), then still write the GNU tokenizer and the whole answerer: ~90% of this library, inside a
  project whose README scope is "the way the go command works" (no GNU flags, no completion). Its
  author has never refused anything in public because nobody asked; GNU flags and completion are
  outside his stated scope. Not a fit; ask only if the maintainer wants the creachadair style for its
  own sake.
- **Contribute to ff v4?** Completion is welcome in principle, but D3 and R20 (flags after
  positionals) are refused on principle (#124), and v4 has been beta for over three years.
- **Fork?** Nothing to fork: creachadair's parse is stdlib `flag` (would be replaced), ffcomplete is
  welded to ffcli and package maps. The 246 lines here are smaller than any fork's diff.
- **New library**, then. Its honest pitch is narrow: "a command tree as plain data, GNU-style flags,
  typed errors, and cobra's Tab protocol, in ~250 lines with no dependencies."

## 5. Where it lives

|                                                                               | A: package in the Headscale module                                                                                                                                                                                                              | B: nested module in the Headscale repo                                                                                                                                                                                                          | C: own repository                                                                                                |
| ----------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------- |
| Import path                                                                   | `github.com/juanfont/headscale/…/cmdline` (not `internal/`, or nobody can import it)                                                                                                                                                            | `github.com/juanfont/headscale/cmdline`                                                                                                                                                                                                         | `github.com/<owner>/<name>`                                                                                      |
| Who can use it                                                                | anyone, but `go get` pulls Headscale's module and its `go 1.27.3` floor (Headscale bumps Go fast)                                                                                                                                               | anyone; own `go` floor, own deps (only cobra, for `script`)                                                                                                                                                                                     | anyone; cleanest                                                                                                 |
| Versioning / release work                                                     | none: rides Headscale's tags (v0.x, breaking allowed)                                                                                                                                                                                           | a `cmdline/vX.Y.Z` tag per change; root requires it by version (two-step change) or by `replace` (breaks `go install …@version` for Headscale); second `go test`/lint entry in Makefile/CI; `vendorhash`/`tools/bump` assume one `go.mod` today | its own CI, tags, flake; every change is a lib PR + tag + bump PR in Headscale (`tools/bump` can carry the bump) |
| "Imports nothing of Headscale" enforced by                                    | a test: `go list -deps` of the package must be std only (~15 lines, travels with the package), or a depguard rule (depguard is disabled in `.golangci.yaml` today; enabling it for one `files:` rule with `list-mode: strict`, `allow: $gostd`) | the `go.mod` itself: a Headscale import would need a require on the root module, visible in review                                                                                                                                              | the repository boundary                                                                                          |
| Library tests, corpus cases, fuzz targets                                     | package dir + `testdata/fuzz`                                                                                                                                                                                                                   | same, run by a second `go test`                                                                                                                                                                                                                 | same                                                                                                             |
| Real-shell tests                                                              | Headscale's D21 CI job drives both the headscale binary and a small test program                                                                                                                                                                | same                                                                                                                                                                                                                                            | the library needs its own pty job (bash, zsh, fish via nix); Headscale keeps D21 for its tree                    |
| Kit-style conformance (D3, D6, D15, D16 …)                                    | stays in Headscale in every option: it tests Headscale's policy, not the grammar                                                                                                                                                                |                                                                                                                                                                                                                                                 |                                                                                                                  |
| `spikes/diff` (differential vs pflag/cobra) and `spikes/corpus` grammar cases | with the library tests (test-only deps)                                                                                                                                                                                                         | same; test deps do not reach consumers                                                                                                                                                                                                          | same                                                                                                             |
| Moving later                                                                  | to C: copy with history (`git filter-repo`), change the import in Headscale's one adapter file and `main`; outside users (if any) change one path                                                                                               | to C: same, plus a module path change                                                                                                                                                                                                           | —                                                                                                                |

Recommendation: **A now, C when a second real user exists.** With one user, B pays C's release
ceremony without C's clean path. The `go list -deps` test is cheaper to keep than a depguard
config and fails in `go test`, where it is seen.

## 6. What it does to the decision

**Being a library does not change the comparison with cobra on behaviour.** The adapter, kit scores
and Tab answers are identical to own-grammar's. It changes two things:

- It adds ~100 lines and an API contract (above), and release work under B or C.
- With D23 the script advantage own-grammar had is gone: library and cobra now ship the same cobra
  v1.10.2 scripts with the same fish `--x=` error and bash comma bugs. What still separates them is
  the answerer (D16, NoSpace only inside lists, `-o <Tab>` at the root, no files after a leaf with no
  file argument), the D11 refusals, and ~42 cobra workaround lines vs 0. A fix for the fish bug now
  has to go upstream to cobra (deep-own found no cobra issue filed).

**Should the library's flag reader be pflag?** Measured here: own-pflag with its 13-line `-ojson`
pre-scan removed (scratch copy, kit v2): **155/155 MUST, STRETCH 8/12**. The four it loses: F05
`-ojson`, F28 `-ho json`, X01 `-e24h` are now accepted, which D11 allows; X02 `-output json` is read
as `-o utput` and ends in "takes no arguments, got 1", a confusing error.

| For pflag inside                                                                                                                                  | Against                                                                                                                                                                 |
| ------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Its years of edge cases: grouped shorts (`-vv`, toy gap closed), attached values, count flags via repeated `Set`, optional values (`NoOptDefVal`) | The library's grammar becomes "whatever pflag does", changed by pflag releases (v1.1.0 changed printing and unknown-flag handling)                                      |
| Typed errors since v1.0.7 (25-line map)                                                                                                           | `Complete` still needs its own tokenizer to know which flag's value is under the cursor and to stop at command words: two tokenizers that must agree                    |
| A user base that reports bugs                                                                                                                     | Every library user takes pflag as a dependency; bool repeats invisible without a custom `Value`; byte-sliced Unicode shorthands (`-ø` → `-Ã`); single active maintainer |
| Without the pre-scan its adapter has 3 WA lines instead of 16                                                                                     | `-output json` → `-o utput`: the one surprise D11 does not cover                                                                                                        |

As the evidence stands: own grammar for the library (smaller, exactly the documented grammar, one
tokenizer for parse and Tab, no dependency), and take pflag's behaviour as a test oracle
instead of a dependency: the differential harness (`spikes/diff`) and the upstream corpus
(`spikes/corpus`) are where pflag's years of edge cases come in. If the maintainer wants `-vv` and
`-ojson` accepted, that is ~10 lines of grammar, not a dependency.

## Open questions for the maintainer

1. **Where does it live?**
   (a) Package in the Headscale module with a `go list -deps` test; cost: users inherit Headscale's
   Go floor and module, no separate versions; move later is one import change.
   (b) Own repository now; cost: a second CI with shell jobs, tags, and a bump PR in Headscale for
   every library change, before a second user exists.
1. **Completer signature: settle before a second user.**
   (a) `func(prefix string)` as now; cost: R62 (live node names, which need `-c` from the line) and
   the toy's `--db` case force a breaking change later.
   (b) `func(m *Match, prefix string)` now; cost: ~6 lines, and the partial line must be parsed
   leniently on Tab.
1. **Grouped short bools (`-vv`).**
   (a) Keep refusing (D11 allows); cost: other users of the library cannot have `-vv`.
   (b) Accept them (~8 lines, no option); cost: Headscale STRETCH F28 flips (`-ho json` becomes help,
   as pflag reads it), one more grammar rule to test.
1. **Variadic positionals and Tab descriptions.**
   (a) Leave out until asked; cost: the first `<file>...` user and every zsh/fish user notice.
   (b) Add `Command.Rest Completer` and `Help string` on `Command`/`Flag` now; cost: 3 fields, ~6
   lines, and Headscale's `Short` texts appear in zsh/fish Tab lists (a visible change).
1. **pflag as the reader?**
   (a) Own grammar, pflag as a differential test oracle; cost: we own every edge (tables, corpus, fuzz).
   (b) pflag inside the library; cost: two tokenizers (pflag for parse, ours for Tab), a dependency
   for every user, and `-output` misread as `-o utput`.
1. **Name.** Working name `cmdline`. Others that fit the job: `argtree`, `clitree`, `tabtree`.
   (a) A plain descriptive name (`cmdline`); cost: collides in search with many packages.
   (b) A distinct short name; cost: says less about what it does.
