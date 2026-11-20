# The typed library: what was built, and every call in it

Date: 2026-11-18. For the writer of `docs/proposals/003-cmdline.md` and for the maintainer. Updated the
same day for two decisions of his on this build: D48 (call 1 stands) and D49 (`--output` is strict).
The build is in `spikes/final-typed/`. `spikes/final/` is untouched; it is the record of the
string-only library. The rules of the typed build are in `rules-typed.md`.

## The task

The maintainer reviewed 003 and wants the library typed (D41–D47 in `DECISIONS.md`). This build
answers: what is the public API, where is the line between the library and Headscale, and do the
old tests still pass. It had to keep every earlier decision.

## Where things are

| Path (`spikes/final-typed/`) | What                                                                                                                                                                                                                                                                                                                      |
| ---------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `cmdline/`                   | the typed library, module `spike/cmdline`: `cmdline.go` (tree, `New`, `Info`), `field.go` (tags, readers, `Opt`, `Repeat`, `Path`), `line.go` (`Parse`, `Line`, `Get`, `Run`, `UsageError`), `complete.go` (Tab)                                                                                                          |
| `cmdline/internal/reader/`   | the string reader of the old build, as the lower layer: its three files and its test file, with two changes (below)                                                                                                                                                                                                       |
| `cmdline/script/`            | the cobra script generators, unchanged (D23)                                                                                                                                                                                                                                                                              |
| `kit/`                       | kit v4: kit v3 with three functions added in `export.go` (`Done`, `Raw`, `Sh`), and for D49 four rows changed, thirteen rows added and one condition in `Exec` (see "Kit cases")                                                                                                                                          |
| `headscale/`                 | Headscale's layer on the typed library: `command.go` (001's spec and the flags the builder adds), `adapter.go` (001's builder, cut down), `specs.go` (the kit's tree as typed specs), `describe.go` (the tree read back as data), `cmd/headscale` (shell-test binary), `shell/` (real-shell run), `RESULT.md` (kit table) |
| `toy/`                       | a second small program on the library, with other choices                                                                                                                                                                                                                                                                 |
| `prog/`                      | the example program of 003: `main.go` and `main_test.go` are the code that 003 shows, `probe_test.go` prints its tables (`probe.txt`), `console.sh` its console blocks (`console.txt`)                                                                                                                                    |
| `corpus/`                    | the corpus driver on the typed build                                                                                                                                                                                                                                                                                      |
| `diff/`                      | the differential runner and the three fuzz targets on the typed build; `results/`                                                                                                                                                                                                                                         |

The two changes to the reader: `Check` returns every problem, joined, not only the first; and the
stdlib-only test moved up to `cmdline`, where it also covers the reader.

## The API in outline

The full `go doc -all` is at the end of this file.

```go
// Declare: a command is a struct of what it takes, and a function.
type setIn struct {
    Node   v0.Node                    `arg:"node"`                          // a late reader looks it up
    Routes []netip.Prefix             `arg:"routes"`                        // a comma list; netip.Prefix reads itself
    Expiry cmdline.Opt[time.Duration] `flag:"expiry" short:"e" help:"..."`  // given or not
    Force  bool                       `flag:"force" help:"Do not ask"`
}

root := cmdline.Group{Name: "prog", Flags: []any{helpFlags{}, configFlags{}}, Commands: []cmdline.Node{
    cmdline.Group{Name: "nodes", Help: "Manage nodes", Flags: []any{helpFlags{}}, Commands: []cmdline.Node{
        cmdline.Command[setIn]{Name: "set", Aliases: []string{"approve"}, Help: "...",
            Flags: []any{helpFlags{}, configFlags{}}, // flags of the layer above, outside setIn
            Run:   func(ctx context.Context, in setIn) error { ... }},
    }},
}}

// Check and build, once. The error names every wrong struct and name.
tree, err := cmdline.New(root,
    cmdline.Reader(time.ParseDuration), // a type that cannot read itself
    cmdline.LateReader(findNode),       // func(ctx, word) (v0.Node, error): runs in Line.Run
)

// Use.
if tree.Serve(os.Stdout, os.Args[1:]) { return }      // the hidden completion entry point
line, err := tree.Parse(os.Args[1:])                  // fills the structs; err is a *cmdline.UsageError
h, _ := cmdline.Get[helpFlags](line)                  // a struct of flags, typed
in, _ := cmdline.Get[setIn](line)                     // the input struct, before any lookup
// ... the caller: help, version, its own mistakes, make the client, put it into ctx ...
err = line.Run(ctx)                                   // the late readers, then Run
```

| Name                                                                  | What                                                                                                                                             |
| --------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------ |
| `Group`, `Command[In]`, `Node`                                        | the tree as the program writes it; `Node` is one of the two                                                                                      |
| `New(root, opts...) (*Tree, error)`                                   | checks and builds; `Reader[T]` and `LateReader[T]` are its options                                                                               |
| `Tree.Parse`, `Tree.Complete`, `Tree.Serve`, `Tree.Root`              | read a line; answer Tab; answer the scripts; the tree as data                                                                                    |
| `Line`, `Given`, `Get[T](line)`, `Line.Run(ctx)`                      | one line: the command reached, the flags and arguments as typed with their positions, the filled structs, and the run                            |
| `UsageError`, `Kind` (7 kinds), `ErrBool`, `ErrEmpty`, `ErrEmptyItem` | mistakes as data                                                                                                                                 |
| `ErrGroup`, `ErrRan`, `ErrNotParsed`                                  | what `Line.Run` returns for a line without a mistake that still does not run: it ends at a group, it has run already, or `Parse` did not make it |
| `Opt[T]`, `Some`, `Repeat[T]`, `Path`                                 | the three types of the library a field may have                                                                                                  |
| `Completer`, `Directive`, `Words`                                     | Tab by the type of the field                                                                                                                     |
| `Info`, `Flag`, `Arg`                                                 | the tree as data, for help, a reference page, a man page, "did you mean"                                                                         |
| `script.Write`                                                        | cobra's scripts (unchanged)                                                                                                                      |

Tags: `arg`, `flag`, `short`, `help`, `default`.

## The line between the library and the caller

| Concern                                            | The library                                                                                                      | The caller (Headscale)                                                                                                      |
| -------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------- |
| how one word is read, `--`, where a flag may stand | decides (the reader, unchanged)                                                                                  | —                                                                                                                           |
| command names, aliases, groups                     | finds the command; gives the tree as data                                                                        | declares them; keeps its old-names table by command path; writes "did you mean" from `Info`                                 |
| which flags a command takes                        | reads the tags of the input struct and of each struct in `Flags`                                                 | writes the structs; its builder adds `--output`, `--config`, `--help`, `--force` and the list flags as structs of their own |
| a flag before the subcommand                       | allowed when a group above declares it and the command reached declares it too (W1, W2)                          | lists `-c`, `-o`, `-h` on the root and on each command that takes them                                                      |
| value types                                        | reads Go's basic types; calls `UnmarshalText`, a `Reader` or a `LateReader` for the rest                         | writes the types (`Expiry`, `Format`, a column) and their methods; gives `Reader`s for types it does not own                |
| lists                                              | `[]T`: splits at commas, refuses an empty list and an empty item                                                 | —                                                                                                                           |
| bool words                                         | `true` and `false` only                                                                                          | —                                                                                                                           |
| a flag given twice                                 | refuses it, unless the field is a `Repeat[T]`                                                                    | gives `--filter` the type `Repeat[...]`                                                                                     |
| given or not given                                 | `Opt[T]`                                                                                                         | uses it                                                                                                                     |
| defaults                                           | reads the `default` tag when the flag is not given                                                               | writes the tag, or sets the default in `Run`                                                                                |
| argument count                                     | counts against the `arg` fields; reports `ArgCount`                                                              | writes the sentence from `len(Line.Args)` and `Info.Args`; shows `--help` first                                             |
| the usage line                                     | makes it from the struct (`Info.Usage`)                                                                          | prints it                                                                                                                   |
| a lookup on the server                             | runs the `LateReader` of the type in `Line.Run`, in line order, after the whole line is right                    | writes the lookup; puts the client into the context of `Run`                                                                |
| several mistakes on one line                       | reports its own leftmost one, with its position                                                                  | places its own mistakes against it (`--version` not alone; a flag at a group that the group does not take)                  |
| error text                                         | kind, path, word, position, flag or argument, value, cause; a default English text                               | every sentence, "did you mean", the exit code                                                                               |
| `--help`, `--version`, a group alone               | no meaning; `Line.Run` at a group returns `ErrGroup`                                                             | decides                                                                                                                     |
| Tab                                                | command names, flag names with help text; asks the type of a field for values; completes the last item of a list | gives its types a `Complete` method; a sign in `--sort -x` and "no space after a filter column" are in its types            |
| files on Tab                                       | `Path`                                                                                                           | uses `Path` for `--config` and file arguments                                                                               |
| help, reference page, man page                     | gives `Info`, `Flag`, `Arg`                                                                                      | writes all text                                                                                                             |
| output, API client, version check, prompts         | —                                                                                                                | all of it                                                                                                                   |
| a valid tree                                       | `New` refuses it and names every problem                                                                         | calls `New` at start and in a test                                                                                          |

## Every design call, with the alternative

Calls 1 and 7 are decided by the maintainer (D48, D49). None of the others is confirmed. Of
those, 2 to 6 and 8 are the ones he should see.

| #   | The call                                                                                                                                                                                                                                                                                                                             | The alternative, and why it was not taken                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| --- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1   | **Decided, D48: as built.** Flags outside the input struct are structs too. A command lists them in `Flags []any` (only the types are read) and the caller reads them with `cmdline.Get[helpFlags](line)`. A group lists them the same way, which is how a flag may stand before the subcommand.                                     | (a) Flags as data (`Flag{Name: "output"}`) read by name: two ways to declare a flag, and a value read by name is a string or an `any`. (b) Pointers handed to `Parse(argv, &help, &out)`: a pointer of a type the tree does not know is a run-time error. (c) Embedding in the input struct: the command would name the builder's flags, and 001 says the builder adds them. Cost of the call: `[]any` is checked by `New`, not by the compiler, and `Get` finds a struct by its type. |
| 2   | **The Line still holds the text and the position of every flag and argument** (`Line.Flags []Given`, `Line.Args`, `Line.ArgAt`).                                                                                                                                                                                                     | Positions only, no text. D41 says the library hands no strings to the caller. But Headscale must place `--version` not alone on the line (D35), also when no struct is filled, and a `Complete` method needs the `-c` value of the line (call 1, T14). See "Conflicts", A.                                                                                                                                                                                                             |
| 3   | **`Reader` and `LateReader` are options of `New`.** No package-level registry.                                                                                                                                                                                                                                                       | A package-level `Register`, as in the sketch: state shared by every tree and every test, set in `init`. Cost: a late reader is given before a client exists, so it takes the client from the context of `Line.Run`. See "Conflicts", B.                                                                                                                                                                                                                                                |
| 4   | **A named type must say how it is read**: a method, a `Reader` or a `LateReader`. Only Go's own basic types are read by the library.                                                                                                                                                                                                 | Read every type by its kind: `type ID uint64` then needs nothing. But `time.Duration` is an `int64`, and `--wait 5` would be five nanoseconds with no error.                                                                                                                                                                                                                                                                                                                           |
| 5   | **Defaults are a `default:"1h"` tag**, read through the type's reader, checked by `New`, shown in `Info`.                                                                                                                                                                                                                            | No defaults in the library: the command uses `Opt[T]` and sets the default in `Run`, as 001 does for the expiry of a key. That is fewer rules, and 001 shows no default tag. The tag was built because the brief asks for defaults as data for the help. Removing it is small.                                                                                                                                                                                                         |
| 6   | **The late readers run inside `Line.Run`**, in the order typed, then the command.                                                                                                                                                                                                                                                    | A separate `Line.Resolve(ctx)`. 001's steps 7, 8 and 9 (lookups, prompt, `Run`) do not need the caller between the lookups and `Run`: the prompt is in Headscale's wrapper around `Run`, which gets the finished struct. `Get[In](line)` before `Run` gives the struct without the looked-up fields, which is what `NeedsServer` (D34) reads.                                                                                                                                          |
| 7   | **Decided, D49: the other way.** `--output` takes only `json`: Headscale's `Format` refuses every other word while the line is read.                                                                                                                                                                                                 | What was built first: a `Format` that refused only the empty word, with "is it json" as a later step of the builder, so that `-o a -o b` stayed a repeat. The maintainer chose the strict type: a wrong format is a mistake of the line and is placed like any other (D35). Four kit rows changed their value to `json`; see "Kit cases". The library did not change.                                                                                                                  |
| 8   | **A list never takes an empty word or an empty item**, and there is no setting for it.                                                                                                                                                                                                                                               | A setting, or leaving it to the element type. 001 states the rule for every list. A program that wants "empty means clear" writes its own type with `UnmarshalText`.                                                                                                                                                                                                                                                                                                                   |
| 9   | **One package, `cmdline`; the string reader is `cmdline/internal/reader`**, with its code and its 59 + 58 + … test rows carried over almost as they were.                                                                                                                                                                            | One package with the reader's types made private: every tested line would change. Or the reader as a second public API: two ways to describe a tree.                                                                                                                                                                                                                                                                                                                                   |
| 10  | **`Group` and `Command[In]` are struct literals; `Node` joins them; `New` builds a `*Tree`.** `Parse` is a method of the tree.                                                                                                                                                                                                       | `Check(root)` and `Parse(root, argv)` as before: reflection on every call, and a tree could be parsed unchecked. With `New`, the "wrong struct" error of D42 is the error of the one function every program calls, and a test calls the same function. There is no separate `Check`.                                                                                                                                                                                                   |
| 11  | **`New` names every problem**, joined.                                                                                                                                                                                                                                                                                               | The first problem only, as the old `Check`. The brief asks for every one.                                                                                                                                                                                                                                                                                                                                                                                                              |
| 12  | **`Get[T](line)` is a package function.**                                                                                                                                                                                                                                                                                            | A generic method `line.Get[T]()`, which this Go has. A function works with every Go that has generics. Either reads well; changing it later is mechanical.                                                                                                                                                                                                                                                                                                                             |
| 13  | **A list is `[]T`, a flag that repeats is `Repeat[T]`,** and `Repeat[[]T]` is both (`--filter a,b --filter c`).                                                                                                                                                                                                                      | A tag `repeat:"true"` on a `[]T`: then `[]T` means two things, and "a list per occurrence" cannot be said.                                                                                                                                                                                                                                                                                                                                                                             |
| 14  | **`Opt[T]` is in the library**, with `Get()` (D17) and `Some(v)` for code that fills a struct by hand. On an argument it means "optional" (D47).                                                                                                                                                                                     | Exported fields `Value` and `Given`: D17 fixed `Get()`.                                                                                                                                                                                                                                                                                                                                                                                                                                |
| 15  | **One error type, `UsageError`, with a `Kind` and fields per kind.** `ArgCount` has `At = len(argv)` and no numbers. `Unwrap` gives the reader's error.                                                                                                                                                                              | An error type per kind (seven types). `Min`, `Max`, `Got` on the error: they are `Info.Args` and `len(Line.Args)`.                                                                                                                                                                                                                                                                                                                                                                     |
| 16  | **A late reader's failure is a `UsageError` of kind `Unresolved`**, though it happens in `Run`.                                                                                                                                                                                                                                      | The lookup's error as it is: the caller would not know which flag or argument it was.                                                                                                                                                                                                                                                                                                                                                                                                  |
| 17  | **Next to a mistake no struct is readable, except next to `ArgCount`.**                                                                                                                                                                                                                                                              | Fill what was read. D19 says a mistake wins over `-h`; with this rule a caller cannot get it wrong.                                                                                                                                                                                                                                                                                                                                                                                    |
| 18  | **A late reader wins over the type's method; a type with a `Reader` and a `LateReader` is refused.** A late value is not checked by `Parse`.                                                                                                                                                                                         | A type with an early check and a late lookup. Not needed yet.                                                                                                                                                                                                                                                                                                                                                                                                                          |
| 19  | **Tab asks the type**: a `Complete` method, called on a zero value, gets the line and the prefix. The library does the commas of a list. `Path` and `Words` are in the library.                                                                                                                                                      | Tags (`complete:"a b"`, `complete:"file"`), as the kit had: text, and no place for the line. Or a function per field. Words that depend on the command (the columns of a list) are solved in Headscale with a generic type, `Column[R]`, as 001's `table.Columns[Row]`. A `Completer` option of `New` for a type that is not the caller's can be added later without breaking anything.                                                                                                |
| 20  | **A tag key the library does not know is refused**, also `json`.                                                                                                                                                                                                                                                                     | Ignore foreign keys. Then `hlep:"..."` passes unseen.                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| 21  | **In a group's scope a flag name belongs to one struct type** (K18).                                                                                                                                                                                                                                                                 | Fill every struct that declares the name.                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| 22  | **`Info` gives the value type as a `reflect.Type`.** No `placeholder` tag.                                                                                                                                                                                                                                                           | A tag for the word shown in the help (`--expiry <when>`). A generator can map the type to a word.                                                                                                                                                                                                                                                                                                                                                                                      |
| 23  | **Numbers are decimal.**                                                                                                                                                                                                                                                                                                             | Go's prefixes (`0x10`).                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| 24  | **Headscale's value types are generic**: `Column[R]`, `Cond[R]`, `Text[W]`, and `listFlags[R]` is the struct the builder adds to a list command.                                                                                                                                                                                     | A data slot on the command for the caller's use (`Meta any`), read by the `Complete` method. The generic type needs no `any`.                                                                                                                                                                                                                                                                                                                                                          |
| 25  | **A line runs once, and only a Line from `Parse` runs.** A second `Line.Run` returns `ErrRan` and calls nothing, also when the first stopped at a late reader. `Run` on the Line that a `Complete` method gets, or on a Line made by hand, returns `ErrNotParsed`. (Added after the 003 writer found that the second case panicked.) | For a second `Run`: run the command again without the lookups, which is what the first build did by accident; or look everything up again. Both let a caller run a command twice without meaning to. For the unparsed Line: a panic, as before.                                                                                                                                                                                                                                        |
| 26  | **The problems in the error of `New` have a fixed order** (K19): two readers for a type; then, command by command as declared, the structs and the command; then the names and spellings in the same order.                                                                                                                          | No promise about the order. 003 states the order, and a test of a caller may compare the text.                                                                                                                                                                                                                                                                                                                                                                                         |
| 27  | **A `Repeat` may have a `default`**: not given, it holds the default as one occurrence; given, only what was given (Y9).                                                                                                                                                                                                             | Refuse it, as for `Opt`.                                                                                                                                                                                                                                                                                                                                                                                                                                                               |

## Conflicts in the decisions

Nothing was unworkable. Two points still need the maintainer (A, B). C is decided.

**A. D41 against D35 and against Tab.** D41: the library "does not hand strings to the caller".
D35: Headscale reports the leftmost mistake, its own included.

```console
$ headscale --version -o json
```

"`--version` takes no other flag" is Headscale's mistake, and it stands at `-o` (position 1). To
place it, Headscale must know that `--version` was given, with the word `true`, at 0, and that
another flag stands at 1. In `headscale --version -o json --bogus` the library reports `--bogus`
at 3 and fills no struct, so the typed fields cannot answer. A `Complete` method has the same
need: on Tab nothing is read into a type, and a completion from a config file needs the word after
`-c`. So `Line.Flags` keeps `Name`, `Value` as typed and `At`. The values a command works with are
typed; the text is there for these two uses. If the text must go, `Given` can lose `Value`, and
Headscale then cannot tell `--version` from `--version=false` in a line with a mistake.

**B. D46 against "no global state" and "a wrong struct is found at start".** The sketch wrote
`typed.RegisterLate(client.FindNode)` with a client that was already there. In Headscale the
client is made after the line is read (it needs `--config`), and `New` must know every late type
before that, or it cannot say "this field cannot be read". So the reader is given first and finds
its client later:

```go
cmdline.LateReader(func(ctx context.Context, word string) (v0.Node, error) {
    return command.From(ctx).API.FindNode(ctx, word) // the client is in the context of Line.Run
})
```

This works (the test `TestLate` and `toy` do exactly this). It means 001's `Ctx` must be reachable
from a `context.Context`.

**C. D41 ("checks every value") against the examples of D35: decided by D49.** 001's table of
mistakes and four kit rows used `-o a` and `-o b` as values that read:

```console
$ headscale nodes list -o a -o b --sort
```

001 said: "`--output` given twice". With a type that takes only `json`, the library reports the
bad value `a` at the first `-o`, which stands further left. Both followed from the decisions. The
first build kept the tests with a lenient `Format`. D49 chose the strict type: the line above is
now "`--output` takes json, not `a`" (kit rows J01, J06). The four kit rows that meant to test a
repeat (E22, H20, P06, P11) use `json` as the value and still test the repeat. Two lines of 001's
table need `json` in the same way: `nodes list -o a -o b --sort` and `nodes list -h -o a -o b`.
In one word a repeat still comes before a bad value: `-o json -o yaml` is the repeat (J12).

## Rule changes against `rules.md`

111 old rules: 73 the same, 31 changed, 6 moved to the library, 1 removed. 45 new rules. 155 rules in all.

| What                                          | Rules                                                                                                                                                                                                                                                                 |
| --------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Moved from Headscale's layer into the library | B3 (bool words), R2 (each flag once), R4 (comma list), R5 (empty list), R6 (empty item), C9 (argument count)                                                                                                                                                          |
| Changed because the result is typed           | V3, V4, B2, R1, R3, R7, C6, C7, C10, M1–M8, X1–X5, T9, T13, T14, E1, E2, E4–E6; R7 and E8 again for D49 (`--output` takes only `json`, checked while the line is read)                                                                                                |
| Removed                                       | K2 (a group with arguments cannot be written)                                                                                                                                                                                                                         |
| The same                                      | groups 1 and 5, 10; the rest of 2, 3, 6, 9, 11; X6–X8; E3, E7                                                                                                                                                                                                         |
| New                                           | Y1–Y12 (reading a value), N1–N4 (late readers), A1–A4 (arguments and count), U1 (the mistakes as data), G1–G7 (the structs of a line, and when a line runs), I1–I2 (the tree as data), K9–K19 (checks of `New`, and the order of its problems), T19–T22 (Tab by type) |

What moved the other way, from the library's caller-facing surface: nothing. What Headscale's
layer still does: `adapter.go` and `command.go`.

## Kit cases

Until D49 no row of the suite had changed. D49 changes four rows and adds thirteen. No row was
weakened: each changed row has the same wanted outcome as before, with a value that still reads.

| Row | Before                        | Now                                 | Wanted outcome (unchanged)                                                       |
| --- | ----------------------------- | ----------------------------------- | -------------------------------------------------------------------------------- |
| E22 | `nodes list -o a -o b --sort` | `nodes list -o json -o json --sort` | `flag-repeated [nodes list] "output"`: the repeat comes before the missing value |
| H20 | `nodes list -o a -o b -h`     | `nodes list -o json -o json -h`     | `flag-repeated [nodes list] "output"`: a repeat wins over `-h`                   |
| P06 | `-o a -o b nodez`             | `-o json -o json nodez`             | `flag-repeated [] "output"`: the repeat comes before the unknown command         |
| P11 | `nodes list -h -o a -o b`     | `nodes list -h -o json -o json`     | `flag-repeated [nodes list] "output"`                                            |

The old lines are rows of their own now, with the new answer, and nine more rows hold D49:

| Row | Line                          | Wanted                                                                        |
| --- | ----------------------------- | ----------------------------------------------------------------------------- |
| J01 | `nodes list -o a -o b`        | `bad-value [nodes list] "output"`: the wrong value `a`, not the repeat        |
| J02 | `nodes list -o yaml`          | `bad-value [nodes list] "output"`                                             |
| J03 | `nodes list --output=JSON`    | `bad-value [nodes list] "output"`                                             |
| J04 | `-o yaml nodes list`          | `bad-value [nodes list] "output"`                                             |
| J05 | `-o yaml`                     | `bad-value [] "output"` (before D49: the root's help)                         |
| J06 | `nodes list -o a -o b --sort` | `bad-value [nodes list] "output"` (the old E22)                               |
| J07 | `nodes list -o a -o b -h`     | `bad-value [nodes list] "output"` (the old H20)                               |
| J08 | `-o a -o b nodez`             | `bad-value [] "output"` (the old P06)                                         |
| J09 | `nodes list -h -o a -o b`     | `bad-value [nodes list] "output"` (the old P11)                               |
| J10 | `nodes list --bogus -o yaml`  | `unknown-flag [nodes list] "bogus"`: it stands further left                   |
| J11 | `nodes delete 12 13 -o yaml`  | `bad-value [nodes delete] "output"`, not the count                            |
| J12 | `nodes list -o json -o yaml`  | `flag-repeated [nodes list] "output"`: in one word the repeat comes first     |
| J13 | `-o yaml check config`        | `unknown-flag [check config] "output"`: the command does not take `-o` at all |

All other rows are those of kit v3, with the same wanted and the same actual outcome as on the old
build. What else changed around the suite:

- **The typed layer does not call `Exec`.** `Exec` was "001's builder, cut down": it refused
  repeats, bool words and empty lists and counted arguments. Those are the library's now, and
  if the adapter called `Exec`, `Exec` would hide any of them that the library missed. The adapter
  does the builder's steps itself and reports the outcome with the new `kit.Done`, which checks
  nothing. `Exec` and the kit's own specs stay for the adapters of the other parsers in `diff/`.
- **`Exec` follows D49 too**: one condition, a `-o` that is not `json` is a bad value (it was: an
  empty `-o`). `Exec` is the layer of the other parsers' adapters in the differential; without this
  every line with `-o yaml` would differ between the typed build and them for a reason that is
  not the parser's. `kit.go` therefore differs from kit v3 in that condition and its comment.
- **The kit's tree exists twice**: as the kit's specs (`kit/specs.go`, field types `string`,
  `*string`, `[]string`, a `complete` tag) and as typed specs (`headscale/specs.go`, `Opt[string]`,
  `Path`, types with `Complete`). `TestTwin` reads the typed tree back through `Info` and compares
  it with the kit's tree, command by command. The corpus does the same for its three trees.
- **The typed tree is built once and shared** by every run and every Tab. The kit's row I01 (every
  case twice, in parallel) therefore also tests that one `Tree` serves many lines at once.
- **`kit.Raw`** hands the differential the line "as the parser read it", as `Exec` did. The
  adapter calls it only when the whole line was read. The first FuzzRun run found the case where
  it was not (below).

## Test results

All runs: Go 1.27.3 from `nix develop` in the worktree, `GOFLAGS=-buildvcs=false`, on
2026-11-18. `W` is the worktree path; paths are under `spikes/final-typed/`.

| Test                                  | Command                                                                                                                        | Result                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| ------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| library                               | `cd cmdline && nix develop $W -c go test -count=1 ./...`                                                                       | 23 tests pass in three packages. Typed layer, 12: TestValues (21 rows and 8 more checks), TestLate, TestMistakes (26 rows, 9 default texts), TestStructs, TestInfo, TestNew (40 rows, 5 tags, the order of the problems), TestTab (22 rows), TestOddTypes, TestRun, TestShared, TestStdlibOnly, the seeds of FuzzParse. The reader: its 9 tests as on the old build (TestParse 59 rows, TestComplete 58, TestOrder 6, TestCheck 18, TestContract, TestServe, TestPure, TestErrorText, the seeds of FuzzParse). `script`: 2 |
| library, race                         | `CGO_ENABLED=1 go test -race -count=3 ./...`                                                                                   | ok in all three packages                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| library, coverage                     | `go test -cover . ./internal/reader`                                                                                           | typed layer 99.2 % of statements, reader 100 %                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| kit v4                                | `cd headscale && nix shell nixpkgs#zsh nixpkgs#powershell -c nix develop $W -c go test -count=1 -v .`                          | **MUST 248/248 (0 skipped) · CALL 28/28 · STRETCH 6/6** · OBSERVE 3 (F05, F28, X01: refused, as before). Before D49: MUST 235/235, the numbers of kit v3 on the old build; the 13 more are J01–J13. `-race -count=3` ok                                                                                                                                                                                                                                                                                                    |
| kit v4 against the old table          | `diff <(cut -d"\|" -f2-7 RESULT.md \| sed 1,4d) <(the same of ../../final/headscale/RESULT.md)`                                | the four changed rows and the thirteen new ones, nothing else: every other row has the same wanted and the same actual outcome as on the old build                                                                                                                                                                                                                                                                                                                                                                         |
| twin, typed input, format, candidates | in the same `go test`                                                                                                          | `TestTwin`, `TestInput`, `TestFormat`, `TestDidYouMean` pass                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| second consumer                       | `cd toy && go test -count=1 .`                                                                                                 | `TestToy` (19 lines: runs, mistakes, help from `Info`, Tab) and `TestNoHeadscale` pass                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| example program of 003                | `cd prog && go vet ./... && go test -count=1 -v .`                                                                             | 9 tests pass (`TestTree`, `TestParse`, `TestRun`, `TestMistake`, `TestTab` and the four that print the tables). `probe.txt` and `console.txt` made again after the move: the same text                                                                                                                                                                                                                                                                                                                                     |
| corpus, 485 cases                     | `cd corpus && go run . -check ../../corpus/corpus.jsonl && go run . -md results.md -tsv results.tsv ../../corpus/corpus.jsonl` | 485 cases, 0 bad; **up 343 · ours 123 · neither 19**; no unexplained case                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| differential, run                     | `cd diff && ./go.sh go run ./cmd/diffrun -n 1000000 -seed 7 -mode run -crate 0.05 -out results/final/run-final.md`             | 1,000,000 lines in 1 min 28 s. No bucket without an explanation and no new bucket: the same buckets as on the old build, with other counts since D49 (below). One of them is a "bug" bucket, "own drops flags read before a group word", in the pair grammar~pflag (1,394 lines). The fault is in the own-pflag adapter, not in the typed build, and the old build has the same bucket                                                                                                                                     |
| differential, Tab                     | the same with `-mode tab -n 125000`, and again with `-offset 125000`, stderr to `/dev/null`                                    | 2 × 125,000 lines in 8.3 s each. The patterns, the pair counts and the buckets are those of the old build                                                                                                                                                                                                                                                                                                                                                                                                                  |
| fuzz, kit level                       | `cd diff && ./fuzz.sh 2m` after D49; `./fuzz.sh 3m` before it (6 workers, one target after the other)                          | After D49, 2 min each: FuzzRun 8.5 M executions, FuzzLeaf 2.2 M, FuzzTab 0.59 M, all pass. Before D49, 3 min each: FuzzRun 12.9 M (second run; the first failed on a fault of the harness, below), FuzzLeaf 2.8 M, FuzzTab 0.80 M, all pass. The regression seeds in `diff/testdata/fuzz` pass                                                                                                                                                                                                                             |
| fuzz, typed layer                     | `cd cmdline && go test -run XXX -fuzz '^FuzzParse$' -fuzztime 3m -parallel 6 .`                                                | 3 min, 35.3 M executions, pass. Run again after the change to `Line.Run`, with one more property (a second `Run` returns `ErrRan`); the run before that change: 35.7 M, pass                                                                                                                                                                                                                                                                                                                                               |
| fuzz, reader                          | `go test -run XXX -fuzz '^FuzzParse$' -fuzztime 60s -parallel 6 ./internal/reader`                                             | 60 s, 11.7 M executions, pass                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| real shells, 41 lines                 | `cd headscale && go build -o bin/headscale ./cmd/headscale && bash shell/run.sh`                                               | bash, zsh, fish (pty and `complete -C`) and PowerShell (`TabExpansion2`) were all there and all ran. `pty-bash.txt`, `pty-zsh.txt`, `fishc.txt`, `pwsh.txt` and the PowerShell script are byte for byte the files of the old build. `pty-fish.txt` is the same once the prompt is taken out: the prompt shows the folder, and the folder moved (D37). Run before D49 and not run again: D49 moves nothing that Tab reads                                                                                                   |
| `__complete` answers                  | old binary against new, the 41 lines, `__complete` and `__completeNoDesc`; again after D49                                     | 82 answers, none differs; the four scripts are identical                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |

**The corpus numbers are those of the old build:** up 343, ours 123, neither 19, and per case the
same verdict and the same outcome text (`results.tsv` against the old one, the adapter name
aside). The 19 are the 19 of `rules.md` section 0.2.

**The differential.** Before D49 the three tables were those of the old build, the timing line
aside: the same counts, the same buckets, the same shrunk lines. D49 changes the run table, as it
must: the generator writes `-o` with many values, and every one that is not `json` is now a
mistake.

| Run mode, 1 M lines       | Old build, and typed before D49 | Typed after D49       |
| ------------------------- | ------------------------------- | --------------------- |
| all three agree           | 519,955                         | 480,182               |
| grammar~pflag differ      | 120,203 in 8 buckets            | 191,368 in 8 buckets  |
| grammar~cobra differ      | 457,186 in 12 buckets           | 495,776 in 12 buckets |
| grammar~plainpflag differ | 42,635 in 4 buckets             | 48,168 in 4 buckets   |
| grammar~stdflag differ    | 7,212 in 5 buckets              | 10,200 in 5 buckets   |

The buckets are the same ones, pair by pair and cause by cause; none is new and none is
unexplained. The lines moved into two of them. "Two mistakes on the line, each side names a
different one first" grew from about 60,000 to 112,000 lines against own-pflag: the other
parsers' adapters hand `Exec` no positions, so it names the wrong `-o` value where the typed build
names the leftmost mistake. "A repeated global flag, or a `-o` that is not json, before a group"
grew from about 42,000 to 62,000 lines against cobra, which shows help there; its label in
`classify.go` now names D49. The Tab tables keep their patterns and pair counts (Tab reads no
value); a few sampled lines sit in another bucket, because the classifier asks the typed build
whether a word earlier on the line is refused.

**The one failure, and what it was.** The first FuzzRun run failed after one second:

```text
trailing --: ["nodes" "set" "--name=" "--name=" "-c"]
      without nodes set [] name=["" ""]
      with    nodes set [] config=["--"] name=["" ""]
```

The library is right on both lines: `--name` given twice, at position 3. The harness was wrong:
the adapter handed the differential "the line as the parser read it" although the reader had
stopped at `-c` (a missing value, further right). Kit v3's `Exec` handed a line over only when
the reader had read all of it; the first adapter did so for every repeat and bad value. The
adapter now checks that every word was read (`whole` in `adapter.go`). The input is kept as a
seed (`diff/testdata/fuzz/FuzzRun/FuzzRun-typed-partial-line`), and the log as
`diff/results/fuzz-FuzzRun-run1-failed.log`. FuzzLeaf and FuzzTab had passed in that first run
(1.94 M and 0.49 M executions). All three were run again after the fix, three minutes each
(FuzzRun 12.9 M, FuzzLeaf 2.8 M, FuzzTab 0.80 M executions, pass; logs `fuzz-*-before-D49.log`),
and again after D49.

**The typed fuzz target** (`FuzzParse` in `cmdline/cmdline_test.go`) holds D35 directly: for a
mistake at position p, the words before p hold no mistake of their own but a wrong count. Also:
no panic, the same answer twice, a mistake is on the line, `Run` never runs a line with a
mistake or a group, a line without a mistake runs once (a second `Run` returns `ErrRan`) and has
no flag twice unless it is a `Repeat`.

## Sizes (non-blank, non-comment lines)

| Part                                                                                                                                                   | Lines          | Old build                             |
| ------------------------------------------------------------------------------------------------------------------------------------------------------ | -------------- | ------------------------------------- |
| Library, typed layer (`cmdline.go` 202, `field.go` 339, `line.go` 197, `complete.go` 56)                                                               | 794            | —                                     |
| Library, the reader (`parse.go` 195, `complete.go` 104, `check.go` 70)                                                                                 | 369            | 368                                   |
| `script`                                                                                                                                               | 20             | 20                                    |
| Library tests (typed 880, reader 388, script 33)                                                                                                       | 1,301          | 431                                   |
| Headscale's layer (`command.go` 134: spec, builder flags, value types; `adapter.go` 165: the builder's steps, of which 31 are the differential's hook) | 299            | 94 (adapter) + 115 (the kit's `Exec`) |
| Headscale: the kit's tree as typed specs / `describe.go` / shell-test `main`                                                                           | 86 / 49 / 16   | (in the kit) / — / 17                 |
| `toy` (program / test)                                                                                                                                 | 143 / 64       | —                                     |
| `prog`, the example of 003 (program / test / the tests that print 003's tables)                                                                        | 185 / 49 / 281 | 104 / 220 (with its probes)           |
| kit v4 additions (`export.go`; D49 rows in `suite.go`)                                                                                                 | 18; 17         | —                                     |

The library is about three times the size of the string-only one. What it took over from
Headscale's layer (the kit's `Exec`, 115 lines) is small against what typing adds: the tags, the
readers, the structs, the checks of `New`.

## What was not checked

- **After D49 only what D49 touches was run again**: kit, corpus, differential, the three kit-level
  fuzz targets (two minutes each), the library's tests, and the 82 Tab answers against the old
  binary. Not run again: the real shells, and the reader's `FuzzParse` (the reader did not
  change). After the change to `Line.Run` the library's tests, `toy`, the kit, the corpus, the
  example program, the typed `FuzzParse` and the regression seeds of the kit-level fuzz targets
  were run again. The differential and the kit-level fuzz runs were not: they call `Run` once
  for each line.
- **Windows and macOS.** Nothing ran there. PowerShell ran on Linux only.
- **The corpus rows have no expectation for the typed fields.** The corpus and the kit grade the
  outcome as text (the flags as typed). That a value lands in the field with the right type is
  held by the library's own tests and by `TestInput`, not by the 485 cases.
- **Real Headscale types.** The kit accepts any text for a value, so the typed specs are text
  types. An `Expiry`, a node lookup and `time.Duration` are tested in the library's tests and in
  `toy`, not on the kit's tree.
- **The fuzz runs are short**: three minutes a target, as asked. FuzzTab made 0.5 M executions.
- **A late reader that is slow, hangs or is cancelled.** `Line.Run` passes its context on and does
  nothing else about it.
- **`Complete` of a type inside a list of files** (`[]Path`): the shell completes the whole word,
  commas included. No test, no rule.
- **Help, the reference page and the man page** were not generated. `toy` prints a help from
  `Info`, and `Describe` rebuilds the kit's whole description from it; that is the evidence that
  the data is enough.
- **The differential says "the same as before", not "right".** It compares against cobra and
  pflag adapters built on the kit's own specs; what it found on the old build is in
  `differential.md`.
- **Generic methods** of this Go were not used, so nothing here depends on them.
- **The three cobra script faults** (S10) are as they were; nothing was reported upstream (D40).

## The public API (`go doc -all`)

```text
package cmdline // import "spike/cmdline"

Package cmdline reads a command line into the typed input struct of a command,
and answers shell completion for the tree of commands.

A command declares what it takes as a struct. Each field is one argument or one
flag, named by a struct tag:

    type setIn struct {
    	Node   string                     `arg:"node"`
    	Routes []netip.Prefix             `arg:"routes"`
    	Expiry cmdline.Opt[time.Duration] `flag:"expiry" short:"e" help:"When it ends"`
    	Force  bool                       `flag:"force" help:"Do not ask"`
    }

The tags are arg, flag, short, help and default. The type of the field says how
its word is read:

    string, bool, int…, uint…, float…   read by the library
    a type with UnmarshalText           reads itself (encoding.TextUnmarshaler)
    a type given to Reader              read by that function; it wins over the method
    a type given to LateReader          read when the command runs, after the whole line is right
    []T                                 one word, a comma list of T
    Opt[T]                              T, and whether it was given; as an argument it is optional
    Repeat[T]                           a flag that may be given more than once

A flag whose value is a bool takes no value word: --force, --force=true and
--force=false. Every other flag is given once.

The grammar: --name, --name=value, --name value, -x, -x=value, -x value.
The word after a value flag is its value, whatever it looks like. Flags
and arguments mix in any order; "--" ends the flags. Attached short values
(-ovalue), grouped shorts (-ab) and abbreviations are unknown flags.

The library has no help, no usage text and no meaning for any flag name.
Parse reports the first mistake on the line as a *UsageError; the caller writes
the sentence. The tree is readable as data through Info.

VARIABLES

var (
	ErrBool      = errors.New("not true or false")
	ErrEmpty     = errors.New("the list is empty")
	ErrEmptyItem = errors.New("the list has an empty item")
)
    What a reader of the library says about a word it refuses; UsageError.Err
    holds it.

var (
	ErrGroup     = errors.New("cmdline: the line ends at a group, which does not run")
	ErrRan       = errors.New("cmdline: the line has run already")
	ErrNotParsed = errors.New("cmdline: the line is not from Parse")
)
    What Line.Run returns for a line that has no mistake and still does not run.


FUNCTIONS

func Get[T any](l *Line) (T, bool)
    Get returns the struct of type T that Parse filled for the line:
    the input struct of the command reached, or one of the structs in its Flags.
    At a group these are the Flags of the group and of the groups above it.
    It reports false when the command has no such struct, and next to a mistake
    other than ArgCount.

func Words(prefix string, words ...string) []string
    Words returns the words that start with prefix, for a Completer with a fixed
    list.


TYPES

type Arg struct {
	Name     string
	Help     string
	Type     reflect.Type // as Flag.Type
	List     bool         // a comma list
	Optional bool         // an Opt[T]: may be left out
	Late     bool         // read by a LateReader
}
    Arg describes one argument of a command.

type Command[In any] struct {
	Name    string
	Aliases []string
	Help    string // one line; Tab shows it next to the name
	Flags   []any  // further structs of flags, for a layer above the command; only the types are read
	Run     func(ctx context.Context, in In) error
}
    Command is a command that runs. In is its input struct: the arguments,
    in field order, and the flags.

type Completer interface {
	Complete(line *Line, prefix string) ([]string, Directive)
}
    Completer is implemented by a type that offers its own words on Tab,
    for a flag value or an argument of that type. line is what was typed before
    the word under the cursor, read as Parse reads it but never refused; no
    struct of it is filled. prefix is the word under the cursor; in a list it is
    the item after the last comma. A word may carry a description after a tab.
    Complete is called on the zero value and must not use it.

    A field whose type has no Complete offers nothing.

type Directive int
    Directive tells the completion script what to do with the words. The bits
    are cobra's ShellCompDirective, so cobra's scripts read them.

const (
	Failed     Directive = 1 << iota // the script shows nothing
	NoSpace                          // no space after the word: room for ",x" or "=x"
	NoFiles                          // offer no file names when there are no words
	FilterExt                        // the words are file extensions to filter by
	FilterDirs                       // offer directories (in the word, if one is given)
	KeepOrder                        // keep the order of the words
)
type Flag struct {
	Name     string // the long name, without dashes
	Short    string // one letter, or ""
	Help     string
	Type     reflect.Type // what one value is read as: T for T, []T, Opt[T] and Repeat[T]
	Bool     bool         // takes no value word
	List     bool         // one value is a comma list
	Repeat   bool         // may be given more than once
	Optional bool         // an Opt[T]: the command sees whether it was given
	Late     bool         // read by a LateReader
	Default  string       // the default tag
}
    Flag describes one flag of a command.

type Given struct {
	Name  string // the flag's long name, whatever spelling was typed
	Value string // as typed; "true" for a bool given bare
	At    int    // the index in argv of the flag word
}
    Given is one flag as it was typed. The typed value is in the struct the flag
    belongs to; Given is for a caller that places a mistake of its own on the
    line, and for a Completer.

type Group struct {
	Name     string
	Aliases  []string
	Help     string // one line; Tab shows it next to the name
	Flags    []any  // structs of flags that may be typed here, and below before the command; only the types are read
	Commands []Node
}
    Group is a command that only leads to other commands. The root's Name is the
    program name.

type Info struct {
	Name     string
	Aliases  []string
	Help     string
	Path     []string // names from the root, the root's own left out
	Usage    string   // the root's name, Path, then <x> per argument and [x] per optional one
	Flags    []Flag   // the flags declared on this command, in field order
	Args     []Arg    // in field order
	Commands []*Info  // the commands of a group; none for a command that runs
}
    Info describes one command as data: what a help text, a reference page or a
    did-you-mean needs.

type Kind int
    Kind says what is wrong with a line.

const (
	UnknownCommand Kind = iota + 1 // Word is not a command of the group at Path
	UnknownFlag                    // Word is no flag where it stands, or no flag of the command reached
	MissingValue                   // the flag is the last word and has no value
	Repeated                       // the flag is given a second time and is no Repeat
	BadValue                       // the reader of the field's type refused the value; Err says why
	ArgCount                       // too few or too many arguments
	Unresolved                     // a LateReader refused the value; Err says why
)
type Line struct {
	Command *Info    // the command reached: one that runs, or a group when the line ends there
	Flags   []Given  // every flag given, in the order typed
	Args    []string // the arguments as typed, in order, without the "--" that ends the flags
	ArgAt   []int    // the index in argv of each argument

	// Has unexported fields.
}
    Line is one command line as Parse read it.

func (l *Line) Run(ctx context.Context) error
    Run runs the command of a line that Parse read without a mistake. First
    every LateReader reads its word, in the order typed; the first that fails
    stops the run with a *UsageError of kind Unresolved. A caller does its own
    work between Parse and Run: show help, make a client and put it into ctx.

    A line with a mistake does not run: Run returns the mistake. Nor does a
    line that ends at a group (ErrGroup), or a Line that Parse did not make,
    such as the one a Complete method gets (ErrNotParsed). A line runs once:
    a second Run returns ErrRan and calls nothing, also when the first one
    stopped at a LateReader.

type Node interface {
	// Has unexported methods.
}
    Node is one command of a tree: a Group or a Command[In].

type Opt[T any] struct {
	// Has unexported fields.
}
    Opt is a value that may be left out. As a flag it records whether the flag
    was given, so --name "" differs from no --name; as an argument it makes the
    argument optional.

func Some[T any](v T) Opt[T]
    Some returns an Opt that was given v, for code that fills an input struct by
    hand.

func (o Opt[T]) Get() (T, bool)
    Get returns the value and whether it was given.

type Option struct {
	// Has unexported fields.
}
    Option tells New how to read a type that cannot say so itself.

func LateReader[T any](read func(ctx context.Context, word string) (T, error)) Option
    LateReader makes read the reader of every field of type T, and puts it off:
    Parse keeps the word, and Line.Run calls read with its context once the
    whole line is right. It is for a value that needs more than the word,
    such as a lookup on a server.

func Reader[T any](read func(string) (T, error)) Option
    Reader makes read the reader of every field of type T. It is for a type that
    has no UnmarshalText and is not yours to give one, such as time.Duration;
    it wins over the method when a type has both.

type Path string
    Path is a file path. Tab offers file names for it.

func (Path) Complete(*Line, string) ([]string, Directive)
    Complete lets the shell offer file names.

func (p *Path) UnmarshalText(b []byte) error
    UnmarshalText takes any word.

type Repeat[T any] []T
    Repeat is a flag that may be given more than once: each occurrence adds
    one T. Every other flag is given once; a list is one comma-separated value
    ([]T).

type Tree struct {
	// Has unexported fields.
}
    Tree is a checked tree of commands. It is read-only: Parse, Complete and
    Serve may run at the same time.

func New(root Node, opts ...Option) (*Tree, error)
    New checks the tree and makes it ready. The error names every problem:
    a struct that cannot be read (a field with no tag or an unknown one,
    a type with no reader, a default that does not read), a name, alias, flag
    or short that is used twice or cannot be typed, a group with no command,
    a command with no Run. A program stops on it at start; a test that builds
    the tree finds it before that.

func (t *Tree) Complete(words []string, cur string) ([]string, Directive)
    Complete answers Tab: words are the words after the program name before
    the cursor, cur is the word under it ("" for a new word). It offers command
    names, flag names and what the Completers of the field types offer. It runs
    no command and no reader.

func (t *Tree) Parse(argv []string) (*Line, error)
    Parse reads argv (without the program name) and fills the structs of the
    command reached. The error is a *UsageError: the first mistake on the line,
    left to right, whatever its kind. A wrong argument count belongs to the
    whole line, so it is reported only when nothing else is wrong.

    The Line is never nil. Next to an error it holds what was read before the
    mistake, so a caller can place a mistake of its own. Its structs are filled
    when there is no error, and next to ArgCount, so a caller can still see a
    flag such as --help.

func (t *Tree) Root() *Info
    Root returns the description of the root; its Commands lead to the rest.

func (t *Tree) Serve(w io.Writer, args []string) bool
    Serve answers the hidden entry point the completion scripts call: when
    args[0] is "__complete" or "__completeNoDesc" it writes the words and the
    directive to w and reports true. A program calls it first in main.

type UsageError struct {
	Kind  Kind
	Path  []string // the command reached, as Info.Path
	At    int      // the index in argv of the word the mistake stands at; len(argv) for ArgCount
	Word  string   // that word: a command word, an argument, or a flag as typed, up to any "="
	Flag  string   // the long name, when the mistake is about a flag the command takes
	Arg   string   // the name, when the mistake is about an argument
	Value string   // BadValue and Unresolved: what was typed for it
	Err   error    // BadValue and Unresolved: what the reader said
}
    UsageError is a mistake on the command line, as data. Its text is a default;
    a caller that writes its own reads the fields.

func (e *UsageError) Error() string
    Error gives the default English text.

func (e *UsageError) Unwrap() error
    Unwrap returns Err, so errors.Is and errors.As find what the reader said.


package script // import "spike/cmdline/script"

Package script writes the completion scripts that call a program's hidden
__complete entry point (cmdline.Tree.Serve). The scripts are cobra's (D23):
this package imports cobra for its generators and nothing else.

FUNCTIONS

func Write(w io.Writer, shell, program string) error
    Write writes the script for shell ("bash", "zsh", "fish" or "powershell")
    for the program named program, with descriptions.
```
