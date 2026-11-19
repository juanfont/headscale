# Headscale command-line parser

**Status:** draft, for discussion, part of [#3375]. It is not meant to be merged as-is.

This document specifies a small Go library. The library reads a command line against a tree of commands and fills the typed input struct of the command that the line names. It answers shell completion (Tab) for the same tree. The new Headscale CLI ([001](001-cli.md)) is built on it. Its name is `cmdline`.

[001](001-cli.md) says what is Headscale's: which commands and flags exist, the types of their values, the error sentences, the help and the command specs. This document says what any program that uses the library gets. A program author and a user who types a line can both predict the result of any command line and any Tab press from this document alone. It names no Headscale command, except in examples that say so.

Each rule has an ID (`L1`, `T7`, …) and at least one test. The [rule index](#rule-index) maps each ID to its tests. A prototype in [`research/spikes/final-typed/`](research/spikes/final-typed/) implements every rule, and its tests hold them.

**The library is typed.** The first version of this document specified a library that gave every value back as the string that was typed. The maintainer reviewed it and asked for types from top to bottom (decision D41). The string reader of the first version is now the lower layer inside the library, with its tests. [The review: a typed library](#the-review-a-typed-library) says what changed and what was measured.

## Contents

- [Words used here](#words-used-here)
- [What the library is](#what-the-library-is)
- [The command tree](#the-command-tree)
- [Values and types](#values-and-types)
- [Reading a command line](#reading-a-command-line)
- [Tab completion](#tab-completion)
- [The completion protocol](#the-completion-protocol)
- [Using the library](#using-the-library)
- [Tests](#tests)
- [Limits, platforms and compatibility](#limits-platforms-and-compatibility)
- [Why Headscale has its own parser](#why-headscale-has-its-own-parser)
- [Decision log](#decision-log)
- [Open points](#open-points)
- [Rule index](#rule-index)
- [References](#references)

## Words used here

| Word            | Meaning                                                                                                     |
| --------------- | ----------------------------------------------------------------------------------------------------------- |
| argv            | the words of the command line after the program name, as the program gets them                              |
| word            | one element of argv                                                                                         |
| position        | the index of a word in argv, from 0                                                                         |
| command         | one node of the tree: a group or a leaf                                                                     |
| root            | the top command; its name is the program name                                                               |
| group           | a command that only leads to other commands (`Group`)                                                       |
| leaf            | a command that runs (`Command[In]`); it has no children                                                     |
| path            | the names of the commands from the root to a command, root not included                                     |
| flag word       | a word that has at least two bytes, starts with `-` and is not exactly `--` (rule L1)                       |
| typed name      | a flag word up to its first `=`, for example `--sort` in `--sort=id`                                        |
| attached value  | the part of a flag word after its first `=`                                                                 |
| bool flag       | a flag that takes no value word                                                                             |
| value flag      | a flag that is not a bool flag                                                                              |
| value word      | the word after a value flag that has no attached value                                                      |
| command word    | a word at a group that is not a flag word and not a value word                                              |
| argument        | a word at a leaf that is not a flag word and not a value word; also the field that the word fills           |
| input struct    | the Go struct type `In` of a leaf: one field for each argument and each flag of the command                 |
| struct of flags | a Go struct type listed in `Flags` of a group or a leaf: one field for each flag                            |
| reader          | the code that makes a value of a field's type from one word                                                 |
| late reader     | a reader that runs when the command runs, not when the line is read                                         |
| scope           | the flags that can be typed at a group: the flags of the root, of the group and of every group between them |
| given           | a flag is given when the line holds it at least once                                                        |
| mistake         | something wrong on the line; the library reports it as a `*UsageError`                                      |
| caller          | the program that uses the library, and its code on top of the library                                       |
| cursor word     | the word under the cursor when Tab is pressed; empty when the cursor stands after a space                   |
| candidate       | one word that Tab offers, with an optional help text after a tab character                                  |
| directive       | a number that tells the shell script what to do with the candidates                                         |
| Completer       | a type that offers candidates for its own values: it has a `Complete` method                                |
| script          | the shell code that tells a shell how to complete the program; cobra's generators write it                  |

The examples use one example program, `prog`. Its code is in [Declare a tree](#declare-a-tree). It has a group `items` with the leaves `list` (alias `ls`) and `delete` (alias `rm`), and the leaves `check` and `completion`. Every example output in this document comes from that program, built on the prototype ([`research/spikes/final-typed/prog/`](research/spikes/final-typed/prog/)).

## What the library is

**The library does five things, and a sub-package does a sixth.**

1. `New` checks a tree of commands and makes it ready. It refuses a wrong tree and names every problem.
1. `Tree.Parse` reads argv against the tree. It fills the input struct of the command reached and its structs of flags: each value is read into the type of its field. It returns the first mistake on the line as data.
1. `Line.Run` runs the command of a line. First it runs the late readers.
1. `Tree.Complete` answers Tab for a line, and `Tree.Serve` answers the hidden entry point that the shell scripts call (`prog __complete …`).
1. `Tree.Root` gives the tree as data: the names, help texts, flags, arguments and usage line of each command.
1. The sub-package `script` writes the shell scripts, with cobra's generators.

**The library does nothing else.** It prints no help and no usage text. It gives no flag name a meaning: `--help` and `--version` are ordinary flags. It does not read the environment or a config file, and it does not exit. It writes only to the writer that `Serve` gets. It keeps no state between calls.

**The type of a field drives the library.** The type says how the word is read, if the flag may repeat, if the command sees "not given", and what Tab offers. A struct tag gives only names and help text.

**The core uses only Go's standard library.** Only the sub-package `script` imports cobra (rule E3). The string reader of the first version is the package `cmdline/reader`. It is public, because Headscale has no `internal/` folders (decision D52). A caller describes its tree with the typed layer; the reader is the layer under it, not a second way to describe a tree.

### Who does what

The library decides the grammar, the command walk, how a word becomes a value of a basic type, lists, bool words, the repeat rule, the argument count, the mistakes with their positions, Tab, the protocol and the tree check (rule E1). The caller decides the rest, and the library has no setting for it (rule E2). Headscale's layer is the first caller; its choices are in [001](001-cli.md).

| Concern                                         | The library                                                                                                                                 | The caller (Headscale, as an example)                                                                                                        |
| ----------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------- |
| how one word is read, flag values, `--`         | decides                                                                                                                                     | —                                                                                                                                            |
| command names, aliases and groups               | finds the command; gives the tree as data                                                                                                   | declares them; writes "Did you mean" from the data                                                                                           |
| which flags and arguments a command takes       | reads the tags of the input struct and of each struct in `Flags`                                                                            | writes the structs; Headscale's builder adds its own flags as structs of flags (E4)                                                          |
| a flag before the subcommand                    | lets it stand there when a group above lists it and the command reached takes it too (W1, W2)                                               | lists the flag on the root and on each command that takes it (W4)                                                                            |
| value types                                     | reads Go's basic types; calls `UnmarshalText`, a `Reader` or a `LateReader` for every other type                                            | writes its own types with their methods; gives a `Reader` for a type that it does not own. Headscale's output format is such a type (R7, E8) |
| lists                                           | `[]T`: cuts the word at commas; refuses an empty list and an empty item                                                                     | —                                                                                                                                            |
| bool words after `=`                            | takes only `true` and `false`                                                                                                               | —                                                                                                                                            |
| a flag given twice                              | refuses it, unless the field is a `Repeat[T]`                                                                                               | chooses the type of the field                                                                                                                |
| given or not given                              | `Opt[T]`                                                                                                                                    | uses it                                                                                                                                      |
| defaults                                        | reads the `default` tag when the flag is not given                                                                                          | writes the tag, or sets the default in `Run`                                                                                                 |
| argument count                                  | counts against the `arg` fields; reports `ArgCount`                                                                                         | writes the sentence from `len(Line.Args)` and `Info.Args`; can show help first                                                               |
| the usage line                                  | makes it from the input struct (`Info.Usage`)                                                                                               | prints it                                                                                                                                    |
| a lookup on a server                            | runs the `LateReader` of the type in `Line.Run`, after the whole line is right                                                              | writes the lookup; puts its client into the context of `Run`                                                                                 |
| several mistakes on one line                    | reports its own leftmost mistake, with its position                                                                                         | places mistakes of its own against it (Headscale: D35)                                                                                       |
| error text                                      | gives the kind, the path, the word, the position, the flag or argument, the value and the cause; a default English text                     | writes every sentence, the "Did you mean" and the exit code (E7)                                                                             |
| `--help`, `-h`, `--version`                     | ordinary bool flags                                                                                                                         | decides what they mean                                                                                                                       |
| a line that ends at a group                     | returns a `Line` at the group; `Line.Run` returns `ErrGroup`                                                                                | decides; Headscale shows the help of the group                                                                                               |
| Tab                                             | reads the line; offers command names and flag names with help texts; asks the type of a field for values; completes the last item of a list | gives its types a `Complete` method (E5, E6)                                                                                                 |
| files on Tab                                    | the type `Path`                                                                                                                             | uses `Path` for a file flag and a file argument                                                                                              |
| help, reference page, man page                  | gives `Info`, `Flag` and `Arg`                                                                                                              | writes all text                                                                                                                              |
| the hidden entry point                          | `Tree.Serve`                                                                                                                                | calls `Serve` first in `main`                                                                                                                |
| scripts                                         | `script.Write`                                                                                                                              | gives the `completion` command                                                                                                               |
| a valid tree                                    | `New` refuses a wrong tree                                                                                                                  | calls `New` at start and in a test (E4)                                                                                                      |
| output, API client, prompts, config, exit codes | —                                                                                                                                           | all of it                                                                                                                                    |

## The command tree

**The caller declares the tree as Go values, and `New` makes a `*Tree` from them.** A tree is a `Node`: a `Group` or a `Command[In]`. The root is a `Group` in most programs. A root that is a `Command[In]` is a program without subcommands. `Parse`, `Complete`, `Serve` and `Root` are methods of the `*Tree`. The tree is read-only: they may run at the same time (M7).

### Groups and commands

| Field      | In            | Meaning                                                                                                          |
| ---------- | ------------- | ---------------------------------------------------------------------------------------------------------------- |
| `Name`     | both          | the word that selects the command. The root's `Name` is the program name; the scripts and the usage lines use it |
| `Aliases`  | both          | other words that select the command. A path holds the `Name`, never an alias (C10)                               |
| `Help`     | both          | one line. Tab shows it next to the name and next to each alias                                                   |
| `Flags`    | both          | structs of flags; see [Flags of a layer above](#flags-of-a-layer-above)                                          |
| `Commands` | `Group`       | the children: at least one `Node`                                                                                |
| `Run`      | `Command[In]` | `func(ctx context.Context, in In) error`: the command. It gets the filled input struct                           |

**A group has no input struct, so it takes no arguments** (C6). A group does not run.

**The library knows only the input type of a command** (decision D44). `Run` returns an `error`. What a command gives back, and how it is printed, is the caller's.

### The input struct

**A command declares its arguments and its flags as the fields of its input struct `In`** (decision D42). Each field is one argument or one flag. A struct tag names it, and the type of the field says how its word is read ([Values and types](#values-and-types)).

| Tag              | On          | Meaning                                                                                                                       |
| ---------------- | ----------- | ----------------------------------------------------------------------------------------------------------------------------- |
| `arg:"name"`     | an argument | the name of the argument, for the usage line and for a mistake. The n-th `arg` field takes the n-th argument of the line (A1) |
| `flag:"name"`    | a flag      | the long name without dashes; typed as `--name`                                                                               |
| `short:"x"`      | a flag      | one character; typed as `-x`                                                                                                  |
| `help:"text"`    | both        | one line. Tab shows it next to a flag; `Info` gives it for a help text                                                        |
| `default:"word"` | a flag      | the word that is read when the flag is not given; see [Defaults](#defaults)                                                   |

- **Every field is exported and has exactly one of the tags `arg` and `flag`** (K10). A field without a tag is refused, so an embedded struct is refused too.
- **The library refuses a tag key that it does not know** (K11). This holds also for a key of another package, such as `json`: a typing error in a key would otherwise pass unseen.
- **The arguments are the `arg` fields in field order.** An `Opt[T]` field is an optional argument, and optional arguments stand last (K15). A command takes a fixed number of arguments, or a fixed number and optional ones after them. There are no variadic arguments.
- **An input struct with no field is valid.** `Command[struct{}]` takes no argument and no flag.

```go
type listIn struct {
	Sort    Column                     `flag:"sort" help:"Sort by"`
	Columns []Column                   `flag:"columns" help:"Columns to show"`
	Filter  cmdline.Repeat[string]     `flag:"filter" help:"Keep matching rows"`
	Limit   int                        `flag:"limit" default:"50" help:"Most rows to show"`
	Name    cmdline.Opt[string]        `flag:"name" help:"Keep items with this name"`
	Since   cmdline.Opt[time.Duration] `flag:"since" help:"Keep items changed in this time"`
}

type deleteIn struct {
	Item  Item `arg:"item" help:"The item to delete"`
	Force bool `flag:"force" help:"Do not ask"`
}

type checkIn struct {
	File cmdline.Opt[cmdline.Path] `arg:"file" help:"The file to check"`
}

type completionIn struct {
	Shell string `arg:"shell" help:"bash, zsh, fish or powershell"`
}
```

### Flags of a layer above

**A layer above the command can add flags that the input struct does not hold** (decision D48). `Flags` is a list of struct values. The library reads only their types: each field is one flag, with the same tags as in an input struct. A struct of flags holds no argument (K15). The caller reads the filled struct with `Get[T](line)` ([The structs of a line](#the-structs-of-a-line)).

- **On a `Command`, `Flags` adds flags to that command.** `Run` does not see them: it gets only `In`. A builder that gives every command `--help` lists one struct for it on every command, and reads it with `Get` before it calls `Run`.
- **On a `Group`, `Flags` lists the flags that can be typed at that group, and below it before the leaf** (W1). See [Where a flag may stand](#where-a-flag-may-stand).
- **`[]any` is checked by `New`, not by the compiler.** An entry that is not a struct value is refused (K9).

```go
// The flags that more than one command takes. Each set is a struct of its own.
type (
	helpFlags struct {
		Help bool `flag:"help" short:"h" help:"Show help"`
	}
	outputFlags struct {
		Output Format `flag:"output" short:"o" help:"Output format"`
	}
	configFlags struct {
		Config cmdline.Path `flag:"config" short:"c" default:"prog.yaml" help:"Config file"`
	}
)
```

### The tree as data

**`Tree.Root()` returns the tree as an `*Info`** (I1). It is what a help text, a reference page, a man page or a "Did you mean" needs. The library prints none of them.

| `Info` field              | Meaning                                                                                                                                                              |
| ------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `Name`, `Aliases`, `Help` | as declared                                                                                                                                                          |
| `Path`                    | the names from the root to the command, the root's own name left out                                                                                                 |
| `Usage`                   | the usage line                                                                                                                                                       |
| `Flags`                   | the flags declared on this command: those of the input struct first, then those of each struct in `Flags`, in field order. For a group: its own flags, not its scope |
| `Args`                    | the arguments, in field order                                                                                                                                        |
| `Commands`                | the children of a group, in the order declared; none for a leaf                                                                                                      |

**The usage line is made from the input struct** (I1, decision D47). It is the root's name, the path, then `<name>` for each needed argument and `[name]` for each optional one. The usage line of a group is the root's name and the path. In the example program: `prog items delete <item>`, `prog check [file]` and `prog items`.

**A `Flag` and an `Arg` describe one field** (I2).

| Field      | In     | Meaning                                                                                                    |
| ---------- | ------ | ---------------------------------------------------------------------------------------------------------- |
| `Name`     | both   | the long name of the flag, without dashes; the name of the argument                                        |
| `Short`    | `Flag` | one character, or empty                                                                                    |
| `Help`     | both   | the `help` tag                                                                                             |
| `Type`     | both   | the `reflect.Type` that one value is read as: `T` for the field types `T`, `[]T`, `Opt[T]` and `Repeat[T]` |
| `Bool`     | `Flag` | the flag takes no value word                                                                               |
| `List`     | both   | one value is a comma list                                                                                  |
| `Repeat`   | `Flag` | the flag may be given more than once                                                                       |
| `Optional` | both   | the field is an `Opt[T]`                                                                                   |
| `Late`     | both   | a late reader reads the value                                                                              |
| `Default`  | `Flag` | the `default` tag                                                                                          |

### A valid tree

**`New(root, options…)` checks the tree and refuses a wrong one** (K1–K18). The error names every problem, one per line, in a fixed order (K19): first a type with two readers; then, command by command in the order declared and a command before its children, what is wrong with the structs and the command; then, in the same order, what is wrong with the names and the spellings. A program stops on it at start. A test that builds the tree finds it in CI. There is no separate check function, and `Parse` is a method of the tree that `New` returned, so no line is read against a tree that was not checked.

| Rule | `New` refuses                                                                                                                                                                                                                                                                       |
| ---- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| K1   | a word, name or alias, that appears twice among the children of one group                                                                                                                                                                                                           |
| K3   | a command name or alias that is empty, holds a space or a control byte, or starts with `-`                                                                                                                                                                                          |
| K4   | a flag name that is empty, holds a space or a control byte, starts with `-` or holds `=`; a short that is not one printable ASCII character other than `-` and `=`                                                                                                                  |
| K5   | a flag name declared twice on one command, in one struct or in two                                                                                                                                                                                                                  |
| K6   | two meanings for one spelling where both can be typed (in a group's scope, or in a leaf's flags together with the scope above it): one long name with two shorts, or bool in one place and value in the other; one short for two long names                                         |
| K7   | a child of the root named `__complete` or `__completeNoDesc`, as name or alias: `Serve` would hide it. Below the root these words are allowed                                                                                                                                       |
| K8   | a help text, of a command or a flag, that holds a line break (`\n` or `\r`): it would break the answer to the scripts (S6)                                                                                                                                                          |
| K9   | an input type that is not a struct; an entry of `Flags` that is not a struct value (a pointer, `nil`, any other value)                                                                                                                                                              |
| K10  | a field that is not exported; a field with no `arg` and no `flag` tag, or with both                                                                                                                                                                                                 |
| K11  | a tag that is not in the form `key:"value"`; a key given twice; a key other than `arg`, `flag`, `short`, `help` and `default`                                                                                                                                                       |
| K12  | a field whose type cannot be read ([Which type is read how](#which-type-is-read-how)); `Opt` or `Repeat` inside `Opt` or `Repeat`; a list of `Opt` or `Repeat`                                                                                                                      |
| K13  | a `short` that is not one character; a `short` or a `default` on an argument                                                                                                                                                                                                        |
| K14  | a `default` that the reader of the field refuses; a `default` on an `Opt` field or on a field with a late reader                                                                                                                                                                    |
| K15  | an argument in a struct of flags; an argument name that is empty or holds a space, a control byte or one of `<>[]`; an argument name used twice in one command; an argument of type `Repeat`; a needed argument after an optional one; a help text of an argument with a line break |
| K16  | a `Command` without `Run`; a `Group` without a command; a command that is `nil`; a root without a name; a `nil` root                                                                                                                                                                |
| K17  | a type with two readers: two `Reader`s, two `LateReader`s, or one of each                                                                                                                                                                                                           |
| K18  | one flag name declared by two struct types where a line can end at a group: a group and the groups above it use one struct type for one flag name, so there is one field to fill (G3)                                                                                               |

Rule K2 of the first version, "a group has no arguments", is gone: a group with arguments cannot be written.

A tree with five problems gives this error:

```text
prog items list: main.badIn.Wait: unknown tag "json"
prog items list: main.badIn.Wait: time.Duration cannot be read: give it an UnmarshalText method, or New a Reader
prog items list: main.badIn.Name: has no arg or flag tag
prog items list: Run is missing
prog items: "list" names two commands
```

Each line names the command path. A problem of a field also names the struct and the field.

## Values and types

**The type of a field says how its word is read** (decision D41). The command gets values, not strings: `Run` reads `in.Limit` as an `int` and `in.Since` as a `time.Duration`.

### Which type is read how

| Type of the field                                                                           | One word is read                             | Rule |
| ------------------------------------------------------------------------------------------- | -------------------------------------------- | ---- |
| `string`, `bool`, `int`, `int8` … `int64`, `uint`, `uint8` … `uint64`, `float32`, `float64` | by the library                               | Y1   |
| a type with `UnmarshalText` (`encoding.TextUnmarshaler`)                                    | by the type itself                           | Y2   |
| a type given to `Reader`                                                                    | by that function                             | Y3   |
| a type given to `LateReader`                                                                | by that function, when the command runs      | N1   |
| `[]T`                                                                                       | as a comma list: each item is read as `T`    | Y5   |
| `Opt[T]`                                                                                    | as `T`; the field records that it was given  | Y7   |
| `Repeat[T]`                                                                                 | as `T`, once for each occurrence of the flag | Y8   |

`T` is any type of the first four rows. `Opt[[]T]` and `Repeat[[]T]` are valid. `Opt` and `Repeat` do not nest, and there is no list of `Opt` or `Repeat` (K12).

**When a type has more than one way, this order decides: a `LateReader`, a `Reader`, the type's own `UnmarshalText`, the library.** So a `Reader` or a `LateReader` wins over the method of the type (Y3, N1). One type has one `Reader` or one `LateReader` at most (K17).

**A value reaches its reader byte for byte** (Y11). The library does not trim it and does not check it for UTF-8 (L8).

**A reader that refuses a word gives the cause of a `BadValue` mistake.** The mistake holds the reader's error unchanged ([Usage errors](#usage-errors)).

### Basic types

**The library reads Go's own basic types** (Y1).

- **A `string` is the word as typed.**
- **A `bool` is `true` or `false`** (B3); see [Bool flags](#bool-flags).
- **An integer is read in base 10, within the range of its type.** The library uses `strconv.ParseInt` and `strconv.ParseUint` with base 10 and the bit size of the type. So `0x10`, `1.5` and the empty word are refused, and `256` is refused for a `uint8`.
- **A float is read as `strconv.ParseFloat` reads it**, with the bit size of the type.

**A named type must say how it is read** (Y4). The library reads only Go's own types by itself. A named type, also one whose kind is a basic one, needs `UnmarshalText`, a `Reader` or a `LateReader`; without one, `New` refuses the field (K12). `time.Duration` is an `int64`: read by its kind, `--wait 5` would be five nanoseconds, with no error.

### Types that read themselves

**A type whose pointer has `UnmarshalText` reads itself** (Y2, decisions D43 and D45). This is Go's `encoding.TextUnmarshaler`. `netip.Addr`, `netip.Prefix` and `time.Time` already have the method, and the same method reads the type from a config file. The error that the method returns is the cause of the mistake.

```go
// Format is the value of --output. It reads itself.
type Format string

var formats = []string{"json", "yaml"}

func (f *Format) UnmarshalText(b []byte) error {
	if !slices.Contains(formats, string(b)) {
		return errors.New("want json or yaml")
	}
	*f = Format(b)
	return nil
}

// Complete offers the formats on Tab.
func (Format) Complete(_ *cmdline.Line, prefix string) ([]string, cmdline.Directive) {
	return cmdline.Words(prefix, formats...), cmdline.NoFiles
}
```

**A type that reads itself is never cut at commas, also when it is a slice** (Y5).

### Reader

**`Reader(f)` is an option of `New`: `f` reads every field of its result type** (Y3, decision D43). It is for a type that has no `UnmarshalText` and that the caller does not own, such as `time.Duration`:

```go
cmdline.Reader(time.ParseDuration)
```

The option belongs to one tree. There is no registry for the whole program.

### Lists

**A `[]T` field takes one word, a comma list** (Y5, R4, decision D6). The library cuts the word at every comma and reads each item as `T`.

- **An empty list is refused** (R5, Y6). The cause is `ErrEmpty`. An empty list never means "clear".
- **An empty item is refused** (R6, Y6): `a,,b` and `a,`. The cause is `ErrEmptyItem`.
- **Both are checked before any item is read**, and also for a list of a late type (Y6).
- **A list flag given twice is a repeat** (R2). A list is one value.
- **An argument can be a list too.**

The library has no setting for these rules. A program that wants another list syntax writes a type with `UnmarshalText`.

### Opt: given or not

**An `Opt[T]` field is read as `T` and records that it was given** (Y7, decision D17). `Get()` returns the value and `true`. When the flag is not given, `Get()` returns the zero value and `false`.

- **An empty value of a flag is a value** (R8). `--name=` is given and empty; an `Opt[string]` field shows the difference from no `--name`.
- **As an argument, `Opt[T]` makes the argument optional** (Y7, A2).
- **`Some(v)` makes an `Opt` that was given `v`.** It is for code that fills an input struct by hand, such as a test of `Run`.

### Repeat

**A `Repeat[T]` field is a flag that may be given more than once** (Y8, R3). `Repeat[T]` is a slice of `T`. Each occurrence adds one `T`, in the order typed. `Repeat[[]T]` reads each occurrence as a comma list. `Repeat[bool]` holds one bool for each occurrence, so a program can count `-v -v`.

### Path

**`Path` is a string type of the library for a file path** (Y12, decision D27). It takes any word, and Tab offers file names for it (T22).

### Defaults

**A flag with a `default` tag that is not given is read from the tag, through the reader of its type** (Y9). `New` reads every default once and refuses one that does not read (K14). A flag that takes its default is not in `Line.Flags`. `Info` gives the tag as `Flag.Default`, for a help text.

- **Every other field that is not given keeps its zero value** (Y9).
- **An `Opt` field and a field with a late reader take no default** (K14). An argument takes none (K13).
- **A `Repeat` field with a default holds the default as its one occurrence when the flag is not given.**

### Late readers

**`LateReader(f)` is an option of `New`: `f` reads every field of its result type, when the command runs** (N1, decision D46). It is for a value that needs more than the word, such as a lookup on a server.

```go
// Item is looked up in the store when the command runs.
type Item struct {
	ID   int
	Name string
}

type storeKey struct{}

// findItem is the late reader of Item. Line.Run calls it; the store is in ctx.
func findItem(ctx context.Context, word string) (Item, error) {
	store, _ := ctx.Value(storeKey{}).([]Item)
	for _, it := range store {
		if strconv.Itoa(it.ID) == word {
			return it, nil
		}
	}
	return Item{}, errors.New("no such item")
}
```

- **`Parse` does not call a late reader.** It keeps the word. It checks only the form of a list (Y6). Until `Run`, the field holds its zero value.
- **`Line.Run` calls the late readers**, after the whole line is right; see [Running a line](#running-a-line).
- **A late reader gets the context of `Run`.** `New` must know every late type, and a program makes its client later, after it read the line. So the caller puts the client into the context that it gives to `Run`, and the late reader takes it from there.
- **A field with a late reader stays a plain type.** `Run` reads `in.Item.ID`.

## Reading a command line

**`tree.Parse(argv)` reads argv from left to right, each word once, and then reads each value into its field.** argv does not hold the program name. The work has two steps. The reader does the grammar and the command walk, and stops at the first word that it cannot read. Then the library reads the values of what the reader read, checks repeats and counts the arguments. The result is the first mistake on the line, or none ([Several mistakes on one line](#several-mistakes-on-one-line)).

The tables below show `Parse` on the example tree. A flag is written as `name=value@position`, with the value as typed (`Line.Flags`). A mistake is written as its kind, the path in brackets, the word and `@position`; a bad value also shows its cause.

### One word

These rules apply to every word that is not a flag's value and does not follow an ending `--`.

- **A word is a flag word if and only if it has at least two bytes, its first byte is `-`, and it is not exactly `--`** (L1). So `-5` and `- h` (one word with a space in it) are flag words, and `—-help` (with an em dash) is not.

- **A word that is not a flag word is a command word at a group, and an argument at a leaf** (L2). `-` alone and the empty word follow this rule: each is an argument at a leaf and an unknown command at a group (L3, L4).

- **At a leaf, the first `--` that is not a flag's value ends the flags** (L5). It is dropped. Every later word is an argument exactly as typed, also `--`, `-`, `-h` and command names. A `--` as the last word changes nothing (L6).

- **Where a command word is expected, `--` is an unknown command named `--`** (L7).

- **Words are compared byte for byte** (L8). There is no case folding, no Unicode normalisation and no trimming. Invalid UTF-8 and NUL bytes have no special meaning. Values and arguments reach their readers byte for byte.

- **A flag word is cut at its first `=`** (L9). Before it is the typed name. After it is the attached value, which may be empty and may hold more `=`.

- **A typed name that starts with `--` names the long flag whose name equals the rest exactly** (L10). `---x` names no flag. `--` with nothing after it (from `--=v`) names no flag.

- **A typed name with one leading dash names the short flag whose short equals the rest exactly** (L11). `-ojson`, `-vv`, `-ho`, `-output` and `-e24h` name no flag, and `-=v` names no flag. So the library refuses attached short values and groups of shorts, and its tests hold that. Headscale does not promise either form to its users (D11). A short is one printable ASCII character in every tree that `New` accepts (K4).

- **Long and short names do not cross** (L12). `--o` is not `-o`, and `-help` is not `--help`.

- **A flag word that names no flag that can be typed where it stands is an unknown flag** (L13). There are no abbreviations: `--sor` is not `--sort`.

| argv                      | Result                                   |
| ------------------------- | ---------------------------------------- |
| `check -`                 | `[check]`, argument `-`                  |
| `check ""`                | `[check]`, argument `""`                 |
| `check -- -h`             | `[check]`, argument `-h`                 |
| `check a.yaml --`         | `[check]`, argument `a.yaml`             |
| `check -5`                | unknown flag `[check]` `-5` @1           |
| `-`                       | unknown command `[]` `-` @0              |
| `""`                      | unknown command `[]` `""` @0             |
| `items -- list`           | unknown command `[items]` `--` @1        |
| `Items`                   | unknown command `[]` `Items` @0          |
| `items list ---sort id`   | unknown flag `[items list]` `---sort` @2 |
| `items list --sor id`     | unknown flag `[items list]` `--sor` @2   |
| `items list -ojson`       | unknown flag `[items list]` `-ojson` @2  |
| `items list -output json` | unknown flag `[items list]` `-output` @2 |
| `items list --o json`     | unknown flag `[items list]` `--o` @2     |

### Flag values

- **A value flag takes its value after `=` when the word has one, and else from the next word** (V1). The forms are `--x=v`, `-x=v`, `--x v` and `-x v`. An attached value may be empty.

- **The next word is the value, whatever it is** (V2). It can be empty, `-`, `--`, `-h`, the name of another flag or the name of a command.

- **A value flag that is the last word and has no `=` is a missing value** (V3). The mistake names the typed name, the long name of the flag, the command reached and the position of the flag word.

- **The reader hands every value on as typed** (V4). It never converts a value, splits it at commas, trims it or checks it. Then the library reads the value into its field ([Values and types](#values-and-types)). `Line.Flags` keeps the text as typed.

- **An attached short value is not a value** (V5). `-ojson` is an unknown flag (L11).

| argv                              | Result                                                                  |
| --------------------------------- | ----------------------------------------------------------------------- |
| `items list -o json`              | `[items list]`, `output=json@2`                                         |
| `items list -o=json`              | `[items list]`, `output=json@2`                                         |
| `items list --sort -name`         | `[items list]`, `sort=-name@2`                                          |
| `items list --filter --sort`      | `[items list]`, `filter=--sort@2`                                       |
| `items list --name=a=b --filter=` | `[items list]`, `name=a=b@2`, `filter=@3` (`filter` is given and empty) |
| `-c items items list`             | `[items list]`, `config=items@0`                                        |
| `items list --sort`               | missing value `[items list]` `--sort` @2                                |
| `-o`                              | missing value `[]` `-o` @0                                              |

### Bool flags

- **A flag is a bool flag when the value type of its field has the kind bool** (Y10): a `bool`, an `Opt[bool]` or a `Repeat[bool]` field. A named type of kind bool that reads itself is a bool flag too. A `[]bool` field is a value flag: it takes a comma list.

- **A bool flag never takes the next word** (B1). In `--force maybe`, the word `maybe` is an argument.

- **A bare bool flag reads `true`** (B2). `--x=v` and `-x=v` hand `v` to the reader of the field.

- **The library takes only the bool words `true` and `false`, in lower case** (B3, decision D26). Any other word, also the empty one, is a bad value with the cause `ErrBool`.

- **There is no `--no-x` form** (B4). Such a word is an unknown flag, unless the tree declares a flag with that name.

- **There is no group of short bools** (B6). `-hf` and `-vv` are unknown flags (L11).

- **`--x=false` is a given flag with the value `false`** (B5). What that means for a flag such as `--help` is the caller's choice. Headscale reads `--help=false` as "help not asked".

| argv                            | Result                                                       |
| ------------------------------- | ------------------------------------------------------------ |
| `items delete --force maybe`    | `[items delete]`, `force=true@2`, argument `maybe`           |
| `items delete 12 --force=false` | `[items delete]`, `force=false@3`, argument `12`             |
| `items delete 12 --force=maybe` | bad value `[items delete]` `--force` @3: `not true or false` |
| `items delete 12 --force=TRUE`  | bad value `[items delete]` `--force` @3: `not true or false` |
| `items delete 12 --no-force`    | unknown flag `[items delete]` `--no-force` @3                |
| `items delete 12 -hf`           | unknown flag `[items delete]` `-hf` @3                       |

### A flag given more than once

- **The reader keeps every occurrence of every flag, in the order typed, in any spelling** (R1). `Line.Flags` lists them all.

- **Each flag is given once** (R2, decision D15). The second occurrence is a `Repeated` mistake. It names the long name of the flag and the spelling of the second occurrence, and it stands at the flag word of the second occurrence. The spellings and the places of the two do not matter: `-o` before the subcommand and `--output` after it are one flag given twice.

- **A flag whose field is a `Repeat[T]` may be given more than once** (R3). The type of the field decides it, not the name of the flag. Headscale gives `--filter` such a type.

| argv                                     | Result                                                                                       |
| ---------------------------------------- | -------------------------------------------------------------------------------------------- |
| `items list -o json -o yaml`             | repeated `[items list]` `-o` @4                                                              |
| `-o json items list --output=yaml`       | repeated `[items list]` `--output` @4                                                        |
| `items delete 12 --force --force=false`  | repeated `[items delete]` `--force` @4                                                       |
| `items list --columns id --columns name` | repeated `[items list]` `--columns` @4 (a list is one value)                                 |
| `items list --filter a --filter b,c`     | `[items list]`, `filter=a@2`, `filter=b,c@4`; `Filter` is `["a" "b,c"]` (a `Repeat[string]`) |

### Where a flag may stand

- **At a group, the flags in scope can be typed: those in `Flags` of the root and of every group on the path** (W1). At a leaf, only the leaf's own flags can be typed: those of its input struct and of its `Flags`.

- **A flag typed before the leaf counts only if the leaf takes a flag with the same spelling** (W2). Otherwise it is an unknown flag. The mistake has the leaf's path, the word as typed, and the position where the word stood.

- **A flag typed before the leaf fills the field of the leaf** (G4). That a group lists the flag only lets the word stand there.

- **A flag word that is not in a group's scope is an unknown flag at that group** (W3). So a leaf's own flag cannot stand before the leaf.

- **"Global" is a pattern, not a property of a flag** (W4). The caller lists one struct of flags on the root and on each command that takes it. Headscale does this for `-c`, `-o` and `-h`.

- **At a leaf, flags and arguments mix in any order** (W5). Flags may follow the last argument.

- **A flag in scope may also stand between group words** (W6).

- **A line that ends at a group holds every flag read on the way down** (W7). The structs of the group and of the groups above it are filled (G3).

- **One spelling names one flag (the same long name, short, and bool or value) everywhere it can be typed** (W8). `New` refuses a tree that breaks this (K6).

| argv                         | Result                                                         |
| ---------------------------- | -------------------------------------------------------------- |
| `-c x.yaml items list`       | `[items list]`, `config=x.yaml@0`                              |
| `items -c x.yaml list`       | `[items list]`, `config=x.yaml@1`                              |
| `items list -c x.yaml`       | `[items list]`, `config=x.yaml@2`                              |
| `items delete --force -h 12` | `[items delete]`, `force=true@2`, `help=true@3`, argument `12` |
| `-h items -o json`           | `[items]`, `help=true@0`, `output=json@2`                      |
| `-o json check a.yaml`       | unknown flag `[check]` `-o` @0 (`check` does not take `-o`)    |
| `items --sort id list`       | unknown flag `[items]` `--sort` @1                             |
| `--force items delete 12`    | unknown flag `[]` `--force` @0                                 |

### The command walk

- **At a group, the first word that is not a flag word and not a flag's value is the command word** (C1).

- **The command word must equal a child's `Name` or one of its `Aliases` exactly** (C2). `New` refuses a word that names two children (K1).

- **Any other command word is an unknown command** (C3). The mistake has the group's path, the word and its position. Suggestions such as "Did you mean" are the caller's: next to the mistake, `Line.Command` is the group, and its `Commands` give the names and aliases.

- **Command names are not abbreviated and not case-folded** (C4).

- **There is no built-in `help` command and no other implicit command** (C5).

- **A group takes no arguments** (C6). Every word at a group is a flag word, a flag's value or a command word.

- **A line that ends at a group is a `Line` at that group, with no arguments** (C7). This holds for the root and for an empty argv. The caller decides what it means; `Line.Run` does not run it (G5). Headscale shows the help of the group.

- **At a leaf, every word that is not a flag word and not a flag's value is an argument** (C8). This holds also for a word that equals a command name.

- **`Line.Command.Path` holds names, never aliases** (C10).

- **argv does not hold the program name** (C11). A word equal to the root's `Name` is an ordinary word.

| argv                | Result                              |
| ------------------- | ----------------------------------- |
| (none)              | `[]` (the root)                     |
| `items`             | `[items]` (the group)               |
| `items ls`          | `[items list]`                      |
| `items rm 12`       | `[items delete]`, argument `12`     |
| `items delete list` | `[items delete]`, argument `list`   |
| `items lst`         | unknown command `[items]` `lst` @1  |
| `help`              | unknown command `[]` `help` @0      |
| `items help`        | unknown command `[items]` `help` @1 |
| `prog items`        | unknown command `[]` `prog` @0      |

### Arguments and their count

- **The n-th argument of the line fills the n-th `arg` field of the input struct, in field order** (A1). Where the flags stand does not matter.

- **The library counts the arguments against the `arg` fields** (C9, A2). An `arg` field that is not an `Opt` is needed. Fewer arguments than needed fields, or more arguments than `arg` fields, is an `ArgCount` mistake. Its position is `len(argv)`, the end of the line, and it has no word. The library writes no sentence with numbers: the caller has `len(Line.Args)` and `Info.Args`.

- **`ArgCount` is reported only when the line has no other mistake** (A3, X4). The arguments that are there are still read: a bad one is a `BadValue`, also when there are too many.

- **Next to `ArgCount`, the structs are filled** (A4): the flags, and the arguments that are there. So a caller can still see a flag such as `--help` and show the help, not the count.

| argv                           | Result                                                                                   |
| ------------------------------ | ---------------------------------------------------------------------------------------- |
| `items delete`                 | argument count `[items delete]` @2                                                       |
| `items delete 12 13`           | argument count `[items delete]` @4                                                       |
| `items list x`                 | argument count `[items list]` @3                                                         |
| `check`                        | `[check]` (`file` is optional)                                                           |
| `check a b`                    | argument count `[check]` @3                                                              |
| `items delete --bogus`         | unknown flag `[items delete]` `--bogus` @2 (the count is not reported)                   |
| `items delete 12 13 --force=x` | bad value `[items delete]` `--force` @4: `not true or false` (the count is not reported) |

### What Parse returns

**`Parse` returns a `*Line` and an error.** The `*Line` is never `nil`. The error is `nil` or a `*UsageError`.

- **A `Line` holds the command reached, the flags given, the arguments as typed, and the filled structs** (M1). `Line.Command` is the `*Info` of the command reached: a leaf, or a group when the line ends there. A flag is given when it has an entry in `Line.Flags`. A flag given with an empty value has an entry with `""`.

- **`Line.Flags` lists every flag given, in the order typed** (M2). Each entry has the flag's long `Name` (whatever spelling was typed), its `Value` as typed (`true` for a bare bool flag), and the position `At` of its flag word. Flags typed before the leaf come first, as they stood. A flag that takes its default has no entry (Y9).

- **`Line.Args` holds the arguments as typed, in order, without the ending `--`; `Line.ArgAt` holds their positions** (M3).

- **The text in `Line.Flags` and `Line.Args` has two uses.** A caller places a mistake of its own on the line with it, and a Completer reads the line with it. The values that a command works with are in the structs.

- **Next to a mistake, the `Line` holds what the reader read** (M5): the command reached, and the flags and arguments before the word that the reader refused. When the reader refused no word, that is the whole line, also the words after a repeat or a bad value. There is one exception to "before the refused word": a flag typed before the leaf that the leaf does not take is found only when the leaf's word is read. The `Line` then has the leaf as its command, and only the flags before the refused one.

- **`Parse`, `Complete` and `Serve` change neither argv nor the tree, keep no state, and may run at the same time on one tree** (M7). Every `Line` has structs of its own.

| argv                                     | `Line` next to the mistake                          | Mistake                                                                                | Structs readable |
| ---------------------------------------- | --------------------------------------------------- | -------------------------------------------------------------------------------------- | ---------------- |
| `-o json items -c x lst`                 | `[items]`, `output=json@0`, `config=x@3`            | unknown command `[items]` `lst` @5                                                     | no               |
| `items list -o json --columns id --sort` | `[items list]`, `output=json@2`, `columns=id@4`     | missing value `[items list]` `--sort` @6                                               | no               |
| `-c a -o json -c b check`                | `[check]`, `config=a@0`                             | unknown flag `[check]` `-o` @2                                                         | no               |
| `items delete -o=json 12 --bogus 13`     | `[items delete]`, `output=json@2`, argument `12` @3 | unknown flag `[items delete]` `--bogus` @4                                             | no               |
| `items list --limit x --sort id`         | `[items list]`, `limit=x@2`, `sort=id@4`            | bad value `[items list]` `--limit` @2: `strconv.ParseInt: parsing "x": invalid syntax` | no               |
| `items delete -h`                        | `[items delete]`, `help=true@2`                     | argument count `[items delete]` @3                                                     | yes              |

### The structs of a line

- **`Parse` makes new structs for every line** (G1): the input struct of the command reached, and one struct of every type in its `Flags`. `Get[T](line)` returns the struct of type `T`.

- **Each field holds the value that was read, the default, or the zero value** (Y9). A field with a late reader holds its zero value until `Run` (N1).

- **`Get` reports `false` in three cases** (G2): for a type that the command reached does not have; next to a mistake other than `ArgCount`; and on the `Line` that a Completer gets. Then it returns the zero value of `T`.

- **Next to a mistake no struct is readable**, so a caller cannot act on a flag such as `--help` when the line is wrong (decision D19). `ArgCount` is the exception (A4).

- **When the line ends at a group, the structs are those in `Flags` of the group and of every group above it** (G3): the flags that can be typed there (W1).

- **`Line.Run` returns `ErrGroup` for a line that ends at a group** (G5).

The values of the example tree:

| argv                            | Result                                                                                    | The field                                                    |
| ------------------------------- | ----------------------------------------------------------------------------------------- | ------------------------------------------------------------ |
| `items list --limit 10`         | `[items list]`, `limit=10@2`                                                              | `Limit` is `10`                                              |
| `items list`                    | `[items list]`                                                                            | `Limit` is `50`, the default                                 |
| `items list --limit 0x10`       | bad value `[items list]` `--limit` @2: `strconv.ParseInt: parsing "0x10": invalid syntax` |                                                              |
| `items list --limit 1.5`        | bad value `[items list]` `--limit` @2: `strconv.ParseInt: parsing "1.5": invalid syntax`  |                                                              |
| `items list --limit=`           | bad value `[items list]` `--limit` @2: `strconv.ParseInt: parsing "": invalid syntax`     |                                                              |
| `items list -o yaml`            | `[items list]`, `output=yaml@2`                                                           | `Output` is `"yaml"`                                         |
| `items list -o xml`             | bad value `[items list]` `-o` @2: `want json or yaml`                                     |                                                              |
| `items list --sort -name`       | `[items list]`, `sort=-name@2`                                                            | `Sort` is `"-name"`                                          |
| `items list --since 90m`        | `[items list]`, `since=90m@2`                                                             | `Since.Get()` is `1h30m0s`, `true`                           |
| `items list --since 5`          | bad value `[items list]` `--since` @2: `time: missing unit in duration "5"`               |                                                              |
| `items list --columns id,-name` | `[items list]`, `columns=id,-name@2`                                                      | `Columns` is `["id" "-name"]`                                |
| `items list --columns=`         | bad value `[items list]` `--columns` @2: `the list is empty`                              |                                                              |
| `items list --columns id,,name` | bad value `[items list]` `--columns` @2: `the list has an empty item`                     |                                                              |
| `items list --columns id,`      | bad value `[items list]` `--columns` @2: `the list has an empty item`                     |                                                              |
| `items list --columns id,size`  | bad value `[items list]` `--columns` @2: `want id or name`                                |                                                              |
| `items list --name=`            | `[items list]`, `name=@2`                                                                 | `Name.Get()` is `""`, `true`                                 |
| `items list`                    | `[items list]`                                                                            | `Name.Get()` is `""`, `false`                                |
| `check a.yaml`                  | `[check]`, argument `a.yaml`                                                              | `File.Get()` is `"a.yaml"`, `true`                           |
| `check`                         | `[check]`                                                                                 | `File.Get()` is `""`, `false`                                |
| `-c x.yaml items delete 12`     | `[items delete]`, `config=x.yaml@0`, argument `12`                                        | `Config` is `"x.yaml"`; `Item` is `{ID:0 Name:}` until `Run` |

### Usage errors

**Every mistake is a `*UsageError`** (M4). It is data: the caller writes the sentence.

| Field   | Meaning                                                                                                            |
| ------- | ------------------------------------------------------------------------------------------------------------------ |
| `Kind`  | what is wrong; one of seven kinds                                                                                  |
| `Path`  | the command reached when reading stopped, as `Info.Path`                                                           |
| `At`    | the position of the word that the mistake stands at; `len(argv)` for `ArgCount`                                    |
| `Word`  | that word: a command word, an argument, or a flag as typed, up to any `=`                                          |
| `Flag`  | the long name, when the mistake is about a flag that the command takes                                             |
| `Arg`   | the name, when the mistake is about an argument                                                                    |
| `Value` | `BadValue` and `Unresolved`: the text that was typed for the flag or the argument. For a list it is the whole list |
| `Err`   | `BadValue` and `Unresolved`: the error that the reader returned                                                    |

**The seven kinds and their fields** (U1):

| Kind             | Value | When                                                                                                                                      | `Word`                                                    | `At`                                                                     | Also set                        |
| ---------------- | ----- | ----------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------- | ------------------------------------------------------------------------ | ------------------------------- |
| `UnknownCommand` | 1     | a command word that names no child, also `--`, `-` and `""` (C3, L3, L4, L7)                                                              | the word                                                  | the command word                                                         | —                               |
| `UnknownFlag`    | 2     | a flag word that names no flag that can be typed where it stands (L13, W3); a flag typed before the leaf that the leaf does not take (W2) | the typed name                                            | the flag word, where it stood                                            | —                               |
| `MissingValue`   | 3     | a value flag that is the last word and has no `=` (V3)                                                                                    | the typed name                                            | the flag word (always the last word)                                     | `Flag`                          |
| `Repeated`       | 4     | a flag given a second time whose field is not a `Repeat` (R2)                                                                             | the typed name of the second occurrence                   | the flag word of the second occurrence                                   | `Flag`                          |
| `BadValue`       | 5     | the reader of the field's type refused the value                                                                                          | for a flag: the typed name; for an argument: the argument | for a flag: the flag word, not the value word; for an argument: its word | `Flag` or `Arg`; `Value`; `Err` |
| `ArgCount`       | 6     | too few or too many arguments (A2)                                                                                                        | empty                                                     | `len(argv)`                                                              | —                               |
| `Unresolved`     | 7     | a late reader refused the value (N3). `Line.Run` returns it, not `Parse`                                                                  | as `BadValue`                                             | as `BadValue`                                                            | as `BadValue`                   |

**`Path` is the command that the reader reached, also when the mistake stands earlier on the line.** In `-h=x items lst` the bad value of `-h` stands at position 0, and its `Path` is `[items]`.

**`Error()` gives a default English text** (M6). The caller is expected to write its own text from the fields. The default is:

```text
unknown command "lst"
unknown command "lst" for "items"
unknown flag --bogus for "items list"
flag --sort needs a value
flag --output is given more than once
flag --limit: "ten": strconv.ParseInt: parsing "ten": invalid syntax
wrong number of arguments for "completion"
wrong number of arguments for "items delete"
argument item: "99": no such item
```

The ` for "path"` part is left out when the path is empty. A missing value, a repeat and a bad value never name the path. `BadValue` and `Unresolved` have the same form: the flag or the argument, the value, the cause.

**`Unwrap` returns `Err`.** So `errors.Is(err, cmdline.ErrBool)` finds a bad bool word, and `errors.As` finds the error type of a reader. The library's own causes are `ErrBool`, `ErrEmpty` and `ErrEmptyItem`; a number that does not read has the error of `strconv`.

**The library has seven kinds; a caller can add its own** (M8). Headscale maps the seven to its own kinds, `Unresolved` to its bad value, and adds two mistakes: a flag that the group reached does not take, and `--version` not alone.

### Several mistakes on one line

**`Parse` reports the leftmost mistake on the line, whatever its kind** (X1, decision D35). The one exception is the argument count (X4).

**Each kind of mistake has one position** (X2):

| Mistake                  | Position                                                                                                                                                              |
| ------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| unknown command          | its word                                                                                                                                                              |
| unknown flag             | its flag word, where it stood. This holds also for a flag typed before the subcommand that the leaf does not take, though the reader finds it only at the leaf's word |
| missing value            | the flag word, which is always the last word                                                                                                                          |
| repeated                 | the flag word of the second occurrence                                                                                                                                |
| bad value of a flag      | the flag word, not the value word                                                                                                                                     |
| bad value of an argument | the argument's word                                                                                                                                                   |
| argument count           | `len(argv)`, the end of the line                                                                                                                                      |

**A flag that is given a second time can have a second mistake in the same word** (X3). With a bad value, the repeat is reported: `--force --force=x` is a repeat. Without its value at the end of the line, the missing value is reported: in `--sort id --sort` the reader stops at the last word, and the library never sees it as a second occurrence.

**A wrong argument count belongs to the whole line** (X4). `Parse` reports it only when the line has no other mistake. It never hides `--help`: next to it the structs are filled (A4).

**How it works** (X5). The reader stops at the first word that it cannot read, and hands over what it read before that word (M5). The library reads the values of that part and checks the repeats in it. It reports its own first mistake when that stands before the reader's, and else the reader's. A mistake to the right of the reader's is never looked at; by X1 it could not win.

**`-h`, `--help` and `--version` have no meaning in the library** (X8). They are ordinary bool flags of the tree. So `-h` never hides a mistake that `Parse` finds.

**No late reader runs on a line with a mistake** (N4). So a failed lookup is never reported before a mistake on the line, a wrong count included.

| argv                                       | Reported                                                                               | Also on the line                   |
| ------------------------------------------ | -------------------------------------------------------------------------------------- | ---------------------------------- |
| `items list --limit x --bogus`             | bad value `[items list]` `--limit` @2: `strconv.ParseInt: parsing "x": invalid syntax` | an unknown flag at 4               |
| `items list --bogus --limit x`             | unknown flag `[items list]` `--bogus` @2                                               | a bad value at 3; it is never read |
| `items list --sort id --sort name --since` | repeated `[items list]` `--sort` @4                                                    | a missing value at 6               |
| `-h=x items lst`                           | bad value `[items]` `-h` @0: `not true or false`                                       | an unknown command at 2            |
| `items list -o xml -o yaml`                | bad value `[items list]` `-o` @2: `want json or yaml`                                  | a repeat at 4                      |
| `items delete 12 --force --force=x`        | repeated `[items delete]` `--force` @4                                                 | a bad value in the same word       |
| `items delete 12 13 --bogus`               | unknown flag `[items delete]` `--bogus` @4                                             | a wrong count                      |
| `items delete --bogus -h`                  | unknown flag `[items delete]` `--bogus` @2                                             | `-h`, and a wrong count            |

**A caller can place mistakes of its own on the line.** The library gives it the flags in the order typed, each with the position of its flag word (`Given.At`); the arguments with their positions (`Line.ArgAt`); the position of the library's mistake (`UsageError.At`); and the `Line` next to a mistake (M5). The caller reports its own mistake when its position is smaller than the library's, and else the library's.

The mistakes that Headscale adds, their positions, and what Headscale does with `--help` (rule X6) and `--version` (rule X7) are Headscale's policy. They are in [001, Errors on the command line](001-cli.md#errors-on-the-command-line) (decision D35).

### Running a line

**`line.Run(ctx)` runs the command of a line that has no mistake.** A caller does its own work between `Parse` and `Run`: it shows help, places its own mistakes, makes a client and puts it into `ctx`. `Get[In](line)` before `Run` gives the input struct without the values that are looked up late.

- **On a `Line` with a mistake, `Run` calls no reader and returns that mistake** (N4). This holds for `ArgCount` too.

- **On a `Line` that ends at a group, `Run` returns `ErrGroup`** (G5).

- **A line runs once** (G6). A second `Run` on one `Line` returns `ErrRan` and calls no reader and no command, also when the first `Run` stopped at a late reader. A line with a mistake and a line at a group give their answer every time.

- **Only a `Line` from `Parse` runs** (G7). On the `Line` that a `Complete` method gets, at a command or at a group, and on a `Line` made by hand, `Run` returns `ErrNotParsed` and calls nothing.

- **`Run` first calls the late readers, with its context, in the order that their words stand on the line** (N2). The items of a list are read from left to right. Then `Run` fills the fields and calls `Run` of the command with the input struct. It returns the error of the command unchanged.

- **The first late reader that fails stops the run** (N3). `Run` returns a `*UsageError` of kind `Unresolved`, with `Flag` or `Arg`, `Word`, `Value`, `At`, and the reader's error as `Err`. The command does not run, and no later word is looked up.

```console
$ prog items rm 12 --force
delete 12 (apple) force=true
$ prog items rm 99
Error: <item>: "99": no such item.
$ prog items rm 99 --bogus
Error: `prog items delete` has no flag --bogus.
```

The last line has two mistakes. The unknown flag is on the line, so no lookup is made.

## Tab completion

**`tree.Complete(words, cur)` answers one Tab press.** `words` are the words after the program name and before the cursor. `cur` is the cursor word, `""` for a new word. It returns the candidates and a directive. `Serve` calls it for the scripts ([The hidden entry point](#the-hidden-entry-point)).

### How Tab reads the line

**Tab reads `words` with the reader of `Parse`, in a mode that refuses nothing** (T1). An unknown flag word is skipped and takes no value. An unknown command word, or a `--` at a group, is skipped, and the reader stays at that group. A flag typed before the leaf that the leaf does not take is dropped. So Tab keeps completing from the last command it understood.

**A refused word never makes Tab offer files** (T2). Files come only from a type that asks for them.

**Tab runs no command and no reader, reads no config and calls nothing but the `Complete` methods of the tree's types** (T16). It reads no value into a field, so a wrong value earlier on the line changes nothing. **For one line, Tab gives the same answer every time** (T17).

### What Tab offers

The first row that fits decides the answer. "The type" is the type `T` of the field; see [The Completer](#the-completer).

| #   | When                                                                                                  | Tab offers                                                                                                                                                                                                                                                                                                 |
| --- | ----------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| T3  | the reader ends on a value flag that waits for its value (no `=`, not itself a value, not after `--`) | what the type of that flag offers, with the whole cursor word as prefix, whatever it looks like. A type that offers nothing gives no candidate, with `NoFiles`                                                                                                                                             |
| T4  | the line is after an ending `--` at a leaf                                                            | the cursor word is an argument: no flag names and no `--x=` values (row T9 applies)                                                                                                                                                                                                                        |
| T5  | the cursor word starts with `-` and holds `=`                                                         | what the type of the flag named before the first `=` offers, among the flags that can be typed there, with the text after `=` as prefix. Candidates come without `--x=`; the scripts put it back. An unknown flag or a bool flag offers nothing, with `NoFiles`. Quotes in the cursor word are not removed |
| T6  | the cursor word starts with `-`                                                                       | the flags of the command reached: at a group, the group's own flags (not its scope); at a leaf, the leaf's. A flag gives `--name` if that starts with the cursor word, and `-x` only when the cursor word is exactly `-x`. So a lone `-` or `--` lists long names only                                     |
| T7  | (applies to T3, T5 and T6)                                                                            | a flag already given, in any spelling and before or after the subcommand, is not offered again, unless its field is a `Repeat`; no value is offered for it when it is typed again                                                                                                                          |
| T8  | the reader is at a group                                                                              | every child `Name` that starts with the cursor word; if none does, every alias that does                                                                                                                                                                                                                   |
| T9  | the reader is at a leaf                                                                               | what the type of argument n offers, where n is the count of arguments before the cursor. A type that offers nothing, or no argument left, gives no candidate, with `NoFiles`                                                                                                                               |

On the example tree (`Complete` called directly; the candidate's help text is left out here):

| `words`                  | `cur`            | Candidates                                                                                          | Directive |
| ------------------------ | ---------------- | --------------------------------------------------------------------------------------------------- | --------- |
| (none)                   | `""`             | `items`, `check`, `completion`                                                                      | 4         |
| `items`                  | `""`             | `list`, `delete`                                                                                    | 4         |
| `items`                  | `l`              | `list`                                                                                              | 4         |
| `items`                  | `r`              | `rm` (no name fits, so the alias)                                                                   | 4         |
| `items list`             | `-`              | `--sort`, `--columns`, `--filter`, `--limit`, `--name`, `--since`, `--help`, `--output`, `--config` | 4         |
| `items list`             | `-o`             | `-o`                                                                                                | 4         |
| `items list`             | `-s`             | none: `--sort` has no short                                                                         | 4         |
| `items list -o`          | `""`             | `json`, `yaml`                                                                                      | 4         |
| `items list`             | `--output=j`     | `json`                                                                                              | 4         |
| `items list`             | `-o=y`           | `yaml`                                                                                              | 4         |
| `items list --sort`      | `-`              | none: the `-` is the value of `--sort`                                                              | 4         |
| `items list --sort id`   | `--`             | `--columns`, `--filter`, `--limit`, `--name`, `--since`, `--help`, `--output`, `--config`           | 4         |
| `items list --filter id` | `--f`            | `--filter` (a `Repeat`)                                                                             | 4         |
| `items list -o json -o`  | `""`             | none: `-o` is given already                                                                         | 4         |
| `-o json items list`     | `--`             | `--sort`, `--columns`, `--filter`, `--limit`, `--name`, `--since`, `--help`, `--config`             | 4         |
| `items list`             | `--config=`      | none: files                                                                                         | 0         |
| `items delete`           | `--force=`       | none: a bool                                                                                        | 4         |
| `items`                  | `--`             | `--help` (the group's own flags)                                                                    | 4         |
| `items delete`           | `""`             | `12`, `13`                                                                                          | 4         |
| `items delete 12`        | `""`             | none: `delete` has one argument                                                                     | 4         |
| `items delete --`        | `--`             | none: an argument, completed by the type of argument 0                                              | 4         |
| `items delete o`         | `""`             | none: `o` is an argument, not `-o`                                                                  | 4         |
| `check`                  | `""`             | none: files                                                                                         | 0         |
| `items list --columns`   | `""`             | `id`, `name`                                                                                        | 4         |
| `items list --columns`   | `id,`            | `id,id`, `id,name` (a list)                                                                         | 6         |
| `items list`             | `--columns=id,n` | `id,name` (a list)                                                                                  | 6         |
| `items list --limit`     | `""`             | none: an `int` offers nothing                                                                       | 4         |
| `itemz`                  | `""`             | `items`, `check`, `completion`                                                                      | 4         |
| `items lst`              | `""`             | `list`, `delete`                                                                                    | 4         |
| `items list --bogus`     | `--so`           | `--sort`                                                                                            | 4         |
| `items list -h`          | `--`             | `--sort`, `--columns`, `--filter`, `--limit`, `--name`, `--since`, `--output`, `--config`           | 4         |

### Matching, order and help texts

- **A candidate matches when the cursor word is a byte prefix of it** (T10). Case matters. Tab never corrects a word.

- **Candidates come in declaration order** (T11): children, then aliases; the flags of the input struct, then those of each struct in `Flags`, in field order, a short right after its long. The library never sorts, never removes duplicates and never sets `KeepOrder`. The shells sort.

- **A candidate from the tree carries a tab and the help text, when the help text is not empty** (T12). A command and each of its aliases carry the command's `Help`. A flag, long or short, carries its `help` tag.

```console
$ prog __complete items ''
list	List items
delete	Delete an item
:4
```

### Directives and files

**The library's own answers carry `NoFiles` and never `NoSpace`** (T13). The candidates and the directive of a type's `Complete` pass through unchanged, except in a list ([Lists on Tab](#lists-on-tab)).

| Directive    | Value | The shell                                                                         |
| ------------ | ----- | --------------------------------------------------------------------------------- |
| `Failed`     | 1     | shows nothing                                                                     |
| `NoSpace`    | 2     | adds no space after a single candidate: room for `,x` or `=x`                     |
| `NoFiles`    | 4     | offers no file names when there is no candidate                                   |
| `FilterExt`  | 8     | reads the candidates as file extensions to filter by                              |
| `FilterDirs` | 16    | offers directories, in the directory named by the first candidate if one is given |
| `KeepOrder`  | 32    | keeps the order of the candidates                                                 |

Directive 0 lets the shell do its default: file names when there is no candidate.

- **`Words(prefix, w…)` returns each word of a fixed list that starts with the prefix.** It is a helper for a `Complete` method. The method chooses the directive.
- **`Path` offers no candidate, with directive 0, so the shell offers file names** (T22). A caller gives a file flag and a file argument the type `Path`.

### The Completer

```go
type Completer interface {
	Complete(line *Line, prefix string) ([]string, Directive)
}
```

**A flag value or an argument is completed by the type of its field** (T19). The field types `T`, `[]T`, `Opt[T]` and `Repeat[T]` all ask `T`. The method can be on the type or on its pointer. The library calls it on a zero value, so the method must not use its receiver.

**`Complete` gets the line so far as a `*Line`, and the prefix** (T14). The `Line` holds the command reached, the flags given in order with their text, and the arguments before the cursor, as T1 read them. No struct of that `Line` is filled: `Get` reports `false` (G2). The prefix is the cursor word, or the text after `=` in the `--x=` form (T5), or in a list the item after the last comma. A candidate may carry a help text after a tab (`"json\tJSON"`).

The method filters by the prefix itself. The library does not filter what it returns. The `Line` is for reading: a `Complete` method does not call `Run` on it.

**A type without `Complete` offers nothing, with `NoFiles`** (T21): free text, a number, a bool. **Tab calls no late reader** (decision D1). A type with a late reader offers candidates only when it has a `Complete` method of its own.

**The method is on the type, so it is the same for every command that uses the type.** It can read `line.Command` and the flags on the line to offer other words in another place.

A `Complete` method that reads the line can offer values that depend on a flag. In the example, the IDs that `items delete` offers come from the file named by `-c`:

```console
$ prog __complete items rm ''
12
13
:4
$ prog __complete -c other.yaml items rm ''
21
22
:4
```

### Lists on Tab

**In a list, only the item after the last comma is completed** (T20). The library hands that item to the type as the prefix. It puts the items before it back in front of every candidate, and it adds `NoSpace`, so the user can type `,` next. Before the first comma the library adds nothing: the candidates and the directive are the type's.

```console
$ prog __complete items list --columns id,
id,id
id,name
:6
```

### What Tab never does

- **Tab treats `-h`, `--help` and `--version` as ordinary flags, and keeps completing after them** (T15).

- **A candidate is never refused because of itself, when the line before it was not already refused for that word** (T18). Tab offers no unknown command, no unknown flag, no flag already given (unless its field is a `Repeat`) and no bool word. One known exception: a caller rule that the library cannot see. Headscale's `--version` must stand alone, and Tab still offers it after another root flag.

## The completion protocol

The library answers the protocol of cobra's shell scripts, so it can use those scripts unchanged (decision D23). This part states the protocol as the scripts of cobra v1.10.2 speak it, the version Headscale pins. It was read from cobra's source at that version: `completions.go`, `bash_completionsV2.go`, `zsh_completions.go`, `fish_completions.go` and `powershell_completions.go`.

### The hidden entry point

**At each Tab, the script runs the program with the hidden first word `__complete` and the words of the line:**

```text
prog __complete <word>… <cursor word>
```

`__completeNoDesc` is the same request without help texts.

- **`tree.Serve(w, args)` answers only when `args[0]` is exactly `__complete` or `__completeNoDesc`** (S1). Otherwise it writes nothing and returns `false`. `args` is argv without the program name. The caller calls `Serve` first in `main`, before it reads any config.

- **The other words are `words`, and the last one is the cursor word** (S2). With no other word, the cursor word is `""` (an empty line).

- **The answer is one candidate per line, then `:` and the directive in decimal, each line ending in `\n`** (S3). It goes to the writer `w`. Nothing goes to stderr.

- **`__completeNoDesc` cuts each candidate at its first tab** (S4).

- **Write errors are dropped, and `Serve` still returns `true`** (S5). The script is the reader and cannot show them.

- **A candidate must not contain `\n`** (S6). `Serve` does not check it and writes the candidate as is. `New` refuses a help text with a line break (K8); the candidates of a `Complete` method are the caller's care.

```console
$ prog __complete items list --s
--sort	Sort by
--since	Keep items changed in this time
:4
$ prog __completeNoDesc items ''
list
delete
:4
$ prog __complete items list --config=
:0
```

A command named `__complete` cannot be reached when `Serve` runs first, so `New` refuses it (K7).

### What a script sends

|                          | bash (V2)                                                                                                        | zsh                                                                                     | fish                                                                                                   | PowerShell                                                                         |
| ------------------------ | ---------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------ | ---------------------------------------------------------------------------------- |
| the program              | the first word as typed (so an alias of the program works)                                                       | the first word                                                                          | the first token                                                                                        | the first word of the line                                                         |
| the words                | the words up to the cursor, read by bash-completion with `=` and `:` not splitting a word; passed through `eval` | the words up to the cursor; passed through `eval`                                       | the tokens before the cursor (`commandline -opc`) and the cursor token, escaped; passed through `eval` | the line up to the cursor, split at its first space; passed to `Invoke-Expression` |
| an empty cursor word     | adds `''`                                                                                                        | adds `""`                                                                               | sends the empty token                                                                                  | adds `""` (an escaped form before PowerShell 7.2/7.3)                              |
| `--x=v` under the cursor | sends the whole word; matches candidates against the text after the first `=`                                    | sends the whole word; puts back the text that matches `-.*=` in front of each candidate | sends the whole word; puts back the text that matches `-.*=` in front of each candidate                | only for `--x=v` (two dashes): splits at the first `=` and puts back `--x=`        |
| environment              | —                                                                                                                | —                                                                                       | sets `PROG_ACTIVE_HELP=0` (the program name in upper case, other characters as `_`)                    | sets the same variable                                                             |
| stderr                   | discarded                                                                                                        | discarded                                                                               | discarded                                                                                              | redirected with `2>&1`                                                             |
| debug log                | `BASH_COMP_DEBUG_FILE`                                                                                           | `BASH_COMP_DEBUG_FILE`                                                                  | `BASH_COMP_DEBUG_FILE`                                                                                 | `BASH_COMP_DEBUG_FILE`                                                             |

Because the words pass through `eval`, the program gets them after the shell removed quotes and expanded variables.

### What a script does with the answer

This table is read from the scripts' source; the faults in the next part were measured. The script reads the last line, after `:`, as the directive. With no such line the directive is 0.

| Directive                      | bash (V2)                               | zsh                                      | fish                                                                                 | PowerShell                                        |
| ------------------------------ | --------------------------------------- | ---------------------------------------- | ------------------------------------------------------------------------------------ | ------------------------------------------------- |
| `Failed`                       | no completion                           | no completion                            | file names                                                                           | no completion                                     |
| `NoSpace`                      | `compopt -o nospace` (bash 4 and later) | `-S ''`                                  | adds a second, longer candidate, unless the single candidate ends in one of `@=/:.,` | no space                                          |
| `NoFiles`                      | turns off the default file names        | no file names when there is no candidate | no file names when there is no candidate                                             | prints an empty string when there is no candidate |
| `FilterExt`                    | `_filedir` with the extensions          | `_files -g`                              | not supported: all file names                                                        | not supported: nothing                            |
| `FilterDirs`                   | `_filedir -d`                           | `_files -/`                              | not supported: all file names                                                        | not supported: nothing                            |
| `KeepOrder`                    | `nosort` (bash 4.4 and later)           | `-V`                                     | `-k`                                                                                 | no sort                                           |
| none of the bits, no candidate | file names                              | file names                               | file names                                                                           | file names                                        |

Help texts: bash shows `word  (help)` when it lists several candidates, cut to the terminal width, and inserts a single candidate without it. zsh gives the help to `_describe`. fish shows it in its own column. PowerShell shows `word  (help)` in its list and the help as a tool tip.

A line that starts with `_activeHelp_ ` is an ActiveHelp line for the bash and zsh scripts: they print it as a message, not as a candidate. The library never writes one.

### Where cobra's own answerer differs

A reader who knows cobra should know where this library's answer is not cobra's:

| cobra v1.10.2                                                                                                     | this library                                           |
| ----------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------ |
| trims each candidate and cuts it at its first newline                                                             | writes the candidate as given (S6)                     |
| writes `Completion ended with directive: …` to stderr                                                             | writes nothing to stderr (S3)                          |
| reads `PROG_COMPLETION_DESCRIPTIONS`, `COBRA_COMPLETION_DESCRIPTIONS`, `PROG_ACTIVE_HELP` and `COBRA_ACTIVE_HELP` | reads no environment variable                          |
| refuses `__complete` with no other word                                                                           | reads it as an empty line (S2)                         |
| answers directive 0 (files) when it cannot find the command                                                       | completes from the last command it understood (T1, T2) |
| lists `-x` short names on a lone `-`                                                                              | long names only (T6)                                   |
| stops completing after `-h`, `--help` or `--version`                                                              | keeps completing (T15)                                 |

### The scripts

- **`script.Write(w, shell, program)` writes cobra's script, with help texts, for `bash` (cobra's V2 script), `zsh`, `fish` and `powershell`** (S8). Any other shell is an error: `no completion script for shell "tcsh"`. `program` is the root's `Name`; the script uses it for its function names and to call the program.

- **The script calls `program __complete <words…> <cursor word>` and reads the answer of S3** (S9). A fault in a script is cobra's. It is fixed in cobra, not in a copy (decision D23).

- **The bits of `Directive` equal the bits of cobra's `ShellCompDirective`** (S7). A test compares them.

**The scripts are not in the library's source.** `script` is about 20 lines that call cobra's generators: `GenBashCompletionV2`, `GenZshCompletion`, `GenFishCompletion` and `GenPowerShellCompletionWithDesc`. The scripts come from the cobra version in `go.mod`. cobra is under the Apache-2.0 licence; no cobra source is copied.

```console
$ prog completion bash | head -1
# bash completion V2 for prog                                 -*- shell-script -*-
```

### Known faults in the scripts

**These faults are in cobra's scripts, not in the library** (S10). They were measured in real shells: bash 5.3 with bash-completion 2.17, zsh 5.9.1, fish 4.9.3 and PowerShell 7.6.5 (through `TabExpansion2`), with cobra v1.10.2. None is reported upstream yet.

| Shell      | Line (Headscale examples), then Tab                                                                         | What happens                                                                                           | Cause                                                                                                                        |
| ---------- | ----------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------- |
| bash       | `headscale nodes list --columns id,na`                                                                      | the line shows `id\,name`; it runs as `id,name`                                                        | the script escapes candidates with `printf %q`                                                                               |
| bash       | `headscale auth keys create alice --tags tag:ci,tag:p`                                                      | the line becomes `tag:ci,tag:tag:ci\,tag:prod`, a wrong value                                          | probably the same escaping together with `:` in `COMP_WORDBREAKS`; it came with cobra v1.9.0 (commit 09d5664, not bisected)  |
| fish       | `headscale nodes list --columns=id,na` and `--filter=ow`                                                    | `string split: --columns=id,name: unknown option` and a stack trace in the terminal; nothing completes | one `NoSpace` candidate in the `--x=` form starts with `-`; `string split --max 1 \t …` in `fish_completions.go` has no `--` |
| zsh        | `eqp list --filter=name=w` (candidate `name=web`)                                                           | nothing                                                                                                | the script puts back `--filter=name=` (up to the last `=`) in front of `name=web`                                            |
| fish       | the same                                                                                                    | offers `--filter=name=name=web`                                                                        | the same                                                                                                                     |
| PowerShell | an empty answer with `NoFiles` (Tab after `headscale nodes list`), and `headscale nodes list --columns id,` | `TabExpansion2` throws                                                                                 | the script prints an empty string; `,` is PowerShell's array operator                                                        |
| PowerShell | `headscale nodes list --config=`                                                                            | no file names                                                                                          | not analysed                                                                                                                 |

bash and PowerShell complete a value that holds `=` correctly in the `--x=` form. All four shells complete `--tags tag:ci,tag:p` correctly except bash.

Reproduction: the first three rows with a 50-line stock cobra program, no library ([`research/spikes/v2/stock-cobra/main.go`](research/spikes/v2/stock-cobra/main.go)), against cobra v1.10.2 and cobra main at `adbc881`; the `=` rows with a 20-line program on the library ([`research/spikes/probe-eq/`](research/spikes/probe-eq/)); the PowerShell rows with the shell job's lines.

None of these faults is reported to cobra. The maintainer decided not to report them now (decision D40). They stay listed here with their reproductions.

### Cobra versions

**The scripts are tested with cobra v1.10.2**, the version Headscale pins. The fault reproduction ran also on cobra main at `adbc881` (v1.10.2 and seven commits).

**A cobra bump changes the scripts and nothing else in the library.** Three tests show the effect of a bump: `TestDirectiveBits` fails when a directive bit moves; `TestWrite` fails when a script no longer calls `__complete`; the real-shell job ([Real shells](#real-shells)), which runs on the bump's pull request, shows a change in what a user gets. A fault in the table above goes away only with a cobra release that fixes it.

## Using the library

The examples are the code of the example program `prog` ([`research/spikes/final-typed/prog/`](research/spikes/final-typed/prog/)), which compiles against the prototype. The import path is the prototype's (`spike/cmdline`). The types `Format` and `Item`, the structs of flags and the input structs are shown in [The command tree](#the-command-tree) and in [Values and types](#values-and-types).

### Declare a tree

```go
// Column is a column of the list. A leading "-" turns the order.
type Column string

func (c *Column) UnmarshalText(b []byte) error {
	if name := strings.TrimPrefix(string(b), "-"); name != "id" && name != "name" {
		return errors.New("want id or name")
	}
	*c = Column(b)
	return nil
}

func (Column) Complete(_ *cmdline.Line, prefix string) ([]string, cmdline.Directive) {
	return cmdline.Words(prefix, "id", "name"), cmdline.NoFiles
}

func tree() *cmdline.Tree {
	common := []any{helpFlags{}, outputFlags{}, configFlags{}}
	t, err := cmdline.New(
		cmdline.Group{Name: "prog", Flags: common, Commands: []cmdline.Node{
			cmdline.Group{Name: "items", Help: "Manage items", Flags: []any{helpFlags{}}, Commands: []cmdline.Node{
				cmdline.Command[listIn]{Name: "list", Aliases: []string{"ls"}, Help: "List items", Flags: common, Run: list},
				cmdline.Command[deleteIn]{Name: "delete", Aliases: []string{"rm"}, Help: "Delete an item", Flags: common, Run: del},
			}},
			cmdline.Command[checkIn]{Name: "check", Help: "Check a file", Flags: []any{helpFlags{}, configFlags{}}, Run: check},
			cmdline.Command[completionIn]{Name: "completion", Help: "Write a completion script", Flags: []any{helpFlags{}}, Run: completion},
		}},
		cmdline.Reader(time.ParseDuration), // time.Duration has no UnmarshalText
		cmdline.LateReader(findItem),       // an Item is looked up when the command runs
	)
	if err != nil {
		panic(err) // a wrong tree is a fault in the program; TestTree finds it first
	}
	return t
}
```

`helpFlags`, `outputFlags` and `configFlags` are listed on the root and again on each command that takes them, so `-h`, `-o` and `-c` can stand before or after the subcommand. `check` does not take `-o`, so `prog -o json check a.yaml` is an unknown flag.

`tree` panics when `New` refuses the tree. That is a fault in the program, not in a command line, and a test finds it first ([Test a CLI built on the library](#test-a-cli-built-on-the-library)).

A `Run` function gets the filled struct:

```go
func list(_ context.Context, in listIn) error {
	name, named := in.Name.Get()
	since, _ := in.Since.Get()
	fmt.Printf("list sort=%q columns=%q filter=%q limit=%d name=%q/%v since=%s\n",
		in.Sort, in.Columns, []string(in.Filter), in.Limit, name, named, since)
	return nil
}

func del(_ context.Context, in deleteIn) error {
	fmt.Printf("delete %d (%s) force=%v\n", in.Item.ID, in.Item.Name, in.Force)
	return nil
}
```

### Parse and run a line

```go
func run(args []string) int {
	t := tree()
	if t.Serve(os.Stdout, args) {
		return 0
	}
	line, err := t.Parse(args)
	if h, _ := cmdline.Get[helpFlags](line); h.Help || err == nil && len(line.Command.Commands) > 0 {
		fmt.Println("usage:", line.Command.Usage)
		return 0
	}
	if err == nil {
		c, _ := cmdline.Get[configFlags](line)
		ctx := context.WithValue(context.Background(), storeKey{}, load(string(c.Config)))
		err = line.Run(ctx) // the late readers, then the command
	}
	if e := (*cmdline.UsageError)(nil); errors.As(err, &e) {
		fmt.Fprintf(os.Stderr, "Error: %s.\n", sentence(line.Command, e))
		return 1
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v.\n", err)
		return 1
	}
	return 0
}

// sentence writes the program's own text from the fields of the mistake.
func sentence(c *cmdline.Info, e *cmdline.UsageError) string {
	where := strings.Join(append([]string{"prog"}, e.Path...), " ")
	what := "<" + e.Arg + ">"
	if e.Flag != "" {
		what = "--" + e.Flag
	}
	switch e.Kind {
	case cmdline.UnknownCommand:
		return fmt.Sprintf("%q is not a command of `%s`", e.Word, where)
	case cmdline.UnknownFlag:
		return fmt.Sprintf("`%s` has no flag %s", where, e.Word)
	case cmdline.MissingValue:
		return fmt.Sprintf("%s needs a value", e.Word)
	case cmdline.Repeated:
		return fmt.Sprintf("%s is given twice", what)
	case cmdline.ArgCount:
		return fmt.Sprintf("usage: %s", c.Usage)
	default: // cmdline.BadValue, cmdline.Unresolved
		return fmt.Sprintf("%s: %q: %v", what, e.Value, e.Err)
	}
}
```

This program shows a usage line for any `-h`, also next to a wrong argument count, and for a line that ends at a group. It makes its store from `--config` before `Run`, and the late reader of `Item` takes the store from the context.

```console
$ prog items rm 12 --force
delete 12 (apple) force=true
$ prog -c other.yaml items rm 21
delete 21 (pear) force=false
$ prog items ls --sort=-id --columns id,name --filter a --filter b --name=
list sort="-id" columns=["id" "name"] filter=["a" "b"] limit=50 name=""/true since=0s
$ prog items list --since 90m --limit 5
list sort="" columns=[] filter=[] limit=5 name=""/false since=1h30m0s
$ prog items
usage: prog items
$ prog items delete -h
usage: prog items delete <item>
$ prog items lst
Error: "lst" is not a command of `prog items`.
$ prog items list --sort
Error: --sort needs a value.
$ prog --force items delete 12
Error: `prog` has no flag --force.
$ prog items list --limit ten
Error: --limit: "ten": strconv.ParseInt: parsing "ten": invalid syntax.
$ prog items list --columns id,size
Error: --columns: "id,size": want id or name.
$ prog items list -o json -o yaml
Error: --output is given twice.
$ prog items rm 12 --force=yes
Error: --force: "yes": not true or false.
$ prog items delete
Error: usage: prog items delete <item>.
$ prog items rm 99
Error: <item>: "99": no such item.
```

### Print help from the tree

The library prints no help. A program writes it from `Info`. The second test program, `toy` ([`research/spikes/final-typed/toy/`](research/spikes/final-typed/toy/)), prints its help from `Info.Usage`, `Info.Args` and `Info.Flags` in about 20 lines:

```console
$ toy net ping -h
Ping a host

  toy net ping <host>
  <host>  The host to ping
  -n, --count int              How many times (default 3)
  --wait duration              Time between two pings (default 1s)
  --from addr                  Source address
  --level level                How much to print (default mid)
  --via host                   Hosts to go through
  -l, --label string           A label; may be given more than once
  --store path                 The store of hosts (default hosts)
  -v, --verbose                Say more
  -h, --help                   Show help
```

### Wire the entry point and the scripts

`run` above calls `Serve` before anything else, so `prog __complete …` never reads a config or does work. The `completion` command calls `script.Write` with the root's name. An error of a command comes back from `Run` as it is:

```console
$ prog completion bash | head -1
# bash completion V2 for prog                                 -*- shell-script -*-
$ prog completion tcsh
Error: no completion script for shell "tcsh".
```

### Complete from the line

```go
// Complete offers the IDs in the store that -c names on the line so far.
func (Item) Complete(line *cmdline.Line, prefix string) ([]string, cmdline.Directive) {
	file := "prog.yaml"
	for _, g := range line.Flags {
		if g.Name == "config" {
			file = g.Value
		}
	}
	var ids []string
	for _, it := range load(file) {
		ids = append(ids, strconv.Itoa(it.ID))
	}
	return cmdline.Words(prefix, ids...), cmdline.NoFiles
}
```

A program may forbid I/O at Tab time; Headscale does (D1).

A `Complete` method runs inside the Tab request. The library sets no time limit on it and does not catch a panic.

### Test a CLI built on the library

**`Parse` is a pure function of the tree and argv, and so is `Complete` when the `Complete` methods are. A table test is the whole harness.** `Serve` writes to an `io.Writer`, so the exact answer that a script reads is testable without a shell. A test that builds the tree makes a wrong tree fail CI. A test of `Run` alone fills the input struct by hand.

```go
// TestTree: New accepts the tree; tree panics when it does not.
func TestTree(t *testing.T) { tree() }

// TestParse: a line, and the structs it fills.
func TestParse(t *testing.T) {
	line, err := tree().Parse([]string{"-c", "x.yaml", "items", "ls", "--columns", "id,-name", "--name="})
	if err != nil {
		t.Fatal(err)
	}
	in, _ := cmdline.Get[listIn](line)
	c, _ := cmdline.Get[configFlags](line)
	name, given := in.Name.Get()
	if !slices.Equal(in.Columns, []Column{"id", "-name"}) || in.Limit != 50 || name != "" || !given || c.Config != "x.yaml" {
		t.Errorf("got %+v %+v", in, c)
	}
}

// TestRun: a command alone. The test fills the input struct by hand.
func TestRun(t *testing.T) {
	in := listIn{Limit: 5, Name: cmdline.Some("fig")}
	if err := list(context.Background(), in); err != nil {
		t.Fatal(err)
	}
}

// TestMistake: a mistake is data.
func TestMistake(t *testing.T) {
	_, err := tree().Parse([]string{"items", "list", "--limit", "ten", "--bogus"})
	var e *cmdline.UsageError
	if !errors.As(err, &e) || e.Kind != cmdline.BadValue || e.Flag != "limit" || e.At != 2 {
		t.Errorf("got %v", err)
	}
}

// TestTab: the answer the shell script reads, line by line.
func TestTab(t *testing.T) {
	for _, tc := range []struct{ line, want string }{
		{"items ", "list\tList items\ndelete\tDelete an item\n:4\n"},
		{"items list --sort ", "id\nname\n:4\n"},
		{"-c other.yaml items rm ", "21\n22\n:4\n"},
	} {
		var b bytes.Buffer
		tree().Serve(&b, append([]string{"__complete"}, strings.Split(tc.line, " ")...))
		if b.String() != tc.want {
			t.Errorf("%q: got %q", tc.line, b.String())
		}
	}
}
```

One tree can serve tests that run in parallel (M7). What a user sees in a shell needs the built binary and the shell; see [Real shells](#real-shells).

### The API

`go doc -all` of the prototype:

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

## Tests

**Four kinds of test hold this specification**: the library's own table tests, the corpus of upstream edge cases, fuzz targets, and a job that drives Tab in real shells. The [rule index](#rule-index) names the tests of each rule.

### The library's own tests

**The typed layer** is tested in `cmdline_test.go`, on a tree with every kind of field: basic types, a type that reads itself, a type with a `Reader`, a type with both, a late type, lists, `Opt`, `Repeat`, `Repeat` of a list, `Path`, defaults, and structs of flags on the root, on a group and on the leaves. Each table row starts with the ID of the rule that it holds.

| Test             | Rows                       | Holds                                                                                                                             |
| ---------------- | -------------------------- | --------------------------------------------------------------------------------------------------------------------------------- |
| `TestValues`     | 21 rows, and 8 more checks | how each type of field is read (Y1–Y12), the cause of a bad value (M6)                                                            |
| `TestLate`       | —                          | late readers: not called by `Parse`, the order, the first failure, no lookup on a line with a mistake (N1–N4)                     |
| `TestMistakes`   | 26 rows, 9 default texts   | the kinds, their fields and positions (U1, R2, X1–X3), the count (A1–A4), no struct next to a mistake (G2), the default text (M6) |
| `TestStructs`    | —                          | which structs a line fills (G1–G5), `Line.Flags`, `Line.Args`, `Line.ArgAt` (M2, M3), the `Line` next to a repeat (M5)            |
| `TestInfo`       | —                          | the tree as data, the usage line (I1, I2)                                                                                         |
| `TestNew`        | 40 rows, 5 wrong tags      | what `New` refuses (K1, K5–K7, K9–K18); `New` names every problem, in order (K19); a root that runs                               |
| `TestOddTypes`   | —                          | a slice and a bool that read themselves, a `Repeat` with a default (Y5, Y9, Y10)                                                  |
| `TestRun`        | —                          | a line runs once; a group, a mistake and a `Line` that `Parse` did not make do not run (G5–G7)                                    |
| `TestTab`        | 22 rows                    | Tab by type, lists, `Path`, the `Line` that `Complete` gets (T7, T12, T14, T19–T22), through `Serve`                              |
| `TestShared`     | 64 lines at once           | one tree serves many lines at the same time (M7); run with `-race`                                                                |
| `TestStdlibOnly` | 1                          | the core, with the reader under it, imports only the standard library (`go list -deps`); it fails when `go list` cannot run       |
| `FuzzParse`      | 7 seeds                    | see [Fuzz targets](#fuzz-targets)                                                                                                 |

**The reader** keeps the tests of the first version, in `reader/reader_test.go`, with the row numbers they had. Its tree has root flags that some commands also take, a group two deep, aliases, bools, a value flag with a Completer, a repeatable flag, a file flag, a non-ASCII short, and arguments with and without a Completer.

| Test            | Rows                | Holds                                                                                                                                                                                              |
| --------------- | ------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `TestParse`     | P01–P59             | the grammar and the walk; each row also checks that argv is not changed                                                                                                                            |
| `TestErrorText` | 4                   | the default text of the reader's three kinds (M6)                                                                                                                                                  |
| `TestComplete`  | T01–T58             | Tab, through `Serve`                                                                                                                                                                               |
| `TestServe`     | S01–S04             | the protocol                                                                                                                                                                                       |
| `TestPure`      | 1                   | the tree is not changed (M7)                                                                                                                                                                       |
| `TestOrder`     | O1–O6, and `Values` | the order and positions of flags, what is read before a refused word                                                                                                                               |
| `TestCheck`     | K0, K1–K8 (17 rows) | the checks of names and spellings                                                                                                                                                                  |
| `TestContract`  | W8, C2, C6, S5, S6  | what the reader does with a tree that the check refuses, and with a failing writer. A caller cannot reach the first three: `New` refuses such a tree                                               |
| `FuzzParse`     | 3 seeds             | no panic; arguments in argv order; flags in order, each at a flag word, before the mistake; a result survives a round trip through its canonical line; `Complete` does not panic on the same words |

`script/script_test.go` has `TestDirectiveBits` (6 bits equal cobra's, S7) and `TestWrite` (four scripts call `__complete`; another shell is an error, S8).

The 23 tests of the three packages pass, also with `-race -count=3`. The tests cover 99.2 % of the statements of the typed layer and 100 % of the reader.

### The corpus of upstream edge cases

**The corpus carries what other parsers learnt into this library's tests.** It has 485 cases: 360 for `Parse` and 125 for Tab. They come from 1,628 upstream test functions, table rows and issues, of which 550 were about the grammar decided here and 1,078 were not (typed values, Go API, validation, help text, environment, deprecation). Every row of the inventory says IN with the case IDs, or OUT with a reason.

| Source                                                                                                     | Cases |
| ---------------------------------------------------------------------------------------------------------- | ----- |
| spf13/pflag tests at `44b0d47`                                                                             | 45    |
| Go's `flag` (go1.27.3)                                                                                     | 12    |
| spf13/cobra `command_test`, `args_test`, `flag_groups_test`, `cobra_test` at `adbc881`                     | 69    |
| spf13/cobra `completions_test` and the shell tests                                                         | 67    |
| issues of pflag, cobra, kong and urfave/cli (6,072 titles screened)                                        | 66    |
| kong, urfave/cli v3, ff, Tailscale's `ffcomplete`, coder/serpent, glibc and util-linux getopt tests, POSIX | 226   |

**Each case is one JSON line that names its source.**

```json
{"id":"pflag-034","src":"spf13/pflag@44b0d47 bool_test.go:106 TestShortFlagExtraArgument","lic":"BSD-3-Clause",
 "kind":"run","topic":"bool","upstream":"-t maybe","expect":"a bool never takes the next word: maybe is a positional",
 "tree":"pf","argv":["run","-b","maybe"],"want":{"kind":"run","path":"run","args":["maybe"],"flags":{"bool":["true"]}}}
```

| Field                | Meaning                                                                                                                     |
| -------------------- | --------------------------------------------------------------------------------------------------------------------------- |
| `id`, `src`, `lic`   | the case, its source (repository, revision, file, line and test, or the issue URL) and the source's licence                 |
| `kind`, `topic`      | `run` or `complete`, and the area of the grammar                                                                            |
| `upstream`, `expect` | the case as the source wrote it, and what the source expects, in words                                                      |
| `tree`, `argv`       | the tree (empty for Headscale's), and argv on that tree; for `complete` the last word is the cursor word                    |
| `want`               | the source's behaviour, carried onto the tree                                                                               |
| `ours`, `why`        | where this library or Headscale decided otherwise: the expected outcome, and the decision (`D11`, …), the quirk or the call |
| complete fields      | `has`, `not`, `exact`, `files` and `nospace`, checked against the `__complete` answer                                       |

**On the typed prototype: 343 cases match the source, 123 match the recorded decision, and 19 match neither.** These are the numbers of the first version, and each case has the same verdict as there. Each of the 19 is named, with its reason, in the driver's `explained` table, and an unexplained case fails the run: empty list values (5), Tab after a refused word (4), files for a path flag (3), no Tab values for bools (3), `--` at a group (1), and byte-wise flag words and kept quotes (3).

**Licence.** A row re-expresses behaviour: argv and an expected outcome, in this project's own form, on its own tree. No upstream code, comment or issue text is copied. Re-expressed rows need no notice from any source; the `src` column is kept for attribution and for the yearly review. The test file carries one line: "Rows re-express behaviour recorded in the tests and trackers named in `src`." Rows from GPL and LGPL sources are facts only, with no text. This is the ordinary reading for test vectors, not legal advice.

**Upkeep.** Once a year, or at a cobra or pflag release if that is rarer: read the changes to the upstream test files since the recorded revision, and search the trackers with the recorded queries. A new IN item becomes a row; an OUT item becomes an inventory line with a reason. A bug report against this library becomes a row with the issue as its source. Measured pace over 12 months: about one pflag change about this grammar, none in cobra.

**The corpus runs through Headscale's layer, on trees with text values.** Each of its three trees has a typed twin, and the driver fails when a twin is not the tree of the same name. A row checks the outcome as text: the command, the flags as typed, the arguments, or the kind of the mistake. No row has an expectation for a typed field; the library's own tests hold those. An expectation of a caller, such as "help", lives with the caller's tests. Splitting the 485 rows into a library part and a caller part is implementation work.

### Fuzz targets

| Target                    | Property                                                                                                                                                                                                                                                                                                                                                                                                                  | Last run                       |
| ------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------ |
| `FuzzParse` (typed layer) | no panic; the same answer twice; a mistake has a position on the line, and only `ArgCount` stands at the end; the words before a mistake hold no mistake of their own but a wrong count (X1); `Run` runs no line with a mistake and no group; a line without a mistake has no flag twice unless its field is a `Repeat`, and runs once: a second `Run` returns `ErrRan` (G6); `Complete` does not panic on the same words | 3 min, 35.3 M executions, pass |
| `FuzzParse` (reader)      | see the table above                                                                                                                                                                                                                                                                                                                                                                                                       | 60 s, 11.7 M, pass             |
| `FuzzRun`                 | no panic, no hang, the same result twice, output bounded by input, a round trip through the canonical line, a trailing `--` on a leaf line changes nothing, flags at a group may move behind the command words                                                                                                                                                                                                            | 2 min, 8.5 M, pass             |
| `FuzzLeaf`                | a value comes back byte for byte in all four spellings; after `--` every word is an argument; where flags stand among arguments changes nothing                                                                                                                                                                                                                                                                           | 2 min, 2.2 M, pass             |
| `FuzzTab`                 | no panic, no hang, the same answer twice, at most 64 candidates; no candidate that the run then refuses because of that candidate, as an unknown command or flag, a repeat or a bad bool word                                                                                                                                                                                                                             | 2 min, 0.59 M, pass            |

argv in `FuzzRun`, `FuzzLeaf` and `FuzzTab` is the fuzz input split at NUL, at most 64 words and 16 KiB, and a call that takes more than 1 second fails. These three run through Headscale's layer. The failing inputs that found bugs are kept as seeds, so `go test` replays them.

### Real shells

**A CI job drives Tab in real shells against the built binary** (decision D21). It runs on every pull request that changes `go.mod` or the CLI, so a cobra bump shows any change in the scripts. It types each line of a fixed list into interactive bash, zsh and fish in a pseudo-terminal, presses Tab once, and reads back the edited line. It also asks fish with `complete -C` and PowerShell with `TabExpansion2`. The list for Headscale has 41 lines ([`lines.txt`](research/spikes/final-typed/headscale/shell/lines.txt)). The harness is about 270 lines of Python and shell, and runs in under two minutes in the nix shells.

**The job is the only test that sees the scripts and the protocol together.** In the bake-off, the `--x=v` form was broken in four of six candidates while every in-process test passed.

**The typed prototype gives the shells the same answers as the first version.** The job ran on it with all four shells. What bash, zsh, fish (`complete -C`) and PowerShell showed is byte for byte what they showed before. The fish pseudo-terminal output differs only in the prompt, which shows the folder. That run was made before decision D49, which changes nothing that Tab reads; the `__complete` answers were compared again after it.

### From a rule to its test

The [rule index](#rule-index) lists, for each rule, its section and its tests. `P`, `T`, `O`, `K` and `S` rows with a number are the reader's tests. A rule ID with a test name (`Y1 rows of TestValues`) is a row of the typed layer's tests. `kit:` rows are the Headscale conformance kit (kit v4: 248 required rows and 28 rows for the assistant's calls, all passing). `corpus:` rows are corpus cases. `sh:` entries are lines of the real-shell job. `toy` is the test of the second test program. `kit:` and `sh:` tests run on Headscale's tree; they are examples of a caller's tests.

## Limits, platforms and compatibility

### Limits

**The library sets no limit** on the number of words, the length of a word, the depth of the tree or the number of candidates. `Parse` and `Complete` read each word once. `New` compares the flags that can be typed at a command in pairs.

**`New` reads the structs by reflection, once.** A program calls it at start. One `__complete` call of the Headscale test binary took 4.7 to 5.3 ms on the typed prototype and 4.0 to 4.8 ms on the first version, process start included (the mean of 500 calls from a shell loop, five rounds each, on the 12-leaf test tree; the loop alone takes about 0.9 ms for each call).

**The library sets no time limit on a late reader or on a `Complete` method.** `Line.Run` hands its context to the late readers and does nothing else about a slow or cancelled lookup. A late reader or a `Complete` method that calls a server is specified when the first one is built: its time limit, and what the user sees when the call fails.

The fuzz targets test argv up to 64 words and 16 KiB.

### Platforms

| What                                                      | Measured                                                                                                                        |
| --------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------- |
| Linux, Go 1.27.3                                          | yes                                                                                                                             |
| bash 5.3 with bash-completion 2.17, zsh 5.9.1, fish 4.9.3 | yes, in a pseudo-terminal                                                                                                       |
| PowerShell 7.6.5                                          | only through `TabExpansion2`, not in an interactive console                                                                     |
| macOS bash 3.2 without bash-completion                    | no. From the script's source: without `compopt` it adds no space after any candidate and cannot honour `NoFiles` or `KeepOrder` |
| zsh frameworks (oh-my-zsh), zsh menu-select styles        | no                                                                                                                              |
| Windows, and Windows argv                                 | no; no Windows build is planned                                                                                                 |

### Compatibility

**There is no compatibility promise while the package lives in Headscale's repository.** A change of the API or of a rule is a change of Headscale's code and tests in the same pull request.

**The promise is written when the package moves to its own repository.** It will cover the exported API in [The API](#the-api), the rules L, V, B, R1–R6, R8, W, C, M1–M7, X1–X5, X8, T, S1–S9, K, Y, N, A, U, G and I, and the protocol, which is cobra's.

### Where the package lives

**The library starts as a package inside the Headscale module** (decision D25). It stands at the top level of the module, next to `cmd` and `hscontrol`: `github.com/juanfont/headscale/cmdline` (decisions D39 and D51). It is not under `internal/`, so other programs can import it. A test fails when the core imports anything outside Go's standard library; `script` is the exception. It moves to its own repository when a second real user exists. Then only the files of Headscale that import it change their import.

**The name is `cmdline`** (decision D51).

## Why Headscale has its own parser

This part gives the research in short. The detail is in [`research/`](research/README.md): [`DECISIONS.md`](research/DECISIONS.md), [`INTERVIEW.md`](research/INTERVIEW.md), [`referee.md`](research/referee.md), [`edge-corpus.md`](research/edge-corpus.md), [`differential.md`](research/differential.md), [`library-design.md`](research/library-design.md), [`discovery.md`](research/discovery.md), [`deep-own.md`](research/deep-own.md) and [`rules.md`](research/rules.md); for the typed library, [`typed-library.md`](research/typed-library.md) and [`rules-typed.md`](research/rules-typed.md).

### Two jobs were left

**001 leaves only two jobs to a framework: read the command line, and answer Tab.** Help, documentation, validation, error text, config and output are Headscale's own ([Our layer, not the framework's](001-cli.md#our-layer-not-the-frameworks)). Viper is gone. So the research asked which tool does those two jobs best, and gave cobra no credit for being in place, except real migration cost and what users see.

### The candidates

**About 45 projects were screened, and five went to deep research:** cobra, urfave/cli v3, kong, creachadair/command and an own parser, in two forms (own grammar, and an own dispatcher over pflag). The screen dropped projects with no release for 24 months, no three-level nesting, a licence that does not fit, or no way to build the tree from data ([`discovery.md`](research/discovery.md), and the three screening notes).

| Candidate                 | Why it did not win                                                                                                                                                                                                                                                                                                                                                                                                                         |
| ------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| cobra                     | It reached every required case only after 13 lines of fixes, and about 42 adapter lines lean on behaviour it does not promise: a `help` command that cannot be removed, groups made runnable so that "unknown command" is not just a string, a double parse in `__complete` (#2527), dash-led values read as flags on the Tab path (#2243). It cannot refuse `-ojson` without a second reader in front of pflag. Its scripts stay: see D23 |
| kong                      | Its tree must be built by generating Go struct types (`reflect.StructOf`). Error kinds come from where its trace stopped. It has no completion of its own. One person merges and tags                                                                                                                                                                                                                                                      |
| creachadair/command       | It reads error kinds from four message texts, accepts `-output` and `--o` as second spellings, and its root takes `-h`, `-o` and `-c` anywhere, even as another flag's value                                                                                                                                                                                                                                                               |
| urfave/cli v3             | Its scripts never send the cursor word unless it starts with `-`, so the alias rule (D16) and the file rules cannot be met inside it. Errors are strings                                                                                                                                                                                                                                                                                   |
| own dispatcher over pflag | The same behaviour as the own grammar, with 16 lines spent switching pflag off; without them pflag reads `-output json` as `-o utput`. pflag gives `-e=` the value `=` (pflag #541). Two readers (pflag for `Parse`, an own one for Tab) must agree                                                                                                                                                                                        |

### The bake-off

**Each finalist got one adapter against a shared test kit, written by a champion.** An independent referee then built a second kit (155 required cases) and drove every binary through real bash, zsh, fish and PowerShell.

|                     | Required, as delivered | After the referee's fixes (required · stretch) | Adapter lines | Workaround lines | New modules |
| ------------------- | ---------------------- | ---------------------------------------------- | ------------- | ---------------- | ----------- |
| own grammar         | **155/155**            | 155 · 12/12                                    | 228           | 0                | 0           |
| own over pflag      | 155/155                | 155 · 12/12                                    | 254           | 16               | 0           |
| creachadair/command | 149/155                | 155 · 10/12                                    | 292           | ~41              | 0           |
| kong                | 148/155                | 155 · 12/12                                    | 246           | ~20              | 1           |
| cobra               | 148/155                | 155 · 8/12                                     | 308           | ~42              | 0           |
| urfave/cli v3       | 146/155                | 155 · 9/12, after its completion was replaced  | 221           | ~23              | 1           |

Tab took 2.1 to 4.8 ms in all six. The referee ranked: own grammar and own over pflag, then kong and creachadair, then cobra, then urfave. The real shells found what no kit row showed: the `--x=v` form was broken in four of six delivered adapters, and cobra's own scripts had three faults ([Known faults in the scripts](#known-faults-in-the-scripts)).

### Three concerns, measured

Before he chose, the maintainer asked three things. Each was measured, on the string-only library of the first version. [The review: a typed library](#the-review-a-typed-library) has the numbers of the typed library.

**1. "What about all the information and knowledge grandfathered into the other ones?"** The corpus answers it ([The corpus of upstream edge cases](#the-corpus-of-upstream-edge-cases)). On 360 parse cases the own grammar had no gap: it matched the source or a recorded decision on all but three, and those three were open questions, not bugs. pflag's own tests and tracker found nothing. The Tab answerer had three real bugs, all of a kind cobra learnt from its users: it offered a flag already given, it completed flag values after `--`, and a bare positional `o` opened the values of `-o`. A differential run of 3 million generated lines against pflag and cobra found no line where pflag reads a correct line correctly and the own grammar does not. On 38 % of the lines only cobra differed, almost always because of its command walk and its help handling, which the decisions refuse.

**What a corpus cannot carry over:** users who find bugs (6,072 issue titles across four trackers are years of reports; after the switch, Headscale's users are the only reporters); shell and platform behaviour (cobra's tracker has 227 shell-specific titles); and future upstream fixes, which no longer reach this parser (about one relevant pflag change in the last year).

**2. "If we are to do our own, we will have a lot of test code that needs to be owned, can we get edge cases from the ones we need?"** The edge cases are the corpus above. The size, measured when the choice was made: the library core was 359 lines and `script` 20; the library's tests were 427 lines; the corpus is 485 data rows and a 328-line driver; the fuzz targets are 255 lines; the shell harness is about 270 lines and 41 Tab lines. Upkeep is the yearly corpus review, about an afternoon.

**3. "Can we keep our parser and structure separate from the headscale layer so it can be reused elsewhere as a library?"** Yes. At that time the edge was where 001 had put it: everything that the kit's builder did stayed Headscale's, and Headscale's adapter was 94 lines. The review later moved the edge: the typed library took over the values, the lists, the repeats, the bool words and the argument count. A second, unrelated program (`kv`, in [`research/spikes/lib-toy/`](research/spikes/lib-toy/)) was written on the first API. It needed four things that the first version lacked, and wanted a fifth. Two were added: a Completer that sees the line, and help texts on candidates. Three were not: groups of short bools (`-vv`), a negative number as a positional (`incr n -1`), and Tab for a variable number of positionals. Being a library cost about 100 lines over a parser written only for Headscale, and an exported API that is a contract. No existing library does this exact job; each lacks two of: tree as data, interspersed GNU-style flags, typed errors, and an answer to cobra's protocol.

### What it cost

**Bugs were found in the own parser on the way:**

| Bug                                                                                                                                                         | Found by                                                      | Fixed                           |
| ----------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------- | ------------------------------- |
| a line that ends at a group lost the flags of the levels above (Headscale example: `headscale --version nodes` showed help)                                 | the differential run, and a fuzz property from the first seed | W7                              |
| Tab decided "waits for a value" from the previous word without reading the line: `-c -o <Tab>` offered the values of `-o`, though `-o` is the value of `-c` | the differential run, fuzzing within one second               | T1, T3                          |
| Tab offered flags already given                                                                                                                             | the differential run, the corpus                              | T7                              |
| Tab matched any number of dashes and an empty short: `---tags=<Tab>` completed, a bare `o` opened `-o`                                                      | fuzzing, the corpus, the library's own table                  | L10, L11                        |
| Tab offered a value for a flag typed a second time (`-o= --output=<Tab>`)                                                                                   | fuzzing, after 85 seconds                                     | T7                              |
| the test kit's builder read `-h=1` as "no help" and ran the command, and showed help before it refused a flag that the command does not take                | the differential run                                          | D26, D19 and D35 in the builder |

**The safety of a destructive command rests on these tests, not on a parser used by thousands of programs.** A parser bug most often ends as a usage error, because the argument count and the prompt that names the target stand behind it, but only while the table cases exist.

### The review: a typed library

**The first version of this document specified a library of strings.** It gave every value back as typed. Headscale's layer converted the values, split the lists, refused repeats and bad bool words, and counted the arguments. The maintainer reviewed that version on the pull request and asked for types:

> strong typing and use of generics for type constraints must be a first class citizen.

> I want the library to be strongly typed, and that we leverage strict typing from top to bottom allowing us to have parsing of dedicated types being implemented on given types. We should use typing to enforce a interface the implementer use.

**He also asked if pflag would be a win. It would not.** pflag's value types are not exported, its getters go by name with a check at run time, and its reader has the two measured faults (`-e=` and `-output json`; see [The candidates](#the-candidates)).

**Small sketches were built before the decisions** ([`research/spikes/typed/`](research/spikes/typed/)).

| Question                         | Sketches                                                                                                                                                                                                                                                                                                                                                                                                    | Decision                               |
| -------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------- |
| how a command declares its input | a `Bind` method that the compiler checks (`typed.go`, `example/`), and struct tags read by reflection (`tags.go`, `example-tags/`). With `Bind`, three wrong programs do not compile (`bad1/`, `bad2/`, `bad3/`: no `Bind` method, a field type without a parser, a parser of another type). With tags, a wrong struct is found when the program starts: in the library as built, `New` refuses it (K9–K15) | tags (D42), against the recommendation |
| which method a type carries      | an own `Parse` method (`example/`), and `encoding.TextUnmarshaler`, with the same type read from the command line and from JSON (`example-text/`)                                                                                                                                                                                                                                                           | `encoding.TextUnmarshaler` (D45)       |
| a value that needs a server      | one lookup function per type, run after the line is read (`example-lookup/`)                                                                                                                                                                                                                                                                                                                                | a late reader in the library (D46)     |

**Then the library was built in full, with the string reader under it, and every test ran again** ([`research/spikes/final-typed/`](research/spikes/final-typed/)). The build had to keep every earlier decision, and nothing was unworkable.

| Test                                                                                 | On the typed prototype                                                                                                                                                                                                                                                                                                  |
| ------------------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| the library's own tests                                                              | 23 tests pass in three packages, also with `-race`; they cover 99.2 % of the statements of the typed layer and 100 % of the reader                                                                                                                                                                                      |
| Headscale's conformance kit                                                          | 248 of 248 required rows pass, 28 of 28 rows for the assistant's calls and 6 of 6 stretch rows. The 235 required rows of the first version give the answers that they gave there; four of them now write `json` as the value of `-o`. 13 rows are new, for D49                                                          |
| the corpus, 485 cases                                                                | 343 match the source, 123 match the recorded decision, 19 match neither: the numbers of the first version, with the same verdict for each case                                                                                                                                                                          |
| the differential run, 1,000,000 generated lines against the pflag and cobra adapters | no bucket without an explanation and no new bucket: the buckets are those of the first version, pair by pair and cause by cause. Before D49 the counts were the same too: all three parsers agree on 519,955 lines. Since D49 they agree on 480,182 lines, because every `-o` value that is not `json` is now a mistake |
| the differential run for Tab, 2 × 125,000 lines                                      | the patterns, the pair counts and the buckets of the first version                                                                                                                                                                                                                                                      |
| fuzzing                                                                              | the typed `FuzzParse`: 3 min, 35.3 M executions; the reader's `FuzzParse`: 60 s, 11.7 M; `FuzzRun`, `FuzzLeaf` and `FuzzTab` through Headscale's layer, after D49: 2 min each, 8.5 M, 2.2 M and 0.59 M executions. All pass                                                                                             |
| the real shells, 41 lines                                                            | bash, zsh, fish and PowerShell show what they showed on the first version, byte for byte; only the fish prompt differs                                                                                                                                                                                                  |
| the `__complete` answers of the old binary against the new one                       | 82 answers, none differs; the four scripts are identical                                                                                                                                                                                                                                                                |

**The rules went from 111 to 155.** Of the 111 rules of the first version, 73 are the same and 31 changed. 6 moved from Headscale's layer into the library: the bool words, each flag once, the comma list, the empty list, the empty item and the argument count. 1 is gone (K2). 45 are new: reading a value (Y), late readers (N), arguments and their count (A), the mistakes as data (U), the structs of a line (G), the tree as data (I), ten more checks of `New` (K9–K18) and Tab by type (T19–T22).

**The typed library is about three times the size of the string-only one.** The lines are non-blank, non-comment lines.

| Part                               | First version                                | Typed |
| ---------------------------------- | -------------------------------------------- | ----- |
| the library: the typed layer       | —                                            | 785   |
| the library: the reader            | 368                                          | 369   |
| `script`                           | 20                                           | 20    |
| the library's tests                | 431                                          | 1,122 |
| Headscale's layer in the prototype | 94 (the adapter) and 115 (the kit's builder) | 299   |

The library took over the 115 lines of the kit's builder from Headscale's layer. That is small against what types add: the tags, the readers, the structs and the checks of `New`.

**A second program was written on the typed library too** ([`research/spikes/final-typed/toy/`](research/spikes/final-typed/toy/), 143 lines). It makes other choices than Headscale: the library's own error text, exit code 2, a group alone is a mistake, and a help text printed from `Info`. A test holds that the library and `toy` name nothing of Headscale.

**One fuzz run failed, and the fault was in the test harness.** The first `FuzzRun` run on the typed prototype failed after one second, on the line `nodes set --name= --name= -c`. The library was right: `--name` is given twice, at position 3. The adapter had handed the differential "the line as the parser read it", though the reader had stopped at `-c`, a missing value further right. The adapter now hands a line over only when every word of it was read. The input is kept as a seed. The other two targets had passed in that run, and all three ran again after the fix.

**What the typed build did not check:**

- Windows and macOS. PowerShell ran on Linux only.
- Typed fields in the corpus and the kit. Both grade the outcome as text. That a value lands in its field with the right type is held by the library's own tests and by one test of Headscale's layer.
- Headscale's real value types. The kit takes any text as a value. A duration, a lookup and a type that reads itself are tested in the library's tests and in `toy`.
- A late reader that is slow, hangs or is cancelled.
- Tab inside a list of `Path`. There is no test and no rule.
- A help text, a reference page and a man page made from `Info`. `toy` prints a help from it, and Headscale's prototype rebuilds the whole description of the kit's tree from it.
- More than "the same as before". The differential run compares with the cobra and pflag adapters; what it found is in [`differential.md`](research/differential.md).

### What nobody measured

- PowerShell in an interactive console, macOS bash 3.2, Windows, zsh frameworks.
- The real tree of about 60 commands. Every number above is on a tree of 12 leaves. The differential run should run once on the real tree when the specs exist.
- A script saved from today's cobra-built Headscale against the new binary. That it keeps working rests on the protocol being the same, not on a test.
- The real-shell job in GitHub's CI. It ran only in local nix shells.
- A late reader or a `Complete` method that calls a server; see [Limits](#limits).

## Decision log

The maintainer made these decisions. Decision numbers are those of [`research/DECISIONS.md`](research/DECISIONS.md); [`research/INTERVIEW.md`](research/INTERVIEW.md) has each question with both alternatives. Decisions that are only Headscale's are in [001](001-cli.md#decision-log); they are here only where the library must make them possible.

| Decision                                                                                                                                                                                                      | Rejected                                                                                                                  | Why                                                                                                                                                                                                                                                                |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| D24: a parser of Headscale's own, as a small library: flag reader, command lookup, usage errors as data, Tab answerer; standard library only                                                                  | cobra; kong; urfave/cli v3; creachadair/command                                                                           | only parsing and Tab were left for a framework; the own grammar alone passed every required case as delivered, with no workaround; see [Why Headscale has its own parser](#why-headscale-has-its-own-parser)                                                       |
| D41: the library is typed. It fills the input struct of a command and checks each value; it does not hand strings to the caller. The tested string reader stays as the lower layer                            | the library of the first version of this document: every value comes back as typed, and the caller converts and checks it | the maintainer's review: "typing driving the interface, validation, programming and implementation style". Generics are first class "ideally, but not must": readable, idiomatic Go weighs more than a check by the compiler                                       |
| D42: a command declares its arguments and flags with struct tags on its input struct. The library reads them by reflection, and `New` refuses a wrong struct at program start. **Against the recommendation** | a `Bind` method on the input struct, so that the compiler checks each field type                                          | both were built ([`research/spikes/typed/`](research/spikes/typed/)); the one difference is build time against start time, and a test that builds the tree finds a wrong struct in CI. The maintainer put readable, idiomatic Go first, and 001 already shows tags |
| D43: a type says how it is read with a method of its own; a type without one gets one `Reader` for the program, and the `Reader` wins over the method                                                         | a method only, and a wrapper type around every type that the program does not own                                         | fields stay plain Go types                                                                                                                                                                                                                                         |
| D45: that method is Go's `encoding.TextUnmarshaler`                                                                                                                                                           | an own `Parse(string) (T, error)` method                                                                                  | `netip.Prefix`, `netip.Addr` and `time.Time` already have it, and the same method reads the type from a config file. Both were built before the choice                                                                                                             |
| D44: the library knows only the input type: `Command[In]` with `Run(ctx, In) error`                                                                                                                           | the input and the output type, `In` and `Out`                                                                             | objects, tables, JSON and the message when a command is done stay in Headscale's own spec type                                                                                                                                                                     |
| D46: a value that needs a server is read by a late reader: one function per type, which the library runs only after the whole line is right                                                                   | a wrapper type in the caller (`Ref[T]`)                                                                                   | the field stays a plain type: `Run` reads `in.Item.ID`                                                                                                                                                                                                             |
| D47: the usage line of a command is made from its input struct                                                                                                                                                | a usage line written in the spec and checked against the fields                                                           | one source; the check "the usage line agrees with the fields" goes                                                                                                                                                                                                 |
| D48: flags that a layer above adds to a command are structs of flags, listed in `Flags []any` and read with `Get[T](line)`                                                                                    | typed handles with no `any`                                                                                               | as built and tested. The known cost: `New` checks the list, not the compiler, and `Get` finds a struct by its type                                                                                                                                                 |
| D49: Headscale's type for `--output` is strict: it takes only `json`. This is Headscale's decision and changes nothing in the library                                                                         | a type that takes any word, and a later check in Headscale's builder, so that `-o a -o b` is "given twice"                | a wrong format is a mistake of the line, and the library places it like any other (D35): `-o a -o b` reports the bad value `a`                                                                                                                                     |
| D17: "not given" against "given empty" is a field of type `Opt[T]` with `Get()`; the type is now in the library. **Against the recommendation**                                                               | a pointer field (`*string`)                                                                                               | the maintainer's choice                                                                                                                                                                                                                                            |
| D23: the scripts come from cobra's generators; only `script` imports cobra. **Against the recommendation**                                                                                                    | copy cobra's scripts into the tree and patch them                                                                         | a fault in a script is fixed upstream, not in a copy. The cost was measured: the fish and bash faults stay until cobra releases a fix                                                                                                                              |
| D1: the binary answers Tab through a hidden entry point; it reads no config and calls no server                                                                                                               | lists baked into the script                                                                                               | one source, the tree; values can come from the line later                                                                                                                                                                                                          |
| D2: bash, zsh and fish are required; PowerShell is a stretch goal                                                                                                                                             | PowerShell and a Windows build required                                                                                   | the maintainer widened the option: PowerShell comes with cobra's generators                                                                                                                                                                                        |
| D21: Tab is tested in real shells in CI                                                                                                                                                                       | Go tests only                                                                                                             | the protocol and script faults are visible only in a shell                                                                                                                                                                                                         |
| D4: the library reports mistakes as data; the caller writes all text                                                                                                                                          | the library writes the text                                                                                               | the caller owns every sentence                                                                                                                                                                                                                                     |
| D35: the first mistake on the line is reported, whatever its kind                                                                                                                                             | parser mistakes first, then value mistakes                                                                                | one rule for every kind. The library places its seven kinds. A caller places its own with `Given.At`, `Line.ArgAt`, `UsageError.At` and the `Line` next to a mistake                                                                                               |
| D20: the word after a value flag is always its value                                                                                                                                                          | a known flag name is never a value                                                                                        | `--sort -last-seen` needs a value that starts with `-`                                                                                                                                                                                                             |
| D11: `-ojson` and groups of shorts are best effort. The library refuses them                                                                                                                                  | the library accepts them, as pflag does                                                                                   | D11 allows either. Refusing needs no code. A reader that takes attached short values is how pflag comes to read `-output json` as `-o utput`                                                                                                                       |
| D9, D26: a bool takes `--x`, `--x=true`, `--x=false`; only `true` and `false`, in lower case; no `--no-x`                                                                                                     | Go's bool words; `--no-x`                                                                                                 | the library's bool reader takes only these two words (B3). In the first version the library returned the word and the caller checked it                                                                                                                            |
| D15, D6: each flag once; a list is one comma-separated value                                                                                                                                                  | the last value wins; repeated list flags                                                                                  | the library refuses a second occurrence (R2) and cuts a `[]T` at commas (R4). A flag repeats only when its field is a `Repeat[T]`; Headscale gives `--filter` that type. In the first version the caller did both                                                  |
| D3: `-c` and `-o` before or after the subcommand                                                                                                                                                              | only after the command                                                                                                    | "global" is a struct of flags listed on the root and on each command that takes it (W4)                                                                                                                                                                            |
| D8, D10: no `help` command; a group alone shows its help                                                                                                                                                      | a `help` command; help on stderr                                                                                          | the library has no implicit command, returns a `Line` at the group and does not run it                                                                                                                                                                             |
| D19: an error on the line wins over `-h`                                                                                                                                                                      | the help wins                                                                                                             | the library gives `-h` no meaning (X8), and next to a mistake no struct is readable (G2), so a caller cannot show help for a wrong line by accident                                                                                                                |
| D16: Tab offers an alias only when no name fits                                                                                                                                                               | aliases always                                                                                                            | real names first                                                                                                                                                                                                                                                   |
| D27: a path flag offers files on Tab; other free text offers nothing                                                                                                                                          | nothing for every value flag                                                                                              | the type `Path`; a type without `Complete` offers nothing                                                                                                                                                                                                          |
| D28: candidates carry their help text                                                                                                                                                                         | bare words                                                                                                                | the `Help` fields and the `help` tags                                                                                                                                                                                                                              |
| D29: a lone `-` or `--` lists long names only                                                                                                                                                                 | long and short names, as cobra                                                                                            | shorter lists                                                                                                                                                                                                                                                      |
| D30: Tab after a mistake keeps completing from the last command it understood                                                                                                                                 | nothing; files, as cobra                                                                                                  | a typo can be fixed later on the line                                                                                                                                                                                                                              |
| D25: a package inside the Headscale repository, with a test that keeps other imports out; its own repository when a second user exists                                                                        | its own repository now                                                                                                    | one user; a second repository costs releases and a second CI before anyone needs them                                                                                                                                                                              |
| D39: the package stands at the top level of the module, `github.com/juanfont/headscale/cmdline`                                                                                                               | under `cmd/headscale/cli/`, next to its one user                                                                          | it is visibly a library and not a part of the CLI; another program imports one plain path; the move later changes one import path                                                                                                                                  |
| D51: the name of the library is `cmdline`                                                                                                                                                                     | a short, distinct name such as `argv`                                                                                     | it says what the package does, and the proposals and the prototype use it already                                                                                                                                                                                  |
| D52: the string reader is the public package `cmdline/reader`, with its code and its tests as they were. **Against the recommendation**                                                                       | the internal package `cmdline/internal/reader`, which a caller cannot import                                              | the maintainer's conventions allow no `internal/` folder. The known cost: another program can import the reader, so the library shows two ways to describe a tree                                                                                                  |
| D40: the faults found in cobra's scripts are not reported upstream now                                                                                                                                        | the assistant drafts three reports and the maintainer posts them                                                          | the maintainer's choice; the faults and their reproductions stay in [Known faults in the scripts](#known-faults-in-the-scripts)                                                                                                                                    |
| D31: the specification is its own document                                                                                                                                                                    | a section of 001                                                                                                          | 001 keeps what is Headscale's                                                                                                                                                                                                                                      |
| D36: all of the research goes into the pull request, under `research/`. **Against the recommendation**                                                                                                        | a summary here and only the data that tests need                                                                          | the maintainer wants the whole record kept                                                                                                                                                                                                                         |
| Fact: `--` ends the flags; flags and arguments mix; no abbreviations; one spelling per flag                                                                                                                   | —                                                                                                                         | from 001 as written                                                                                                                                                                                                                                                |
| Fact: pflag is not the reader and not a standing test oracle                                                                                                                                                  | pflag under the dispatcher; pflag's value types under the typed layer; a differential test in CI                          | a differential test against pflag would have caught none of the bugs found. For the typed layer pflag is no win: its value types are not exported, and its getters go by name with a check at run time                                                             |
| Fact: no variadic arguments                                                                                                                                                                                   | an argument field that takes the rest of the line                                                                         | no command in Headscale's tree takes a variable number of arguments                                                                                                                                                                                                |

## Open points

### Not decided

Nothing. The name was the last point, and it is decided (D51).

### Calls not confirmed by the maintainer

The assistant settled these to make the rules complete. Each one is in the text above. The maintainer can confirm or change each one while reading. The first table has the calls of the typed library, each with its alternative in [`research/typed-library.md`](research/typed-library.md). The second table has the earlier calls that still hold.

| Call of the typed library                                                                                                                                                                                                                                                     | Where                         | The other choice                                                                                                                                              |
| ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| the `Line` keeps the text and the position of every flag and argument, though D41 says that a caller gets no strings. A caller needs the text to place a mistake of its own that depends on a word, and a `Complete` method needs it to read a flag of the line               | M1–M3, T14                    | positions only. Then Headscale cannot tell `--version` from `--version=false` on a line with a mistake, and a `Complete` method cannot read the value of `-c` |
| `Reader` and `LateReader` are options of `New`; there is no registry for the whole program. So a late reader is given before a client exists, and takes the client from the context of `Line.Run`. For Headscale, the `Ctx` of 001 must be reachable from a `context.Context` | Y3, N1                        | a package-level registry, filled in `init`: state shared by every tree and every test                                                                         |
| a named type must say how it is read; the library reads only Go's own basic types                                                                                                                                                                                             | Y4                            | read every type by its kind: `type ID uint64` then needs nothing, and `time.Duration` reads `5` as five nanoseconds                                           |
| defaults are a `default` tag, read through the reader of the type, checked by `New` and shown in `Info`                                                                                                                                                                       | Y9, K14                       | no defaults in the library: a command uses `Opt[T]` and sets the default in `Run`. 001 shows no default tag                                                   |
| a `Repeat` flag may have a default; it is then the one occurrence of a flag that is not given                                                                                                                                                                                 | Y9                            | refuse a default on a `Repeat`                                                                                                                                |
| the late readers run inside `Line.Run`; there is no separate step                                                                                                                                                                                                             | N2                            | a separate `Line.Resolve(ctx)` between `Parse` and `Run`                                                                                                      |
| a line runs once: a second `Run` returns `ErrRan`. `Run` on a `Line` that `Parse` did not make returns `ErrNotParsed`                                                                                                                                                         | G6, G7                        | run the command again without the lookups, which the prototype did at first; no defined answer for the Completer's `Line`, where the prototype panicked       |
| the problems in the error of `New` come in a fixed order                                                                                                                                                                                                                      | K19                           | no promise about the order                                                                                                                                    |
| a list never takes an empty word or an empty item, and there is no setting for it                                                                                                                                                                                             | R5, R6                        | a setting, or leave it to the type of the items                                                                                                               |
| `Group` and `Command[In]` are struct values, `New` builds a `*Tree`, and `Parse` is a method of the tree. `New` is the only check, and it names every problem                                                                                                                 | [A valid tree](#a-valid-tree) | `Check(root)` and `Parse(root, argv)` as in the first version: a tree can be read unchecked, and `Check` named the first problem only                         |
| `Get[T](line)` is a package function                                                                                                                                                                                                                                          | G1                            | a generic method `line.Get[T]()`                                                                                                                              |
| a list is `[]T`, a flag that repeats is `Repeat[T]`, and `Repeat[[]T]` is both                                                                                                                                                                                                | Y5, Y8                        | a tag `repeat:"true"` on a `[]T`: then `[]T` means two things, and "a list for each occurrence" cannot be said                                                |
| `Opt[T]` has `Get()` and `Some(v)`; on an argument it means "optional"                                                                                                                                                                                                        | Y7                            | exported fields for the value and for "given"                                                                                                                 |
| one error type, `UsageError`, with a `Kind` and fields by kind. `ArgCount` carries no numbers                                                                                                                                                                                 | U1, A2                        | one error type for each kind; the least, the most and the given count on the error                                                                            |
| the failure of a late reader is a `UsageError` of kind `Unresolved`, though it happens in `Run`                                                                                                                                                                               | N3                            | the error of the lookup as it is: the caller does not know which flag or argument it was                                                                      |
| next to a mistake no struct is readable, except next to `ArgCount`                                                                                                                                                                                                            | G2, A4                        | fill what was read                                                                                                                                            |
| a late reader wins over the type's own method; a type with a `Reader` and a `LateReader` is refused; `Parse` does not check a late value                                                                                                                                      | N1, K17                       | a type with an early check and a late lookup                                                                                                                  |
| Tab asks the type of the field: a `Complete` method, called on a zero value. The commas of a list are the library's                                                                                                                                                           | T19, T20                      | a tag (`complete:"a b"`), which has no place for the line; or a function for each field                                                                       |
| a tag key that the library does not know is refused, also `json`                                                                                                                                                                                                              | K11                           | ignore the keys of other packages; then `hlep:"…"` passes unseen                                                                                              |
| where a line can end at a group, a flag name belongs to one struct type                                                                                                                                                                                                       | K18                           | fill every struct that declares the name                                                                                                                      |
| `Info` gives the value type as a `reflect.Type`; there is no tag for the word that a help text shows for a value                                                                                                                                                              | I2                            | a tag for that word                                                                                                                                           |
| numbers are decimal                                                                                                                                                                                                                                                           | Y1                            | Go's prefixes (`0x10`)                                                                                                                                        |
| words on Tab that depend on the command come from a generic type of the caller, one instance for each command (Headscale's layer: a column type for each row type)                                                                                                            | T19, E6                       | a slot on the command for the caller's data, which a `Complete` method reads                                                                                  |

| Earlier call                                                                                                                                                      | Where                                            | The other choice                                                                      |
| ----------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------ | ------------------------------------------------------------------------------------- |
| a `Complete` method gets the line so far (`*Line`), not only the prefix                                                                                           | T14                                              | the prefix only; a later change breaks every caller                                   |
| `--` where a command word is expected is an unknown command                                                                                                       | L7                                               | drop it and read on, as cobra                                                         |
| `-` and `""` at a group are unknown commands                                                                                                                      | L3, L4                                           | skip them, as cobra's walk does                                                       |
| the library refuses `-ojson` and groups of shorts (`-vv`), and its tests hold that; Headscale promises neither form to its users (D11)                            | L11, B6                                          | leave both forms unspecified                                                          |
| Tab keeps completing after `-h`, `--help` and `--version`                                                                                                         | T15                                              | stop, as cobra                                                                        |
| no Tab values for bools (`--force=<Tab>` offers nothing)                                                                                                          | T5                                               | offer `true` and `false`                                                              |
| no compatibility promise while the package is in Headscale's repository                                                                                           | [Compatibility](#compatibility)                  | a promise from the start                                                              |
| a flag word is any word of two or more bytes that starts with `-`; names are compared byte for byte; shorts are ASCII                                             | L1, L8, K4                                       | Unicode rules                                                                         |
| flags in scope may stand between group words                                                                                                                      | W6                                               | only before the first command word or at the leaf                                     |
| at a group, Tab lists the group's own flags, not its scope                                                                                                        | T6                                               | the scope                                                                             |
| candidates in declaration order, never sorted, duplicates kept                                                                                                    | T11                                              | sorted and unique                                                                     |
| an alias carries its command's help text                                                                                                                          | T12                                              | no help on aliases                                                                    |
| the library's own answers carry `NoFiles`, and `NoSpace` only inside a list                                                                                       | T13, T20                                         | a setting per command                                                                 |
| write errors in `Serve` are dropped; a newline in a candidate is not checked                                                                                      | S5, S6                                           | an error from `Serve`; cut at the newline, as cobra                                   |
| Tab offers `--version` after another root flag, though Headscale's layer then refuses it                                                                          | T18                                              | hide `--version` once another flag is given: the library would need the caller's rule |
| the corpus is reviewed once a year                                                                                                                                | [The corpus](#the-corpus-of-upstream-edge-cases) | only bug reports feed it                                                              |
| the corpus rows are split into a library part and a caller part when the library is built                                                                         | [The corpus](#the-corpus-of-upstream-edge-cases) | keep all rows in Headscale's tests                                                    |
| a file argument has the type `Path`, like a file flag, and Tab offers files (001's open question 6)                                                               | T9, T22                                          | nothing for arguments                                                                 |
| `-h` may stand before the subcommand, like `-c` and `-o` (001's open question 4)                                                                                  | W4                                               | only after the command                                                                |
| a wrong argument count has the end of the line as its position, after every other mistake                                                                         | X4, A2                                           | the first extra argument; then the caller must know `--help` before the line is read  |
| "`--version` not alone" stands at the second of the two words (Headscale's layer)                                                                                 | X2                                               | always at `--version`                                                                 |
| several mistakes in one word: a repeat comes before a bad value. Headscale's layer puts "the group does not take the flag" before both and "not alone" after both | X3                                               | no order; D35 reports one mistake, so one is needed                                   |
| the sets of `New`: names not empty, no space or control byte, no leading `-`, no `=` in a flag name; shorts printable ASCII                                       | K3, K4                                           | stricter: `[a-z0-9-]` for names, letters or digits for shorts                         |
| the real-shell job runs on every pull request that changes `go.mod` or the CLI                                                                                    | [Real shells](#real-shells)                      | only on CLI changes, and by hand on a cobra bump                                      |
| `New` refuses a child of the root named `__complete` or `__completeNoDesc`, and a help text with a line break                                                     | K7, K8                                           | leave both to the caller                                                              |
| a late reader or a `Complete` method that calls a server is specified when the first one is built                                                                 | [Limits](#limits)                                | specify the time limit and the failure now                                            |

## Rule index

The groups: L, V, B, R, W, C, M and X are reading a line (X6 and X7 are Headscale's rules, in 001); Y is reading a value; N is the late readers; A is the arguments; U is the mistakes as data; G is the structs of a line; I is the tree as data; T is Tab; S is the protocol; K is the tree check; E is the edge between the library and the caller. There is no K2: a group with arguments cannot be written. The tests are described in [From a rule to its test](#from-a-rule-to-its-test).

| Rule | Section                                                                  | Held by                                                                                                                                                                           |
| ---- | ------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| L1   | [One word](#one-word)                                                    | P06 `-5`, P13, P19; corpus:issues-006 (`- h` is an unknown flag), corpus:issues-041 (`—-help` is a positional)                                                                    |
| L2   | [One word](#one-word)                                                    | P48, P55, kit:A04                                                                                                                                                                 |
| L3   | [One word](#one-word)                                                    | P02, P04, kit:F20, kit:O10, kit:O11                                                                                                                                               |
| L4   | [One word](#one-word)                                                    | P03, P05, kit:F11, corpus:issues-061                                                                                                                                              |
| L5   | [One word](#one-word)                                                    | P09, kit:D01–D08, kit:F23, kit:F24, FuzzLeaf (after `--`), corpus:cobracmd-011                                                                                                    |
| L6   | [One word](#one-word)                                                    | P10, kit:D06, FuzzRun (trailing `--`)                                                                                                                                             |
| L7   | [One word](#one-word)                                                    | P07, P08, kit:O06, kit:O07, corpus:issues-023                                                                                                                                     |
| L8   | [One word](#one-word)                                                    | P11, P12, P15, FuzzLeaf (values byte for byte), corpus:cobracmd-032, corpus:cobracmd-033                                                                                          |
| L9   | [One word](#one-word)                                                    | P25, P26, corpus:issues-045                                                                                                                                                       |
| L10  | [One word](#one-word)                                                    | P16, P17, P23, P24, kit:E12, kit:X06                                                                                                                                              |
| L11  | [One word](#one-word)                                                    | P13, P14, P18–P21 (they stay), K4, kit:X02, kit:X05, kit:F05/F28/X01 (OBSERVE: Headscale's "either")                                                                              |
| L12  | [One word](#one-word)                                                    | P22, kit:X03–X05                                                                                                                                                                  |
| L13  | [One word](#one-word)                                                    | P23, kit:E09–E12                                                                                                                                                                  |
| V1   | [Flag values](#flag-values)                                              | kit:F01–F04, kit:F06, kit:F11–F13, P25, P26, P37                                                                                                                                  |
| V2   | [Flag values](#flag-values)                                              | P27–P31, kit:F14–F17, kit:F26, kit:F27, kit:O01, kit:O02, kit:G12, FuzzLeaf                                                                                                       |
| V3   | [Flag values](#flag-values)                                              | P32–P34, O4, U1, kit:E13–E15                                                                                                                                                      |
| V4   | [Flag values](#flag-values)                                              | P25, P36, P29, Y11                                                                                                                                                                |
| V5   | [Flag values](#flag-values)                                              | P19, kit:F05 (OBSERVE)                                                                                                                                                            |
| B1   | [Bool flags](#bool-flags)                                                | P35, kit:B11, corpus:pflag-034                                                                                                                                                    |
| B2   | [Bool flags](#bool-flags)                                                | P36, P40, Y10                                                                                                                                                                     |
| B3   | [Bool flags](#bool-flags)                                                | Y10, kit:B04, kit:B06–B10, kit:V12                                                                                                                                                |
| B4   | [Bool flags](#bool-flags)                                                | kit:B03, corpus:issues-058                                                                                                                                                        |
| B5   | [Bool flags](#bool-flags)                                                | kit:B02, kit:O05, kit:V10                                                                                                                                                         |
| B6   | [Bool flags](#bool-flags)                                                | P20, kit:F28 (OBSERVE)                                                                                                                                                            |
| R1   | [A flag given more than once](#a-flag-given-more-than-once)              | P38–P40, O1, R2 rows of TestMistakes                                                                                                                                              |
| R2   | [A flag given more than once](#a-flag-given-more-than-once)              | R2 rows of TestMistakes, kit:B05, kit:G11, kit:L02, kit:L03, kit:R01–R06, kit:V09                                                                                                 |
| R3   | [A flag given more than once](#a-flag-given-more-than-once)              | Y8, kit:F19, kit:L08                                                                                                                                                              |
| R4   | [Lists](#lists)                                                          | Y5, kit:L01, kit:L02                                                                                                                                                              |
| R5   | [Lists](#lists)                                                          | Y6, kit:L04–L07, kit:F22, kit:H21                                                                                                                                                 |
| R6   | [Lists](#lists)                                                          | Y6, kit:L09–L11                                                                                                                                                                   |
| R7   | [Who does what](#who-does-what)                                          | kit:L12, kit:P07, kit:J01–J13, headscale `TestFormat`                                                                                                                             |
| R8   | [Opt: given or not](#opt-given-or-not)                                   | Y7, kit:L13, kit:F11, kit:F12                                                                                                                                                     |
| W1   | [Where a flag may stand](#where-a-flag-may-stand)                        | P41, P44, P54                                                                                                                                                                     |
| W2   | [Where a flag may stand](#where-a-flag-may-stand)                        | P42, P43, O5, kit:G07–G10, kit:V05, kit:P01                                                                                                                                       |
| W3   | [Where a flag may stand](#where-a-flag-may-stand)                        | P44, kit:O04, corpus:cobracmd-015                                                                                                                                                 |
| W4   | [Where a flag may stand](#where-a-flag-may-stand)                        | kit:G01–G06, kit:G13–G15, kit:H16, kit:H17                                                                                                                                        |
| W5   | [Where a flag may stand](#where-a-flag-may-stand)                        | P45, kit:F07–F10, kit:A01–A03, FuzzLeaf (placement)                                                                                                                               |
| W6   | [Where a flag may stand](#where-a-flag-may-stand)                        | P41, kit:O03                                                                                                                                                                      |
| W7   | [Where a flag may stand](#where-a-flag-may-stand)                        | P54, kit:O08, kit:V11, kit:H18, FuzzRun (flags at a group)                                                                                                                        |
| W8   | [Where a flag may stand](#where-a-flag-may-stand)                        | K6, TestContract W8                                                                                                                                                               |
| C1   | [The command walk](#the-command-walk)                                    | P48–P50                                                                                                                                                                           |
| C2   | [The command walk](#the-command-walk)                                    | P48, P49, kit:T02–T05, TestContract C2                                                                                                                                            |
| C3   | [The command walk](#the-command-walk)                                    | P50–P52, kit:E01–E08, kit:T06                                                                                                                                                     |
| C4   | [The command walk](#the-command-walk)                                    | P52, P15, corpus:cobracmd-007, corpus:issues-047                                                                                                                                  |
| C5   | [The command walk](#the-command-walk)                                    | P51, kit:H11–H13                                                                                                                                                                  |
| C6   | [The command walk](#the-command-walk)                                    | P50                                                                                                                                                                               |
| C7   | [The command walk](#the-command-walk)                                    | P01, P53, G5, kit:T12–T15                                                                                                                                                         |
| C8   | [The command walk](#the-command-walk)                                    | P55, kit:A04, kit:A05                                                                                                                                                             |
| C9   | [Arguments and their count](#arguments-and-their-count)                  | A2, kit:E16–E20                                                                                                                                                                   |
| C10  | [The command walk](#the-command-walk)                                    | P48, P49, TestStructs                                                                                                                                                             |
| C11  | [The command walk](#the-command-walk)                                    | P57                                                                                                                                                                               |
| M1   | [What Parse returns](#what-parse-returns)                                | P25, P26, TestStructs, kit:F11                                                                                                                                                    |
| M2   | [What Parse returns](#what-parse-returns)                                | O1, O3–O6, TestStructs, FuzzParse of the reader (order and positions)                                                                                                             |
| M3   | [What Parse returns](#what-parse-returns)                                | P09, O1, O2, TestStructs                                                                                                                                                          |
| M4   | [Usage errors](#usage-errors)                                            | every ERR row of the reader's TestParse, U1                                                                                                                                       |
| M5   | [What Parse returns](#what-parse-returns)                                | M5 of TestStructs, O3–O6, G2, FuzzParse of the reader                                                                                                                             |
| M6   | [Usage errors](#usage-errors)                                            | M6 rows of TestMistakes and TestValues, the reader's TestErrorText, toy                                                                                                           |
| M7   | [What Parse returns](#what-parse-returns)                                | TestShared, G1, the reader's TestPure, kit:I01, `-race -count=3`                                                                                                                  |
| M8   | [Usage errors](#usage-errors)                                            | kit rows of every kind                                                                                                                                                            |
| X1   | [Several mistakes on one line](#several-mistakes-on-one-line)            | X1 rows of TestMistakes, FuzzParse of the typed layer (the words before the mistake hold none), kit:E21–E26, kit:P01–P11                                                          |
| X2   | [Several mistakes on one line](#several-mistakes-on-one-line)            | X2 and R2 rows of TestMistakes, P46, O3–O6, kit:P01–P10, kit:E22, kit:E23                                                                                                         |
| X3   | [Several mistakes on one line](#several-mistakes-on-one-line)            | X3 rows of TestMistakes, kit:R04, kit:P12                                                                                                                                         |
| X4   | [Several mistakes on one line](#several-mistakes-on-one-line)            | A2–A4, kit:E24, kit:P05, kit:A01, kit:H06, kit:H23                                                                                                                                |
| X5   | [Several mistakes on one line](#several-mistakes-on-one-line)            | X1 rows of TestMistakes, O3–O5, kit:P01–P04                                                                                                                                       |
| X6   | [001, Errors on the command line](001-cli.md#errors-on-the-command-line) | kit:H05–H23, kit:B10, kit:P11                                                                                                                                                     |
| X7   | [001, Errors on the command line](001-cli.md#errors-on-the-command-line) | kit:V04–V12, kit:P10                                                                                                                                                              |
| X8   | [Several mistakes on one line](#several-mistakes-on-one-line)            | P30, P54, P58, P59                                                                                                                                                                |
| T1   | [How Tab reads the line](#how-tab-reads-the-line)                        | T34–T39, kit:Q12–Q16, corpus:cobracomp-004, corpus:issues-033                                                                                                                     |
| T2   | [How Tab reads the line](#how-tab-reads-the-line)                        | T34, T37, kit:Q12–Q16; sh:"headscale nodez "; sh:"headscale policy set --bogus " (files: the positional's own Completer)                                                          |
| T3   | [What Tab offers](#what-tab-offers)                                      | T08, T13, T18–T21, T32, T55, kit:C11–C14, kit:N18, kit:Q01, kit:Q02, kit:Q21, kit:Q24; sh:"headscale -c -o "                                                                      |
| T4   | [What Tab offers](#what-tab-offers)                                      | T26–T28, kit:N21, kit:Q23; sh:"headscale nodes routes set 12 -- --"                                                                                                               |
| T5   | [What Tab offers](#what-tab-offers)                                      | T14–T17, T33, T51, kit:Q03, kit:Q27, corpus:others-167–169, corpus:others-197; sh:"headscale nodes list --columns=id,na", sh:"headscale nodes list --config="                     |
| T6   | [What Tab offers](#what-tab-offers)                                      | T09–T12, T45, T46, T53, T54, kit:Q08–Q11, kit:Q29; sh:"headscale nodes list -", sh:"headscale nodes list -c"                                                                      |
| T7   | [What Tab offers](#what-tab-offers)                                      | T40–T43, T56–T58, kit:Q17–Q20, kit:Q30–Q32, FuzzTab; sh:"headscale nodes list --sort id --s", sh:"headscale nodes list --filter id --f"                                           |
| T8   | [What Tab offers](#what-tab-offers)                                      | T01–T07, kit:N01–N07, kit:C01–C07; sh:"headscale nodes routes ap", sh:"headscale nodes routes "                                                                                   |
| T9   | [What Tab offers](#what-tab-offers)                                      | T22–T25, T30, T31, T48–T50, T19 and T21 rows of TestTab, kit:C15–C17, kit:N08–N14, kit:Q25; sh:"headscale policy set ", sh:"headscale nodes delete o "                            |
| T10  | [Matching, order and help texts](#matching-order-and-help-texts)         | T52                                                                                                                                                                               |
| T11  | [Matching, order and help texts](#matching-order-and-help-texts)         | T03, T09                                                                                                                                                                          |
| T12  | [Matching, order and help texts](#matching-order-and-help-texts)         | T01–T06, T09, kit:Q06–Q08; sh:"headscale nodes " (zsh, fish, pwsh, bash)                                                                                                          |
| T13  | [Directives and files](#directives-and-files)                            | T01, T47, T48, T30, T19 and T20 rows of TestTab                                                                                                                                   |
| T14  | [The Completer](#the-completer)                                          | T14 row of TestTab, T47, T48, T51, S04, toy (`--store` decides the hosts offered)                                                                                                 |
| T15  | [What Tab never does](#what-tab-never-does)                              | T43, T44, kit:Q28                                                                                                                                                                 |
| T16  | [How Tab reads the line](#how-tab-reads-the-line)                        | every kit completion row checks "a command ran"; S05                                                                                                                              |
| T17  | [How Tab reads the line](#how-tab-reads-the-line)                        | FuzzTab, kit:I01                                                                                                                                                                  |
| T18  | [What Tab never does](#what-tab-never-does)                              | FuzzTab (extended property)                                                                                                                                                       |
| T19  | [The Completer](#the-completer)                                          | T19 rows of TestTab, kit:C11–C15                                                                                                                                                  |
| T20  | [Lists on Tab](#lists-on-tab)                                            | T20 rows of TestTab, kit:C18, kit:N20, kit:Q35; sh:"headscale nodes list --columns id,na"                                                                                         |
| T21  | [The Completer](#the-completer)                                          | T21 rows of TestTab, kit:Q04, kit:Q05; toy (`Host` is late and has `Complete`)                                                                                                    |
| T22  | [Directives and files](#directives-and-files)                            | T22 rows of TestTab, kit:Q01–Q03                                                                                                                                                  |
| S1   | [The hidden entry point](#the-hidden-entry-point)                        | S01                                                                                                                                                                               |
| S2   | [The hidden entry point](#the-hidden-entry-point)                        | S02                                                                                                                                                                               |
| S3   | [The hidden entry point](#the-hidden-entry-point)                        | S02, S03, every T row                                                                                                                                                             |
| S4   | [The hidden entry point](#the-hidden-entry-point)                        | S03                                                                                                                                                                               |
| S5   | [The hidden entry point](#the-hidden-entry-point)                        | TestContract S5                                                                                                                                                                   |
| S6   | [The hidden entry point](#the-hidden-entry-point)                        | TestContract S6, K8                                                                                                                                                               |
| S7   | [The scripts](#the-scripts)                                              | TestDirectiveBits                                                                                                                                                                 |
| S8   | [The scripts](#the-scripts)                                              | TestWrite, kit:S-bash … S-powershell                                                                                                                                              |
| S9   | [The scripts](#the-scripts)                                              | the shell run                                                                                                                                                                     |
| S10  | [Known faults in the scripts](#known-faults-in-the-scripts)              | sh lines `--columns id,na`, `--tags tag:ci,tag:p`, `--columns=id,na`, `--filter=ow`, `nodes list `, `--config=`; `spikes/probe-eq/RESULT.md`                                      |
| K1   | [A valid tree](#a-valid-tree)                                            | K1 (two rows of the reader), K1 row of TestNew; headscale builds its tree with `New` (`KitTree`)                                                                                  |
| K3   | [A valid tree](#a-valid-tree)                                            | K3 (two rows)                                                                                                                                                                     |
| K4   | [A valid tree](#a-valid-tree)                                            | K4 (four rows), Check refuses the test tree's `-ø`                                                                                                                                |
| K5   | [A valid tree](#a-valid-tree)                                            | K5                                                                                                                                                                                |
| K6   | [A valid tree](#a-valid-tree)                                            | K6 (three rows)                                                                                                                                                                   |
| K7   | [A valid tree](#a-valid-tree)                                            | K7 (two rows: refused at the root, accepted below)                                                                                                                                |
| K8   | [A valid tree](#a-valid-tree)                                            | K8 (two rows)                                                                                                                                                                     |
| K9   | [A valid tree](#a-valid-tree)                                            | K9                                                                                                                                                                                |
| K10  | [A valid tree](#a-valid-tree)                                            | K10 (also the rows with `embedded`), K12                                                                                                                                          |
| K11  | [A valid tree](#a-valid-tree)                                            | K11                                                                                                                                                                               |
| K12  | [A valid tree](#a-valid-tree)                                            | K12                                                                                                                                                                               |
| K13  | [A valid tree](#a-valid-tree)                                            | K13                                                                                                                                                                               |
| K14  | [A valid tree](#a-valid-tree)                                            | K14                                                                                                                                                                               |
| K15  | [A valid tree](#a-valid-tree)                                            | K15                                                                                                                                                                               |
| K16  | [A valid tree](#a-valid-tree)                                            | K16                                                                                                                                                                               |
| K17  | [A valid tree](#a-valid-tree)                                            | K17                                                                                                                                                                               |
| K18  | [A valid tree](#a-valid-tree)                                            | K18                                                                                                                                                                               |
| K19  | [A valid tree](#a-valid-tree)                                            | K19 of TestNew                                                                                                                                                                    |
| E1   | [Who does what](#who-does-what)                                          | the library's own tests                                                                                                                                                           |
| E2   | [Who does what](#who-does-what)                                          | kit v4; `toy` shows another set                                                                                                                                                   |
| E3   | [Who does what](#who-does-what)                                          | TestStdlibOnly in `cmdline` (fails, not skips, when `go list` cannot run)                                                                                                         |
| E4   | [Who does what](#who-does-what)                                          | kit:G01–G15, kit:Q06–Q08, kit:V04, headscale `TestTwin`                                                                                                                           |
| E5   | [Who does what](#who-does-what)                                          | kit:Q01–Q05, kit:C16, kit:C17                                                                                                                                                     |
| E6   | [Who does what](#who-does-what)                                          | kit:C12–C14, kit:C18–C20, kit:N19, kit:N20, kit:Q33–Q35; sh:"headscale nodes list --sort -la", sh:"headscale nodes list --columns id,-ho", sh:"headscale nodes list --filter -ow" |
| E7   | [Who does what](#who-does-what)                                          | **not modelled** in the kit                                                                                                                                                       |
| E8   | [Who does what](#who-does-what)                                          | kit:J01–J13; times and list items **not modelled** beyond R6                                                                                                                      |
| Y1   | [Basic types](#basic-types)                                              | Y1 rows of TestValues                                                                                                                                                             |
| Y2   | [Types that read themselves](#types-that-read-themselves)                | Y2 row of TestValues (`level`), toy (`Level`, `netip.Addr`)                                                                                                                       |
| Y3   | [Reader](#reader)                                                        | Y3 row of TestValues (`upper` has both; `time.Duration` has a Reader)                                                                                                             |
| Y4   | [Basic types](#basic-types)                                              | K12 rows of TestNew (`time.Month`, `time.Duration`)                                                                                                                               |
| Y5   | [Lists](#lists)                                                          | Y5 row of TestValues, Y5 of TestOddTypes (`set`, `[]set`), kit:L01                                                                                                                |
| Y6   | [Lists](#lists)                                                          | Y6 rows of TestValues                                                                                                                                                             |
| Y7   | [Opt: given or not](#opt-given-or-not)                                   | TestValues (`Name`, `Dry`, `File`), headscale `TestInput`                                                                                                                         |
| Y8   | [Repeat](#repeat)                                                        | TestValues (`Tag`, `Rule`, `Verbose`), headscale `TestInput` (`--filter`)                                                                                                         |
| Y9   | [Defaults](#defaults)                                                    | TestValues (`Count`, `Wait`), Y9 of TestOddTypes (`Label`, `Lists`), toy                                                                                                          |
| Y10  | [Bool flags](#bool-flags)                                                | Y10 rows of TestValues, Y10 of TestOddTypes (`yesno`), TestInfo (`Bool`)                                                                                                          |
| Y11  | [Which type is read how](#which-type-is-read-how)                        | Y11 of TestValues, FuzzLeaf                                                                                                                                                       |
| Y12  | [Path](#path)                                                            | T22 rows of TestTab, kit:Q01–Q03, kit:C16, kit:C17                                                                                                                                |
| N1   | [Late readers](#late-readers)                                            | N1 of TestLate, Y6 row (`--others 1,,2`)                                                                                                                                          |
| N2   | [Running a line](#running-a-line)                                        | N2 of TestLate, toy                                                                                                                                                               |
| N3   | [Running a line](#running-a-line)                                        | N3 of TestLate, toy                                                                                                                                                               |
| N4   | [Running a line](#running-a-line)                                        | N4 of TestLate, FuzzParse of the typed layer, toy (`net ping nobody --bogus`)                                                                                                     |
| A1   | [Arguments and their count](#arguments-and-their-count)                  | A1 of TestMistakes                                                                                                                                                                |
| A2   | [Arguments and their count](#arguments-and-their-count)                  | A2 rows of TestMistakes, kit:E16–E20                                                                                                                                              |
| A3   | [Arguments and their count](#arguments-and-their-count)                  | A3 rows of TestMistakes, kit:E24, kit:P05                                                                                                                                         |
| A4   | [Arguments and their count](#arguments-and-their-count)                  | A4 of TestMistakes, kit:H06, kit:H23, toy (`net ping -h`)                                                                                                                         |
| U1   | [Usage errors](#usage-errors)                                            | U1, R2, X2 rows of TestMistakes; every error row of TestValues and TestLate                                                                                                       |
| G1   | [The structs of a line](#the-structs-of-a-line)                          | G1 of TestStructs, TestShared, headscale `TestInput`                                                                                                                              |
| G2   | [The structs of a line](#the-structs-of-a-line)                          | G2 of TestStructs and TestMistakes, T14 row of TestTab                                                                                                                            |
| G3   | [The structs of a line](#the-structs-of-a-line)                          | G3 of TestStructs, kit:O08, kit:O09, kit:V01                                                                                                                                      |
| G4   | [Where a flag may stand](#where-a-flag-may-stand)                        | G4 of TestStructs, kit:G01–G06                                                                                                                                                    |
| G5   | [The structs of a line](#the-structs-of-a-line)                          | G5 of TestStructs and TestRun, FuzzParse of the typed layer                                                                                                                       |
| G6   | [Running a line](#running-a-line)                                        | G6 of TestRun, FuzzParse of the typed layer                                                                                                                                       |
| G7   | [Running a line](#running-a-line)                                        | G7 of TestRun                                                                                                                                                                     |
| I1   | [The tree as data](#the-tree-as-data)                                    | I1 of TestInfo, headscale `TestTwin`, toy (its help)                                                                                                                              |
| I2   | [The tree as data](#the-tree-as-data)                                    | I2 of TestInfo, headscale `Describe`                                                                                                                                              |

## References

- [001](001-cli.md): the CLI, which is built on this library. Its parts [How flags are written](001-cli.md#how-flags-are-written), [Errors on the command line](001-cli.md#errors-on-the-command-line), [Our layer, not the framework's](001-cli.md#our-layer-not-the-frameworks) and [Shell completion](001-cli.md#shell-completion) state what a Headscale user sees.
- [002](002-api.md): the API that the CLI calls.
- [`research/`](research/README.md): every note, the decisions, the interview record, the corpus and the test builds.
    - [`research/typed-library.md`](research/typed-library.md): the typed library: its API, the line between the library and Headscale, every design call with its alternative, and all test results.
    - [`research/rules-typed.md`](research/rules-typed.md): the numbered rules of the typed library, each with its source and its test.
    - [`research/spikes/final-typed/`](research/spikes/final-typed/): the prototype (`cmdline/`, with the reader in `cmdline/internal/reader/`), the second test program (`toy/`), the example program of this document with the tests that print its tables (`prog/`), Headscale's layer and shell job (`headscale/`), the conformance kit (`kit/`), the corpus driver (`corpus/`), and the differential run and fuzz targets (`diff/`).
    - [`research/spikes/typed/`](research/spikes/typed/): the sketches behind the decisions D42 to D46.
    - [`research/rules.md`](research/rules.md) and [`research/spikes/final/`](research/spikes/final/): the rules and the prototype of the first version, the string-only library.
    - [`research/spikes/corpus/corpus.jsonl`](research/spikes/corpus/corpus.jsonl): the corpus, and `inventory/` with all 1,628 rows screened.
    - [`research/spikes/v2/shell/`](research/spikes/v2/shell/): the real-shell harness.
- cobra v1.10.2: `completions.go`, `active_help.go`, `bash_completionsV2.go`, `zsh_completions.go`, `fish_completions.go`, `powershell_completions.go` ([spf13/cobra](https://github.com/spf13/cobra/tree/v1.10.2)).
- cobra issues named here: [#2243](https://github.com/spf13/cobra/issues/2243), [#2527](https://github.com/spf13/cobra/issues/2527). pflag: [#541](https://github.com/spf13/pflag/issues/541).

[#3375]: https://github.com/juanfont/headscale/pull/3375
