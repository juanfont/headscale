# Headscale command-line parser

**Status:** draft, for discussion, part of [#3375]. It is not meant to be merged as-is.

This document specifies a small Go library. The library reads a command line against a tree of commands, and it answers shell completion (Tab) for the same tree. The new Headscale CLI ([001](001-cli.md)) is built on it. Its working name is `cmdline`. The maintainer chooses the real name when the library is built.

[001](001-cli.md) says what is Headscale's: which commands and flags exist, that a flag may be given once, which bool words count, the error sentences, the help and the command specs. This document says what any program that uses the library gets. A program author and a user who types a line can both predict the result of any command line and any Tab press from this document alone. It names no Headscale command, except in examples that say so.

Each rule has an ID (`L1`, `T7`, …) and at least one test. The [rule index](#rule-index) maps each ID to its tests. A prototype in [`research/spikes/final/`](research/spikes/final/) implements every rule, and its tests hold them.

## Contents

- [Words used here](#words-used-here)
- [What the library is](#what-the-library-is)
- [The command tree](#the-command-tree)
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

| Word           | Meaning                                                                                                     |
| -------------- | ----------------------------------------------------------------------------------------------------------- |
| argv           | the words of the command line after the program name, as the program gets them                              |
| word           | one element of argv                                                                                         |
| position       | the index of a word in argv, from 0                                                                         |
| command        | one node of the tree: a name, aliases, flags, positionals and children                                      |
| root           | the top command; its name is the program name                                                               |
| group          | a command with at least one child                                                                           |
| leaf           | a command with no children                                                                                  |
| path           | the names of the commands from the root to a command, root not included                                     |
| flag word      | a word that has at least two bytes, starts with `-` and is not exactly `--` (rule L1)                       |
| typed name     | a flag word up to its first `=`, for example `--sort` in `--sort=id`                                        |
| attached value | the part of a flag word after its first `=`                                                                 |
| bool flag      | a flag that takes no value word                                                                             |
| value flag     | a flag that is not a bool flag                                                                              |
| value word     | the word after a value flag that has no attached value                                                      |
| command word   | a word at a group that is not a flag word and not a value word                                              |
| positional     | a word at a leaf that is not a flag word and not a value word                                               |
| scope          | the flags that can be typed at a group: the flags of the root, of the group and of every group between them |
| given          | a flag is given when the line holds it at least once                                                        |
| caller         | the program that uses the library, and its code on top of the library                                       |
| cursor word    | the word under the cursor when Tab is pressed; empty when the cursor stands after a space                   |
| candidate      | one word that Tab offers, with an optional help text after a tab character                                  |
| directive      | a number that tells the shell script what to do with the candidates                                         |
| Completer      | a function of the caller that offers candidates for one value or one positional                             |
| script         | the shell code that tells a shell how to complete the program; cobra's generators write it                  |

The examples use one example program, `prog`. Its tree is in [Declare a tree](#declare-a-tree). It has a group `items` with the leaves `list` (alias `ls`) and `delete` (alias `rm`), and the leaves `check` and `completion`. Every example output in this document comes from that program, built on the prototype ([`research/spikes/final/prog/`](research/spikes/final/prog/)).

## What the library is

**The library does four things, and a sub-package does a fifth.**

1. `Parse` reads argv against the tree. It returns the command reached, every flag given and every positional, or a typed error.
1. `Complete` answers Tab for a line: it returns the candidates and a directive.
1. `Serve` answers the hidden entry point that the shell scripts call (`prog __complete …`).
1. `Check` refuses a tree that `Parse` would read in two ways.
1. The sub-package `script` writes the shell scripts, with cobra's generators.

**The library does nothing else.** It has no help and no usage text. It does not convert values, count positionals, read the environment or a config file, or exit. It writes only to the writer that `Serve` gets. It keeps no state between calls. Every value comes back as the string that was typed.

**The core uses only Go's standard library.** Only the sub-package `script` imports cobra (rule E3).

### Who does what

The library decides the grammar, the command walk, the errors that it can see, Tab, the protocol and the tree check (rule E1). The caller decides the rest, and the library has no setting for it (rule E2). Headscale's layer is the first caller; its choices are in [001](001-cli.md).

| Concern                                 | The library                                                                 | The caller (Headscale, as an example)                                                         |
| --------------------------------------- | --------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------- |
| how one word is read, flag values, `--` | decides                                                                     | —                                                                                             |
| command names and aliases               | finds the command                                                           | declares them                                                                                 |
| which flags a command takes             | reads them from the tree                                                    | declares them; a "global" flag is declared on the root and on each command that takes it (W4) |
| a flag given twice                      | keeps every occurrence                                                      | decides; Headscale refuses a repeat, except `--filter`                                        |
| bool words after `=`                    | returns the word as typed                                                   | decides; Headscale takes only `true` and `false`                                              |
| `--help`, `-h`, `--version`             | ordinary bool flags                                                         | decides what they mean                                                                        |
| a line that ends at a group             | returns a match at the group                                                | decides; Headscale shows the help of the group                                                |
| argument count                          | —                                                                           | checks it                                                                                     |
| value types, lists, time values         | —                                                                           | parses and splits                                                                             |
| error text                              | gives the kind, the path, the word and the position; a default English text | writes every sentence, the "Did you mean" and the exit code (E7)                              |
| several mistakes on one line            | stops at its first mistake and hands over what it read                      | finds its own mistakes and reports the first one on the line (Headscale: D35)                 |
| Tab                                     | reads the line; offers command names and flag names; calls the Completers   | gives the Completers: value lists, files, no space inside a list (E5, E6)                     |
| the hidden entry point                  | `Serve`                                                                     | calls `Serve` first in `main`                                                                 |
| scripts                                 | `script.Write`                                                              | gives the `completion` command                                                                |
| a valid tree                            | `Check`                                                                     | runs `Check` in a test (E4)                                                                   |

## The command tree

**The caller describes the commands as plain data.** A tree is a `*Command`, the root. The library reads the tree and never changes it.

### Commands and flags

| `Command` field | Meaning                                                                                                                                                                  |
| --------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `Name`          | the word that selects the command. The root's `Name` is the program name; the scripts use it                                                                             |
| `Aliases`       | other words that select the command. `Match.Path` holds the `Name`, never an alias (C10)                                                                                 |
| `Help`          | one line. Tab shows it next to the name and next to each alias                                                                                                           |
| `Flags`         | the flags that can be typed at this command. A flag of a group can also be typed below the group, before the leaf; see [Where a flag may stand](#where-a-flag-may-stand) |
| `Args`          | one Completer per positional, by position. A `nil` entry offers nothing. Only a leaf has `Args` (K2)                                                                     |
| `Commands`      | the children. A command with children is a group                                                                                                                         |

| `Flag` field | Meaning                                                                                                |
| ------------ | ------------------------------------------------------------------------------------------------------ |
| `Name`       | the long name without dashes; typed as `--Name`                                                        |
| `Short`      | one character, or 0; typed as `-x`                                                                     |
| `Bool`       | the flag takes no value word                                                                           |
| `Repeat`     | Tab offers the flag again after it is given. `Parse` keeps every occurrence of every flag in all cases |
| `Help`       | one line. Tab shows it next to the flag                                                                |
| `Complete`   | the Completer for the value. `nil` offers nothing. `Files` lets the shell offer file names             |

A flag that may stand before and after the subcommand is declared on the root and on each command that takes it ([W4](#where-a-flag-may-stand)). `Args` completes by position. There are no variadic positionals: a positional after the last entry of `Args` offers nothing.

### A valid tree

**`Check(root)` refuses a tree that `Parse` would read in two ways.** It walks the tree in declaration order and returns the first problem. `Parse` and `Complete` never call it. A caller runs it once, in a test or at start.

| Rule | `Check` refuses                                                                                                                                                                                                                                             |
| ---- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| K1   | a word, name or alias, that appears twice among the children of one group                                                                                                                                                                                   |
| K2   | a group with `Args`                                                                                                                                                                                                                                         |
| K3   | a command name or alias that is empty, holds a space or a control byte, or starts with `-`                                                                                                                                                                  |
| K4   | a flag name that is empty, holds a space or a control byte, starts with `-` or holds `=`; a `Short` that is not one printable ASCII character other than `-` and `=`                                                                                        |
| K5   | a flag name declared twice on one command                                                                                                                                                                                                                   |
| K6   | two meanings for one spelling where both can be typed (in a group's scope, or in a leaf's flags together with the scope above it): one long name with two `Short` letters, or bool in one place and value in the other; one short letter for two long names |
| K7   | a child of the root named `__complete` or `__completeNoDesc`, as name or alias: `Serve` would hide it. Below the root these words are allowed                                                                                                               |
| K8   | a `Help` text, of a command or a flag, that holds a line break (`\n` or `\r`): it would break the answer to the scripts (S6)                                                                                                                                |

The error is a plain `error` whose text names the command path, for example:

```text
prog items: "ls" names two commands
prog items: a group takes no positionals
prog: "-x" cannot be typed as a command word
prog: flag name "a=b" cannot be typed
prog: --x: short 'ø' is not one printable ASCII letter
prog: flag --help declared twice
prog items delete: --config and --count: one spelling, two flags
```

**`Parse` assumes a valid tree and does not check it.** On a tree that `Check` refuses, the result is fixed by the code, not by a promise: with one spelling for two flags, the flag declared at the leaf decides how a word typed before the leaf was read (W8); with two children of one name, the first child wins (C2); a group with `Args` still reads every word as a command word (C6).

## Reading a command line

**`Parse(root, argv)` reads argv from left to right, each word once.** argv does not hold the program name. A word equal to the root's `Name` is an ordinary word (C11). `Parse` stops at the first word that it cannot read.

The tables below show `Parse` on the example tree. A flag is written as `name=value@position`. An error is written as its kind, the path in brackets, the word and `@position`.

### One word

These rules apply to every word that is not a flag's value and does not follow an ending `--`.

- **A word is a flag word if and only if it has at least two bytes, its first byte is `-`, and it is not exactly `--`** (L1). So `-5` and `- h` (one word with a space in it) are flag words, and `—-help` (with an em dash) is not.

- **A word that is not a flag word is a command word at a group, and a positional at a leaf** (L2). `-` alone and the empty word follow this rule: each is a positional at a leaf and an unknown command at a group (L3, L4).

- **At a leaf, the first `--` that is not a flag's value ends the flags** (L5). It is dropped. Every later word is a positional exactly as typed, also `--`, `-`, `-h` and command names. A `--` as the last word changes nothing (L6).

- **Where a command word is expected, `--` is an unknown command named `--`** (L7).

- **Words are compared byte for byte** (L8). There is no case folding, no Unicode normalisation and no trimming. Invalid UTF-8 and NUL bytes have no special meaning. Values and positionals come back byte for byte.

- **A flag word is cut at its first `=`** (L9). Before it is the typed name. After it is the attached value, which may be empty and may hold more `=`.

- **A typed name that starts with `--` names the long flag whose `Name` equals the rest exactly** (L10). `---x` names no flag. `--` with nothing after it (from `--=v`) names no flag.

- **A typed name with one leading dash names the short flag whose `Short` equals the rest exactly** (L11). `-ojson`, `-vv`, `-ho`, `-output` and `-e24h` name no flag, and `-=v` names no flag. So the library refuses attached short values and groups of shorts, and its tests hold that. Headscale does not promise either form to its users (D11). `Parse` compares the rest with the UTF-8 bytes of `Short`; `Check` accepts only ASCII characters.

- **Long and short names do not cross** (L12). `--o` is not `-o`, and `-help` is not `--help`.

- **A flag word that names no flag that can be typed where it stands is an unknown flag** (L13). There are no abbreviations: `--sor` is not `--sort`.

| argv                         | Result                                        |
| ---------------------------- | --------------------------------------------- |
| `items delete 12 -`          | `[items delete]`, positionals `12`, `-`       |
| `items delete 12 ""`         | `[items delete]`, positionals `12`, `""`      |
| `items delete -- --force -h` | `[items delete]`, positionals `--force`, `-h` |
| `items delete 12 --`         | `[items delete]`, positional `12`             |
| `items delete -5`            | unknown flag `[items delete]` `-5` @2         |
| `-`                          | unknown command `[]` `-` @0                   |
| `""`                         | unknown command `[]` `""` @0                  |
| `items -- list`              | unknown command `[items]` `--` @1             |
| `Items`                      | unknown command `[]` `Items` @0               |
| `items list ---sort id`      | unknown flag `[items list]` `---sort` @2      |
| `items list --sor id`        | unknown flag `[items list]` `--sor` @2        |
| `items list -ojson`          | unknown flag `[items list]` `-ojson` @2       |
| `items list -output json`    | unknown flag `[items list]` `-output` @2      |
| `items list --o json`        | unknown flag `[items list]` `--o` @2          |

### Flag values

- **A value flag takes its value after `=` when the word has one, and else from the next word** (V1). The forms are `--x=v`, `-x=v`, `--x v` and `-x v`. An attached value may be empty.

- **The next word is the value, whatever it is** (V2). It can be empty, `-`, `--`, `-h`, the name of another flag or the name of a command.

- **A value flag that is the last word and has no `=` is a missing value** (V3). The error names the typed name, the command reached and the position of the flag word.

- **The library returns values as typed** (V4). It never converts, splits at commas, trims or checks them.

- **An attached short value is not a value** (V5). `-ojson` is an unknown flag (L11).

| argv                              | Result                                            |
| --------------------------------- | ------------------------------------------------- |
| `items list -o json`              | `[items list]`, `output=json@2`                   |
| `items list -o=json`              | `[items list]`, `output=json@2`                   |
| `items list --sort -name`         | `[items list]`, `sort=-name@2`                    |
| `items list --sort --filter x`    | `[items list]`, `sort=--filter@2`, positional `x` |
| `items list --sort=a=b --filter=` | `[items list]`, `sort=a=b@2`, `filter=@3` (empty) |
| `items list -o=`                  | `[items list]`, `output=@2` (empty)               |
| `-c items items list`             | `[items list]`, `config=items@0`                  |
| `items list --sort`               | missing value `[items list]` `--sort` @2          |
| `-o`                              | missing value `[]` `-o` @0                        |

### Bool flags

- **A bool flag never takes the next word** (B1). In `--force maybe`, the word `maybe` is a positional.

- **A bare bool flag reads `"true"`** (B2). `--x=v` and `-x=v` read `v` as typed. The library refuses no bool word; the caller decides which words count (B3).

- **There is no `--no-x` form** (B4). Such a word is an unknown flag, unless the tree declares a flag with that name.

- **There is no group of short bools** (B6). `-hf` and `-vv` are unknown flags (L11).

- **`--x=false` is a given flag with the value `false`** (B5). What that means is the caller's choice. Headscale reads `--help=false` as "help not asked".

| argv                            | Result                                               |
| ------------------------------- | ---------------------------------------------------- |
| `items delete --force maybe`    | `[items delete]`, `force=true@2`, positional `maybe` |
| `items delete 12 --force=false` | `[items delete]`, `force=false@3`, positional `12`   |
| `items delete 12 --force=maybe` | `[items delete]`, `force=maybe@3`, positional `12`   |
| `items delete 12 --no-force`    | unknown flag `[items delete]` `--no-force` @3        |
| `items delete 12 -hf`           | unknown flag `[items delete]` `-hf` @3               |

### A flag given more than once

**`Parse` keeps every occurrence of every flag, in the order typed, in any spelling, and refuses none** (R1). The caller decides what a repeat means. Headscale refuses it, except for `--filter` (R2–R8, in [001](001-cli.md#how-flags-are-written)). Another caller can keep the last value, or count `-v -v`, from the same data.

| argv                                    | Result                                                   |
| --------------------------------------- | -------------------------------------------------------- |
| `items list -o a -o b`                  | `[items list]`, `output=a@2`, `output=b@4`               |
| `-o a items -o b list -o c`             | `[items list]`, `output=a@0`, `output=b@3`, `output=c@6` |
| `items delete 12 --force --force=false` | `[items delete]`, `force=true@3`, `force=false@4`        |

### Where a flag may stand

- **At a group, the flags in scope can be typed: those of the root and of every group on the path** (W1). At a leaf, only the leaf's own flags can be typed.

- **A flag typed before the leaf counts only if the leaf declares a flag with the same spelling** (W2). Otherwise it is an unknown flag. The error has the leaf's path, the word as typed, and the position where the word stood.

- **A flag word that is not in a group's scope is an unknown flag at that group** (W3). So a leaf's own flag cannot stand before the leaf.

- **"Global" is a pattern, not a property of a flag** (W4). The caller declares the flag on the root and on each command that takes it. The same `Flag` value can go in each list. Headscale does this for `-c`, `-o` and `-h`.

- **At a leaf, flags and positionals mix in any order** (W5). Flags may follow the last positional.

- **A flag in scope may also stand between group words** (W6).

- **A line that ends at a group returns every flag read on the way down** (W7).

- **One spelling names one flag (the same `Name`, `Short` and `Bool`) everywhere it can be typed** (W8). `Check` refuses a tree that breaks this (K6). `Parse` assumes it.

| argv                         | Result                                                           |
| ---------------------------- | ---------------------------------------------------------------- |
| `-c x.yaml items list`       | `[items list]`, `config=x.yaml@0`                                |
| `items -c x.yaml list`       | `[items list]`, `config=x.yaml@1`                                |
| `items list -c x.yaml`       | `[items list]`, `config=x.yaml@2`                                |
| `items delete --force -h 12` | `[items delete]`, `force=true@2`, `help=true@3`, positional `12` |
| `-h items -o json`           | `[items]`, `help=true@0`, `output=json@2`                        |
| `-o json check a.yaml`       | unknown flag `[check]` `-o` @0 (`check` does not declare `-o`)   |
| `items --sort id list`       | unknown flag `[items]` `--sort` @1                               |
| `--force items delete 12`    | unknown flag `[]` `--force` @0                                   |

### The command walk

- **At a group, the first word that is not a flag word and not a flag's value is the command word** (C1).

- **The command word must equal a child's `Name` or one of its `Aliases` exactly** (C2). If two children match, the first one wins; `Check` refuses such a tree (K1).

- **Any other command word is an unknown command** (C3). The error has the group's path, the word and its position. Suggestions such as "Did you mean" are the caller's.

- **Command names are not abbreviated and not case-folded** (C4).

- **There is no built-in `help` command and no other implicit command** (C5).

- **A group takes no positionals** (C6). Every word at a group is a flag word, a flag's value or a command word.

- **A line that ends at a group is a match at that group, with no positionals** (C7). This holds for the root and for an empty argv. The caller decides what it means. Headscale shows the help of the group.

- **At a leaf, every word that is not a flag word and not a flag's value is a positional** (C8). This holds also for a word that equals a command name.

- **The library never counts positionals** (C9). The caller checks the count.

- **`Match.Path` holds names, never aliases** (C10).

- **argv does not hold the program name** (C11). A word equal to the root's `Name` is an ordinary word.

| argv                | Result                              |
| ------------------- | ----------------------------------- |
| (none)              | `[]`, the root                      |
| `items`             | `[items]`, the group                |
| `items ls`          | `[items list]`                      |
| `items rm 12`       | `[items delete]`, positional `12`   |
| `items delete list` | `[items delete]`, positional `list` |
| `items lst`         | unknown command `[items]` `lst` @1  |
| `help`              | unknown command `[]` `help` @0      |
| `items help`        | unknown command `[items]` `help` @1 |
| `prog items`        | unknown command `[]` `prog` @0      |

### What Parse returns

**`Parse` returns a `*Match` and an error.** The `*Match` is never `nil`.

- **A match holds the command reached, its path, the flags given and the positionals** (M1). A flag is given when it has an entry. A flag given with an empty value has an entry with `""`.

- **`Match.Flags` lists every flag given, in the order typed** (M2). Each entry has the flag's long `Name` (whatever spelling was typed), its `Value` as typed, and the position `At` of its flag word. Flags typed before the leaf come first, as they stood. `Values(name)` returns one flag's values in order, or `nil` when the flag was not given.

- **`Match.Args` holds the positionals in order, without the ending `--`; `Match.ArgAt` holds their positions** (M3).

- **Next to an error, the match holds what `Parse` read before the refused word** (M5): the flags and positionals before it, and the command reached. Nothing after the refused word is read, with one exception: a flag typed before the leaf that the leaf does not declare is found only when the leaf's word is read. The match then has the leaf as its command and path, and only the flags before the refused one.

- **`Parse`, `Complete` and `Check` change neither argv nor the tree, keep no state, and may run at the same time** (M7).

| argv                              | Match next to the error                            | Error                                      |
| --------------------------------- | -------------------------------------------------- | ------------------------------------------ |
| `-o a items -o b lst`             | `[items]`, `output=a@0`, `output=b@3`              | unknown command `[items]` `lst` @5         |
| `items list -o a -o b --sort`     | `[items list]`, `output=a@2`, `output=b@4`         | missing value `[items list]` `--sort` @6   |
| `-c a -o j -c b check`            | `[check]`, `config=a@0`                            | unknown flag `[check]` `-o` @2             |
| `items delete -o=x 12 --bogus 13` | `[items delete]`, `output=x@2`, positional `12` @3 | unknown flag `[items delete]` `--bogus` @4 |

### Usage errors

**Every error of `Parse` is a `*cmdline.Error`** (M4). It has four fields: `Kind`, `Path` (the command reached when reading stopped), `Word` and `At` (the position of the word).

| Kind             | Value | When                                                                                                                                         | `Word`                    | `At`                                 |
| ---------------- | ----- | -------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------- | ------------------------------------ |
| `UnknownCommand` | 1     | a command word that names no child, also `--`, `-` and `""` (C3, L3, L4, L7)                                                                 | the word                  | the command word                     |
| `UnknownFlag`    | 2     | a flag word that names no flag that can be typed where it stands (L13, W3); a flag typed before the leaf that the leaf does not declare (W2) | the typed name, up to `=` | the flag word, where it stood        |
| `MissingValue`   | 3     | a value flag that is the last word and has no `=` (V3)                                                                                       | the typed name            | the flag word (always the last word) |

**`Error()` gives a default English text** (M6). The caller is expected to write its own text from the fields. The default is:

```text
unknown command "lst" for "items"
unknown flag --bogus for "items list"
flag --sort needs a value
```

The ` for "path"` part is left out when the path is empty. A missing value never names the path.

**The library has three kinds; the caller adds its own** (M8). Headscale adds a flag given twice, a bad value, a wrong argument count, and `--version` not alone. Each of them carries the command's path and a word, as the library's kinds do.

### Several mistakes on one line

**`Parse` stops at the first word that it cannot read, left to right** (X5). It returns that mistake with its position, and the match of what it read before it (M5). A mistake to the right of it is never looked at.

**`-h`, `--help` and `--version` have no meaning in the library** (X8). They are ordinary bool flags of the tree. So `-h` never hides a mistake that `Parse` finds.

**A caller can report the leftmost mistake on the line, whatever its kind** (X1). The library gives it three things: the flags in the order typed, each with the position of its flag word (`Given.At`); the positionals with their positions (`Match.ArgAt`); and the position of the parser's own mistake (`Error.At`). The caller checks what `Parse` handed over, in order, and finds its own first mistake. It reports its own mistake when that position is smaller than the parser's, and else the parser's.

The positions that Headscale gives to its own kinds of mistake, and its exceptions (a wrong argument count, `--help`, `--version`), are Headscale's policy. They are in [001, Errors on the command line](001-cli.md#errors-on-the-command-line) (decision D35).

## Tab completion

**`Complete(root, words, cur)` answers one Tab press.** `words` are the words after the program name and before the cursor. `cur` is the cursor word, `""` for a new word. It returns the candidates and a directive. `Serve` calls it for the scripts ([The hidden entry point](#the-hidden-entry-point)).

### How Tab reads the line

**Tab reads `words` with the reader of `Parse`, in a mode that refuses nothing** (T1). An unknown flag word is skipped and takes no value. An unknown command word, or a `--` at a group, is skipped, and the reader stays at that group. A flag typed before the leaf that the leaf does not declare is dropped. So Tab keeps completing from the last command it understood.

**A refused word never makes Tab offer files** (T2). Files come only from a Completer that asks for them.

**Tab runs no command, reads no config and calls nothing but the tree's Completers** (T16). **For one line, Tab gives the same answer every time** (T17).

### What Tab offers

The first row that fits decides the answer.

| #   | When                                                                                                  | Tab offers                                                                                                                                                                                                                                                                                          |
| --- | ----------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| T3  | the reader ends on a value flag that waits for its value (no `=`, not itself a value, not after `--`) | that flag's Completer, with the whole cursor word as prefix, whatever it looks like. A flag with no Completer offers nothing, with `NoFiles`                                                                                                                                                        |
| T4  | the line is after an ending `--` at a leaf                                                            | the cursor word is a positional: no flag names and no `--x=` values (row T9 applies)                                                                                                                                                                                                                |
| T5  | the cursor word starts with `-` and holds `=`                                                         | the Completer of the flag named before the first `=`, among the flags that can be typed there, with the text after `=` as prefix. Candidates come without `--x=`; the scripts put it back. An unknown flag or a bool flag offers nothing, with `NoFiles`. Quotes in the cursor word are not removed |
| T6  | the cursor word starts with `-`                                                                       | the flags of the command reached: at a group, the group's own `Flags` (not its scope); at a leaf, the leaf's. A flag gives `--Name` if that starts with the cursor word, and `-x` only when the cursor word is exactly `-x`. So a lone `-` or `--` lists long names only                            |
| T7  | (applies to T3, T5 and T6)                                                                            | a flag already given, in any spelling and before or after the subcommand, is not offered again, unless it has `Repeat`; no value is offered for it when it is typed again                                                                                                                           |
| T8  | the reader is at a group                                                                              | every child `Name` that starts with the cursor word; if none does, every alias that does                                                                                                                                                                                                            |
| T9  | the reader is at a leaf                                                                               | the Completer of positional n, where n is the count of positionals before the cursor. No entry, or `nil`, offers nothing, with `NoFiles`                                                                                                                                                            |

On the example tree (`Complete` called directly; the candidate's help text is left out here):

| `words`                  | `cur`        | Candidates                                                      | Directive |
| ------------------------ | ------------ | --------------------------------------------------------------- | --------- |
| (none)                   | `""`         | `items`, `check`, `completion`                                  | 4         |
| `items`                  | `""`         | `list`, `delete`                                                | 4         |
| `items`                  | `l`          | `list`                                                          | 4         |
| `items`                  | `r`          | `rm` (no name fits, so the alias)                               | 4         |
| `items list`             | `-`          | `--help`, `--output`, `--config`, `--sort`, `--filter`          | 4         |
| `items list`             | `-o`         | `-o`                                                            | 4         |
| `items list`             | `-s`         | none (`--sort` has no short)                                    | 4         |
| `items list -o`          | `""`         | `json`, `yaml`                                                  | 4         |
| `items list`             | `--output=j` | `json`                                                          | 4         |
| `items list`             | `-o=y`       | `yaml`                                                          | 4         |
| `items list --sort`      | `-`          | none (the `-` is the value of `--sort`)                         | 4         |
| `items list --sort id`   | `--`         | `--help`, `--output`, `--config`, `--filter`                    | 4         |
| `items list --filter id` | `--f`        | `--filter` (`Repeat`)                                           | 4         |
| `items list -o json -o`  | `""`         | none (`-o` is given already)                                    | 4         |
| `-o json items list`     | `--`         | `--help`, `--config`, `--sort`, `--filter`                      | 4         |
| `items list`             | `--config=`  | none: files                                                     | 0         |
| `items delete`           | `--force=`   | none (a bool)                                                   | 4         |
| `items`                  | `--`         | `--help` (the group's own flags)                                | 4         |
| `items delete`           | `""`         | `12`, `13`                                                      | 4         |
| `items delete 12`        | `""`         | none (`delete` has one positional)                              | 4         |
| `items delete --`        | `--`         | none (a positional, completed by the Completer of positional 0) | 4         |
| `items delete o`         | `""`         | none (`o` is a positional, not `-o`)                            | 4         |
| `check`                  | `""`         | none: files                                                     | 0         |
| `itemz`                  | `""`         | `items`, `check`, `completion`                                  | 4         |
| `items lst`              | `""`         | `list`, `delete`                                                | 4         |
| `items list --bogus`     | `--s`        | `--sort`                                                        | 4         |
| `items list -h`          | `--`         | `--output`, `--config`, `--sort`, `--filter`                    | 4         |

### Matching, order and help texts

- **A candidate matches when the cursor word is a byte prefix of it** (T10). Case matters. Tab never corrects a word.

- **Candidates come in declaration order** (T11): children, then aliases; flags in the order of `Flags`, a short right after its long. The library never sorts, never removes duplicates and never sets `KeepOrder`. The shells sort.

- **A candidate from the tree carries a tab and the `Help` text, when `Help` is not empty** (T12). A command and each of its aliases carry the command's `Help`. A flag, long or short, carries the flag's `Help`.

```console
$ prog __complete items ''
list	List items
delete	Delete an item
:4
```

### Directives and files

**The library's own answers carry `NoFiles` and never `NoSpace`** (T13). A Completer's candidates and directive pass through unchanged.

| Directive    | Value | The shell                                                                         |
| ------------ | ----- | --------------------------------------------------------------------------------- |
| `Failed`     | 1     | shows nothing                                                                     |
| `NoSpace`    | 2     | adds no space after a single candidate: room for `,x` or `=x`                     |
| `NoFiles`    | 4     | offers no file names when there is no candidate                                   |
| `FilterExt`  | 8     | reads the candidates as file extensions to filter by                              |
| `FilterDirs` | 16    | offers directories, in the directory named by the first candidate if one is given |
| `KeepOrder`  | 32    | keeps the order of the candidates                                                 |

Directive 0 lets the shell do its default: file names when there is no candidate.

- **`Words(w…)` offers each word of a fixed list that starts with the prefix, with `NoFiles`.**
- **`Files` offers nothing, with directive 0, so the shell offers file names.** A caller marks a path flag or a file positional with it.

**Space after a candidate is the caller's choice.** A Completer that completes one item of a comma list returns `NoSpace`, so the user can type `,` next. Headscale does so for its list flags (E6).

### The Completer

```go
type Completer func(line *Match, prefix string) ([]string, Directive)
```

**A Completer gets the line so far as a `*Match`, and the prefix** (T14). The match holds the command reached, its path, the flags given in order, and the positionals before the cursor, as T1 read them. The prefix is the cursor word, or the text after `=` in the `--x=` form (T5). A candidate may carry a help text after a tab (`"json\tJSON"`).

The Completer filters by the prefix itself. The library does not filter what a Completer returns.

A Completer that reads the line can offer values that depend on a flag. In the example, the IDs that `items delete` offers come from the file named by `-c`:

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

### What Tab never does

- **Tab treats `-h`, `--help` and `--version` as ordinary flags, and keeps completing after them** (T15).

- **A candidate is never refused because of itself, when the line before it was not already refused for that word** (T18). Tab offers no unknown command, no unknown flag, no flag already given (unless `Repeat`) and no bool word. One known exception: a caller rule that the library cannot see. Headscale's `--version` must stand alone, and Tab still offers it after another root flag.

## The completion protocol

The library answers the protocol of cobra's shell scripts, so it can use those scripts unchanged (decision D23). This part states the protocol as the scripts of cobra v1.10.2 speak it, the version Headscale pins. It was read from cobra's source at that version: `completions.go`, `bash_completionsV2.go`, `zsh_completions.go`, `fish_completions.go` and `powershell_completions.go`.

### The hidden entry point

**At each Tab, the script runs the program with the hidden first word `__complete` and the words of the line:**

```text
prog __complete <word>… <cursor word>
```

`__completeNoDesc` is the same request without help texts.

- **`Serve(w, root, args)` answers only when `args[0]` is exactly `__complete` or `__completeNoDesc`** (S1). Otherwise it writes nothing and returns `false`. `args` is argv without the program name. The caller calls `Serve` first in `main`, before it reads any config.

- **The other words are `words`, and the last one is the cursor word** (S2). With no other word, the cursor word is `""` (an empty line).

- **The answer is one candidate per line, then `:` and the directive in decimal, each line ending in `\n`** (S3). It goes to the writer `w`. Nothing goes to stderr.

- **`__completeNoDesc` cuts each candidate at its first tab** (S4).

- **Write errors are dropped, and `Serve` still returns `true`** (S5). The script is the reader and cannot show them.

- **A candidate must not contain `\n`** (S6). `Serve` does not check it and writes the candidate as is. `Check` refuses a `Help` text with a line break (K8); a Completer's candidates are the caller's care.

```console
$ prog __complete items list --s
--sort	Sort by
:4
$ prog __completeNoDesc items ''
list
delete
:4
$ prog __complete items list --config=
:0
```

A command named `__complete` cannot be reached when `Serve` runs first, so `Check` refuses it (K7).

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

The examples come from the example program `prog`, which compiles against the prototype; only `loadIDs`, a stub, is left out. The import path is the prototype's (`spike/cmdline`).

### Declare a tree

```go
func tree() *cmdline.Command {
	help := cmdline.Flag{Name: "help", Short: 'h', Bool: true, Help: "Show help"}
	output := cmdline.Flag{Name: "output", Short: 'o', Help: "Output format", Complete: cmdline.Words("json", "yaml")}
	config := cmdline.Flag{Name: "config", Short: 'c', Help: "Config file", Complete: cmdline.Files}

	return &cmdline.Command{
		Name:  "prog",
		Flags: []cmdline.Flag{help, output, config},
		Commands: []*cmdline.Command{
			{Name: "items", Help: "Manage items", Flags: []cmdline.Flag{help}, Commands: []*cmdline.Command{
				{Name: "list", Aliases: []string{"ls"}, Help: "List items", Flags: []cmdline.Flag{help, output, config,
					{Name: "sort", Help: "Sort by", Complete: cmdline.Words("id", "name")},
					{Name: "filter", Repeat: true, Help: "Keep matching rows", Complete: cmdline.Words("id", "name")},
				}},
				{Name: "delete", Aliases: []string{"rm"}, Help: "Delete an item", Flags: []cmdline.Flag{help, output, config,
					{Name: "force", Bool: true, Help: "Do not ask"},
				}, Args: []cmdline.Completer{itemIDs}},
			}},
			{Name: "check", Help: "Check a file", Flags: []cmdline.Flag{help, config},
				Args: []cmdline.Completer{cmdline.Files}},
			{Name: "completion", Help: "Write a completion script", Flags: []cmdline.Flag{help},
				Args: []cmdline.Completer{cmdline.Words("bash", "zsh", "fish", "powershell")}},
		},
	}
}
```

`-h`, `-o` and `-c` are declared on the root and again on each command that takes them, so they can stand before or after the subcommand. `check` does not take `-o`, so `prog -o json check a.yaml` is an unknown flag.

### Parse a line

```go
func run(args []string) int {
	root := tree()
	if cmdline.Serve(os.Stdout, root, args) {
		return 0
	}
	m, err := cmdline.Parse(root, args)
	if e := (*cmdline.Error)(nil); errors.As(err, &e) {
		fmt.Fprintf(os.Stderr, "Error: %s.\n", usage(e))
		return 1
	}
	if m.Values("help") != nil || len(m.Command.Commands) > 0 {
		fmt.Printf("help of %q\n", strings.Join(m.Path, " "))
		return 0
	}
	switch strings.Join(m.Path, " ") {
	case "completion":
		if len(m.Args) != 1 || script.Write(os.Stdout, m.Args[0], root.Name) != nil {
			fmt.Fprintln(os.Stderr, "Error: completion takes bash, zsh, fish or powershell.")
			return 1
		}
	default:
		fmt.Printf("run %q flags=%v args=%q\n", strings.Join(m.Path, " "), m.Flags, m.Args)
	}
	return 0
}

// usage writes the program's own sentence from the error's fields.
func usage(e *cmdline.Error) string {
	where := strings.Join(append([]string{"prog"}, e.Path...), " ")
	switch e.Kind {
	case cmdline.UnknownCommand:
		return fmt.Sprintf("%q is not a command of `%s`", e.Word, where)
	case cmdline.UnknownFlag:
		return fmt.Sprintf("`%s` has no flag %s", where, e.Word)
	default: // cmdline.MissingValue
		return fmt.Sprintf("%s needs a value", e.Word)
	}
}
```

This program shows the help for any `-h`, and for a line that ends at a group. It does not check repeats, bool words or the argument count; a real caller does.

```console
$ prog items rm 12 --force
run "items delete" flags=[{force true 3}] args=["12"]
$ prog -c x.yaml items ls --sort=-id
run "items list" flags=[{config x.yaml 0} {sort -id 4}] args=[]
$ prog items
help of "items"
$ prog items lst
Error: "lst" is not a command of `prog items`.
$ prog items list --sort
Error: --sort needs a value.
$ prog --force items delete 12
Error: `prog` has no flag --force.
```

### Wire the entry point and the scripts

`run` above calls `Serve` before anything else, so `prog __complete …` never reads a config or does work. The `completion` command calls `script.Write` with the root's name:

```console
$ prog completion tcsh
Error: completion takes bash, zsh, fish or powershell.
```

### Complete from the line

```go
// itemIDs offers the IDs from the config file named on the line so far.
func itemIDs(line *cmdline.Match, prefix string) ([]string, cmdline.Directive) {
	file := "prog.yaml"
	if v := line.Values("config"); v != nil {
		file = v[len(v)-1]
	}
	var out []string
	for _, id := range loadIDs(file) {
		if strings.HasPrefix(id, prefix) {
			out = append(out, id)
		}
	}
	return out, cmdline.NoFiles
}
```

A program may forbid I/O at Tab time; Headscale does (D1).

A Completer runs inside the Tab request. The library sets no time limit on it and does not catch a panic.

### Test a CLI built on the library

**`Parse` is a pure function of the tree and argv, and so is `Complete` when its Completers are. A table test is the whole harness.** `Serve` writes to an `io.Writer`, so the exact answer that a script reads is testable without a shell. `Check` belongs in a test, so a tree that `Parse` would read in two ways fails CI.

```go
func TestTree(t *testing.T) {
	if err := cmdline.Check(tree()); err != nil {
		t.Fatal(err)
	}
}

func TestTab(t *testing.T) {
	for _, tc := range []struct{ line, want string }{
		{"items ", "list\tList items\ndelete\tDelete an item\n:4\n"},
		{"items list --sort ", "id\nname\n:4\n"},
		{"-c other.yaml items rm ", "21\n22\n:4\n"},
	} {
		var b bytes.Buffer
		cmdline.Serve(&b, tree(), append([]string{"__complete"}, strings.Split(tc.line, " ")...))
		if b.String() != tc.want {
			t.Errorf("%q: got %q", tc.line, b.String())
		}
	}
}
```

A tree can be shared by tests that run in parallel (M7). What a user sees in a shell needs the built binary and the shell; see [Real shells](#real-shells).

### The API

`go doc -all` of the prototype, with the doc comments cut to the field lines:

```text
package cmdline // import "spike/cmdline"

func Check(root *Command) error
func Serve(w io.Writer, root *Command, args []string) bool
type Command struct {
	Name     string
	Aliases  []string
	Help     string      // one line; Tab shows it next to the name
	Flags    []Flag
	Args     []Completer // Tab for the n-th positional; nil entries offer nothing
	Commands []*Command
}
type Completer func(line *Match, prefix string) ([]string, Directive)
    func Words(words ...string) Completer
type Directive int
    const Failed, NoSpace, NoFiles, FilterExt, FilterDirs, KeepOrder Directive = 1, 2, 4, 8, 16, 32
    func Complete(root *Command, words []string, cur string) ([]string, Directive)
    func Files(*Match, string) ([]string, Directive)
type Error struct {
	Kind ErrorKind
	Path []string // the command reached, as in Match.Path
	Word string
	At   int      // the index in argv of the word
}
    func (e *Error) Error() string
type ErrorKind int
    const UnknownCommand, UnknownFlag, MissingValue ErrorKind = 1, 2, 3
type Flag struct {
	Name     string    // long name, without dashes
	Short    rune      // one letter, or 0
	Bool     bool      // takes no value: "--x" reads "true", "--x=v" reads "v"
	Repeat   bool      // Tab offers it again once given; Parse keeps every occurrence of every flag
	Help     string    // one line; Tab shows it next to the name
	Complete Completer // Tab for the value; nil offers nothing, Files offers file names
}
type Given struct {
	Name  string // the flag's long name, whatever spelling was typed
	Value string // as typed; "true" for a bool given bare
	At    int    // the index in argv of the flag word
}
type Match struct {
	Command *Command
	Path    []string // names from the root (not aliases), root excluded
	Flags   []Given  // every flag given, in the order typed
	Args    []string // positionals, in order
	ArgAt   []int    // the index in argv of each positional
}
    func Parse(root *Command, argv []string) (*Match, error)
    func (m *Match) Values(name string) []string

package script // import "spike/cmdline/script"
func Write(w io.Writer, shell, program string) error
```

## Tests

**Four kinds of test hold this specification**: the library's own table tests, the corpus of upstream edge cases, fuzz targets, and a job that drives Tab in real shells. The [rule index](#rule-index) names the tests of each rule.

### The library's own tests

In `cmdline_test.go` and `script/script_test.go`, on a small tree with every shape that matters: root flags that some commands also take, a group two deep, aliases, bools, a value flag with a Completer, a repeatable flag, a file flag, a non-ASCII short, positionals with and without a Completer, and help texts.

| Test                | Rows                | Holds                                                                                                                                                                                             |
| ------------------- | ------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `TestParse`         | P01–P59             | the grammar and the walk; each row also checks that argv is not changed                                                                                                                           |
| `TestErrorText`     | 4                   | the default text (M6)                                                                                                                                                                             |
| `TestComplete`      | T01–T58             | Tab, through `Serve`                                                                                                                                                                              |
| `TestServe`         | S01–S04             | the protocol                                                                                                                                                                                      |
| `TestPure`          | 1                   | the tree is not changed (M7)                                                                                                                                                                      |
| `TestOrder`         | O1–O6, and `Values` | the order and positions of flags, the match next to an error                                                                                                                                      |
| `TestCheck`         | K0, K1–K8 (17 rows) | the tree check                                                                                                                                                                                    |
| `TestContract`      | W8, C2, C6, S5, S6  | what the library does with a tree that `Check` refuses, and with a failing writer                                                                                                                 |
| `TestStdlibOnly`    | 1                   | the core imports only the standard library (`go list -deps`)                                                                                                                                      |
| `FuzzParse`         | 3 seeds             | no panic; positionals in argv order; flags in order, each at a flag word, before the error; a match survives a round trip through its canonical line; `Complete` does not panic on the same words |
| `TestDirectiveBits` | 6                   | the bits equal cobra's (S7)                                                                                                                                                                       |
| `TestWrite`         | 5                   | four scripts call `__complete`; another shell is an error (S8)                                                                                                                                    |

`FuzzParse` ran 60 seconds, 38 million executions, with no failure. `-race -count=3` passes on the library and on Headscale's layer.

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

**On the prototype: 343 cases match the source, 123 match the recorded decision, and 19 match neither.** Each of the 19 is named, with its reason, in the driver's `explained` table, and an unexplained case fails the run: empty list values (5), Tab after a refused word (4), files for a path flag (3), no Tab values for bools (3), `--` at a group (1), and byte-wise flag words and kept quotes (3).

**Licence.** A row re-expresses behaviour: argv and an expected outcome, in this project's own form, on its own tree. No upstream code, comment or issue text is copied. Re-expressed rows need no notice from any source; the `src` column is kept for attribution and for the yearly review. The test file carries one line: "Rows re-express behaviour recorded in the tests and trackers named in `src`." Rows from GPL and LGPL sources are facts only, with no text. This is the ordinary reading for test vectors, not legal advice.

**Upkeep.** Once a year, or at a cobra or pflag release if that is rarer: read the changes to the upstream test files since the recorded revision, and search the trackers with the recorded queries. A new IN item becomes a row; an OUT item becomes an inventory line with a reason. A bug report against this library becomes a row with the issue as its source. Measured pace over 12 months: about one pflag change about this grammar, none in cobra.

**Each row carries the library's expectation: a match or a `*cmdline.Error`.** An expectation of a caller, such as "flag given twice" or "help", lives with the caller's tests. Today the 485 rows run through Headscale's layer; splitting them is implementation work.

### Fuzz targets

| Target                | Property                                                                                                                                                                                                       | Last run                    |
| --------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------- |
| `FuzzParse` (library) | see the table above                                                                                                                                                                                            | 60 s, 38 M executions, pass |
| `FuzzRun`             | no panic, no hang, the same result twice, output bounded by input, a round trip through the canonical line, a trailing `--` on a leaf line changes nothing, flags at a group may move behind the command words | 3 min, 10.5 M, pass         |
| `FuzzLeaf`            | a value comes back byte for byte in all four spellings; after `--` every word is a positional; where flags stand among positionals changes nothing                                                             | 3 min, 2.6 M, pass          |
| `FuzzTab`             | no panic, no hang, the same answer twice, at most 64 candidates; no candidate that the run then refuses because of that candidate, as an unknown command or flag, a repeat or a bad bool word                  | 3 min, 0.46 M, pass         |

argv in `FuzzRun`, `FuzzLeaf` and `FuzzTab` is the fuzz input split at NUL, at most 64 words and 16 KiB, and a call that takes more than 1 second fails. These three run through Headscale's layer. The failing inputs that found bugs are kept as seeds, so `go test` replays them.

### Real shells

**A CI job drives Tab in real shells against the built binary** (decision D21). It runs on every pull request that changes `go.mod` or the CLI, so a cobra bump shows any change in the scripts. It types each line of a fixed list into interactive bash, zsh and fish in a pseudo-terminal, presses Tab once, and reads back the edited line. It also asks fish with `complete -C` and PowerShell with `TabExpansion2`. The list for Headscale has 41 lines ([`lines.txt`](research/spikes/final/headscale/shell/lines.txt)). The harness is about 270 lines of Python and shell, and runs in under two minutes in the nix shells.

**The job is the only test that sees the scripts and the protocol together.** In the bake-off, the `--x=v` form was broken in four of six candidates while every in-process test passed.

### From a rule to its test

The [rule index](#rule-index) lists, for each rule, its section and its tests. `P`, `T`, `O`, `K` and `S` rows are the library's own tests. `kit:` rows are the Headscale conformance kit (kit v3: 235 required rows and 28 rows for the assistant's calls, all passing). `corpus:` rows are corpus cases. `sh:` entries are lines of the real-shell job. `kit:` and `sh:` tests run on Headscale's tree; they are examples of a caller's tests.

## Limits, platforms and compatibility

### Limits

**The library sets no limit** on the number of words, the length of a word, the depth of the tree or the number of candidates. `Parse` and `Complete` read each word once. `Check` compares the flags that can be typed at a command in pairs.

**A Completer that calls a server is specified when the first one is built**: its time limit, and what Tab shows when the call fails.

Measured on the 12-leaf test tree: one `__complete` call took 2.1 to 4.8 ms, process start included. The fuzz targets test argv up to 64 words and 16 KiB.

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

**The promise is written when the package moves to its own repository.** It will cover the exported API in [The API](#the-api), the rules L, V, B1, B2, B4, B6, R1, W, C, M1–M7, X5, X8, T, S1–S9 and K, and the protocol, which is cobra's.

### Where the package lives

**The library starts as a package inside the Headscale module** (decision D25). It stands at the top level of the module, next to `cmd` and `hscontrol`: `github.com/juanfont/headscale/cmdline` with the working name (decision D39). It is not under `internal/`, so other programs can import it. A test fails when the core imports anything outside Go's standard library; `script` is the exception. It moves to its own repository when a second real user exists. Then only Headscale's one adapter file and its `main` change their import.

**The name is the maintainer's to choose.** The working name is `cmdline`.

## Why Headscale has its own parser

This part gives the research in short. The detail is in [`research/`](research/README.md): [`DECISIONS.md`](research/DECISIONS.md), [`INTERVIEW.md`](research/INTERVIEW.md), [`referee.md`](research/referee.md), [`edge-corpus.md`](research/edge-corpus.md), [`differential.md`](research/differential.md), [`library-design.md`](research/library-design.md), [`discovery.md`](research/discovery.md), [`deep-own.md`](research/deep-own.md) and [`rules.md`](research/rules.md).

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

Before he chose, the maintainer asked three things. Each was measured.

**1. "What about all the information and knowledge grandfathered into the other ones?"** The corpus answers it ([The corpus of upstream edge cases](#the-corpus-of-upstream-edge-cases)). On 360 parse cases the own grammar had no gap: it matched the source or a recorded decision on all but three, and those three were open questions, not bugs. pflag's own tests and tracker found nothing. The Tab answerer had three real bugs, all of a kind cobra learnt from its users: it offered a flag already given, it completed flag values after `--`, and a bare positional `o` opened the values of `-o`. A differential run of 3 million generated lines against pflag and cobra found no line where pflag reads a correct line correctly and the own grammar does not. On 38 % of the lines only cobra differed, almost always because of its command walk and its help handling, which the decisions refuse.

**What a corpus cannot carry over:** users who find bugs (6,072 issue titles across four trackers are years of reports; after the switch, Headscale's users are the only reporters); shell and platform behaviour (cobra's tracker has 227 shell-specific titles); and future upstream fixes, which no longer reach this parser (about one relevant pflag change in the last year).

**2. "If we are to do our own, we will have a lot of test code that needs to be owned, can we get edge cases from the ones we need?"** The edge cases are the corpus above. The measured size: the library core is 359 lines and `script` 20; the library's tests are 427 lines; the corpus is 485 data rows and a 328-line driver; the fuzz targets are 255 lines; the shell harness is about 270 lines and 41 Tab lines. Upkeep is the yearly corpus review, about an afternoon.

**3. "Can we keep our parser and structure separate from the headscale layer so it can be reused elsewhere as a library?"** Yes, and the edge is where 001 already put it. Everything the kit's builder did stays Headscale's. Headscale's adapter is 94 lines (tree conversion, the error hand-over, and its list convention for Tab). A second, unrelated program (`kv`, in [`research/spikes/lib-toy/`](research/spikes/lib-toy/)) was written on the same API. It needed four things that the first version lacked, and wanted a fifth. Two were added: a Completer that sees the line, and help texts on candidates. Three were not: groups of short bools (`-vv`), a negative number as a positional (`incr n -1`), and Tab for a variable number of positionals. Being a library cost about 100 lines over a parser written only for Headscale, and an exported API that is a contract. No existing library does this exact job; each lacks two of: tree as data, interspersed GNU-style flags, typed errors, and an answer to cobra's protocol.

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

### What nobody measured

- PowerShell in an interactive console, macOS bash 3.2, Windows, zsh frameworks.
- The real tree of about 60 commands. Every number above is on a tree of 12 leaves. The differential run should run once on the real tree when the specs exist.
- A script saved from today's cobra-built Headscale against the new binary. That it keeps working rests on the protocol being the same, not on a test.
- The real-shell job in GitHub's CI. It ran only in local nix shells.
- A Completer that calls a server (live names); see [Limits](#limits).

## Decision log

The maintainer made these decisions. Decision numbers are those of [`research/DECISIONS.md`](research/DECISIONS.md); [`research/INTERVIEW.md`](research/INTERVIEW.md) has each question with both alternatives. Decisions that are only Headscale's are in [001](001-cli.md#decision-log); they are here only where the library must make them possible.

| Decision                                                                                                                                   | Rejected                                                         | Why                                                                                                                                                                                                          |
| ------------------------------------------------------------------------------------------------------------------------------------------ | ---------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| D24: a parser of Headscale's own, as a small library: flag reader, command lookup, typed usage errors, Tab answerer; standard library only | cobra; kong; urfave/cli v3; creachadair/command                  | only parsing and Tab were left for a framework; the own grammar alone passed every required case as delivered, with no workaround; see [Why Headscale has its own parser](#why-headscale-has-its-own-parser) |
| D23: the scripts come from cobra's generators; only `script` imports cobra. **Against the recommendation**                                 | copy cobra's scripts into the tree and patch them                | a fault in a script is fixed upstream, not in a copy. The cost was measured: the fish and bash faults stay until cobra releases a fix                                                                        |
| D1: the binary answers Tab through a hidden entry point; it reads no config and calls no server                                            | lists baked into the script                                      | one source, the tree; values can come from the line later                                                                                                                                                    |
| D2: bash, zsh and fish are required; PowerShell is a stretch goal                                                                          | PowerShell and a Windows build required                          | the maintainer widened the option: PowerShell comes with cobra's generators                                                                                                                                  |
| D21: Tab is tested in real shells in CI                                                                                                    | Go tests only                                                    | the protocol and script faults are visible only in a shell                                                                                                                                                   |
| D4: the library reports mistakes as data; the caller writes all text                                                                       | the library writes the text                                      | the caller owns every sentence                                                                                                                                                                               |
| D35: the first mistake on the line is reported, whatever its kind; the parser hands over the flags in order with their positions           | parser mistakes first, then value mistakes                       | one rule for every kind; it needs `Given.At`, `Error.At` and the match next to an error                                                                                                                      |
| D20: the word after a value flag is always its value                                                                                       | a known flag name is never a value                               | `--sort -last-seen` needs a value that starts with `-`                                                                                                                                                       |
| D11: `-ojson` and groups of shorts are best effort. The library refuses them                                                               | the library accepts them, as pflag does                          | D11 allows either. Refusing needs no code. A reader that takes attached short values is how pflag comes to read `-output json` as `-o utput`                                                                 |
| D9, D26: a bool takes `--x`, `--x=true`, `--x=false`; only `true` and `false`, in lower case; no `--no-x`                                  | Go's bool words; `--no-x`                                        | the library returns the word; the caller checks it                                                                                                                                                           |
| D15, D6: each flag once, except `--filter`; a list is one comma-separated value                                                            | the last value wins; repeated list flags                         | the caller decides; the library keeps every occurrence and has `Repeat` only for Tab                                                                                                                         |
| D3: `-c` and `-o` before or after the subcommand                                                                                           | only after the command                                           | "global" is a flag declared on the root and on each command that takes it (W4)                                                                                                                               |
| D8, D10: no `help` command; a group alone shows its help                                                                                   | a `help` command; help on stderr                                 | the library has no implicit command and returns a match at the group                                                                                                                                         |
| D19: an error on the line wins over `-h`                                                                                                   | the help wins                                                    | the library gives `-h` no meaning (X8), so the order of reading decides                                                                                                                                      |
| D16: Tab offers an alias only when no name fits                                                                                            | aliases always                                                   | real names first                                                                                                                                                                                             |
| D27: a path flag offers files on Tab; other free text offers nothing                                                                       | nothing for every value flag                                     | `Files` and `nil` Completers                                                                                                                                                                                 |
| D28: candidates carry their help text                                                                                                      | bare words                                                       | the `Help` fields                                                                                                                                                                                            |
| D29: a lone `-` or `--` lists long names only                                                                                              | long and short names, as cobra                                   | shorter lists                                                                                                                                                                                                |
| D30: Tab after a mistake keeps completing from the last command it understood                                                              | nothing; files, as cobra                                         | a typo can be fixed later on the line                                                                                                                                                                        |
| D25: a package inside the Headscale repository, with a test that keeps other imports out; its own repository when a second user exists     | its own repository now                                           | one user; a second repository costs releases and a second CI before anyone needs them                                                                                                                        |
| D39: the package stands at the top level of the module, `github.com/juanfont/headscale/cmdline` (working name)                             | under `cmd/headscale/cli/`, next to its one user                 | it is visibly a library and not a part of the CLI; another program imports one plain path; the move later changes one import                                                                                 |
| D40: the faults found in cobra's scripts are not reported upstream now                                                                     | the assistant drafts three reports and the maintainer posts them | the maintainer's choice; the faults and their reproductions stay in [Known faults in the scripts](#known-faults-in-the-scripts)                                                                              |
| D31: the specification is its own document                                                                                                 | a section of 001                                                 | 001 keeps what is Headscale's                                                                                                                                                                                |
| D36: all of the research goes into the pull request, under `research/`. **Against the recommendation**                                     | a summary here and only the data that tests need                 | the maintainer wants the whole record kept                                                                                                                                                                   |
| Fact: `--` ends the flags; flags and positionals mix; no abbreviations; one spelling per flag                                              | —                                                                | from 001 as written                                                                                                                                                                                          |
| Fact: pflag is not the reader and not a standing test oracle                                                                               | pflag under the dispatcher; a differential test in CI            | a differential test against pflag would have caught none of the bugs found                                                                                                                                   |
| Fact: no variadic positionals                                                                                                              | a `Rest` Completer                                               | no command in Headscale's tree takes a variable number of arguments                                                                                                                                          |

## Open points

### Not decided

- **The name.** (a) A plain descriptive name (`cmdline`): it says what the package does, but many packages share it. (b) A short, distinct name: easy to search, but it says less.

### Calls not confirmed by the maintainer

The assistant settled these to make the rules complete. Each one is in the text above. The maintainer can confirm or change each one while reading.

| Call                                                                                                                                  | Where                                            | The other choice                                                                              |
| ------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------ | --------------------------------------------------------------------------------------------- |
| A Completer gets the parsed line (`*Match`), not only the prefix                                                                      | T14                                              | the prefix only; a later change breaks every caller                                           |
| `--` where a command word is expected is an unknown command                                                                           | L7                                               | drop it and read on, as cobra                                                                 |
| `-` and `""` at a group are unknown commands                                                                                          | L3, L4                                           | skip them, as cobra's walk does                                                               |
| Tab keeps completing after `-h`, `--help` and `--version`                                                                             | T15                                              | stop, as cobra                                                                                |
| no Tab values for bools (`--force=<Tab>` offers nothing)                                                                              | T5                                               | offer `true` and `false`                                                                      |
| `Check(root)` exists and refuses K1–K6                                                                                                | K1–K6                                            | no check in the library; the caller's specs check it                                          |
| no compatibility promise while the package is in Headscale's repository                                                               | [Compatibility](#compatibility)                  | a promise from the start                                                                      |
| a flag word is any word of two or more bytes that starts with `-`; names are compared byte for byte; shorts are ASCII in a valid tree | L1, L8, K4                                       | Unicode rules                                                                                 |
| flags in scope may stand between group words                                                                                          | W6                                               | only before the first command word or at the leaf                                             |
| at a group, Tab lists the group's own flags, not its scope                                                                            | T6                                               | the scope                                                                                     |
| candidates in declaration order, never sorted, duplicates kept                                                                        | T11                                              | sorted and unique                                                                             |
| an alias carries its command's help text                                                                                              | T12                                              | no help on aliases                                                                            |
| the library's own answers carry `NoFiles` and never `NoSpace`                                                                         | T13                                              | a setting per command                                                                         |
| write errors in `Serve` are dropped; a newline in a candidate is not checked                                                          | S5, S6                                           | an error from `Serve`; cut at the newline, as cobra                                           |
| Tab offers `--version` after another root flag, though the layer then refuses it                                                      | T18                                              | hide `--version` once another flag is given: the library would need the caller's rule         |
| the corpus is reviewed once a year                                                                                                    | [The corpus](#the-corpus-of-upstream-edge-cases) | only bug reports feed it                                                                      |
| a file positional is marked like a path flag, and Tab offers files (001's open question 6)                                            | T9                                               | nothing for positionals                                                                       |
| `-h` may stand before the subcommand, like `-c` and `-o` (001's open question 4)                                                      | W4                                               | only after the command                                                                        |
| a wrong argument count has the end of the line as its position, after every other mistake (Headscale's layer)                         | X4                                               | the first extra positional; then the builder must know `--help` before the parser has read it |
| "`--version` not alone" stands at the second of the two words (Headscale's layer)                                                     | X2                                               | always at `--version`                                                                         |
| several mistakes in one word: not taken, repeat, bad value, not alone (Headscale's layer)                                             | X3                                               | no order; D35 reports one mistake, so one is needed                                           |
| the sets of `Check`: names not empty, no space or control byte, no leading `-`, no `=` in a flag name; shorts printable ASCII         | K3, K4                                           | stricter: `[a-z0-9-]` for names, letters or digits for shorts                                 |
| the real-shell job runs on every pull request that changes `go.mod` or the CLI                                                        | [Real shells](#real-shells)                      | only on CLI changes, and by hand on a cobra bump                                              |
| `Check` refuses a child of the root named `__complete` or `__completeNoDesc`, and a `Help` with a line break                          | K7, K8                                           | leave both to the caller                                                                      |

## Rule index

The groups: L, V, B, R, W, C, M, X are the parser (X2–X4, X6 and X7 are Headscale's rules, in 001); T is Tab; S is the protocol; K is the tree check; E is the edge between the library and the caller. `P`, `T`, `O`, `K`, `S` tests are the library's own; `kit:`, `corpus:`, `sh:` and the fuzz targets are described in [Tests](#tests).

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
| L11  | [One word](#one-word)                                                    | P13, P14, P18–P21, kit:X02, kit:X05, kit:F05/F28/X01 (OBSERVE)                                                                                                                    |
| L12  | [One word](#one-word)                                                    | P22, kit:X03–X05                                                                                                                                                                  |
| L13  | [One word](#one-word)                                                    | P23, kit:E09–E12                                                                                                                                                                  |
| V1   | [Flag values](#flag-values)                                              | kit:F01–F04, kit:F06, kit:F11–F13, P25, P26, P37                                                                                                                                  |
| V2   | [Flag values](#flag-values)                                              | P27–P31, kit:F14–F17, kit:F26, kit:F27, kit:O01, kit:O02, kit:G12, FuzzLeaf                                                                                                       |
| V3   | [Flag values](#flag-values)                                              | P32–P34, O4, kit:E13–E15                                                                                                                                                          |
| V4   | [Flag values](#flag-values)                                              | P25, P36, P29                                                                                                                                                                     |
| V5   | [Flag values](#flag-values)                                              | P19, kit:F05 (OBSERVE)                                                                                                                                                            |
| B1   | [Bool flags](#bool-flags)                                                | P35, kit:B11, corpus:pflag-034                                                                                                                                                    |
| B2   | [Bool flags](#bool-flags)                                                | P36, P40                                                                                                                                                                          |
| B3   | [Bool flags](#bool-flags)                                                | kit:B04, kit:B06–B10, kit:V12                                                                                                                                                     |
| B4   | [Bool flags](#bool-flags)                                                | kit:B03, corpus:issues-058                                                                                                                                                        |
| B5   | [Bool flags](#bool-flags)                                                | kit:B02, kit:O05, kit:V10                                                                                                                                                         |
| B6   | [Bool flags](#bool-flags)                                                | P20, kit:F28 (OBSERVE)                                                                                                                                                            |
| R1   | [A flag given more than once](#a-flag-given-more-than-once)              | P38–P40, O1                                                                                                                                                                       |
| R2   | [A flag given more than once](#a-flag-given-more-than-once)              | kit:B05, kit:G11, kit:L02, kit:L03, kit:R01–R06, kit:V09                                                                                                                          |
| R3   | [A flag given more than once](#a-flag-given-more-than-once)              | kit:F19, kit:L08                                                                                                                                                                  |
| R4   | [A flag given more than once](#a-flag-given-more-than-once)              | kit:L01, kit:L02                                                                                                                                                                  |
| R5   | [A flag given more than once](#a-flag-given-more-than-once)              | kit:L04–L07, kit:F22, kit:H21                                                                                                                                                     |
| R6   | [A flag given more than once](#a-flag-given-more-than-once)              | kit:L09–L11                                                                                                                                                                       |
| R7   | [A flag given more than once](#a-flag-given-more-than-once)              | kit:L12, kit:P07                                                                                                                                                                  |
| R8   | [A flag given more than once](#a-flag-given-more-than-once)              | kit:L13, kit:F11, kit:F12                                                                                                                                                         |
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
| C6   | [The command walk](#the-command-walk)                                    | P50, TestContract C6                                                                                                                                                              |
| C7   | [The command walk](#the-command-walk)                                    | P01, P53, kit:T12–T15                                                                                                                                                             |
| C8   | [The command walk](#the-command-walk)                                    | P55, kit:A04, kit:A05                                                                                                                                                             |
| C9   | [The command walk](#the-command-walk)                                    | P56, kit:E16–E20                                                                                                                                                                  |
| C10  | [The command walk](#the-command-walk)                                    | P48, P49                                                                                                                                                                          |
| C11  | [The command walk](#the-command-walk)                                    | P57                                                                                                                                                                               |
| M1   | [What Parse returns](#what-parse-returns)                                | P25, P26, kit:F11                                                                                                                                                                 |
| M2   | [What Parse returns](#what-parse-returns)                                | O1, O3–O6, TestOrder Values, FuzzParse (order and positions)                                                                                                                      |
| M3   | [What Parse returns](#what-parse-returns)                                | P09, O1, O2                                                                                                                                                                       |
| M4   | [Usage errors](#usage-errors)                                            | every ERR row of TestParse, FuzzParse                                                                                                                                             |
| M5   | [What Parse returns](#what-parse-returns)                                | O3–O6, FuzzParse (flags before the error)                                                                                                                                         |
| M6   | [Usage errors](#usage-errors)                                            | TestErrorText                                                                                                                                                                     |
| M7   | [What Parse returns](#what-parse-returns)                                | TestParse (argv unchanged), S05, kit:I01, `-race -count=3`                                                                                                                        |
| M8   | [Several mistakes on one line](#several-mistakes-on-one-line)            | kit rows of every kind                                                                                                                                                            |
| X1   | [Several mistakes on one line](#several-mistakes-on-one-line)            | kit:E21–E26, kit:P01–P11                                                                                                                                                          |
| X2   | [001, Errors on the command line](001-cli.md#errors-on-the-command-line) | P46, O3–O6, kit:P01–P10, kit:E22, kit:E23                                                                                                                                         |
| X3   | [001, Errors on the command line](001-cli.md#errors-on-the-command-line) | kit:R04, kit:P12                                                                                                                                                                  |
| X4   | [001, Errors on the command line](001-cli.md#errors-on-the-command-line) | kit:E24, kit:P05, kit:A01, kit:H06, kit:H23                                                                                                                                       |
| X5   | [Several mistakes on one line](#several-mistakes-on-one-line)            | kit:P01–P04, O3–O5                                                                                                                                                                |
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
| T9   | [What Tab offers](#what-tab-offers)                                      | T22–T25, T30, T31, T48–T50, kit:C15–C17, kit:N08–N14, kit:Q25; sh:"headscale policy set ", sh:"headscale nodes delete o "                                                         |
| T10  | [Matching, order and help texts](#matching-order-and-help-texts)         | T52                                                                                                                                                                               |
| T11  | [Matching, order and help texts](#matching-order-and-help-texts)         | T03, T09                                                                                                                                                                          |
| T12  | [Matching, order and help texts](#matching-order-and-help-texts)         | T01–T06, T09, kit:Q06–Q08; sh:"headscale nodes " (zsh, fish, pwsh, bash)                                                                                                          |
| T13  | [Directives and files](#directives-and-files)                            | T01, T47, T48, T30                                                                                                                                                                |
| T14  | [The Completer](#the-completer)                                          | T47, T48, T51, S04                                                                                                                                                                |
| T15  | [What Tab never does](#what-tab-never-does)                              | T43, T44, kit:Q28                                                                                                                                                                 |
| T16  | [How Tab reads the line](#how-tab-reads-the-line)                        | every kit completion row checks "a command ran"; S05                                                                                                                              |
| T17  | [How Tab reads the line](#how-tab-reads-the-line)                        | FuzzTab, kit:I01                                                                                                                                                                  |
| T18  | [What Tab never does](#what-tab-never-does)                              | FuzzTab (extended property)                                                                                                                                                       |
| S1   | [The hidden entry point](#the-hidden-entry-point)                        | S01                                                                                                                                                                               |
| S2   | [The hidden entry point](#the-hidden-entry-point)                        | S02                                                                                                                                                                               |
| S3   | [The hidden entry point](#the-hidden-entry-point)                        | S02, S03, every T row                                                                                                                                                             |
| S4   | [The hidden entry point](#the-hidden-entry-point)                        | S03                                                                                                                                                                               |
| S5   | [The hidden entry point](#the-hidden-entry-point)                        | TestContract S5                                                                                                                                                                   |
| S6   | [The hidden entry point](#the-hidden-entry-point)                        | TestContract S6                                                                                                                                                                   |
| S7   | [The scripts](#the-scripts)                                              | TestDirectiveBits                                                                                                                                                                 |
| S8   | [The scripts](#the-scripts)                                              | TestWrite, kit:S-bash … S-powershell                                                                                                                                              |
| S9   | [The scripts](#the-scripts)                                              | the shell run                                                                                                                                                                     |
| S10  | [Known faults in the scripts](#known-faults-in-the-scripts)              | sh lines `--columns id,na`, `--tags tag:ci,tag:p`, `--columns=id,na`, `--filter=ow`, `nodes list `, `--config=`                                                                   |
| K1   | [A valid tree](#a-valid-tree)                                            | K1 (two rows), headscale `TestCheck`                                                                                                                                              |
| K2   | [A valid tree](#a-valid-tree)                                            | K2                                                                                                                                                                                |
| K3   | [A valid tree](#a-valid-tree)                                            | K3 (two rows)                                                                                                                                                                     |
| K4   | [A valid tree](#a-valid-tree)                                            | K4 (four rows), Check refuses the test tree's `-ø`                                                                                                                                |
| K5   | [A valid tree](#a-valid-tree)                                            | K5                                                                                                                                                                                |
| K6   | [A valid tree](#a-valid-tree)                                            | K6 (three rows)                                                                                                                                                                   |
| K7   | [A valid tree](#a-valid-tree)                                            | K7 (two rows)                                                                                                                                                                     |
| K8   | [A valid tree](#a-valid-tree)                                            | K8 (two rows)                                                                                                                                                                     |
| E1   | [Who does what](#who-does-what)                                          | the library's own tests                                                                                                                                                           |
| E2   | [Who does what](#who-does-what)                                          | kit v3; `lib-toy` showed another set                                                                                                                                              |
| E3   | [Who does what](#who-does-what)                                          | TestStdlibOnly                                                                                                                                                                    |
| E4   | [Who does what](#who-does-what)                                          | kit:G01–G15, kit:Q06–Q08, kit:V04, headscale `TestCheck`                                                                                                                          |
| E5   | [Who does what](#who-does-what)                                          | kit:Q01–Q05, kit:C16, kit:C17                                                                                                                                                     |
| E6   | [Who does what](#who-does-what)                                          | kit:C12–C14, kit:C18–C20, kit:N19, kit:N20, kit:Q33–Q35; sh:"headscale nodes list --sort -la", sh:"headscale nodes list --columns id,-ho", sh:"headscale nodes list --filter -ow" |
| E7   | [Who does what](#who-does-what)                                          | **not modelled** in the kit                                                                                                                                                       |
| E8   | [Who does what](#who-does-what)                                          | **not modelled** beyond R6, R7                                                                                                                                                    |

## References

- [001](001-cli.md): the CLI, which is built on this library. Its parts [How flags are written](001-cli.md#how-flags-are-written), [Errors on the command line](001-cli.md#errors-on-the-command-line), [Our layer, not the framework's](001-cli.md#our-layer-not-the-frameworks) and [Shell completion](001-cli.md#shell-completion) state what a Headscale user sees.
- [002](002-api.md): the API that the CLI calls.
- [`research/`](research/README.md): every note, the decisions, the interview record, the corpus and the test builds.
    - [`research/rules.md`](research/rules.md): the numbered rules, each with its source and its test.
    - [`research/spikes/final/`](research/spikes/final/): the prototype (`cmdline/`), Headscale's adapter and shell job (`headscale/`), the corpus driver (`corpus/`), and the fuzz targets (`diff/`).
    - [`research/spikes/corpus/corpus.jsonl`](research/spikes/corpus/corpus.jsonl): the corpus, and `inventory/` with all 1,628 rows screened.
    - [`research/spikes/v2/shell/`](research/spikes/v2/shell/): the real-shell harness.
- cobra v1.10.2: `completions.go`, `active_help.go`, `bash_completionsV2.go`, `zsh_completions.go`, `fish_completions.go`, `powershell_completions.go` ([spf13/cobra](https://github.com/spf13/cobra/tree/v1.10.2)).
- cobra issues named here: [#2243](https://github.com/spf13/cobra/issues/2243), [#2527](https://github.com/spf13/cobra/issues/2527). pflag: [#541](https://github.com/spf13/pflag/issues/541).

[#3375]: https://github.com/juanfont/headscale/pull/3375
