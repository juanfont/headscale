# The interview: every question, both alternatives, and the maintainer's answer

Date: 2026-11-17. This is the record of the "reverse interview" for the CLI framework work.
`DECISIONS.md` holds the result of each answer as a rule. This file holds what was asked, what
the alternative was, and the maintainer's own words where he did not pick an option as written.
"(R)" marks the option the assistant recommended.

## The request

> ok, next, based on the cli proposal. I want you to set up some research agents to validate if
> cobra is still the correct CLI framework for us. We have a pretty comprehensive spec and
> requirements, This exercise should allow us to:
>
> - close any remaining requirements that are missing
> - ensure that we use the best tool available for the job
> - We no longer use viper, cobras config brother
>
> Use suitable opus, sonnet, medium, high to break down the research as needed, dont hold back.
>
> For missing requirements, unclear things, tradeoffs and the rest, continue to use the "reverse
> interview" where you ask me well defined questions and well researched and laid out
> alternatives.
>
> Here are projects I know about, check, but disqualify early and then deep research the best
> 3-4 projects. Do not limit yourself to this list, or the version in this list if you find other
> ones. And do look for other ones: spf13/cobra, urfave/cli, alecthomas/kong, alexflint/go-arg,
> devfacet/gocmd, mitchellh/cli, peterbourgon/ff/v4, creachadair/command

## Round 1 (after the screening started)

| #   | Question                                        | Option A                                                                                       | Option B                                  | Answer                                                                                                        |
| --- | ----------------------------------------------- | ---------------------------------------------------------------------------------------------- | ----------------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| D1  | Tab completion: who gives the list of values?   | (R) The binary answers through a hidden `__complete` command; reads no config, calls no server | Lists are baked into the generated script | A                                                                                                             |
| D2  | Which shells must `completion <shell>` support? | (R) bash, zsh, fish                                                                            | Also PowerShell and a Windows build       | In his words: "Powershell can be a stretch goal, if it is available in the one we pick, then we should do it" |
| D3  | May `-c` and `-o` stand before the subcommand?  | (R) Before or after                                                                            | Only after the command                    | A                                                                                                             |
| D4  | Who writes the text of a command-line error?    | (R) Our layer; the parser reports what is wrong as data                                        | The framework                             | A                                                                                                             |

## Round 2

| #   | Question                                       | Option A                                                | Option B                          | Answer                                                                                                                                                                                                                                          |
| --- | ---------------------------------------------- | ------------------------------------------------------- | --------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| D5  | Unknown command: suggest the nearest real one? | (R) Suggest, by spelling, from the specs                | Plain error                       | In his words: "suggest, can we hookin a table of "expected" mispellings? preauth, preauthkeys and so on points to auth keys". The assistant answered yes and proposed that each spec carries its own old names; he saw that and did not object. |
| D6  | May a list flag be repeated?                   | (R) Comma only; `--filter` is the one flag that repeats | Comma or repeated, as today       | A                                                                                                                                                                                                                                               |
| D7  | Should `headscale --version` work?             | (R) Yes: version line only, no update check             | Only the `version` command        | A                                                                                                                                                                                                                                               |
| D8  | A `help` command next to `--help`?             | (R) Only `--help` and `-h`                              | Add `headscale help [command...]` | A                                                                                                                                                                                                                                               |

## Round 3

| #   | Question                                                  | Option A                                                | Option B               | Answer                                                                                                                                                                    |
| --- | --------------------------------------------------------- | ------------------------------------------------------- | ---------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| D9  | Bool flags: are `--force=true` and `--force=false` valid? | (R) Yes; no `--no-force`                                | Only the bare flag     | A                                                                                                                                                                         |
| D10 | A group with no command (`headscale nodes`)?              | (R) Group help on stdout, exit 0                        | Help on stderr, exit 1 | A                                                                                                                                                                         |
| D11 | `-ojson` (short flag with attached value)?                | (R) Not required; only `-o json` and `-o=json` promised | Keep `-ojson` valid    | A, and later in his words: "this is kind of best effort, not requirement." So: no test fixes it either way and no workaround is spent on it.                              |
| D12 | Man pages?                                                | (R) No man pages                                        | Generate man pages     | In his words: "generate investigate, we are building a generator anyways, might as well investigate. But we want `man headscale` No? not some sort of guess where to go?" |

## Man pages (after the man page research)

| #   | Question                             | Option A                                                         | Option B                                     | Answer |
| --- | ------------------------------------ | ---------------------------------------------------------------- | -------------------------------------------- | ------ |
| D13 | Layout for about 60 commands?        | (R) One page `headscale(1)` with the full tree and every command | Top page plus about 10 group pages           | A      |
| D14 | How does the page get into packages? | (R) Generated, committed, CI fails on a difference and lints it  | Generated at package build time by a command | A      |

## Round 4 (after the test kit was built)

| #   | Question                                                       | Option A                                                                                | Option B                             | Answer                            |
| --- | -------------------------------------------------------------- | --------------------------------------------------------------------------------------- | ------------------------------------ | --------------------------------- |
| D15 | A flag given twice (`-o json -o yaml`, `--force --force`)?     | (R) Always an error; only `--filter` repeats                                            | Last one wins, as today              | A                                 |
| D16 | Does Tab offer aliases?                                        | (R) Only when no real name fits the prefix                                              | Always                               | A                                 |
| D17 | How does the input struct tell "not given" from "given empty"? | (R) A pointer field (`*string`)                                                         | A `command.Opt[T]` type with `Get()` | **B**, against the recommendation |
| D18 | How does a spec say it takes `--output` and `--config`?        | (R) Derived, with opt-outs (`ReadsConfig: true`; the debug tools opt out of `--output`) | Two explicit fields on every spec    | A                                 |

## Round 5 (while the referee worked)

| #   | Question                                                   | Option A                                          | Option B                           | Answer |
| --- | ---------------------------------------------------------- | ------------------------------------------------- | ---------------------------------- | ------ |
| D19 | `-h` together with a mistake (`nodes list --bogus -h`)?    | (R) The error wins                                | Help wins                          | A      |
| D20 | A flag value that looks like a flag (`--sort --filter x`)? | (R) Always a value                                | A known flag name is never a value | A      |
| D21 | Test Tab completion in real shells in CI?                  | (R) Yes: bash, zsh, fish against the built binary | Syntax check only                  | A      |
| D22 | The two debug test tools?                                  | (R) Command specs like every other command        | Hand-written, outside the specs    | A      |

## The framework, first time

| #   | Question                                             | Option A                                              | Option B                                    | Answer                                                                                                                                                                               |
| --- | ---------------------------------------------------- | ----------------------------------------------------- | ------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| —   | Framework?                                           | (R) Our own parser                                    | Stay on cobra                               | Not answered. In his words: "I would like it presented in chat the full breakdown of pros and cons of own (how that would look with examples), kong, creachadair and kong and cobra" |
| D23 | If own parser: where do the shell scripts come from? | (R) Copy cobra's scripts into our tree and patch them | Import cobra for the script generators only | **B**, against the recommendation                                                                                                                                                    |

After the breakdown, in his words:

> > -ojson
>
> this is kind of best effort, not requirement.
>
> > Own parser
>
> what about all the information and knowledge grandfathered into the other ones?
>
> if we are to do our own, we will have a lot of test code that needs to be owned, can we get
> edge cases from the ones we need? Can we keep our parser and structure separate from the
> headscale layer so it can be reused elsewhere as a library?

These three concerns started the third research round (`edge-corpus.md`, `differential.md`,
`library-design.md`).

## The framework, second time (with the three concerns measured)

| #   | Question                                              | Option A                                                                      | Option B                                     | Answer |
| --- | ----------------------------------------------------- | ----------------------------------------------------------------------------- | -------------------------------------------- | ------ |
| D24 | Framework?                                            | (R) Own parser, as a library                                                  | Stay on cobra                                | A      |
| D25 | Where does the library live at the start?             | (R) A package in the Headscale repo, with a test that keeps other imports out | Its own repository from day one              | A      |
| D26 | Which bool words are valid after `=`?                 | (R) Only `true` and `false`                                                   | All of Go's bool words (`1`, `t`, `TRUE`, …) | A      |
| D27 | Tab after a flag that takes a file path (`-c <Tab>`)? | (R) Offer files for flags marked as a path                                    | Offer nothing                                | A      |

## Tab details

| #   | Question                                 | Option A                          | Option B       | Answer |
| --- | ---------------------------------------- | --------------------------------- | -------------- | ------ |
| D28 | Do Tab candidates carry their help text? | (R) Yes, from the specs, as today | Bare words     | A      |
| D29 | Tab on a lone dash?                      | (R) Long names only               | Long and short | A      |
| D30 | Tab after a mistake earlier on the line? | (R) Keep completing               | Offer nothing  | A      |

## The spec

He asked: "Are we making a complete spec?"

| #   | Question                                                  | Option A                                           | Option B                      | Answer |
| --- | --------------------------------------------------------- | -------------------------------------------------- | ----------------------------- | ------ |
| D31 | Where is the complete spec of the parser library written? | (R) A new document `docs/proposals/003-cmdline.md` | A new section in `001-cli.md` | A      |

Then: "lets go", and "Make sure you capture all our decisions and research".

## Open questions of the 001 draft and the rule list

| #   | Question                                                                                                          | Option A                                                                   | Option B                                                    | Answer |
| --- | ----------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------- | ----------------------------------------------------------- | ------ |
| D32 | `hs-authkey alice --expiry 48h` passes `--expiry` twice (the script adds `--expiry 24h`); D15 makes that an error | (R) The script drops its default when the caller passes `--expiry` or `-e` | The script sets no expiry (contract change: 1 hour default) | A      |
| D33 | How does the input struct carry `--expiry` with `never` and `now`?                                                | (R) A type of its own, `command.Opt[command.Expiry]`                       | `command.Opt[string]`, parsed in `Run`                      | A      |
| D34 | `Local` is fixed, but two commands switch on a flag                                                               | (R) A function in the spec that reads the parsed input                     | The command makes its client in `Run`                       | A      |
| D35 | Two mistakes on one line: which error is shown?                                                                   | (R) The first on the line, left to right                                   | Parser errors first, then value errors                      | A      |

Open points of the 003 draft:

| #   | Question                                               | Option A                                                             | Option B                   | Answer                            |
| --- | ------------------------------------------------------ | -------------------------------------------------------------------- | -------------------------- | --------------------------------- |
| D38 | Approve the drafted sentences for command-line errors? | (R) Approve as drafted                                               | I want changes             | A                                 |
| D39 | Where does the library live inside the repository?     | (R) Top level of the module, `github.com/juanfont/headscale/cmdline` | Under `cmd/headscale/cli/` | A                                 |
| D40 | Report the three faults in cobra's scripts upstream?   | (R) The assistant drafts the reports, the maintainer posts them      | Not now                    | **B**, against the recommendation |

Capture:

| #   | Question                                             | Option A                                                          | Option B                                                                             | Answer                            |
| --- | ---------------------------------------------------- | ----------------------------------------------------------------- | ------------------------------------------------------------------------------------ | --------------------------------- |
| D36 | How much of the research goes into the pull request? | (R) Summary in 003 plus the data that tests need                  | Everything: also the raw notes and all test builds, under `docs/proposals/research/` | **B**, against the recommendation |
| D37 | Where do the raw notes and test builds live?         | (R) Moved to `~/git/headscale-cli-research`, local git, no remote | Left in `~/.cache`                                                                   | A                                 |

## Recommendations the maintainer did not follow

- D17: `command.Opt[T]` instead of a pointer field.
- D36: everything goes into the pull request, not only a summary and the test data.
- D40: the faults in cobra's scripts are not reported upstream now.
- D23: import cobra for the scripts instead of a copy. Known cost, measured: two Tab lines fail
  in fish (`--columns=id,na`, `--filter=ow`) until cobra releases a fix, and bash writes a wrong
  value for `--tags tag:ci,tag:p<Tab>`.
- D5, D2, D12: he widened or changed the option (the old-names table; PowerShell as a stretch
  goal; investigate man pages with `man headscale` as the way in).

## Not asked, decided by the assistant

See "Calls made by the assistant" at the end of `DECISIONS.md`. The maintainer has not confirmed
them.
