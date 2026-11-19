# Implementation plan

This file is for the session that drives the implementation of the three proposals: [001](001-cli.md) (the CLI), [002](002-api.md) (the API `/api/headscale/v0`) and [003](003-cmdline.md) (the parser library). It was written with the maintainer on 2026-11-19. It is a start, not an order: adopt it, check it against the code, and change it where it is wrong.

## How to use this file

1. Read this file, and then the "Implementation notes" of each proposal.
1. Do the checks in [To check before the first pull request](#to-check-before-the-first-pull-request).
1. Make the plan of the whole work with the plan tool, from [The stack](#the-stack) and [The team](#the-team). The maintainer approves it there.
1. When a part of the stack starts, fill the TODO tool with the tasks of that part. Close them before the next part starts.

The plan tool holds the whole. The TODO tool holds one part at a time.

## Goal

Headscale 0.30 has the new CLI, the API v0 and its own parser library. The old cobra CLI is gone. `/api/v1` is frozen, and the changelog says that it is removed in 0.33.

The proposals are the specification, and they will be wrong in places. The CLI is the first real client of v0. The work is cut so that those places show early, when a change is cheap.

## Sources

- The proposals are on the branch `cli-restructure-proposal` (pull request #3375). That branch is never merged. The stack is built on `main`, in other worktrees.
- The prototype of the library is in [`research/spikes/final-typed/cmdline/`](research/spikes/final-typed/cmdline/).
- The decisions behind the library are in [`research/DECISIONS.md`](research/DECISIONS.md), [`research/typed-library.md`](research/typed-library.md) and [`research/rules-typed.md`](research/rules-typed.md).

## Decisions

| Decision                                                             | Rejected                                    | Why                                                                                                               |
| -------------------------------------------------------------------- | ------------------------------------------- | ----------------------------------------------------------------------------------------------------------------- |
| slices: one resource in each pull request, from the API to the CLI   | the whole API first                         | a fault in 002 shows in the first slice                                                                           |
| a stack of pull requests on GitHub                                   | one long branch                             | `main` moves fast, and a small pull request can be reviewed                                                       |
| no code joins the old CLI and the new one                            | a root that sends the old groups to cobra   | a bridge is thrown away                                                                                           |
| the new CLI is built beside the old one, and the old one leaves last | delete the old CLI first                    | the integration tests set up every tailnet with the CLI; while they are red, nothing guards the server work       |
| the build tag `newcli` selects the new CLI                           | no way to run it before the swap            | the integration tests run on the new CLI before the old one is deleted                                            |
| the library starts as a copy of the prototype                        | write it again from 003                     | the prototype passes every case of the test kit                                                                   |
| one root session, and builders one after the other                   | builders side by side                       | every slice changes the OpenAPI file, the generated client, `hscontrol/app.go` and the command builder            |
| all of it is in 0.30                                                 | the API in one release, the CLI in the next | 002 removes `/api/v1` three releases after v0, and the changelog of 0.30 already describes what this work changes |

## The stack

Every pull request is green on its own. In a pull request, the API operations, the server work, the commands and the generated files are separate commits.

1. **The library.** A copy of the prototype with its tests, its fuzz tests and its rule index. Done when the tests of 003 pass in CI. The name is open; `cmdline` is the working name.
1. **The empty API.** Step 1 of the order of work in 002: the package, the wiring in `hscontrol/app.go`, the problem type, the auth middleware with its one caller value, the client generation, and `GET /me`, `GET /version` and `GET /health`. Done when the guard tests in the "Tests" part of 002 exist and pass.
1. **The base of the CLI.** The builder (`command.Spec[In, Out]`) and the shared building blocks of 001. The commands `version`, `api whoami` and `completion`. The test helper of "Every command is tested" in 001. The `newcli` build tag, and a CI build with it. Done when `headscale api whoami` works over the socket in a test.
1. **Users.** The first real slice. It proves the base, so expect it to change parts 2 and 3.
1. **Nodes.** With `revision`, tags, routes, and paging on a snapshot of the NodeStore.
1. **Credentials.** Auth keys, API keys and OAuth clients. The soft delete. The column for the creator, with its migration.
1. **The rest.** `policy`, `auth`, `debug`, `check`, `generate`, `serve`.
1. **The integration tests move.** `Dockerfile.integration` builds with `-tags newcli`, and the tests use the new commands and the new JSON.
1. **The swap.** Remove the tag, `cmd/headscale/cli`, pterm, and cobra as the command framework. Change what must match the default binary: the NixOS test kit with its BREAKING entry, the GitHub automation, the commands that the server prints, the docs, the generated reference and man page. Edit the changelog as 001 lists, and add the removal of `/api/v1` in 0.33. Put the deprecation marks on `/api/v1`.

Parts 1 and 2 do not need each other and can be built at the same time. No other parts can.

A slice is done when every row of "This document as tests" in 001 that belongs to it has its cases, and the tests that 002 asks for its operations exist.

How the two CLIs live in one tree until the swap is in "How the old CLI leaves" in 001.

## The team

- **The root session** owns this plan and the proposals. A slice will find things that change the API or the CLI. The root decides each one, or asks the maintainer when it is his to decide, and writes the result into 001, 002 or 003 on the proposal branch. It writes no product code. It keeps its state in the plan, the TODO list and the stack, so that a summary of its context loses nothing.
- **A builder** (Opus) builds one slice, in a worktree on top of the slice before it. One builder works at a time.
- **Reviewers** read slice N while slice N+1 is built: Claude reviewers, and Codex in two Rex panes on the right, one above the other, with `gpt-6.1-sol` and `gpt-6-astra`. Codex reviews start on 2026-11-22.
- A finding goes back to the builder of that slice. The slices above it are rebased.

## Rules of the maintainer

These come on top of `AGENTS.md` and the maintainer's own instructions.

- No push, no pull request and no comment on GitHub without his word. Text for GitHub names no person with `@`.
- A decision for him goes through the question tool: two options, the recommended one first. The examples and the comparison go in the chat text, with short labels in the dialog.
- When an option is not built yet and he asks to see it, build it before the question.
- A proposal that is wrong is corrected in the same step as the code. The proposals stay true to the code.

## To check before the first pull request

- **Where the stack branches live.** The base of pull request N+1 is the branch of pull request N, so the branches likely must be in `juanfont/headscale` and not in a fork. `gh stack` is installed. Neither is verified.
- **Open pull requests on the same code.** #3707 and #3708 change `/api/v2` and the user create. They land first, or the stack carries the conflicts.
- **The legacy API before it is frozen.** 002 names three places where `/api/v1` differs from 0.29. They have no place in the stack yet.
- **Open points.** The "Open points" of 001, and the two tables "Calls not confirmed by the maintainer" in 003.
- **The notes on the code.** "What the code does today" in 001 was checked against `main` only for the files that changed in the last rebase.
