# Overnight CLI property investigation

Joined CLI/API part 10 (`9fc7f92e5e70`) was the primary target. Separate part 11 (`a226689b85b0`) supplied a second implementation for comparison. The draft targets published part 9 (#3730), so its full diff includes the unpublished part 10 prerequisite. For the investigation alone, compare the draft head with `9fc7f92e5e70`.

From 20:41 to 07:21 Amsterdam time on November 22–23, the scheduled workers completed 26,991 passing batches across 48 named tests and 185 executable digests. They recorded 3,319,387,562 passing examples, including repeated inputs. Five fixture startups failed before any product assertion. All five passed with the original binary and seed after serial replay or a shorter Unix socket path. Targeted boundary experiments, independent expected results and reviewer replays produced the product findings. [Six run ledgers](rounds.md) · [Separate reproducers, fixes and test models](commits.md)

## What broke

| Surface                      | Reproducer and cause                                                                                                                                                                                                                                | Outcome                                                                                                                                                                                                                                 |
| ---------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Integer filters and sorts    | A user with one node disappeared for `--filter='count>0.99999999999999999'`. Adjacent integers above 2⁵³ sorted as ties. A missing ID could also make IDs 2 and 10 sort as text. Floating-point conversion or a missing row changed the comparison. | Compare at declared width and preserve the filter threshold. Preparing a tied threshold once reduced the measured median from 11 allocations to 3.                                                                                      |
| Unicode usernames            | Both CLIs rejected `users create אב`, accepted the single character `李`, and permitted `٢x`. Shared validation classified the first UTF-8 byte and counted bytes for the minimum length.                                                           | Validate the first rune and count runes. A census of 145,672 letters and 770 decimal digits found zero remaining mismatches for the tested shapes. Existing short names remain readable. Resubmitting one to validation now fails.      |
| Parser and builder ownership | Reusing the argv slice changed a deferred error. Tab could alter shared aliases. Mutating caller-owned command children or column declarations after construction changed later behavior.                                                           | Snapshot the values at the point where the parser or builder assumes ownership.                                                                                                                                                         |
| Completion                   | A sealed invalid filter still offered suffixes. Doubling a column modifier could pass validation. Tabs in list values split a protocol record.                                                                                                      | Validate sealed items, preserve cursor whitespace and suppress unrepresentable prefixes. Tab expands `id,-ho` to `id,-hostname`. Executing a mixed plain/signed list still errors. On its own, `-hostname` removes that default column. |
| Future JSON fields           | A new field differing only in capitalization could overwrite a known field or break list decoding.                                                                                                                                                  | Match response and problem fields by their exact wire names. Separate mutation checks pin unfamiliar numbers and their JSON spelling.                                                                                                   |
| User PATCH diagnostics       | Independently invalid fields masked each other. Deduplicated diagnostics reported the wrong omitted count. A null username received unusable repair advice.                                                                                         | Validate fields independently, preserve useful diagnostics and count the actual errors. Profile histories check both users after each attempted write.                                                                                  |
| Relative time                | A node expiring 105 days plus one nanosecond away failed a strict greater-than filter. A first correction missed zero and saturated at the duration limit.                                                                                          | Compare against the actual timestamp cutoff. Keep all three boundary cases.                                                                                                                                                             |
| Terminal width               | Normalization, emoji presentation and clipping shifted columns. Two real terminal emulators disagreed on 320 of 595 probes.                                                                                                                         | Both reviewers hold the renderer changes. Their commits are in this draft for reproduction.                                                                                                                                             |

## What the tests now distinguish

- Parser generators cover scoped and reordered options, aliases, empty and whitespace-only argv, numeric readers at their declared widths, deferred reads, callback error identity and both completion protocols. The tagged executable matched expected exit, stdout and stderr for 299,520 three-global-option invocations, 26,720 one/two-option invocations, and a further 25,050 scoped force/version/help invocations across the two tips.
- Stateful CLI fixtures reuse symbolic names, IDs and emails across commands. They check model state against both CLI results and stored/API state after creates, edits, refusals, identity reuse and lookups. The common user collection recorded 68,976 histories and 774,278 CLI operations. Additional histories exercise international usernames.
- API and list models check pagination order and restart, errors sharing an HTTP status, projections, unknown JSON numbers, timestamps and empty lists. All seven real list commands returned `[]`. Changing the API to return `null` still yielded CLI stdout `[]`. Checking both layers caught the regression.
- Of the initial 17 isolated mutations, selected shipped examples caught nine. The new properties caught all 17 on both tips. Full shipped suites also caught some mutations missed by the selected examples. Later controls exposed states the earlier generators could never draw, including an absent numeric selector and a positional argument containing only a space.
- A completion property detected a carriage-return mutation in 18 of 32 seeded runs at 64 draws. Checking each delimiter independently detected it in all 32 runs by draw four. The initial profile model also leaked setup state between shrinking trials. Resetting both users restored replay. Eight older long profile streams require an explicit stop draw on healthy replay.
- Actual argv diversity was lower than the draw count. Four 262,144-draw dispatch sampling runs yielded roughly 128,000 unique argv each. The deterministic regressions retain rare boundary cases even when a short CI seed misses them.

## Statement coverage

Counts compare shipped examples and selected Rapid tests on the integrated review tree. The columns partition the measured Go statements. Two subprocess tests that assert exact stderr ran in the ordinary and race gates outside coverage instrumentation.

| Package group     |  Both | Examples only | Rapid only | Unreached |
| ----------------- | ----: | ------------: | ---------: | --------: |
| Parser and reader |   458 |           117 |          3 |         0 |
| CLI               | 1,554 |         1,607 |          3 |       125 |
| v0 API            |   506 |         1,031 |          2 |        65 |
| Utilities         |    10 |           291 |          0 |       132 |

## Replay

From the repository root, run the short selection or the affected package suites. The short selection defaults to 64 generated examples per Rapid check. Four measured seeds each exercised 76 Rapid checks, taking 70–110 seconds on the investigation host. The nine affected test packages passed 455 top-level tests and 77 Rapid checks on the combined overnight tree under both ordinary and race builds. One initial race process received SIGTERM. The complete same-seed retry passed in 319 seconds.

```sh
RAPID_SEED=13 sh tools/rapid-cli/short-ci.sh
RAPID_SEED=23154 RAPID_CHECKS=100 go test -count=1 ./cmdline/... ./cmd/headscale/newcli/... ./hscontrol/api/headscale/v0 ./hscontrol/util ./hscontrol/types
CGO_ENABLED=1 RAPID_SEED=23155 RAPID_CHECKS=32 go test -race -count=1 ./cmdline/... ./cmd/headscale/newcli/... ./hscontrol/api/headscale/v0 ./hscontrol/util ./hscontrol/types
```

The archive holds 607 original case paths and 198 distinct Rapid draw streams. Each file contains the saved version, seed and draws. The same stream can appear on multiple revisions or fixtures. Historical streams depend on the originating generator's draw order. Some are witnesses against a deliberately changed implementation. This example replays one stream without fresh draws.

```sh
casefile=$(mktemp)
tar -xOzf tools/rapid-cli/minimized.tar.gz overnight/match-evidence/whitespace/joined/sole-space/TestRapidReaderWhitespace_positional-20261123055657-747637.fail > "$casefile"
go test -count=1 -v ./cmdline/reader -run '^TestRapidReaderWhitespace$/^positional$' -rapid.checks=0 -rapid.v -rapid.failfile="$casefile"
```

## Open at handoff

Generic Bash filename insertion still searches for the entire comma-prefixed word. Separate part 11 invokes an early value reader on Tab. Other open cases include an optional response field appearing under unexpected capitalization, extreme underflow for string-valued numeric IDs, and displayed versus exact float32 comparisons. No shipped endpoint was identified that emits exponent-form IDs. Terminal-width behavior still needs a policy that matches the supported terminals.
