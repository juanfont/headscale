=== v3.14.0 2026-10-02

## What's Changed

- chore(deps): bump mkdocs-git-revision-date-localized-plugin from 1.5.4 to 1.6.0 in the python-packages group by @dependabot[bot] in https://github.com/urfave/cli/pull/2436
- fix: set BoolWithInverseFlag in a short option group by @lazerg in https://github.com/urfave/cli/pull/2440
- Keep arguments after a bare dash by @official-burak in https://github.com/urfave/cli/pull/2419
- fix: handle a multi-byte flag at the end of a short option group by @SulimanAbdulrazzaq in https://github.com/urfave/cli/pull/2438
- fix: complete persistent flags in shell completion by @sb123sb123 in https://github.com/urfave/cli/pull/2437
- fix: restore Unwrap on the error returned by Exit by @fadiroot in https://github.com/urfave/cli/pull/2444
- fix: reject a parent's Local flag inside a short option group by @fadiroot in https://github.com/urfave/cli/pull/2445
- fix: report a flag that needs an argument but is not last in a short group by @yu2971512385-ui in https://github.com/urfave/cli/pull/2443
- Use prefixFor so flag suggestions agree with help on rune count by @januththedev in https://github.com/urfave/cli/pull/2448
- fix: reject duplicate flag names by @deepakganesh78 in https://github.com/urfave/cli/pull/2396
- fix: date a time-only timestamp today when Timezone is not UTC by @breken-ai in https://github.com/urfave/cli/pull/2450
- fix: let a subcommand's command-line value replace a persistent flag's env/file value by @breken-ai in https://github.com/urfave/cli/pull/2449
- Add urfave_cli_no_template build tag by @kolyshkin in https://github.com/urfave/cli/pull/2441
- fix: skip empty source values for flags that cannot parse them by @abo3losh1 in https://github.com/urfave/cli/pull/2451

## New Contributors

- @lazerg made their first contribution in https://github.com/urfave/cli/pull/2440
- @official-burak made their first contribution in https://github.com/urfave/cli/pull/2419
- @SulimanAbdulrazzaq made their first contribution in https://github.com/urfave/cli/pull/2438
- @sb123sb123 made their first contribution in https://github.com/urfave/cli/pull/2437
- @fadiroot made their first contribution in https://github.com/urfave/cli/pull/2444
- @yu2971512385-ui made their first contribution in https://github.com/urfave/cli/pull/2443
- @januththedev made their first contribution in https://github.com/urfave/cli/pull/2448
- @deepakganesh78 made their first contribution in https://github.com/urfave/cli/pull/2396
- @breken-ai made their first contribution in https://github.com/urfave/cli/pull/2450
- @abo3losh1 made their first contribution in https://github.com/urfave/cli/pull/2451

**Full Changelog**: https://github.com/urfave/cli/compare/v3.13.0...v3.14.0

=== v3.13.0 2026-09-20

## What's Changed

- Trim the key of a map flag when TrimSpace is set by @youdie006 in https://github.com/urfave/cli/pull/2431
- Fix inverse bool flag counting with an external counter by @jakezwang in https://github.com/urfave/cli/pull/2432
- feat: add Deprecated field to flags and commands by @anandghegde in https://github.com/urfave/cli/pull/2429
- fix: parse single-rune Unicode flags by @znnnnnnn-wil in https://github.com/urfave/cli/pull/2434

## New Contributors

- @jakezwang made their first contribution in https://github.com/urfave/cli/pull/2432
- @anandghegde made their first contribution in https://github.com/urfave/cli/pull/2429
- @znnnnnnn-wil made their first contribution in https://github.com/urfave/cli/pull/2434

**Full Changelog**: https://github.com/urfave/cli/compare/v3.12.0...v3.13.0

=== v3.12.0 2026-09-14

## What's Changed

- feat: add Command.ArgValidator for tree-wide argument validation by @dearchap in https://github.com/urfave/cli/pull/2377
- Single-value arguments can be marked as required by @idelchi in https://github.com/urfave/cli/pull/2393
- docs: clarify that named Arguments are excluded from cmd.Args() by @dearchap in https://github.com/urfave/cli/pull/2411
- fix: never run command action on shell completion past a double dash by @dearchap in https://github.com/urfave/cli/pull/2412
- chore(deps): bump github.com/stretchr/testify from 1.11.1 to 1.12.0 by @app/dependabot in https://github.com/urfave/cli/pull/2413
- Support custom FlagStringer for MutuallyExclusiveFlags by @SHIVANSHGARG07 in https://github.com/urfave/cli/pull/2414
- Add TextFlag for encoding.TextMarshaler/TextUnmarshaler values by @ChrisJr404 in https://github.com/urfave/cli/pull/2415
- chore(deps): bump github.com/stretchr/testify from 1.12.0 to 1.12.1 by @app/dependabot in https://github.com/urfave/cli/pull/2416
- chore(deps): bump the python-packages group with 2 updates by @app/dependabot in https://github.com/urfave/cli/pull/2417
- Show inherited persistent flags in child help by @justadityaraj in https://github.com/urfave/cli/pull/2421
- fix: preserve whitespace in positional arguments by @lenamonj in https://github.com/urfave/cli/pull/2423
- fix: preserve whitespace in equals-form flag values by @BenYang12 in https://github.com/urfave/cli/pull/2425
- fix: complete subcommand flags after positional arguments by @fzlzjerry in https://github.com/urfave/cli/pull/2426
- Fix a year-less timestamp layout losing January 1 by @youdie006 in https://github.com/urfave/cli/pull/2427
- docs: add go-size-analyzer, module version, and reflection by @imsumedhaa in https://github.com/urfave/cli/pull/2428

## New Contributors

- @idelchi made their first contribution in https://github.com/urfave/cli/pull/2393
- @SHIVANSHGARG07 made their first contribution in https://github.com/urfave/cli/pull/2414
- @ChrisJr404 made their first contribution in https://github.com/urfave/cli/pull/2415
- @justadityaraj made their first contribution in https://github.com/urfave/cli/pull/2421
- @lenamonj made their first contribution in https://github.com/urfave/cli/pull/2423
- @BenYang12 made their first contribution in https://github.com/urfave/cli/pull/2425
- @youdie006 made their first contribution in https://github.com/urfave/cli/pull/2427
- @imsumedhaa made their first contribution in https://github.com/urfave/cli/pull/2428

**Full Changelog**: https://github.com/urfave/cli/compare/v3.11.0...v3.12.0

=== v3.11.0 2026-08-16

## What's Changed

- fix: correct a typo in the help message for the powershell autocompletion by @suzuki-shunsuke in https://github.com/urfave/cli/pull/2383
- Escape backslashes in fish completion descriptions by @mahirhir in https://github.com/urfave/cli/pull/2378
- chore(deps): bump actions/setup-go from 6 to 7 by @dependabot[bot] in https://github.com/urfave/cli/pull/2389
- chore(deps): bump mkdocs-material from 9.7.6 to 9.7.7 in the python-packages group by @dependabot[bot] in https://github.com/urfave/cli/pull/2391
- chore(deps): bump actions/setup-python from 6 to 7 by @dependabot[bot] in https://github.com/urfave/cli/pull/2390
- fix: skip all hidden flags in shell completion, not just bool flags by @vidigoat in https://github.com/urfave/cli/pull/2388
- Fix nil pointer dereference for interface-typed flag values by @mrueg in https://github.com/urfave/cli/pull/2400
- Fix index out of range panic when Run is given no arguments by @mrueg in https://github.com/urfave/cli/pull/2401
- fix: honor BoolWithInverseFlag DefaultText by @fzlzjerry in https://github.com/urfave/cli/pull/2403
- Fix Issue #2385 by @BrandonIrizarry in https://github.com/urfave/cli/pull/2386
- fix: inherit HideHelpCommand in subcommands by @utkarshalpha in https://github.com/urfave/cli/pull/2395
- test: cover Run-with-no-arguments paths (#2406) by @dearchap in https://github.com/urfave/cli/pull/2407
- test: add shell-completion case for hidden BoolWithInverseFlag by @dearchap in https://github.com/urfave/cli/pull/2408
- test: fix ineffective mutex error-string assertion and add mirror cases by @dearchap in https://github.com/urfave/cli/pull/2410

## New Contributors

- @mahirhir made their first contribution in https://github.com/urfave/cli/pull/2378
- @vidigoat made their first contribution in https://github.com/urfave/cli/pull/2388
- @fzlzjerry made their first contribution in https://github.com/urfave/cli/pull/2403
- @BrandonIrizarry made their first contribution in https://github.com/urfave/cli/pull/2386
- @utkarshalpha made their first contribution in https://github.com/urfave/cli/pull/2395

**Full Changelog**: https://github.com/urfave/cli/compare/v3.10.1...v3.11.0

=== v3.10.1 2026-06-29

## What's Changed

- chore(deps): bump actions/checkout from 6 to 7 by @dependabot[bot] in https://github.com/urfave/cli/pull/2371
- fix: align gfmrun example counter with actual runnable count by @dearchap in https://github.com/urfave/cli/pull/2369
- v3: yield the version flag's -v alias to a user-defined flag by @c-tonneslan in https://github.com/urfave/cli/pull/2330
- fix: keep completion subcommand order deterministic in help output by @suzuki-shunsuke in https://github.com/urfave/cli/pull/2374
- fix: allow DefaultCommand to handle its own flags by @lihan3238 in https://github.com/urfave/cli/pull/2322

## New Contributors

- @lihan3238 made their first contribution in https://github.com/urfave/cli/pull/2322

**Full Changelog**: https://github.com/urfave/cli/compare/v3.10.0...v3.10.1

=== v3.10.0 2026-06-14

## What's Changed

- feat: add Flag.SchemaType() and Flag.SchemaItemsType() for JSON Schema introspection by @dearchap in https://github.com/urfave/cli/pull/2368
- feat: add Command.Walk() and Command.Path() convenience methods by @dearchap in https://github.com/urfave/cli/pull/2353
- fix: let --help flag take precedence over parse errors by @dearchap in https://github.com/urfave/cli/pull/2360
- fix: resolve remaining help invocation inconsistencies by @dearchap in https://github.com/urfave/cli/pull/2361
- fix: skip After hook when help is displayed on subcommand by @dearchap in https://github.com/urfave/cli/pull/2363
- fix: show GLOBAL OPTIONS in SubcommandHelpTemplate by @dearchap in https://github.com/urfave/cli/pull/2359
- fix: resolve broken links in CHANGELOG.md by @dearchap in https://github.com/urfave/cli/pull/2357
- docs: document what happened to build tags in v3 migration guide by @dearchap in https://github.com/urfave/cli/pull/2358
- Various docs updates and dependency bumps

**Full Changelog**: https://github.com/urfave/cli/compare/v3.9.1...v3.10.0

=== v3.9.1 2026-06-10

## What's Changed

- fix: inherit Reader/Writer/ErrWriter from parent on subcommand setup by @c-tonneslan in https://github.com/urfave/cli/pull/2329
- fix: correct greedy colon parsing in bash completion script by @TimSoethout in https://github.com/urfave/cli/pull/2336
- fix: Honor env sources on duplicated flags by @ibobgunardi in https://github.com/urfave/cli/pull/2355
- fix: Remove incorrect flag check by @MohitPanchariya in https://github.com/urfave/cli/pull/2280
- fix: let completion command use normal flag parsing pipeline by @suzuki-shunsuke in https://github.com/urfave/cli/pull/2279
- fix: bash completion spacing by @cyphercodes in https://github.com/urfave/cli/pull/2337
- fix: fish custom completion arguments by @puneetdixit200 in https://github.com/urfave/cli/pull/2338
- fix: empty positional arg after a flag regression test by @c-tonneslan in https://github.com/urfave/cli/pull/2328
- docs: document build tags in v3 migration guide by @dearchap in https://github.com/urfave/cli/pull/2358
- chore(deps): bump mkdocs-git-revision-date-localized-plugin by @dependabot in https://github.com/urfave/cli/pull/2347
- Fix typos by @myfloss in https://github.com/urfave/cli/pull/2339

**Full Changelog**: https://github.com/urfave/cli/compare/v3.9.0...v3.9.1

=== v3.9.0 2026-05-12

## What's Changed

- chore(deps): bump codecov/codecov-action from 5 to 6 by @dependabot[bot] in https://github.com/urfave/cli/pull/2300
- chore(deps): bump the python-packages group across 1 directory with 3 updates by @dependabot[bot] in https://github.com/urfave/cli/pull/2301
- docs: fix typo by @acrobatstick in https://github.com/urfave/cli/pull/2299
- feat: add descriptions for bash and powershell autocompletion by @gabelluardo in https://github.com/urfave/cli/pull/2298
- Made command help more consistent by @markshep-wbg in https://github.com/urfave/cli/pull/2287
- Fix:(issue_2285): correct function and variable naming in fish completion script by @TimSoethout in https://github.com/urfave/cli/pull/2286
- fix(ci): update docs after bash completion update by @gabelluardo in https://github.com/urfave/cli/pull/2307
- fix: apply SliceFlagSeparator to env var sources by @lawrence3699 in https://github.com/urfave/cli/pull/2309
- fix: don't print empty line to stderr when Exit message is empty by @Yanhu007 in https://github.com/urfave/cli/pull/2310
- flag: prevent BoolWithInverseFlag.String from panicking without a tab by @alliasgher in https://github.com/urfave/cli/pull/2311
- refactor: bash completion script by @gabelluardo in https://github.com/urfave/cli/pull/2308
- fix: drop shebang from bash completion template by @barry3406 in https://github.com/urfave/cli/pull/2317
- fix: show flag completions when completing a double-dash prefix by @morozov in https://github.com/urfave/cli/pull/2316
- fix: parse flags for help subcommand (#2271) by @barry3406 in https://github.com/urfave/cli/pull/2319
- fix: show BoolWithInverseFlag aliases in help text by @wucm667 in https://github.com/urfave/cli/pull/2321

## New Contributors

- @gabelluardo made their first contribution in https://github.com/urfave/cli/pull/2298
- @markshep-wbg made their first contribution in https://github.com/urfave/cli/pull/2287
- @lawrence3699 made their first contribution in https://github.com/urfave/cli/pull/2309
- @Yanhu007 made their first contribution in https://github.com/urfave/cli/pull/2310
- @alliasgher made their first contribution in https://github.com/urfave/cli/pull/2311
- @barry3406 made their first contribution in https://github.com/urfave/cli/pull/2317
- @morozov made their first contribution in https://github.com/urfave/cli/pull/2316
- @wucm667 made their first contribution in https://github.com/urfave/cli/pull/2321

**Full Changelog**: https://github.com/urfave/cli/compare/v3.8.0...v3.9.0

=== v3.8.0 2026-03-25

## What's Changed

- chore(deps): bump mkdocs-material from 9.7.1 to 9.7.2 in the python-packages group by @dependabot[bot] in https://github.com/urfave/cli/pull/2267
- chore(deps): bump mkdocs-material from 9.7.2 to 9.7.3 in the python-packages group by @dependabot[bot] in https://github.com/urfave/cli/pull/2272
- chore(deps): bump mkdocs-material from 9.7.3 to 9.7.4 in the python-packages group by @dependabot[bot] in https://github.com/urfave/cli/pull/2276
- Fix: check MutuallyExclusiveFlags across parent command chain by @siutsin in https://github.com/urfave/cli/pull/2274
- Modernize source code by @kolyshkin in https://github.com/urfave/cli/pull/2289
- flag: replace regexp use by @kolyshkin in https://github.com/urfave/cli/pull/2288
- chore(deps): bump mkdocs-material from 9.7.4 to 9.7.5 in the python-packages group by @dependabot[bot] in https://github.com/urfave/cli/pull/2284
- Fix:(issue_2281) Remove incorrect check for local flag for set by @dearchap in https://github.com/urfave/cli/pull/2290
- Fix:(issue_2275) Make flag action execution consistent by @dearchap in https://github.com/urfave/cli/pull/2295
- Fix:(issue_2293) --flag="" no longer rejected as missing argument by @idelchi in https://github.com/urfave/cli/pull/2297
- Fix:(issue_2292) Empty positional args no longer break parse loop by @idelchi in https://github.com/urfave/cli/pull/2296

## New Contributors

- @idelchi made their first contribution in https://github.com/urfave/cli/pull/2297

**Full Changelog**: https://github.com/urfave/cli/compare/v3.7.0...v3.8.0

=== v3.7.0 2026-03-01

## What's Changed

- Fix: use the correct type name in the tracef message by @icholy in https://github.com/urfave/cli/pull/2251
- chore(deps): bump mkdocs-git-revision-date-localized-plugin from 1.5.0 to 1.5.1 in the python-packages group by @dependabot[bot] in https://github.com/urfave/cli/pull/2252
- Fix:(issue_2254) Fix incorrect handling of arg after short option token by @dearchap in https://github.com/urfave/cli/pull/2255
- feat: ShellComplete for fish by @marcusramberg in https://github.com/urfave/cli/pull/2256
- Fix: propagate MutuallyExclusiveFlags persistent flags to subcommands by @siutsin in https://github.com/urfave/cli/pull/2266
- feat: support dynamic fish completion by @Maks1mS in https://github.com/urfave/cli/pull/2270
- fix(help): show GLOBAL OPTIONS for leaf subcommands when HideHelpCommand is true by @TimSoethout in https://github.com/urfave/cli/pull/2269

## New Contributors

- @marcusramberg made their first contribution in https://github.com/urfave/cli/pull/2256
- @siutsin made their first contribution in https://github.com/urfave/cli/pull/2266
- @TimSoethout made their first contribution in https://github.com/urfave/cli/pull/2269

**Full Changelog**: https://github.com/urfave/cli/compare/v3.6.2...v3.7.0

=== v3.6.2 2026-01-18

## What's Changed

- chore(deps): bump actions/checkout from 5 to 6 by @dependabot[bot] in https://github.com/urfave/cli/pull/2230
- chore(deps): bump mkdocs-material from 9.6.23 to 9.7.0 in the python-packages group by @dependabot[bot] in https://github.com/urfave/cli/pull/2231
- Improve test coverage by @dearchap in https://github.com/urfave/cli/pull/2236
- Add more tests to improve code coverage by @dearchap in https://github.com/urfave/cli/pull/2237
- Fix:(issue_2238) Dont process flags for completion command by @dearchap in https://github.com/urfave/cli/pull/2239
- Fix:(issue_2228) Fix for default command by @dearchap in https://github.com/urfave/cli/pull/2232
- chore(deps): bump mkdocs-material from 9.7.0 to 9.7.1 in the python-packages group by @dependabot[bot] in https://github.com/urfave/cli/pull/2242
- Docs: correct typo in migration guide by @kzygmans in https://github.com/urfave/cli/pull/2243
- Fix:(issue_2244) Dont check req flags for help and completion commands by @dearchap in https://github.com/urfave/cli/pull/2245
- Only show separator if command has usage text by @mikecluck in https://github.com/urfave/cli/pull/2247

## New Contributors

- @kzygmans made their first contribution in https://github.com/urfave/cli/pull/2243
- @mikecluck made their first contribution in https://github.com/urfave/cli/pull/2247

**Full Changelog**: https://github.com/urfave/cli/compare/v3.6.1...v3.6.2

=== v3.6.1 2025-11-16

## What's Changed

- chore(deps): bump golangci/golangci-lint-action from 8 to 9 by @dependabot[bot] in https://github.com/urfave/cli/pull/2222
- feat: add ability to override usage text of default help command by @Maks1mS in https://github.com/urfave/cli/pull/2196
- Fix:(issue_2223) Fix incorrect processing of empty value after = by @dearchap in https://github.com/urfave/cli/pull/2224

## New Contributors

- @Maks1mS made their first contribution in https://github.com/urfave/cli/pull/2196

**Full Changelog**: https://github.com/urfave/cli/compare/v3.6.0...v3.6.1

=== v3.6.0 2025-11-09

## What's Changed

- support parallel running of commands by @oprudkyi in https://github.com/urfave/cli/pull/2215
- Fix:(issue_2208) Fix local flag by @dearchap in https://github.com/urfave/cli/pull/2211
- chore(deps): bump the python-packages group with 2 updates by @dependabot[bot] in https://github.com/urfave/cli/pull/2219
- Call actions on flags set from env by @malclocke in https://github.com/urfave/cli/pull/2221

## New Contributors

- @malclocke made their first contribution in https://github.com/urfave/cli/pull/2221

**Full Changelog**: https://github.com/urfave/cli/compare/v3.5.0...v3.6.0

=== v3.5.0 2025-10-21

## What's Changed

- Update mkdocs reqs by @meatballhat in https://github.com/urfave/cli/pull/2190
- Allow the user to stop processing flags after seeing N args by @adrian-thurston in https://github.com/urfave/cli/pull/2163
- chore(deps): bump github.com/stretchr/testify from 1.10.0 to 1.11.0 by @dependabot[bot] in https://github.com/urfave/cli/pull/2194
- chore(deps): bump mkdocs-material from 9.6.16 to 9.6.18 in the python-packages group by @dependabot[bot] in https://github.com/urfave/cli/pull/2195
- chore(deps): bump actions/setup-go from 5 to 6 by @dependabot[bot] in https://github.com/urfave/cli/pull/2198
- chore(deps): bump actions/setup-node from 4 to 5 by @dependabot[bot] in https://github.com/urfave/cli/pull/2199
- chore(deps): bump actions/setup-python from 5 to 6 by @dependabot[bot] in https://github.com/urfave/cli/pull/2200
- chore(deps): bump github.com/stretchr/testify from 1.11.0 to 1.11.1 by @dependabot[bot] in https://github.com/urfave/cli/pull/2197
- chore(deps): bump mkdocs-material from 9.6.18 to 9.6.19 in the python-packages group by @dependabot[bot] in https://github.com/urfave/cli/pull/2201
- chore(deps): bump mkdocs-material from 9.6.19 to 9.6.20 in the python-packages group by @dependabot[bot] in https://github.com/urfave/cli/pull/2202
- feat: add name of argument into error message when parsing fails by @oprudkyi in https://github.com/urfave/cli/pull/2203
- chore(deps): bump mkdocs-material from 9.6.20 to 9.6.21 in the python-packages group by @dependabot[bot] in https://github.com/urfave/cli/pull/2204
- add space between arguments usage by @dimfu in https://github.com/urfave/cli/pull/2207
- chore(deps): bump mkdocs-material from 9.6.21 to 9.6.22 in the python-packages group by @dependabot[bot] in https://github.com/urfave/cli/pull/2213
- Fix: Make DefaultText behaviour consistent by @dearchap in https://github.com/urfave/cli/pull/2214

## New Contributors

- @adrian-thurston made their first contribution in https://github.com/urfave/cli/pull/2163
- @oprudkyi made their first contribution in https://github.com/urfave/cli/pull/2203
- @dimfu made their first contribution in https://github.com/urfave/cli/pull/2207

**Full Changelog**: https://github.com/urfave/cli/compare/v3.4.1...v3.5.0

=== v3.4.1 2025-08-12

## What's Changed

- Use recommended GitHub Actions runner labels by @meatballhat in https://github.com/urfave/cli/pull/2181
- chore(deps): bump actions/checkout from 4 to 5 by @dependabot[bot] in https://github.com/urfave/cli/pull/2179
- Document that `v3` series is recommended for new development by @meatballhat in https://github.com/urfave/cli/pull/2186

**Full Changelog**: https://github.com/urfave/cli/compare/v3.4.0...v3.4.1

=== v3.4.0 2025-08-12

## What's Changed

- Export help display functions as variables to allow custom help display logic by @almas-x in https://github.com/urfave/cli/pull/2150
- Invoke OnUsageError when missing required flags by @MohitPanchariya in https://github.com/urfave/cli/pull/2161
- Fix:(issue_2169) Allow trim space for string slice flags by @dearchap in https://github.com/urfave/cli/pull/2171
- Add example of flag groups to docs by @jllovet in https://github.com/urfave/cli/pull/2178
- Add installation instructions for gfmrun by @jllovet in https://github.com/urfave/cli/pull/2177
- Ensure public vars reference public types by @meatballhat in https://github.com/urfave/cli/pull/2180

## New Contributors

- @almas-x made their first contribution in https://github.com/urfave/cli/pull/2150
- @MohitPanchariya made their first contribution in https://github.com/urfave/cli/pull/2161
- @jllovet made their first contribution in https://github.com/urfave/cli/pull/2178

**Full Changelog**: https://github.com/urfave/cli/compare/v3.3.9...v3.4.0

=== v3.3.9 2025-08-12

## What's Changed

- Fix typos in documentation for customizations and full API example by @amarjit03 in https://github.com/urfave/cli/pull/2165
- Update advanced.md by @thetillhoff in https://github.com/urfave/cli/pull/2170

## New Contributors

- @amarjit03 made their first contribution in https://github.com/urfave/cli/pull/2165
- @thetillhoff made their first contribution in https://github.com/urfave/cli/pull/2170

**Full Changelog**: https://github.com/urfave/cli/compare/v3.3.8...v3.3.9

=== v3.3.8 2025-06-13

## What's Changed

- Remove "alpha" wording around `v3` series by @meatballhat in https://github.com/urfave/cli/pull/2155

**Full Changelog**: https://github.com/urfave/cli/compare/v3.3.7...v3.3.8

=== v3.3.7 2025-06-13

## What's Changed

- fix: add missing `IsLocal` for BoolWithInverseFlag by @huiyifyj in https://github.com/urfave/cli/pull/2151
- Fix OnUsageError Trigger When Error Is Caused by Mutually Exclusive Flags by @Ali-Doustkani in https://github.com/urfave/cli/pull/2152

## New Contributors

- @Ali-Doustkani made their first contribution in https://github.com/urfave/cli/pull/2152

**Full Changelog**: https://github.com/urfave/cli/compare/v3.3.6...v3.3.7

=== v3.3.6 2025-06-13

## What's Changed

- Fish completions with identically named sub-commands now work by @bittrance in https://github.com/urfave/cli/pull/2130

**Full Changelog**: https://github.com/urfave/cli/compare/v3.3.5...v3.3.6

=== v3.3.5 2025-06-13

## What's Changed

- Fix:(issue_2137) Ensure default value for bool with inverse flag is h… by @dearchap in https://github.com/urfave/cli/pull/2138
- Fix:(issue_2131) Show help text for BoolWithInverseFlag by @Juneezee in https://github.com/urfave/cli/pull/2142

**Full Changelog**: https://github.com/urfave/cli/compare/v3.3.4...v3.3.5

=== v3.3.4 2025-06-13

## What's Changed

- Fix Docs(issue_2125) Add PathFlag to StringFlag migration by @dearchap in https://github.com/urfave/cli/pull/2136
- fix: remove extraneous space from subcommand help template by @G-Rath in https://github.com/urfave/cli/pull/2140
- Fix:(issue_2135) Correct formatting of default subcommand USAGE text by @zzspoon in https://github.com/urfave/cli/pull/2139

## New Contributors

- @zzspoon made their first contribution in https://github.com/urfave/cli/pull/2139

**Full Changelog**: https://github.com/urfave/cli/compare/v3.3.3...v3.3.4

=== v3.3.3 2025-05-10

## What's Changed

- Simpler top-level context detection for fish completions by @bittrance in https://github.com/urfave/cli/pull/2121
- Fish completion inside hidden commands by @bittrance in https://github.com/urfave/cli/pull/2122
- chore(deps): bump golangci/golangci-lint-action from 7 to 8 by @dependabot in https://github.com/urfave/cli/pull/2123
- fix: off-by-one in timestamp parsing by @nickajacks1 in https://github.com/urfave/cli/pull/2127
- Fish completions tests invokes setup by @bittrance in https://github.com/urfave/cli/pull/2124
- Fix docs by @dearchap in https://github.com/urfave/cli/pull/2128

## New Contributors

- @nickajacks1 made their first contribution in https://github.com/urfave/cli/pull/2127

**Full Changelog**: https://github.com/urfave/cli/compare/v3.3.2...v3.3.3

=== v3.3.2 2025-04-28

## What's Changed

- Add docs for advanced value source by @dearchap in https://github.com/urfave/cli/pull/2119
- docs: add renames to v3 migration doc by @G-Rath in https://github.com/urfave/cli/pull/2111

## New Contributors

- @G-Rath made their first contribution in https://github.com/urfave/cli/pull/2111

**Full Changelog**: https://github.com/urfave/cli/compare/v3.3.1...v3.3.2

=== v3.3.1 2025-04-27

## What's Changed

- Avoid suggesting files in fish command completions. by @bittrance in https://github.com/urfave/cli/pull/2114
- Cleanup docs by @dearchap in https://github.com/urfave/cli/pull/2118

**Full Changelog**: https://github.com/urfave/cli/compare/v3.3.0...v3.3.1

=== v3.3.0 2025-04-27

## What's Changed

- Add v3 issue template by @dearchap in https://github.com/urfave/cli/pull/2104
- Fix:(issue_2105) Ensure fish completion works by @dearchap in https://github.com/urfave/cli/pull/2106
- add test for MutuallyExclusiveFlags with After by @bystones in https://github.com/urfave/cli/pull/2107
- use correct context in After function with subcommand by @bystones in https://github.com/urfave/cli/pull/2108
- Enable to customize completion commands by @suzuki-shunsuke in https://github.com/urfave/cli/pull/2103
- Fish completions no longer suggest subcommands that have already been picked by @bittrance in https://github.com/urfave/cli/pull/2117
- feat: adds support for explicit `float32` and `float64` by @ldez in https://github.com/urfave/cli/pull/2112

## New Contributors

- @bystones made their first contribution in https://github.com/urfave/cli/pull/2107
- @bittrance made their first contribution in https://github.com/urfave/cli/pull/2117

**Full Changelog**: https://github.com/urfave/cli/compare/v3.2.0...v3.3.0

=== v3.2.0 2025-04-20

**Breaking change IntFlag now uses int type and not int64. Please change to using Int64Flag for int64 types. Similar behavior for UintFlag as well. See https://pkg.go.dev/github.com/urfave/cli/v3 for a full list of flag types. See #2094 for full patch for this**

## What's Changed

- chore: Bump golangci-lint to v2 by @mrueg in https://github.com/urfave/cli/pull/2083
- Fix docs for shell completions by @antimatter96 in https://github.com/urfave/cli/pull/2090
- docs: improve migration guides render by @ldez in https://github.com/urfave/cli/pull/2091
- docs: improve migration guide v3 by @ldez in https://github.com/urfave/cli/pull/2093
- feat!: add more integers and unsigned integers type flags by @somebadcode in https://github.com/urfave/cli/pull/2094
- PR-2094: Fix docs by @dearchap in https://github.com/urfave/cli/pull/2099
- Fix:(PR-2094) Update docs for new types by @dearchap in https://github.com/urfave/cli/pull/2100
- Fix:(issue_2056) Add cmd.XXXArgs() functions for retrieving args by @dearchap in https://github.com/urfave/cli/pull/2088
- Add docs for arg types by @dearchap in https://github.com/urfave/cli/pull/2101

## New Contributors

- @antimatter96 made their first contribution in https://github.com/urfave/cli/pull/2090
- @ldez made their first contribution in https://github.com/urfave/cli/pull/2091
- @somebadcode made their first contribution in https://github.com/urfave/cli/pull/2094

**Full Changelog**: https://github.com/urfave/cli/compare/v3.1.1...v3.2.0

=== v3.1.0 2025-03-31

## What's Changed

- go.mod: Require go1.22 by @mrueg in https://github.com/urfave/cli/pull/2026
- Fix:(issue_2030) Add support for trailing hypen for short options by @dearchap in https://github.com/urfave/cli/pull/2031
- Run Before actions after setting up subcommand by @fjl in https://github.com/urfave/cli/pull/2028
- The example have some problem in api by @jokemanfire in https://github.com/urfave/cli/pull/2039
- Rename "Bash Completions" to "Shell Completions" by @abitrolly in https://github.com/urfave/cli/pull/2044
- Support root level map keys in map sources by @lukasbindreiter in https://github.com/urfave/cli/pull/2047
- while print flag , the placeholder if need but not set. by @jokemanfire in https://github.com/urfave/cli/pull/2043
- Add dependabot by @mrueg in https://github.com/urfave/cli/pull/2025
- Bump github.com/stretchr/testify from 1.9.0 to 1.10.0 by @dependabot in https://github.com/urfave/cli/pull/2054
- Bump golangci/golangci-lint-action from 5 to 6 by @dependabot in https://github.com/urfave/cli/pull/2053
- Bump codecov/codecov-action from 4 to 5 by @dependabot in https://github.com/urfave/cli/pull/2052
- Fix:(issue_2032) Support for post parse config loading by @dearchap in https://github.com/urfave/cli/pull/2033
- Fix:(issue_2066) Remove dependency on golang flag library by @dearchap in https://github.com/urfave/cli/pull/2074
- Fix:(issue_1891) Roll out v3 docs by @dearchap in https://github.com/urfave/cli/pull/2080
- Fix:(issue_2077) Make sure onUsageError is invoked for command when a… by @dearchap in https://github.com/urfave/cli/pull/2081

## New Contributors

- @mrueg made their first contribution in https://github.com/urfave/cli/pull/2026
- @jokemanfire made their first contribution in https://github.com/urfave/cli/pull/2039
- @lukasbindreiter made their first contribution in https://github.com/urfave/cli/pull/2047
- @dependabot made their first contribution in https://github.com/urfave/cli/pull/2054

**Full Changelog**: https://github.com/urfave/cli/compare/v3.0.0-beta1.01...v3.1.0
