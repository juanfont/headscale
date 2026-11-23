# Review commits

Each commit is reachable from the draft. Use `git show <sha>` to inspect a reproducer, correction or generator independently.

## Reproducers and corrections

The terminal-width pairs are held for a terminal policy decision. One pair updates the test fixture, and the last pair measures performance. Generator source and generated client output for exact-field decoding have individual commits.

| Subject                                                                                  | Focused case or prerequisite | Correction or generated output |
| ---------------------------------------------------------------------------------------- | ---------------------------- | ------------------------------ |
| Distinguish numeric IDs that round to the same float                                     | `5276a66648c7`               | `9fdfc7cbc475`                 |
| Validate sealed filter items before completion                                           | `c0a6fb9fff26`               | `896f6ecbf03c`                 |
| Consume one column modifier during validation                                            | `1f381a00a413`               | `332cbc834bfd`                 |
| Trim list items during validation                                                        | `dce220f0a625`               | `e2f278437797`                 |
| Exclude missing IDs when choosing the sort order                                         | `caa528beb644`               | `a3e553d0f688`                 |
| Preserve words returned by list completers                                               | `b998be95070b`               | `7051d946fe2c`                 |
| Validate sealed columns before name completion                                           | `acfbc3eab728`               | `f83c53be466e`                 |
| Preserve cursor whitespace in list completion                                            | `e9388aa92009`               | `12eadb11de84`                 |
| Restrict sort completion to valid directions                                             | `054e22128019`               | `7551a3b72c6f`                 |
| Compare relative times against an exact cutoff                                           | `c1ddaf6e9e21`               | `4d140d20cd5b`                 |
| Suppress unrepresentable list completion prefixes                                        | `bb9ceae8ffae`               | `63f9efd5c2cc`                 |
| Preserve file metadata after a comma                                                     | `aaaf5db8e7c5`               | `dd006c067dda`                 |
| Check online node times against the API response (fixture)                               | `c2e55b34237a`               | `f6886f352ff6`                 |
| Retain the parsed word for late errors                                                   | `bc98c5b92699`               | `9d7c70cdbbdb`                 |
| Regenerate the v0 client with exact response decoding (schema template → generated file) | `8a1ca801ded0`               | `989c4c3f18da`                 |
| Decode successful answers by exact field name                                            | `35490d232083`               | `acc95a8e6616`                 |
| Decode problem fields by exact name                                                      | `474ce1541b4e`               | `05f25714a07a`                 |
| Measure and truncate whole display cells **(held)**                                      | `4a5421dbb8a6`               | `62af3b4a414e`                 |
| Account for emoji presentation when clipping **(held)**                                  | `6966a3885028`               | `7c8bbfd45aa6`                 |
| Report user field errors alongside schema errors                                         | `3b634104fa4b`               | `12593acdec2f`                 |
| Retain declared aliases when building a tree                                             | `ea0ab0b592a5`               | `47e4429bab0e`                 |
| Keep command descriptions independent                                                    | `1d5f50dbda25`               | `333e8b0936e2`                 |
| Check user fields independently in JSON objects (see later error-count correction)       | `c0bd30711666`               | `636721aa4720`                 |
| Snapshot group children for suggestions                                                  | `de284c40751c`               | `44694969ef34`                 |
| Keep an independent table declaration per spec                                           | `c7240a6b8f9d`               | `c5c430a50e37`                 |
| Give a valid repair for null usernames                                                   | `322402a88325`               | `82dd552a3f07`                 |
| Count field errors after removing duplicate diagnostics                                  | `f44439e4048e`               | `f112b0b8227d`                 |
| Sort native integer fields at their declared width                                       | `8cc140a01859`               | `b0729f3edaaa`                 |
| Compare integer fields against exact numeric thresholds                                  | `40637516f169`               | `1af0d5032e7c`                 |
| Read first username letter as a rune                                                     | `fd10a2dbeb2a`               | `5e3165ca2249`                 |
| Count the first two username characters by rune                                          | `4891e4560631`               | `2099bf756833`                 |
| Prepare tied thresholds once for integer columns (benchmark → optimization)              | `ebad47c9c94b`               | `6188ce98447f`                 |

## Test models and supporting fixtures

| Commit         | Change                                                                 |
| -------------- | ---------------------------------------------------------------------- |
| `03e5a45f3750` | cmdline: model option scope, declarations and late reads               |
| `cf38d68092ca` | newcli: check query and rename results against fixture state           |
| `17934bbc8dc3` | newcli: check numeric boundaries, parse offsets and empty API pages    |
| `3c67a2d90921` | newcli/command: model page history and retry across list endpoints     |
| `7a8c6df7120a` | newcli/command: check row order within each API page                   |
| `971fdec64d48` | apiv0: check node timestamps on the wire                               |
| `5ff738802ffb` | newcli/command: preserve page errors with shared HTTP status           |
| `9d573aa64acc` | newcli/command: check terminal page errors after a restart             |
| `09fd2244e82e` | newcli: check unknown JSON fields through list queries                 |
| `aca15558b6b7` | newcli: sample fractional and exponent JSON numbers in list output     |
| `dc4dcb90b620` | newcli: reuse a Unix listener across raw list property draws           |
| `348246649d1b` | newcli: sample alternate JSON number spellings in list output          |
| `e5ee607612d8` | newcli: exercise user profile patches through the CLI and API          |
| `7fdd0979ab08` | newcli: check the first inapplicable global flag                       |
| `ef81201295a6` | reader: verify the first inapplicable flag diagnostic                  |
| `a3bbcf81bf5e` | newcli: check node column projections against API rows                 |
| `d35392c6417a` | newcli: include renames and text replies in profile sequences          |
| `0fa9d37e7e19` | newcli: check rejected fields and conflicting profile owners           |
| `452b386c6498` | newcli: compare node column values with API fields                     |
| `cb38b1c911f7` | cmdline: check alias lifetime across tree constructions                |
| `90b6686a7540` | newcli: reset both user profiles before each property trial            |
| `7b65dcde1c78` | newcli: exercise varying node fields and spaces within cells           |
| `49197bcd6de3` | api/headscale/v0: test independent user field errors and wire status   |
| `f584477189ba` | newcli/command: test declaration reuse across list and sheet output    |
| `78b0e876f982` | cmdline: test rounding at both floating point widths                   |
| `a2a474d844ec` | newcli: generate complete node cases before checking output            |
| `cc4b0ce0e5b6` | newcli: test user collections across command histories                 |
| `4a5335af5fc5` | newcli: recreate user identities before each profile trial             |
| `2f80ed94e587` | cmdline: test floating point limits in decimal and hexadecimal         |
| `6ded12889fa0` | newcli: verify refusal details across user histories                   |
| `12afa3217eca` | api/headscale/v0: test the reported count of user field errors         |
| `c170ad694dbf` | newcli/table: test integer orders and exact filter thresholds          |
| `821ebb672e8c` | newcli: exercise missing numeric user selectors before deletion        |
| `3dbb6e802180` | util: generate valid username letters across writing systems           |
| `8ec115e2d0bb` | cmdline/reader: preserve trailing space in positional words            |
| `fd756ee96472` | cmdline: vary positional words and unknown spellings in reader matches |
| `9cbc64ec8e71` | newcli: check generated international names across user histories      |
| `a357b6bd9b4d` | newcli: check exact numeric and transferred email selectors            |
| `6f205bf69ac1` | cmdline: cover a carriage return before a list comma                   |
| `2e5f3af22dd3` | cmdline: exercise generic list completion through both protocols       |
| `1ea748d9b41a` | cmdline/reader: cover a sole space and a padded command alias          |
| `a673cb9aa00d` | cmdline/reader: check whitespace at command and value positions        |
| `17f48afc15c5` | util: check an Arabic digit at both ends of a username                 |
| `b8b12623c4d4` | util: check generated decimal digits across username positions         |
| `a484d4dfa4ca` | cmdline: check completion delimiters separately across generated lists |
