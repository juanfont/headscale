# Scheduled runs

| Round               | Last batch (UTC) | Passed batches | Passed examples | Startup failures |
| ------------------- | ---------------- | -------------: | --------------: | ---------------: |
| [1](round-1.csv.gz) | 21:41:17         |          2,851 |     600,454,674 |                0 |
| [2](round-2.csv.gz) | 23:41:22         |          4,751 |     666,121,770 |                0 |
| [3](round-3.csv.gz) | 01:41:22         |          5,262 |     674,830,112 |                3 |
| [4](round-4.csv.gz) | 03:41:21         |          6,101 |     689,098,438 |                0 |
| [5](round-5.csv.gz) | 05:41:21         |          5,961 |     532,453,252 |                2 |
| [6](round-6.csv.gz) | 06:21:40         |          2,065 |     156,429,316 |                0 |

Each compressed CSV records one row per completed batch with UTC timestamps, seed, test name, target and executable SHA-256. The first 149 batches predate binary retention.

## What changed between runs

| Round | Experiments, failures and corrections                                                                                                                                                                                                                                                                                                 |
| ----- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1     | Reviewers replayed callback-error identity, invalid sealed filters and empty arrays. Enumerating command aliases and flag placement supplied a finite comparison. Tagged checks reproduced adjacent-ID rounding, a missing-ID sort error and a strict expiry boundary.                                                                |
| 2     | Reviewer counterexamples caught zero-duration behavior in the first time correction and a scalar-completion regression in the first protocol correction. Seven real list endpoints supplied an independent empty-array check. Retained page tokens and an online-node fixture crossing a minute boundary gained focused tests.        |
| 3     | Reusing argv changed a deferred error. Differently capitalized future fields changed real query output. The numeric oracle initially rounded away a mutation in unknown JSON. Raw-token checks exposed it. Three TCP fixture startups failed, then passed serial replay.                                                              |
| 4     | User PATCH tests exposed missing diagnostics, and fresh state per shrink trial restored reproducibility. Terminal probes found disagreement on Thai and Indic text after the first clipping fix. Builder tests exposed shared alias, child and column storage.                                                                        |
| 5     | Independent state checks caught wrong-user and missing-ID mutations that shipped tests passed. Two long Unix socket paths stopped workers before their first draw. Shorter paths restored their exact seeds. Decimal cutoff, adjacent integer, Unicode username and API diagnostic cases yielded separate reproducer and fix commits. |
| 6     | Reviewer controls added a whitespace-only positional argument, padded command aliases and non-ASCII digit positions. Fixed-budget trials exposed infrequent carriage-return detection. Isolating each delimiter caught every measured seed by draw four. The closing partial round passed all 2,065 batches.                          |
