# hi — Headscale Integration test runner

`hi` wraps Docker container orchestration around the tests in
[`../../integration`](../../integration) and extracts debugging artefacts
(logs, database snapshots, MapResponse protocol captures) for post-mortem
analysis.

**Read this file in full before running any `hi` command.** The test
runner has sharp edges — wrong flags produce stale containers, lost
artefacts, or hung CI.

For test-authoring patterns (scenario setup, `EventuallyWithT`,
`IntegrationSkip`, helper variants), read
[`../../integration/README.md`](../../integration/README.md).

## Quick Start

```bash
# Verify system requirements (Docker, Go, disk space, images)
go run ./cmd/hi doctor

# Run a single test (the default flags are tuned for development)
go run ./cmd/hi run "TestPingAllByIP"

# Run a database-heavy test against PostgreSQL
go run ./cmd/hi run "TestExpireNode" --postgres

# Pattern matching
go run ./cmd/hi run "TestSubnet*"
```

Run `doctor` before the first `run` in any new environment. Tests
generate ~100 MB of logs per run in `control_logs/`; `doctor` verifies
there is enough space and that the required Docker images are available.

## Commands

| Command            | Purpose                                              |
| ------------------ | ---------------------------------------------------- |
| `run [pattern]`    | Execute the test(s) matching `pattern`               |
| `doctor`           | Verify system requirements                           |
| `clean networks`   | Prune unused Docker networks                         |
| `clean images`     | Clean old test images                                |
| `clean containers` | Kill **all** test containers (dangerous — see below) |
| `clean cache`      | Clean Go module cache volume                         |
| `clean all`        | Run all cleanup operations                           |

## Flags

Defaults are tuned for single-test development runs. Review before
changing.

| Flag                | Default        | Purpose                                                                     |
| ------------------- | -------------- | --------------------------------------------------------------------------- |
| `--timeout`         | `120m`         | Total test timeout. Use the built-in flag — never wrap with bash `timeout`. |
| `--postgres`        | `false`        | Use PostgreSQL instead of SQLite                                            |
| `--failfast`        | `true`         | Stop on first test failure                                                  |
| `--go-version`      | auto           | Detected from `go.mod` (currently 1.26.1)                                   |
| `--clean-before`    | `true`         | Clean stale (stopped/exited) containers before starting                     |
| `--clean-after`     | `true`         | Clean this run's containers after completion                                |
| `--keep-on-failure` | `false`        | Preserve containers for manual inspection on failure                        |
| `--logs-dir`        | `control_logs` | Where to save run artefacts                                                 |
| `--verbose`         | `false`        | Verbose output                                                              |
| `--stats`           | `false`        | Collect container resource-usage stats                                      |
| `--hs-memory-limit` | `0`            | Fail if any headscale container exceeds N MB (0 = disabled)                 |
| `--ts-memory-limit` | `0`            | Fail if any tailscale container exceeds N MB                                |

### Timeout guidance

The default `120m` is generous for a single test. If you must tune it,
these are realistic floors by category:

| Test type                 | Minimum     | Examples                              |
| ------------------------- | ----------- | ------------------------------------- |
| Basic functionality / CLI | 900s (15m)  | `TestPingAllByIP`, `TestCLI*`         |
| Route / ACL               | 1200s (20m) | `TestSubnet*`, `TestACL*`             |
| HA / failover             | 1800s (30m) | `TestHASubnetRouter*`                 |
| Long-running              | 2100s (35m) | `TestNodeOnlineStatus` (~12 min body) |
| Full suite                | 45m         | `go test ./integration -timeout 45m`  |

**Never** use the shell `timeout` command around `hi`. It kills the
process mid-cleanup and leaves stale containers:

```bash
timeout 300 go run ./cmd/hi run "TestName"   # WRONG — orphaned containers
go run ./cmd/hi run "TestName" --timeout=900s  # correct
```

## Concurrent Execution

Multiple `hi run` invocations can run simultaneously on the same Docker
daemon. Each invocation gets a unique **Run ID** (format
`YYYYMMDD-HHMMSS-6charhash`, e.g. `20260409-104215-mdjtzx`).

- **Container names** include the short run ID: `ts-mdjtzx-1-74-fgdyls`
- **Docker labels**: `hi.run-id={runID}` on every container
- **Port allocation**: dynamic — kernel assigns free ports, no conflicts
- **Cleanup isolation**: each run cleans only its own containers
- **Log directories**: `control_logs/{runID}/`

```bash
# Start three tests in parallel — each gets its own run ID
go run ./cmd/hi run "TestPingAllByIP" &
go run ./cmd/hi run "TestACLAllowUserDst" &
go run ./cmd/hi run "TestOIDCAuthenticationPingAll" &
```

### Safety rules for concurrent runs

- ✅ Your run cleans only containers labelled with its own `hi.run-id`
- ✅ `--clean-before` removes only stopped/exited containers
- ❌ **Never** run `docker rm -f $(docker ps -q --filter name=hs-)` —
  this destroys other agents' live test sessions
- ❌ **Never** run `docker system prune -f` while any tests are running
- ❌ **Never** run `hi clean containers` / `hi clean all` while other
  tests are running — both kill all test containers on the daemon

To identify your own containers:

```bash
docker ps --filter "label=hi.run-id=20260409-104215-mdjtzx"
```

The run ID appears at the top of the `hi run` output — copy it from
there rather than trying to reconstruct it.

## Artefacts

Every run saves debugging artefacts under `control_logs/{runID}/`:

```
control_logs/20260409-104215-mdjtzx/
├── hs-<test>-<hash>.stderr.log        # headscale server errors
├── hs-<test>-<hash>.stdout.log        # headscale server output
├── hs-<test>-<hash>.db                # database snapshot (SQLite)
├── hs-<test>-<hash>_metrics.txt       # Prometheus metrics dump
├── hs-<test>-<hash>-mapresponses/     # MapResponse protocol captures
├── ts-<client>-<hash>.stderr.log      # tailscale client errors
├── ts-<client>-<hash>.stdout.log      # tailscale client output
└── ts-<client>-<hash>_status.json     # client network-status dump
```

Artefacts persist after cleanup. Old runs accumulate fast — delete
unwanted directories to reclaim disk.

## Debugging workflow

When a test fails, read the artefacts **in this order**:

1. **`hs-*.stderr.log`** — headscale server errors, panics, policy
   evaluation failures. Most issues originate server-side.

   ```bash
   grep -E "ERROR|panic|FATAL" control_logs/*/hs-*.stderr.log
   ```

2. **`ts-*.stderr.log`** — authentication failures, connectivity issues,
   DNS resolution problems on the client side.

3. **MapResponse JSON** in `hs-*-mapresponses/` — protocol-level
   debugging for network map generation, peer visibility, route
   distribution, policy evaluation results.

   ```bash
   ls control_logs/*/hs-*-mapresponses/
   jq '.Peers[] | {Name, Tags, PrimaryRoutes}' \
       control_logs/*/hs-*-mapresponses/001.json
   ```

4. **`*_status.json`** — client peer-connectivity state.

5. **`hs-*.db`** — SQLite snapshot for post-mortem consistency checks.

   ```bash
   sqlite3 control_logs/<runID>/hs-*.db
   sqlite> .tables
   sqlite> .schema nodes
   sqlite> SELECT id, hostname, user_id, tags FROM nodes WHERE hostname LIKE '%problematic%';
   ```

6. **`*_metrics.txt`** — Prometheus dumps for latency, NodeStore
   operation timing, database query performance, memory usage.

## Heuristic: infrastructure vs code

**Before blaming Docker, disk, or network: read `hs-*.stderr.log` in
full.** In practice, well over 99% of failures are code bugs (policy
evaluation, NodeStore sync, route approval) rather than infrastructure.

Actual infrastructure failures have signature error messages:

| Signature                                                       | Cause                     | Fix                                                           |
| --------------------------------------------------------------- | ------------------------- | ------------------------------------------------------------- |
| `failed to resolve "hs-...": no DNS fallback candidates remain` | Docker DNS                | Reset Docker networking                                       |
| `container creation timeout`, no progress >2 min                | Resource exhaustion       | `docker system prune -f` (when no other tests running), retry |
| OOM kills, slow Docker daemon                                   | Too many concurrent tests | Reduce concurrency, wait for completion                       |
| `no space left on device`                                       | Disk full                 | Delete old `control_logs/`                                    |

If you don't see a signature error, **assume it's a code regression** —
do not retry hoping the flake goes away.

## Common failure patterns (code bugs)

### Route advertisement timing

Test asserts route state before the client has finished propagating its
Hostinfo update. Symptom: `nodes[0].GetAvailableRoutes()` empty when
the test expects a route.

- **Wrong fix**: `time.Sleep(5 * time.Second)` — fragile and slow.
- **Right fix**: wrap the assertion in `EventuallyWithT`. See
  [`../../integration/README.md`](../../integration/README.md).

### NodeStore sync issues

Route changes not reflected in the NodeStore snapshot. Symptom: route
advertisements in logs but no tracking updates in subsequent reads.

The sync point is `State.UpdateNodeFromMapRequest()` in
`hscontrol/state/state.go`. If you added a new kind of client state
update, make sure it lands here.

### HA failover: routes disappearing on disconnect

`TestHASubnetRouterFailover` fails because approved routes vanish when
a subnet router goes offline. **This is a bug, not expected behaviour.**
Route approval must not be coupled to client connectivity — routes
stay approved; only the primary-route selection is affected by
connectivity.

### Policy evaluation race

Symptom: tests that change policy and immediately assert peer visibility
fail intermittently. Policy changes trigger async recomputation.

- See recent fixes in `git log -- hscontrol/state/` for examples (e.g.
  the `PolicyChange` trigger on every Connect/Disconnect).

### SQLite vs PostgreSQL timing differences

Some race conditions only surface on one backend. If a test is flaky,
try the other backend with `--postgres`:

```bash
go run ./cmd/hi run "TestName" --postgres --verbose
```

PostgreSQL generally has more consistent timing; SQLite can expose
races during rapid writes.

## Keeping containers for inspection

If you need to inspect a failed test's state manually:

```bash
go run ./cmd/hi run "TestName" --keep-on-failure
# containers survive — inspect them
docker exec -it ts-<runID>-<...> /bin/sh
docker logs hs-<runID>-<...>
# clean up manually when done
go run ./cmd/hi clean all   # only when no other tests are running
```
