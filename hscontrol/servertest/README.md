# Server stress tests

`TestScale` exercises a real Headscale server, SQLite, policy compilation,
the NodeStore, mapper workers, Noise, and Tailscale control clients over the
existing in-memory network. Every registered node has a live control client.
The test cases and their policies are together in `scale_test.go`.

The ordinary test suite runs all five policies with 12 nodes. Larger runs
require `HEADSCALE_STRESS_NODES`; setting it replaces the small node count.
Nothing large is enabled by `go test ./...` or by omitting `-short`.

| Case               | Expected visibility                                          | Main pressure                                      |
| ------------------ | ------------------------------------------------------------ | -------------------------------------------------- |
| `allow_all`        | Everyone sees everyone                                       | Dense graph, map size, broadcast fan-out           |
| `isolated`         | No peers                                                     | Registration and state updates without peer output |
| `personal_devices` | Up to ten devices belonging to the same user                 | Per-node policy compilation and isolation          |
| `shared_service`   | One tagged service sees everyone; everyone else sees only it | Uneven fan-out and tag identity                    |
| `personal_ssh`     | Personal devices, with SSH to the same user's devices        | Per-node SSH policy generation                     |

Each case enrolls its clients, sends three Hostinfo bursts, revokes access,
restores access, and reconnects one client per user. Bursts change one node
per ten-node user; the final user can have fewer nodes. Registration uses
batches of at most 32 concurrent logins. Mapper workers are
`min(4, GOMAXPROCS)`, with the harness's 50 ms mapper delay, 30-frame session
buffer. Explicit scale runs use the server's default NodeStore batching;
the routine 12-node smoke run shortens its batch wait to 10 ms.

Completion means the intended state reached every affected client, with the
exact permitted peer IDs, fresh OS markers, and online peers. Bounded
IPv4/IPv6 filter probes check allowed TCP traffic and denied ports, protocols,
and cross-user access. SSH checks the accept action, root mapping, and exact
same-user principal addresses. After reconnecting, a new policy generation
broadcast checks delivery on every recovered stream, including isolated nodes.
Policy changes carry a new node attribute so an old map cannot satisfy a
policy wait. Revocation also checks that packet filter rules are empty.
Each phase checks both client streams and server connections and rejects
mapper work errors. Convergence has a shared two-minute deadline per wait,
and existing login helpers retain their ten-second registration timeout.
There are no sleep-based completion checks or automatic reconnect retries.

## Run

Use the pinned Go toolchain from `nix develop`, as for the other server tests.

```sh
# Fast coverage of every case; this also runs in the ordinary suite.
go test ./hscontrol/servertest -run '^TestScale$' -count=1 -v

# Select a scale and one policy. All nodes are real connected control clients.
HEADSCALE_STRESS_NODES=500 GOMAXPROCS=4 \
  go test ./hscontrol/servertest -run '^TestScale/500_nodes/personal_devices$' \
  -count=1 -v -timeout=20m

HEADSCALE_STRESS_NODES=1000 GOMAXPROCS=4 \
  go test ./hscontrol/servertest -run '^TestScale/1000_nodes/shared_service$' \
  -count=1 -v -timeout=30m

HEADSCALE_STRESS_NODES=10000 GOMAXPROCS=4 \
  go test ./hscontrol/servertest -run '^TestScale/10000_nodes/personal_devices$' \
  -count=1 -v -timeout=60m

# A compute-constrained run: one Go execution thread and one mapper worker.
HEADSCALE_STRESS_NODES=500 GOMAXPROCS=1 GOMEMLIMIT=512MiB \
  go test ./hscontrol/servertest -run '^TestScale/500_nodes/personal_devices$' \
  -count=1 -v -timeout=30m
```

Omit the final policy component of `-run` to run every policy at that size.
Choose large dense runs deliberately: 10,000 all-to-all clients hold
99,990,000 directed peer entries before accounting for serialized maps and
other state. A sparse output graph still requires policy/peer calculations;
it does not guarantee linear CPU use. `GOMEMLIMIT` is a soft Go heap target,
not an RSS cap. Go's resource settings constrain server and clients together.

## Read results and find congestion

Each phase logs wall time, allocated bytes during the phase, ending heap
bytes, GC cycles, goroutines, registered nodes, live clients, and visible
peer entries. Ending heap is not peak memory or RSS. These numbers cover
the whole test process, including clients and assertions. They are useful
for comparing identical workloads and finding limits, not server-only
latency or memory claims. Old client netmap histories are disabled; the
current maps remain, as they do in connected clients.

Repeat one selected workload with fixed toolchain, node count, runtime
settings, and hardware. Disable Go's test cache with `-count=1`, run each
sample in a fresh process, keep unrelated heavy jobs off the host,
and save the commit ID, `go version`, CPU model, and command with the log.
Keep enrollment and steady-state phase results separate. Failures and
timeouts are results, not samples to silently retry or discard.

```sh
mkdir -p control_logs/server-scale
HEADSCALE_STRESS_NODES=500 GOMAXPROCS=4 \
  go test ./hscontrol/servertest -run '^TestScale/500_nodes/personal_devices$' \
  -count=1 -v -timeout=20m \
  -cpuprofile=control_logs/server-scale/cpu.prof \
  -memprofile=control_logs/server-scale/heap.prof \
  >control_logs/server-scale/run.log 2>&1
go tool pprof control_logs/server-scale/cpu.prof
```

Use `-trace=control_logs/server-scale/trace.out` in a separate diagnostic run
to inspect scheduling, blocking, and GC. Profiles include setup, teardown,
test clients, and assertions. In the pinned Tailscale dependency, zstd also
performs extra runtime stack inspection in test binaries; confirm CPU
findings against a standalone server before optimizing them. Docker/real
tailscaled tests remain necessary for network behavior, data-plane traffic,
and a server-only resource ceiling.
