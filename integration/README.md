# Integration testing

Headscale's integration tests start a real Headscale server and run
scenarios against real Tailscale clients across supported versions, all
inside Docker. They are the safety net that keeps us honest about
Tailscale protocol compatibility.

This file documents **how to write** integration tests. For **how to
run** them, see [`../cmd/hi/README.md`](../cmd/hi/README.md).

Tests live in files ending with `_test.go`; the framework lives in the
rest of this directory (`scenario.go`, `tailscale.go`, helpers, and the
`hsic/`, `tsic/`, `dockertestutil/` packages).

## Running tests

For local runs, use [`cmd/hi`](../cmd/hi):

```bash
go run ./cmd/hi doctor
go run ./cmd/hi run "TestPingAllByIP"
```

Alternatively, [`act`](https://github.com/nektos/act) runs the GitHub
Actions workflow locally:

```bash
act pull_request -W .github/workflows/test-integration.yaml
```

Each test runs as a separate workflow on GitHub Actions. To add a new
test, run `go generate` inside `../cmd/gh-action-integration-generator/`
and commit the generated workflow file.

## Framework overview

The integration framework has four layers:

- **`scenario.go`** — `Scenario` orchestrates a test environment: a
  Headscale server, one or more users, and a collection of Tailscale
  clients. `NewScenario(spec)` returns a ready-to-use environment.
- **`hsic/`** — "Headscale Integration Container": wraps a Headscale
  server in Docker. Options for config, DB backend, DERP, OIDC, etc.
- **`tsic/`** — "Tailscale Integration Container": wraps a single
  Tailscale client. Options for version, hostname, auth method, etc.
- **`dockertestutil/`** — low-level Docker helpers (networks, container
  lifecycle, `IsRunningInContainer()` detection).

Tests compose these pieces via `ScenarioSpec` and `CreateHeadscaleEnv`
rather than calling Docker directly.

## Required scaffolding

### `IntegrationSkip(t)`

**Every** integration test function must call `IntegrationSkip(t)` as
its first statement. Without it, the test runs in the wrong environment
and fails with confusing errors.

```go
func TestMyScenario(t *testing.T) {
    IntegrationSkip(t)
    // ... rest of the test
}
```

`IntegrationSkip` is defined in `integration/scenario_test.go:15` and:

- skips the test when not running inside the Docker test container
  (`dockertestutil.IsRunningInContainer()`),
- skips when `-short` is passed to `go test`.

### Scenario setup

The canonical setup creates users, clients, and the Headscale server in
one shot:

```go
func TestMyScenario(t *testing.T) {
    IntegrationSkip(t)
    t.Parallel()

    spec := ScenarioSpec{
        NodesPerUser: 2,
        Users:        []string{"alice", "bob"},
    }
    scenario, err := NewScenario(spec)
    require.NoError(t, err)
    defer scenario.ShutdownAssertNoPanics(t)

    err = scenario.CreateHeadscaleEnv(
        []tsic.Option{tsic.WithSSH()},
        hsic.WithTestName("myscenario"),
    )
    require.NoError(t, err)

    allClients, err := scenario.ListTailscaleClients()
    require.NoError(t, err)

    headscale, err := scenario.Headscale()
    require.NoError(t, err)

    // ... assertions
}
```

Review `scenario.go` and `hsic/options.go` / `tsic/options.go` for the
full option set (DERP, OIDC, policy files, DB backend, ACL grants,
exit-node config, etc.).

## The `EventuallyWithT` pattern

Integration tests operate on a distributed system with real async
propagation: clients advertise state, the server processes it, updates
stream to peers. Direct assertions after state changes fail
intermittently. Wrap external calls in `assert.EventuallyWithT`:

```go
assert.EventuallyWithT(t, func(c *assert.CollectT) {
    status, err := client.Status()
    assert.NoError(c, err)
    for _, peerKey := range status.Peers() {
        peerStatus := status.Peer[peerKey]
        requirePeerSubnetRoutesWithCollect(c, peerStatus, expectedRoutes)
    }
}, 10*time.Second, 500*time.Millisecond, "client should see expected routes")
```

### External calls that need wrapping

These read distributed state and may reflect stale data until
propagation completes:

- `headscale.ListNodes()`
- `client.Status()`
- `client.Curl()`
- `client.Traceroute()`
- `client.Execute()` when the command reads state

### Blocking operations that must NOT be wrapped

State-mutating commands run exactly once and either succeed or fail
immediately — not eventually. Wrapping them in `EventuallyWithT` hides
real failures behind retry.

Use `client.MustStatus()` when you only need an ID for a blocking call:

```go
// CORRECT — mutation runs once
for _, client := range allClients {
    status := client.MustStatus()
    _, _, err := client.Execute([]string{
        "tailscale", "set",
        "--advertise-routes=" + expectedRoutes[string(status.Self.ID)],
    })
    require.NoErrorf(t, err, "failed to advertise route: %s", err)
}
```

Typical blocking operations: any `tailscale set` (routes, exit node,
accept-routes, ssh), node registration via the CLI, user creation via
gRPC.

### The four rules

1. **One external call per `EventuallyWithT` block.** Related assertions
   on the result of a single call go together in the same block.

   **Loop exception**: iterating over a collection of clients (or peers)
   and calling `Status()` on each inside a single block is allowed — it
   is the same logical "check all clients" operation. The rule applies
   to distinct calls like `ListNodes()` + `Status()`, which must be
   split into separate blocks.

2. **Never nest `EventuallyWithT` calls.** A nested retry loop
   multiplies timing windows and makes failures impossible to diagnose.

3. **Use `*WithCollect` helper variants** inside the block. Regular
   helpers use `require` and abort on the first failed assertion,
   preventing retry.

4. **Always provide a descriptive final message** — it appears on
   failure and is your only clue about what the test was waiting for.

### Variable scoping

Variables used across multiple `EventuallyWithT` blocks must be declared
at function scope. Inside the block, assign with `=`, not `:=` — `:=`
creates a shadow invisible to the outer scope:

```go
var nodes []*v1.Node
var err error
assert.EventuallyWithT(t, func(c *assert.CollectT) {
    nodes, err = headscale.ListNodes()   // = not :=
    assert.NoError(c, err)
    assert.Len(c, nodes, 2)
    requireNodeRouteCountWithCollect(c, nodes[0], 2, 2, 2)
}, 10*time.Second, 500*time.Millisecond, "nodes should have expected routes")

// nodes is usable here because it was declared at function scope
```

### Helper functions

Inside `EventuallyWithT` blocks, use the `*WithCollect` variants so
assertion failures restart the wait loop instead of failing the test
immediately:

- `requirePeerSubnetRoutesWithCollect(c, status, expected)` —
  `integration/route_test.go:2941`
- `requireNodeRouteCountWithCollect(c, node, announced, approved, subnet)` —
  `integration/route_test.go:2958`
- `assertTracerouteViaIPWithCollect(c, traceroute, ip)` —
  `integration/route_test.go:2898`

When you write a new helper to be called inside `EventuallyWithT`, it
must accept `*assert.CollectT` as its first parameter, not `*testing.T`.

## Identifying nodes by property, not position

The order of `headscale.ListNodes()` is not stable. Tests that index
`nodes[0]` will break when node ordering changes. Look nodes up by ID,
hostname, or tag:

```go
// WRONG — relies on array position
require.Len(t, nodes[0].GetAvailableRoutes(), 1)

// CORRECT — find the node that should have the route
expectedRoutes := map[string]string{"1": "10.33.0.0/16"}
for _, node := range nodes {
    nodeIDStr := fmt.Sprintf("%d", node.GetId())
    if route, shouldHaveRoute := expectedRoutes[nodeIDStr]; shouldHaveRoute {
        assert.Contains(t, node.GetAvailableRoutes(), route)
    }
}
```

## Full example: advertising and approving a route

```go
func TestRouteAdvertisementBasic(t *testing.T) {
    IntegrationSkip(t)
    t.Parallel()

    spec := ScenarioSpec{
        NodesPerUser: 2,
        Users:        []string{"user1"},
    }
    scenario, err := NewScenario(spec)
    require.NoError(t, err)
    defer scenario.ShutdownAssertNoPanics(t)

    err = scenario.CreateHeadscaleEnv([]tsic.Option{}, hsic.WithTestName("route"))
    require.NoError(t, err)

    allClients, err := scenario.ListTailscaleClients()
    require.NoError(t, err)

    headscale, err := scenario.Headscale()
    require.NoError(t, err)

    // --- Blocking: advertise the route on one client ---
    router := allClients[0]
    _, _, err = router.Execute([]string{
        "tailscale", "set",
        "--advertise-routes=10.33.0.0/16",
    })
    require.NoErrorf(t, err, "advertising route: %s", err)

    // --- Eventually: headscale should see the announced route ---
    var nodes []*v1.Node
    assert.EventuallyWithT(t, func(c *assert.CollectT) {
        nodes, err = headscale.ListNodes()
        assert.NoError(c, err)
        assert.Len(c, nodes, 2)

        for _, node := range nodes {
            if node.GetName() == router.Hostname() {
                requireNodeRouteCountWithCollect(c, node, 1, 0, 0)
            }
        }
    }, 10*time.Second, 500*time.Millisecond, "route should be announced")

    // --- Blocking: approve the route via headscale CLI ---
    var routerNode *v1.Node
    for _, node := range nodes {
        if node.GetName() == router.Hostname() {
            routerNode = node
            break
        }
    }
    require.NotNil(t, routerNode)

    _, err = headscale.ApproveRoutes(routerNode.GetId(), []string{"10.33.0.0/16"})
    require.NoError(t, err)

    // --- Eventually: a peer should see the approved route ---
    peer := allClients[1]
    assert.EventuallyWithT(t, func(c *assert.CollectT) {
        status, err := peer.Status()
        assert.NoError(c, err)
        for _, peerKey := range status.Peers() {
            if peerKey == router.PublicKey() {
                requirePeerSubnetRoutesWithCollect(c,
                    status.Peer[peerKey],
                    []netip.Prefix{netip.MustParsePrefix("10.33.0.0/16")})
            }
        }
    }, 10*time.Second, 500*time.Millisecond, "peer should see approved route")
}
```

## Common pitfalls

- **Forgetting `IntegrationSkip(t)`**: the test runs outside Docker and
  fails in confusing ways. Always the first line.
- **Using `require` inside `EventuallyWithT`**: aborts after the first
  iteration instead of retrying. Use `assert.*` + the `*WithCollect`
  helpers.
- **Mixing mutation and query in one `EventuallyWithT`**: hides real
  failures. Keep mutation outside, query inside.
- **Assuming node ordering**: look up by property.
- **Ignoring `err` from `client.Status()`**: retry only retries the
  whole block; don't silently drop errors from mid-block calls.
- **Timeouts too tight**: 5s is reasonable for local state, 10s for
  state that must propagate through the map poll cycle. Don't go lower
  to "speed up the test" — you just make it flaky.

## Debugging failing tests

Tests save comprehensive artefacts to `control_logs/{runID}/`. Read them
in this order: server stderr, client stderr, MapResponse JSON, database
snapshot. The full debugging workflow, heuristics, and failure patterns
are documented in [`../cmd/hi/README.md`](../cmd/hi/README.md).
