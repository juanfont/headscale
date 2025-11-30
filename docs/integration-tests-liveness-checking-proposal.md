# Integration Test Suite Proposal: Node Liveness Checking

## Executive Summary

This document proposes a comprehensive integration test suite for the node liveness checking feature introduced in commit `d1f66b75`. The test suite will validate the ping scheduler functionality across diverse Tailscale client versions and various configuration scenarios.

## Feature Overview

The liveness checking feature consists of:

1. **PingScheduler** (`hscontrol/ping_scheduler.go`):
   - Periodically sends health check pings to nodes
   - Distributes pings with jitter to prevent bunching
   - Configurable intervals, jitter, and timeouts
   - Handles unresponsive nodes

2. **Configuration** (`hscontrol/types/config.go`):
   ```yaml
   node_liveness:
     enable_scheduler: false  # default: disabled
     ping_interval: 2m        # interval between ping rounds
     ping_jitter: 30s         # random jitter for distribution
     ping_timeout: 10s        # timeout for ping responses
   ```

3. **Integration Points**:
   - Uses existing ping infrastructure (`ping.go`)
   - Leverages MapBatcher for direct node updates
   - Works with NodeStore for node state management

## Test Suite Architecture

### Version Coverage Strategy

The test suite will use a matrix approach to test across Tailscale versions:

```go
// Version groups for comprehensive testing
type VersionGroup struct {
    Name        string
    Description string
    Versions    []string
}

var LivenessTestVersionGroups = []VersionGroup{
    {
        Name:        "bleeding-edge",
        Description: "Latest unstable releases",
        Versions:    []string{"head", "unstable"},
    },
    {
        Name:        "current",
        Description: "Latest stable releases",
        Versions:    AllVersions[2:4], // Two most recent stable
    },
    {
        Name:        "legacy",
        Description: "Oldest supported versions",
        Versions:    AllVersions[len(AllVersions)-2:], // Two oldest
    },
    {
        Name:        "mixed",
        Description: "Mix of old and new versions",
        Versions:    []string{"head", AllVersions[len(AllVersions)-1]},
    },
}
```

### Test Categories

## 1. Basic Scheduler Functionality Tests

### Test: `TestLivenessSchedulerStartStop`
**Purpose**: Verify scheduler lifecycle management  
**Versions**: bleeding-edge only  
**Scenario**:
```go
spec := ScenarioSpec{
    Users:        []string{"user1"},
    NodesPerUser: 2,
    Versions:     []string{"head"},
}
```
**Validations**:
- Scheduler starts successfully when enabled
- Scheduler remains stopped when disabled
- Scheduler shuts down gracefully
- No pings sent when scheduler is disabled
- Metrics reflect scheduler state

---

### Test: `TestLivenessSchedulerBasicPingRound`
**Purpose**: Verify basic ping round execution  
**Versions**: current (2 latest stable)  
**Configuration**:
```yaml
node_liveness:
  enable_scheduler: true
  ping_interval: 30s
  ping_jitter: 5s
  ping_timeout: 10s
```
**Scenario**:
```go
spec := ScenarioSpec{
    Users:        []string{"user1", "user2"},
    NodesPerUser: 2,
    Versions:     MustTestVersions[2:4], // Latest stable
}
```
**Validations**:
- All nodes receive health check pings within expected window
- Pings are distributed with jitter (not bunched)
- Ping responses indicate success
- Scheduler respects configured interval
- No pings sent to expired nodes

---

### Test: `TestLivenessSchedulerPingDistribution`
**Purpose**: Verify jitter distribution prevents synchronization  
**Versions**: mixed (head + oldest)  
**Configuration**:
```yaml
node_liveness:
  enable_scheduler: true
  ping_interval: 60s
  ping_jitter: 20s
  ping_timeout: 10s
```
**Scenario**:
```go
spec := ScenarioSpec{
    Users:        []string{"user1"},
    NodesPerUser: 10,
    Versions:     []string{"head", AllVersions[len(AllVersions)-1]}, // Mix
}
```
**Validations**:
- Ping timestamps show distribution across 20s window
- No more than 2 pings within 1s of each other
- All pings complete within interval + jitter window
- CPU/network load is spread over time (not spiked)

---

## 2. Multi-Version Compatibility Tests

### Test: `TestLivenessSchedulerAcrossVersions`
**Purpose**: Verify scheduler works with diverse client versions  
**Versions**: all major versions  
**Scenario**:
```go
spec := ScenarioSpec{
    Users:        []string{"user1"},
    NodesPerUser: 6,
    Versions:     AllVersions, // All supported versions
}
```
**Validations**:
- All versions respond to health check pings
- No version-specific failures
- Response format compatible across versions
- Older clients handle ping requests gracefully
- Newer clients provide enhanced ping data

---

### Test: `TestLivenessSchedulerLegacyClientSupport`
**Purpose**: Verify graceful degradation with legacy clients  
**Versions**: legacy (2 oldest supported)  
**Scenario**:
```go
spec := ScenarioSpec{
    Users:        []string{"legacy-user"},
    NodesPerUser: 4,
    Versions:     AllVersions[len(AllVersions)-2:], // Oldest
}
```
**Validations**:
- Legacy clients respond to pings
- Scheduler handles missing/incomplete responses
- No crashes or errors with older protocol versions
- Fallback behavior works correctly

---

### Test: `TestLivenessSchedulerMixedVersionsTopology`
**Purpose**: Verify scheduler in diverse version topology  
**Versions**: all groups mixed  
**Scenario**:
```go
spec := ScenarioSpec{
    Users:        []string{"bleeding", "current", "legacy"},
    NodesPerUser: 2,
    Versions:     []string{"head", "unstable", 
                           AllVersions[2], AllVersions[3],
                           AllVersions[len(AllVersions)-2], 
                           AllVersions[len(AllVersions)-1]},
}
```
**Validations**:
- All nodes across all versions receive pings
- No version-specific bias in ping distribution
- Mixed topology doesn't affect scheduler reliability

---

## 3. Configuration Variation Tests

### Test: `TestLivenessSchedulerShortInterval`
**Purpose**: Validate rapid ping intervals  
**Versions**: current  
**Configuration**:
```yaml
node_liveness:
  enable_scheduler: true
  ping_interval: 10s
  ping_jitter: 2s
  ping_timeout: 5s
```
**Scenario**:
```go
spec := ScenarioSpec{
    Users:        []string{"user1"},
    NodesPerUser: 3,
    MaxWait:      2 * time.Minute,
}
```
**Validations**:
- System handles rapid ping intervals
- No resource exhaustion or backpressure
- Ping rounds complete before next round starts
- Metrics show expected ping frequency

---

### Test: `TestLivenessSchedulerLongInterval`
**Purpose**: Validate extended ping intervals  
**Versions**: current  
**Configuration**:
```yaml
node_liveness:
  enable_scheduler: true
  ping_interval: 5m
  ping_jitter: 30s
  ping_timeout: 15s
```
**Scenario**:
```go
spec := ScenarioSpec{
    Users:        []string{"user1"},
    NodesPerUser: 2,
    MaxWait:      7 * time.Minute,
}
```
**Validations**:
- Scheduler waits full interval between rounds
- First ping round happens after initial delay
- Long intervals don't cause scheduler drift
- Nodes remain healthy despite infrequent pings

---

### Test: `TestLivenessSchedulerZeroJitter`
**Purpose**: Validate scheduler with no jitter  
**Versions**: current  
**Configuration**:
```yaml
node_liveness:
  enable_scheduler: true
  ping_interval: 30s
  ping_jitter: 0s
  ping_timeout: 10s
```
**Validations**:
- Pings are distributed across interval without jitter
- No errors or panics with zero jitter
- Distribution still prevents bunching

---

### Test: `TestLivenessSchedulerHighJitter`
**Purpose**: Validate scheduler with high jitter relative to interval  
**Versions**: current  
**Configuration**:
```yaml
node_liveness:
  enable_scheduler: true
  ping_interval: 30s
  ping_jitter: 25s
  ping_timeout: 10s
```
**Validations**:
- High jitter doesn't cause pings to exceed interval
- All pings complete before next round
- Distribution is maximally spread

---

## 4. Scale and Performance Tests

### Test: `TestLivenessSchedulerManyNodes`
**Purpose**: Verify scheduler scales with many nodes  
**Versions**: current  
**Scenario**:
```go
spec := ScenarioSpec{
    Users:        []string{"user1", "user2", "user3"},
    NodesPerUser: 10,
    Versions:     MustTestVersions[2:4],
}
```
**Validations**:
- Scheduler handles 30+ nodes efficiently
- Ping distribution scales appropriately
- Memory usage remains bounded
- CPU usage is reasonable
- All nodes receive pings within expected window

---

### Test: `TestLivenessSchedulerConcurrentPingRounds`
**Purpose**: Verify scheduler doesn't overlap ping rounds  
**Versions**: current  
**Configuration**:
```yaml
node_liveness:
  enable_scheduler: true
  ping_interval: 20s
  ping_jitter: 15s
  ping_timeout: 5s
```
**Scenario**:
```go
spec := ScenarioSpec{
    Users:        []string{"user1"},
    NodesPerUser: 8,
}
```
**Validations**:
- Ping rounds don't overlap
- If round takes too long, next round waits
- No duplicate concurrent pings to same node
- Scheduler maintains state consistency

---

## 5. Failure and Recovery Tests

### Test: `TestLivenessSchedulerUnresponsiveNode`
**Purpose**: Verify handling of nodes that don't respond  
**Versions**: current  
**Scenario**:
```go
spec := ScenarioSpec{
    Users:        []string{"user1"},
    NodesPerUser: 3,
}
```
**Test Flow**:
1. Start all nodes with scheduler enabled
2. Bring one node down (container stop)
3. Wait for ping round
4. Verify unresponsive node handling
5. Bring node back up
6. Verify recovery

**Validations**:
- Unresponsive node detected after timeout
- Other nodes continue to receive pings
- Node marked as potentially offline (logged)
- Node recovery detected in subsequent round
- No scheduler crashes or hangs

---

### Test: `TestLivenessSchedulerNodeExpiration`
**Purpose**: Verify expired nodes are skipped  
**Versions**: current  
**Scenario**:
```go
spec := ScenarioSpec{
    Users:        []string{"user1"},
    NodesPerUser: 3,
}
```
**Test Flow**:
1. Create ephemeral nodes with short expiry (2 minutes)
2. Wait for nodes to expire
3. Verify scheduler skips expired nodes
4. Create new non-expired node
5. Verify new node receives pings

**Validations**:
- Expired nodes are not pinged
- Scheduler continues with non-expired nodes
- New nodes are added to ping rotation
- Logs show expired nodes were skipped

---

### Test: `TestLivenessSchedulerNodeChurn`
**Purpose**: Verify scheduler adapts to node changes  
**Versions**: current  
**Scenario**:
```go
spec := ScenarioSpec{
    Users:        []string{"user1"},
    NodesPerUser: 2,
}
```
**Test Flow**:
1. Start with 2 nodes
2. During scheduler operation:
   - Add 2 new nodes
   - Remove 1 node
   - Add 1 more node
3. Monitor ping distribution

**Validations**:
- New nodes receive pings in next round
- Removed nodes stop receiving pings
- Scheduler adjusts distribution dynamically
- No stale state or memory leaks

---

### Test: `TestLivenessSchedulerNetworkPartition`
**Purpose**: Verify behavior during network issues  
**Versions**: current  
**Scenario**:
```go
spec := ScenarioSpec{
    Users:        []string{"user1"},
    NodesPerUser: 2,
    Networks: map[string][]string{
        "network1": {"user1"},
        "network2": {"user1"},
    },
}
```
**Test Flow**:
1. Start nodes in separate networks
2. Simulate network partition
3. Verify ping failures handled gracefully
4. Restore network
5. Verify recovery

**Validations**:
- Partitioned nodes timeout appropriately
- Scheduler continues despite failures
- Network recovery is detected
- No cascading failures

---

## 6. Integration Tests

### Test: `TestLivenessSchedulerWithManualPing`
**Purpose**: Verify scheduler coexists with manual ping commands  
**Versions**: current  
**Scenario**:
```go
spec := ScenarioSpec{
    Users:        []string{"user1"},
    NodesPerUser: 3,
}
```
**Test Flow**:
1. Enable scheduler
2. Manually trigger pings via CLI/API
3. Verify both scheduler and manual pings work
4. Check for conflicts or race conditions

**Validations**:
- Manual pings don't interfere with scheduler
- Both types of pings succeed
- No duplicate ping handling issues
- PingManager handles concurrent requests

---

### Test: `TestLivenessSchedulerWithNodeUpdate`
**Purpose**: Verify scheduler during node state changes  
**Versions**: current  
**Scenario**:
```go
spec := ScenarioSpec{
    Users:        []string{"user1"},
    NodesPerUser: 3,
}
```
**Test Flow**:
1. Start scheduler
2. Update node properties (hostinfo, routes, etc.)
3. Verify scheduler continues normally
4. Check pings reflect updated state

**Validations**:
- Scheduler unaffected by node updates
- Pings use current node state
- NodeStore synchronization works correctly
- No stale data in pings

---

### Test: `TestLivenessSchedulerWithPolicyChanges`
**Purpose**: Verify scheduler works with ACL policy updates  
**Versions**: current  
**Scenario**:
```go
spec := ScenarioSpec{
    Users:        []string{"user1", "user2"},
    NodesPerUser: 2,
}
```
**Test Flow**:
1. Start with permissive policy
2. Enable scheduler
3. Change policy to isolate users
4. Verify scheduler adapts

**Validations**:
- Policy changes don't break scheduler
- Scheduled pings respect policy (if applicable)
- No crashes during policy updates

---

## 7. Edge Cases and Corner Cases

### Test: `TestLivenessSchedulerSingleNode`
**Purpose**: Verify scheduler with minimal nodes  
**Versions**: current  
**Scenario**:
```go
spec := ScenarioSpec{
    Users:        []string{"user1"},
    NodesPerUser: 1,
}
```
**Validations**:
- Single node receives health checks
- No errors with minimal topology
- Self-ping scenarios handled

---

### Test: `TestLivenessSchedulerNoNodes`
**Purpose**: Verify scheduler with no registered nodes  
**Versions**: current  
**Configuration**:
```yaml
node_liveness:
  enable_scheduler: true
  ping_interval: 30s
```
**Test Flow**:
1. Start headscale with scheduler enabled
2. Don't register any nodes
3. Verify scheduler runs without errors
4. Add node and verify ping starts

**Validations**:
- Empty node list doesn't crash scheduler
- Scheduler continues running
- New nodes are detected and pinged

---

### Test: `TestLivenessSchedulerRapidNodeRegistration`
**Purpose**: Verify scheduler during burst node registration  
**Versions**: current  
**Test Flow**:
1. Start scheduler
2. Register 10 nodes rapidly (within 5s)
3. Verify all nodes are eventually pinged

**Validations**:
- Rapid registration doesn't cause issues
- All new nodes added to ping rotation
- No race conditions or panics

---

### Test: `TestLivenessSchedulerConfigReload`
**Purpose**: Verify scheduler behavior on config changes  
**Versions**: current  
**Test Flow**:
1. Start with scheduler disabled
2. Update config to enable scheduler
3. Reload configuration (if supported)
4. Verify behavior

**Validations**:
- Config changes handled gracefully
- Scheduler state transitions correctly
- Note: This may require restart in current implementation

---

## 8. Database Backend Tests

### Test: `TestLivenessSchedulerWithPostgres`
**Purpose**: Verify scheduler works with PostgreSQL backend  
**Versions**: current  
**Scenario**:
```go
spec := ScenarioSpec{
    Users:        []string{"user1"},
    NodesPerUser: 3,
}
// Run with --postgres flag
```
**Validations**:
- Scheduler works identically with Postgres
- Node lookups perform adequately
- Database connections managed properly

---

### Test: `TestLivenessSchedulerWithSQLite`
**Purpose**: Verify scheduler works with SQLite backend  
**Versions**: current  
**Scenario**:
```go
spec := ScenarioSpec{
    Users:        []string{"user1"},
    NodesPerUser: 3,
}
// Default SQLite backend
```
**Validations**:
- Scheduler works with SQLite
- File locking doesn't cause issues
- Performance is acceptable

---

## 9. Metrics and Observability Tests

### Test: `TestLivenessSchedulerMetrics`
**Purpose**: Verify scheduler exposes useful metrics  
**Versions**: current  
**Scenario**:
```go
spec := ScenarioSpec{
    Users:        []string{"user1"},
    NodesPerUser: 3,
}
```
**Validations**:
- Prometheus metrics available
- Metrics show ping success/failure counts
- Latency metrics are accurate
- Scheduler state reflected in metrics

---

### Test: `TestLivenessSchedulerLogging`
**Purpose**: Verify appropriate logging levels and content  
**Versions**: current  
**Scenario**:
```go
spec := ScenarioSpec{
    Users:        []string{"user1"},
    NodesPerUser: 2,
}
```
**Validations**:
- Info logs show ping rounds starting
- Debug logs show individual pings
- Warnings logged for failures
- Log volume is reasonable
- Sensitive data not leaked in logs

---

## Implementation Guidelines

### Test File Structure

```
integration/
├── liveness_basic_test.go           # Tests 1-3
├── liveness_multiversion_test.go    # Test 4-6
├── liveness_config_test.go          # Test 7-9
├── liveness_scale_test.go           # Test 10-11
├── liveness_failure_test.go         # Test 12-16
├── liveness_integration_test.go     # Test 17-19
├── liveness_edge_cases_test.go      # Test 20-24
├── liveness_backends_test.go        # Test 25-26
└── liveness_observability_test.go   # Test 27-28
```

### Test Naming Convention

All tests should follow the pattern:
```go
func TestLiveness<FeatureArea><Specific>(t *testing.T)
```

### Helper Functions

Create shared helper functions for common patterns:

```go
// Helper to create headscale with liveness enabled
func createHeadscaleWithLiveness(
    t *testing.T,
    scenario *Scenario,
    interval, jitter, timeout time.Duration,
) (ControlServer, error)

// Helper to verify ping distribution timing
func verifyPingDistribution(
    t *testing.T,
    pings []PingEvent,
    expectedWindow time.Duration,
    maxBunching int,
)

// Helper to wait for ping round completion
func waitForPingRound(
    t *testing.T,
    headscale ControlServer,
    nodeCount int,
    timeout time.Duration,
) error

// Helper to verify unresponsive node handling
func verifyUnresponsiveNodeDetection(
    t *testing.T,
    headscale ControlServer,
    nodeID uint64,
    timeout time.Duration,
) error

// Helper to check scheduler metrics
func verifySchedulerMetrics(
    t *testing.T,
    headscale ControlServer,
    expectedPings int,
    expectedFailures int,
) error
```

### EventuallyWithT Patterns

All tests must follow integration test best practices:

```go
// External calls wrapped in EventuallyWithT
assert.EventuallyWithT(t, func(c *assert.CollectT) {
    nodes, err := headscale.ListNodes()
    assert.NoError(c, err)
    
    // Verify all nodes received recent pings
    for _, node := range nodes {
        lastPing := getLastPingTime(node)
        assert.WithinDuration(c, time.Now(), lastPing, 
            interval+jitter, "Node should have been pinged recently")
    }
}, timeout, retryInterval, "Waiting for ping round to complete")
```

### Version Matrix Testing

Tests should use subtests for version coverage:

```go
func TestLivenessSchedulerAcrossVersions(t *testing.T) {
    for _, vg := range LivenessTestVersionGroups {
        t.Run(vg.Name, func(t *testing.T) {
            spec := ScenarioSpec{
                Users:        []string{"user1"},
                NodesPerUser: len(vg.Versions),
                Versions:     vg.Versions,
            }
            // Test logic here
        })
    }
}
```

## Test Execution Strategy

### Priority Levels

1. **P0 - Must Run Always**:
   - Basic functionality tests (1-3)
   - Key integration tests (17-19)
   - Critical failure tests (12-14)

2. **P1 - Run on PR**:
   - Multi-version compatibility (4-6)
   - Configuration variations (7-9)
   - Edge cases (20-24)

3. **P2 - Run Nightly**:
   - Scale tests (10-11)
   - Extended failure scenarios (15-16)
   - Database backend tests (25-26)
   - Observability tests (27-28)

### Execution Commands

```bash
# Run all liveness tests with default versions
go run ./cmd/hi run "TestLiveness*" --verbose

# Run with PostgreSQL backend
go run ./cmd/hi run "TestLiveness*" --verbose --postgres

# Run specific test category
go run ./cmd/hi run "TestLivenessSchedulerBasic*" --verbose

# Run with all version groups
HEADSCALE_TEST_ALL_VERSIONS=1 go run ./cmd/hi run "TestLiveness*" --verbose
```

## Success Criteria

The test suite is considered successful when:

1. ✅ All P0 tests pass with current and bleeding-edge versions
2. ✅ No panics or crashes during any test execution
3. ✅ All version groups show >= 95% test pass rate
4. ✅ Performance tests show reasonable resource usage
5. ✅ Failure tests demonstrate graceful degradation
6. ✅ Integration tests show no conflicts with existing features
7. ✅ Test execution completes within reasonable time (< 30 min total)

## Future Enhancements

### Additional Test Scenarios

1. **Test with DERP relay**: Verify scheduler works when nodes communicate via DERP
2. **Test with subnet routers**: Ensure router nodes are properly monitored
3. **Test with exit nodes**: Verify exit nodes receive health checks
4. **Test with ephemeral nodes**: Validate handling of ephemeral node lifecycle
5. **Test pause/resume scheduler**: If API is added for runtime control

### Advanced Observability

1. **Distributed tracing**: Add trace validation for ping flows
2. **Detailed latency profiling**: Per-version latency breakdown
3. **Network topology visualization**: Verify ping patterns match topology

### Chaos Engineering

1. **Random node failures**: Simulate arbitrary node crashes
2. **Network jitter injection**: Add artificial latency/packet loss
3. **Resource constraints**: Test under CPU/memory pressure
4. **Time drift simulation**: Verify scheduler with clock skew

## Conclusion

This comprehensive test suite ensures the node liveness checking feature:
- Works reliably across all supported Tailscale versions
- Handles various configuration scenarios gracefully
- Scales appropriately with network size
- Recovers from failures elegantly
- Integrates seamlessly with existing headscale features

