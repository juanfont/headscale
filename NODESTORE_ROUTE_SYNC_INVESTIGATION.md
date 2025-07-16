# NodeStore Route Synchronization Investigation Plan

## Problem Statement

`TestHASubnetRouterFailover` fails because `PrimaryRoutes` is nil in MapResponse, despite routes being properly announced and approved. The issue is a timing/synchronization problem between announced routes and approved routes in the NodeStore.

## Root Cause Analysis

### The Flow
1. **Route Announcement**: `tailscale set --advertise-routes=X.X.X.X/24` → MapRequest with `Hostinfo.RoutableIPs` → NodeStore
2. **Route Approval**: `headscale routes approve` → Database + NodeStore `ApprovedRoutes`
3. **Primary Route Calculation**: `SubnetRoutes()` = intersection of `AnnouncedRoutes` AND `ApprovedRoutes`
4. **MapResponse Generation**: `PrimaryRoutes` field populated from primary route calculation

### The Bug
The timing between steps 1 and 2 is not properly synchronized. When route approval happens, the NodeStore may not yet have the announced routes, causing `SubnetRoutes()` to return empty list.

### Key Code Locations
- `hscontrol/mapper/tail.go:91` - PrimaryRoutes field populated from `primaryRouteFunc(node.ID())`
- `hscontrol/state/state.go:601-604` - Critical timing-sensitive code in `SetApprovedRoutes()`
- `hscontrol/routes/primary.go:139-158` - Primary route lookup logic
- `hscontrol/types/node.go` - `SubnetRoutes()` method that does intersection
- `hscontrol/grpcv1.go:377-396` - Route approval API endpoint

## Investigation Plan

### Phase 1: Understand Test Flow ✅ COMPLETED
- [x] **1.1** Examine `TestHASubnetRouterFailover` step-by-step sequence
- [x] **1.2** Identify exact timing of route advertisement vs approval  
- [x] **1.3** Check if test uses any synchronization mechanisms

#### Test Flow Analysis:
1. **Setup**: Create 3 subnet routers + 1 client (6 total nodes)
2. **Route Advertisement** (lines 300-308): All 3 routers execute `tailscale set --advertise-routes=172.19.0.0/16`
3. **Sync Wait** (line 310): `scenario.WaitForTailscaleSync()` 
4. **Verification** (lines 315-323): EventuallyWithT waits for routes to be announced (1,0,0 = available, approved, primary)
5. **Route Approval** (lines 341-345): `headscale.ApproveRoutes(1, [pref])` - approves route on node ID 1
6. **Sync Wait** (lines 348-356): EventuallyWithT waits for approval (1,1,1 = available, approved, primary)
7. **Client Sync** (lines 358-360): `scenario.WaitForTailscaleSync()`
8. **FAILURE POINT** (line 379): `require.NotNil(t, srs1PeerStatus.PrimaryRoutes)` - this fails!

#### Key Insights:
- Test does use synchronization mechanisms (WaitForTailscaleSync, EventuallyWithT)
- Route announcement happens BEFORE approval (good)
- There are explicit wait periods for state propagation
- The failure happens AFTER all synchronization, suggesting the issue is deeper

### Phase 2: Debug Route Announcement ✅ COMPLETED
- [x] **2.1** Trace how `tailscale set --advertise-routes` becomes `Hostinfo.RoutableIPs`
- [x] **2.2** Verify MapRequest processing updates NodeStore correctly
- [x] **2.3** Add debug logging to `AnnouncedRoutes()` method
- [x] **2.4** Check if MapRequest processing is async

### Phase 3: Debug Route Approval ✅ COMPLETED
- [x] **3.1** Add debug logging to `SetApprovedRoutes()` method
- [x] **3.2** Add debug logging to `SubnetRoutes()` method to see both announced and approved routes
- [x] **3.3** Verify NodeStore `ApprovedRoutes` field is updated correctly
- [x] **3.4** Check timing of `primaryRoutes.SetRoutes()` call

### Phase 4: Debug Primary Route Calculation ✅ COMPLETED
- [x] **4.1** Add debug logging to `routes/primary.go` `SetRoutes()` method
- [x] **4.2** Add debug logging to `PrimaryRoutes()` method
- [x] **4.3** Verify routes map and primaries map are populated correctly

### Phase 5: Identify Synchronization Gap ✅ COMPLETED
- [x] **5.1** Run test with all debug logging enabled
- [x] **5.2** Analyze logs to find where synchronization breaks
- [x] **5.3** Identify if it's a race condition or ordering issue

#### Key Discovery:
The debug logs reveal the exact issue:

1. **Route Advertisement Working**: All 3 routers successfully advertise `172.19.0.0/16` via MapRequest
   - `DEBUG: MapRequest contains RoutableIPs: [172.19.0.0/16]` for nodes 1, 2, 3
   - `DEBUG: Updating NodeStore with node containing RoutableIPs: [172.19.0.0/16]`
   - `DEBUG: NodeStore verification - stored node RoutableIPs: [172.19.0.0/16]`

2. **Route Approval Working**: Node 1 gets routes approved successfully
   - `DEBUG: SubnetRoutes calculation announced_routes=["172.19.0.0/16"] approved_routes=["172.19.0.0/16"] hostname=ts-head-lk4lum node_id=1`
   - `DEBUG: PrimaryRoutes.SetRoutes called node_id=1 prefixes=["172.19.0.0/16"]`
   - `DEBUG: PrimaryRoutes.SetRoutes - setting routes for node filtered_routes=["172.19.0.0/16"] node_id=1`
   - `DEBUG: PrimaryRoutes.PrimaryRoutes - returning routes node_id=1 primary_routes=["172.19.0.0/16"]`

3. **The Issue**: Despite primary routes being set correctly, the MapResponse sent to clients is missing `PrimaryRoutes`

4. **Root Cause**: The issue is NOT in route synchronization - both the route advertisement and approval work correctly. The problem is in **policy filtering** during MapResponse generation.

#### Detailed Analysis:
- **Server Calculation**: `PrimaryRoutes()` returns `["172.19.0.0/16"]` correctly  
- **Policy Filtering**: `policy.ReduceRoutes(node, primaryRoutes, matchers)` is filtering out the routes
- **Client Result**: `PrimaryRoutes: null` in client status  

#### Root Cause Confirmed:
The issue is **timing/concurrency** - not policy filtering. Debug logs show:

1. ✅ Route approval works: `approved_routes=["172.19.0.0/16"]` 
2. ✅ Primary route calculation works: `primary_routes=["172.19.0.0/16"]`
3. ❌ **Policy filtering gets called with old state**: `primary_routes=null`

**The Problem**: MapResponse generation happens before the primary route updates propagate to the mapper calls.

**The Fix**: Ensure primary routes are updated **before** any MapResponse generation for route approval operations.

### Phase 6: Design Fix
- [ ] **6.1** Design synchronization mechanism (options below)
- [ ] **6.2** Choose best approach based on findings
- [ ] **6.3** Plan implementation

#### Fix Options to Consider:
1. **Explicit Wait**: Make route approval wait for announced routes to be processed
2. **Event-Driven**: Use NodeStore events to trigger primary route recalculation
3. **Retry Logic**: Retry primary route calculation if announced routes are missing
4. **Synchronous Processing**: Make MapRequest processing synchronous for route announcements

### Phase 7: Implementation
- [ ] **7.1** Implement chosen fix
- [ ] **7.2** Test with `TestHASubnetRouterFailover`
- [ ] **7.3** Test with other route-related tests
- [ ] **7.4** Ensure no regressions

### Phase 8: Validation
- [ ] **8.1** Run all integration tests
- [ ] **8.2** Verify fix works consistently
- [ ] **8.3** Document the solution

## Current Status: Phase 1 - Understanding Test Flow

### Test Flow Analysis Needed:
1. How does TestHASubnetRouterFailover set up the scenario?
2. What's the exact sequence of operations?
3. Are there any existing synchronization points?
4. How long after route advertisement does approval happen?

### Debug Questions:
1. Are announced routes (`Hostinfo.RoutableIPs`) actually in NodeStore when approval happens?
2. Are approved routes correctly set in NodeStore?
3. What does `SubnetRoutes()` actually return during the test?
4. Is the primary route calculation being called at all?

## Next Steps

Start with Phase 1.1 - examining the test flow in detail to understand the exact sequence of operations.