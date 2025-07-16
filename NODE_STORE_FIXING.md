# NodeStore Integration Tests Fixing Plan - SYSTEMATIC APPROACH

## Background

After introducing NodeStore (an in-memory cache for nodes sitting between the database and application), several integration tests have started failing. The NodeStore serves all reads about nodes, while writes go to both the NodeStore and database.

**IMPORTANT**: Previous analysis was theoretical. This plan focuses on **ACTUALLY RUNNING EACH TEST** and fixing real failures.

## Core NodeStore Requirements

Based on the original instruction, the key principles are:
- **ALL node READS must come from NodeStore**
- **ALL node WRITES must go to NodeStore AND the database**  
- NodeStore and database must stay synchronized
- The bugs are most likely related to NodeStore synchronization issues

## Potential Root Causes

1. **Read Path Issues**: Code still reading from DB instead of NodeStore
2. **Write Synchronization**: Writes going to DB but not NodeStore (or vice versa)
3. **Data Format Differences**: NodeStore returning data in different format than DB
4. **Error Handling**: NodeStore returning "not found" differently than DB
5. **Timing Issues**: NodeStore updates happening after DB updates causing races

## Systematic Testing Plan

### Phase 1: First Test Execution
**Target**: TestSubnetRouterMultiNetwork (--postgres)
**Status**: PENDING

#### Methodology:
1. **Run Test**: `go run ./cmd/hi run "TestSubnetRouterMultiNetwork" --postgres`
2. **Capture Complete Output**: Full logs, stack traces, error messages
3. **Analyze Failure**: Identify exact failure point and root cause
4. **Map to NodeStore**: Determine if it's read/write/sync issue
5. **Apply Fix**: Make specific code changes to address root cause
6. **Verify Fix**: Run test repeatedly until it passes completely
7. **Document**: Record what was broken and why the fix works
8. **Commit**: Commit fix before moving to next test

### Phase 2: Remaining Tests (Execute Sequentially)
Each test follows the same 7-step methodology:

1. **TestACLAutogroupTagged**
2. **TestAuthKeyLogoutAndReloginSameUserExpiredKey**
3. **TestAutoApproveMultiNetwork**
4. **TestExpireNode**
5. **TestHASubnetRouterFailover**
6. **TestNodeCommand**
7. **TestNodeOnlineStatus**
8. **TestOIDCExpireNodesBasedOnTokenExpiry**
9. **TestSubnetRouteACL**
10. **TestSubnetRouterMultiNetworkExitNode**

### Phase 3: Final Verification
- Run all fixed tests together to ensure no regressions
- Document common patterns found across fixes
- Create additional unit tests if needed

## Success Criteria Per Test

- ✅ Test runs to completion without any errors
- ✅ No panics, crashes, or timeouts
- ✅ All assertions pass
- ✅ Test completes within reasonable time (< 25 minutes)
- ✅ Fix is committed with clear explanation

## Tracking Progress

- **Current Status**: Phase 1 - Planning Complete ✅
- **Tests Fixed**: 0/11
- **Current Test**: None (about to start TestSubnetRouterMultiNetwork)
- **Commits Made**: 0

## Test Results Log

### TestSubnetRouterMultiNetwork (--postgres)
**Status**: FAILED - ROOT CAUSE IDENTIFIED
**Expected Duration**: Up to 25 minutes
**Failure Analysis**: 
- Route advertisements from `tailscale set --advertise-routes=172.18.0.0/16` aren't being stored in NodeStore
- Test expects `node.GetAvailableRoutes()` to return 1 route but gets 0
- `GetAvailableRoutes()` calls `node.AnnouncedRoutes()` which returns `node.Hostinfo.RoutableIPs`
- The `Hostinfo.RoutableIPs` field is empty even though client sends route advertisements
- Line 420 in poll.go already calls `UpdateNodeInStore()` but RoutableIPs still empty

**Root Cause**: Route advertisements in Hostinfo updates aren't populating `RoutableIPs` field correctly

**Fix Applied**: None yet - investigating why RoutableIPs field is not populated from client route advertisements
**Result**: FAILED - Test completed but routes not advertised

## Notes

- Each test MUST pass completely before moving to next
- Maximum 25 minutes per test run
- Use `--postgres` flag where specified
- Keep detailed logs of actual failures (not theoretical)
- Document WHY each fix was needed based on actual test failure
- Commit between each successful fix