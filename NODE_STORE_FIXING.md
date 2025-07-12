# NodeStore Bug Fixing Plan

## Overview
After introducing NodeStore as an intermediate layer between the database and application, several integration tests are failing. The NodeStore should serve all node reads while writes go to both NodeStore and database.

## Key Investigation Areas
1. **NodeStore Update Synchronization**: Ensure all node updates are properly propagated to NodeStore
2. **Database Direct Access**: Find places where database is accessed directly instead of NodeStore
3. **Data Consistency**: Verify NodeStore and DB stay in sync
4. **Error Handling**: Check if NodeStore returns errors differently than DB (e.g., not found vs invalid)
5. Use Sequantial thinking at every step to plan out your moves

## Test Categories and Investigation Plan

### 1. ACL Related Tests
**Test: TestACLAutogroupTagged**
- **Hypothesis**: ACL evaluation might be reading directly from DB or NodeStore doesn't properly handle tag updates
- **Investigation Steps**:
  - [x] Trace ACL evaluation path to ensure it uses NodeStore
  - [x] Check if tag updates are propagated to NodeStore
  - [x] Verify autogroup tag resolution uses NodeStore
- **Status**: PASSED - No changes needed
- **Finding**: Test is now passing, likely fixed by recent NodeStore changes

### 2. Auth Related Tests
**Test: TestOIDCExpireNodesBasedOnTokenExpiry**
- **Hypothesis**: Node expiry/logout operations might not update NodeStore or auth state checks bypass NodeStore
- **Investigation Steps**:
  - [x] Check node expiry update path
  - [x] Verify logout updates NodeStore
  - [x] Ensure auth key validation uses NodeStore
  - [x] Check node online/offline state updates
- **Status**: FIXED - Issue was NodeStore not being updated when nodes expire
- **Finding**: ExpireExpiredNodes only updated database, not NodeStore. Added NodeStore update logic.
- **Fix**: Modified ExpireExpiredNodes in state.go to update NodeStore with expired nodes

**Test: TestAuthKeyLogoutAndReloginSameUser**
- **Status**: Not Started

**Test: TestAuthKeyLogoutAndReloginSameUserExpiredKey**
- **Status**: Not Started

### 3. Route Related Tests
**Tests: TestAutoApproveMultiNetwork, TestEnablingRoutes, TestHASubnetRouterFailover, TestSubnetRouteACLFiltering, TestSubnetRouterMultiNetwork**
- **Hypothesis**: Route updates not reflected in NodeStore or route evaluation bypasses NodeStore
- **Investigation Steps**:
  - [ ] Trace route enable/disable path
  - [ ] Check if route approval updates NodeStore
  - [ ] Verify subnet router failover logic uses NodeStore
  - [ ] Ensure ACL filtering for routes uses NodeStore data
- **Status**: Not Started

### 4. Ping/Online Related Tests
**Tests: TestPingAllByIPManyUpDown (both SQLite and PostgreSQL)**
- **Hypothesis**: Node online/offline state not properly synchronized in NodeStore
- **Investigation Steps**:
  - [ ] Check node state update mechanism
  - [ ] Verify ping/poll updates NodeStore
  - [ ] Ensure peer list generation uses NodeStore
- **Status**: Not Started

### 5. Ephemeral Related Tests
**Test: TestEphemeral2006DeletedTooQuickly**
- **Hypothesis**: Ephemeral node deletion not properly handled in NodeStore
- **Investigation Steps**:
  - [ ] Check ephemeral node cleanup path
  - [ ] Verify deletion removes from NodeStore
  - [ ] Ensure timing of deletion is consistent
- **Status**: Not Started

## Execution Strategy
1. Start with simplest category (ACL) to understand NodeStore behavior
2. Fix one test at a time, running full test to completion
3. Document findings and fixes
4. Commit after each successful fix
5. Update this document with findings

## Common Patterns to Check
- [ ] All `db.GetNodeBy*` calls should be replaced with NodeStore equivalents
- [ ] All node updates must call both NodeStore and DB update methods
- [ ] Event propagation must update NodeStore state
- [ ] Error handling consistency between DB and NodeStore

## Progress Tracking
- Total Tests to Fix: 11
- Tests Fixed: 2
- Current Test: TestEnablingRoutes
