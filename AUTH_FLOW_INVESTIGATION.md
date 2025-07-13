# Authentication Flow Investigation and Fix Plan

## Overview

After successfully resolving NodeStore integration issues, two authentication flow tests remain failing:

1. **TestAuthKeyLogoutAndReloginSameUserExpiredKey**: Clients timeout instead of receiving "authkey expired" error
2. **TestOIDCExpireNodesBasedOnTokenExpiry**: Node status stays "Running" instead of changing to "NeedsLogin" after token expiry

## Problem Analysis

### Issue 1: Auth Key Expiration Not Properly Handled

**Test Flow:**
1. ✅ Create pre-auth keys and register clients successfully
2. ✅ All clients log out (verified in logs)
3. ✅ Expire the pre-auth keys via CLI
4. ❌ Clients try to reconnect with expired keys → **TIMEOUT** instead of "authkey expired" error

**Current Behavior:**
- Clients establish noise connections (TLS handshake succeeds)
- No registration requests appear in headscale logs
- Clients timeout after 2+ minutes
- No authentication validation reached

**Expected Behavior:**
- Client sends registration request with expired auth key
- Server validates key via `pak.Validate()` → returns `PAKError("authkey expired")`
- Server responds with HTTP 401 "authkey expired"
- Client receives error immediately

### Issue 2: OIDC Token Expiry Not Detected

**Test Flow:**
1. ✅ Nodes authenticate via OIDC successfully
2. ✅ OIDC tokens expire (time-based)
3. ❌ Node status should change to "NeedsLogin" but remains "Running"

**Root Cause:** 
- OIDC token validation not happening periodically
- Node status update mechanism not triggered on token expiry
- Background token checking process may be missing or broken

## Investigation Plan

### Phase 1: Trace Auth Key Flow Issue

**✅ COMPLETED: Core Auth Validation Logic**
- ✅ Unit test `TestCanUsePreAuthKey` confirms `pak.Validate()` correctly returns `PAKError("authkey expired")`
- ✅ Auth key validation logic is working correctly
- ✅ Error type handling is correct

**ISSUE IDENTIFIED: Integration Test Timing**
- The test `TestAuthKeyLogoutAndReloginSameUserExpiredKey` has a 5-minute sleep for non-HTTPS cases
- Test timeouts occur before reaching auth validation due to this sleep
- The auth validation code appears to be working correctly

**1.1 Debug HTTP Error Path** 

Files to investigate:
- ✅ `hscontrol/auth.go` - Add logging to `handleRegisterWithAuthKey()` (COMPLETED)
- ✅ `hscontrol/noise.go` - Add logging to see what requests are being received (COMPLETED)
- ✅ `hscontrol/state/state.go` - Add logging to `HandleNodeFromPreAuthKey` (COMPLETED)

Debug points:
```go
// In auth.go handleRegisterWithAuthKey
log.Debug().Str("auth_key", regReq.Auth.AuthKey).Msg("DEBUG: Registration attempt with auth key")

// In noise.go 
log.Debug().Str("path", r.URL.Path).Str("method", r.Method).Msg("DEBUG: Noise request received")

// Add to registration handlers
log.Debug().Interface("request", regReq).Msg("DEBUG: Registration request details")
```

**1.2 Examine Client-Side Behavior**

Check test logs for:
- Exact `tailscale up` command being executed
- Client stderr/stdout for connection errors
- Network-level timeouts vs auth-level failures

**1.3 Verify Auth Key Expiration Path**

Files to verify:
- `hscontrol/state/state.go:873` - Confirm `pak.Validate()` is reached
- `hscontrol/types/preauth_key.go:64` - Confirm expiration check logic
- `hscontrol/auth.go:177` - Confirm error handling path

### Phase 2: Fix Auth Key Flow

**2.1 Root Cause Analysis**
Determine why clients aren't sending registration requests:
- Client-side timeout configuration
- TLS certificate issues
- Noise protocol handshake issues
- HTTP routing problems

**2.2 Implement Fix**
Based on root cause:
- If client timeout: Investigate tailscale client retry behavior
- If server routing: Fix HTTP handlers to properly route registration requests  
- If protocol issue: Debug noise protocol flow

**2.3 Verify Fix**
- Add test logging to trace complete auth flow
- Verify "authkey expired" error is returned properly
- Confirm test passes consistently

### Phase 3: Investigate OIDC Token Expiry

**3.1 Find OIDC Token Validation Code**

Search for:
```bash
grep -r "token.*expir" hscontrol/
grep -r "OIDC" hscontrol/
grep -r "NeedsLogin" hscontrol/
```

Files likely involved:
- `hscontrol/oidc.go` - OIDC authentication logic
- `hscontrol/auth.go` - General auth flows  
- `hscontrol/poll.go` - Periodic node status checks
- Background workers or cron jobs for token validation

**3.2 Add OIDC Debug Logging**

Debug points:
```go
// Token validation
log.Debug().Time("token_expiry", tokenExp).Time("now", time.Now()).Msg("DEBUG: OIDC token expiry check")

// Node status updates
log.Debug().Str("node", node.Hostname).Str("old_status", oldStatus).Str("new_status", newStatus).Msg("DEBUG: Node status change")

// Periodic checks
log.Debug().Int("nodes_checked", count).Msg("DEBUG: OIDC token validation sweep")
```

**3.3 Test OIDC Flow**

Run test with enhanced logging:
```bash
go run ./cmd/hi run "TestOIDCExpireNodesBasedOnTokenExpiry" --postgres
```

Analyze logs for:
- When tokens actually expire
- If expiration is detected
- If node status update is triggered
- Background process execution

### Phase 4: Fix OIDC Token Flow

**4.1 Implement Token Expiry Detection**

If missing, add:
- Periodic background process to check OIDC token validity
- Node status update mechanism on token expiry
- Proper error handling and logging

**4.2 Update Node Status Correctly**

Ensure:
- Node status transitions from "Running" to "NeedsLogin" 
- Status change is persisted to database
- Status change is propagated to clients via MapResponse

**4.3 Verify OIDC Fix**

- Confirm token expiry is detected correctly
- Verify node status updates work
- Test passes consistently

## Implementation Checklist

### Auth Key Issue
- [ ] Add debug logging to registration flow
- [ ] Run TestAuthKeyLogoutAndReloginSameUserExpiredKey with logging
- [ ] Analyze why registration requests aren't reaching server
- [ ] Implement fix for root cause
- [ ] Verify "authkey expired" error is returned
- [ ] Test passes consistently

### OIDC Issue  
- [ ] Find OIDC token validation code
- [ ] Add debug logging to token expiry flow
- [ ] Run TestOIDCExpireNodesBasedOnTokenExpiry with logging  
- [ ] Identify missing or broken token validation
- [ ] Implement proper token expiry detection
- [ ] Implement node status update on token expiry
- [ ] Test passes consistently

## Expected Outcomes

**Auth Key Fix:**
- Clients receive "authkey expired" error immediately instead of timing out
- TestAuthKeyLogoutAndReloginSameUserExpiredKey passes
- Auth key validation flow works as designed

**OIDC Fix:**
- Node status properly transitions to "NeedsLogin" when tokens expire
- TestOIDCExpireNodesBasedOnTokenExpiry passes  
- OIDC token lifecycle management works correctly

## Success Criteria

1. Both authentication tests pass consistently
2. Auth flows work as designed in integration tests
3. No regression in previously passing tests
4. Authentication error messages are clear and immediate
5. All NodeStore fixes remain working

---

*This investigation builds on the successful NodeStore integration fixes and focuses specifically on authentication flow issues.*