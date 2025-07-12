# State Package Exported Functions Analysis

## Overview
Analysis of all exported functions in `hscontrol/state/state.go` to determine which can be unexported.

## Exported Functions Usage

| Function | Line | Usage Count | Can Unexport? | Notes |
|----------|------|-------------|---------------|-------|
| `NewState` | 70 | 1 | No | Constructor - required |
| `Close` | 132 | Many | No | Cleanup method |
| `DERPMap` | 184 | 6 | No | Used in app, poll, mapper, debug |
| `ReloadPolicy` | 190 | 1 | No | Used in app.go |
| `AutoApproveNodes` | 212 | 1 | No | Used in grpcv1.go |
| `CreateUser` | 218 | 40+ | No | Heavily used across CLI, gRPC, tests |
| `UpdateUser` | 240 | 1 | No | Used in oidc.go |
| `DeleteUser` | 277 | 6 | No | Used in CLI, gRPC |
| `RenameUser` | 282 | 9 | No | Used in CLI, gRPC, tests |
| `GetUserByID` | 290 | 5 | No | Used in grpcv1.go |
| `GetUserByName` | 295 | 4 | No | Used in grpcv1.go |
| `GetUserByOIDCIdentifier` | 300 | 1 | No | Used in oidc.go |
| `ListUsersWithFilter` | 305 | 3 | No | Used in grpcv1.go |
| `ListAllUsers` | 310 | 1 | No | Used in grpcv1.go |
| `CreateNode` | 316 | 0 | **Yes** | Not used outside package |
| `SaveNode` | 369 | 5 | No | Used in oidc, grpcv1, auth, poll |
| `DeleteNode` | 390 | 8 | No | Used in CLI, gRPC, app, auth |
| `Connect` | 407 | 2 | No | Used in poll.go |
| `Disconnect` | 418 | 1 | No | Used in poll.go |
| `GetNodeByID` | 441 | 13 | No | Used in app, grpcv1, poll |
| `GetNodeByNodeKey` | 446 | 2 | No | Used in auth.go, noise.go |
| `ListNodes` | 451 | 50+ | No | Heavily used across all packages |
| `ListNodesByUser` | 474 | 1 | No | Used in grpcv1.go |
| `ListPeers` | 479 | 8 | No | Used in mapper, tests |
| `ListEphemeralNodes` | 502 | 2 | No | Used in app.go |
| `SetNodeExpiry` | 517 | 2 | No | Used in grpcv1.go, auth.go |
| `SetNodeTags` | 534 | 1 | No | Used in grpcv1.go |
| `SetApprovedRoutes` | 551 | 5 | No | Used in CLI, gRPC |
| `RenameNode` | 568 | 5 | No | Used in CLI, gRPC |
| `SetLastSeen` | 585 | 0 | **Yes** | Not used outside package |
| `AssignNodeToUser` | 606 | 1 | No | Used in grpcv1.go |
| `BackfillNodeIPs` | 628 | 6 | No | Used in CLI, gRPC |
| `ExpireExpiredNodes` | 634 | 1 | No | Used in app.go |
| `SSHPolicy` | 639 | 5 | No | Used in mapper, grpcv1, debug |
| `Filter` | 644 | 11 | No | Used in mapper, policy, debug |
| `NodeCanHaveTag` | 649 | 4 | No | Used in grpcv1, mapper |
| `SetPolicy` | 654 | 8 | No | Used in CLI, gRPC, tests |
| `AutoApproveRoutes` | 659 | 6 | No | Used in oidc, grpcv1, poll, auth |
| `PolicyDebugString` | 669 | 1 | No | Used in debug.go |
| `GetPolicy` | 674 | 6 | No | Used in CLI, gRPC, debug |
| `SetPolicyInDB` | 679 | 1 | No | Used in grpcv1.go |
| `SetNodeRoutes` | 684 | 2 | No | Used in poll.go, grpcv1.go |
| `GetNodePrimaryRoutes` | 689 | 5 | No | Used in grpcv1, mapper |
| `PrimaryRoutesString` | 694 | 1 | No | Used in debug.go |
| `ValidateAPIKey` | 699 | 9 | No | Used in app.go, tests |
| `CreateAPIKey` | 704 | 6 | No | Used in grpcv1, tests |
| `GetAPIKey` | 709 | 4 | No | Used in grpcv1, db |
| `ExpireAPIKey` | 714 | 2 | No | Used in grpcv1, tests |
| `ListAPIKeys` | 719 | 3 | No | Used in grpcv1, tests |
| `DestroyAPIKey` | 724 | 1 | No | Used in grpcv1.go |
| `CreatePreAuthKey` | 729 | 27 | No | Heavily used |
| `GetPreAuthKey` | 734 | 3 | No | Used in CLI, gRPC |
| `ListPreAuthKeys` | 739 | 7 | No | Used in CLI, gRPC |
| `ExpirePreAuthKey` | 744 | 5 | No | Used in CLI, gRPC |
| `GetRegistrationCacheEntry` | 749 | 1 | No | Used in auth.go |
| `SetRegistrationCacheEntry` | 759 | 2 | No | Used in grpcv1, auth |
| `HandleNodeFromAuthPath` | 764 | 2 | No | Used in oidc, grpcv1 |
| `HandleNodeFromPreAuthKey` | 799 | 1 | No | Used in auth.go |
| `AllocateNextIPs` | 886 | 0 | **Yes** | Not used outside package |
| `PingDB` | 931 | 1 | No | Used in handlers.go |

## Summary

### Total Exported Functions: 60

### Functions to Unexport: 3
1. **`CreateNode`** (line 316) - Not used outside the state package
2. **`SetLastSeen`** (line 585) - Not used outside the state package  
3. **`AllocateNextIPs`** (line 886) - Not used outside the state package

### Functions to Keep Exported: 57
All other functions are actively used by other packages and must remain exported.

## Recommendations

The three functions identified for unexporting appear to be internal implementation details:
- `CreateNode` - Likely used internally for node creation logic
- `SetLastSeen` - Probably called internally during node updates
- `AllocateNextIPs` - Internal IP allocation helper

These can be safely unexported without breaking any external dependencies.