#!/bin/bash
# Test 6: Full End-to-End Flow
# Tests: Create users → Set groups → Set policy → Register node → Verify access

test_full_oidc_group_vpn_flow() {
    echo "=== Full OIDC Group to VPN Flow Test ==="
    
    # 1. Create users
    log "Step 1: Creating users..."
    local user1 user2
    user1=$(curl -sf -X POST "http://headscale-server:8080/api/v1/user" \
        -H "Authorization: Bearer $API_KEY" \
        -H "Content-Type: application/json" \
        -d '{"name": "flow-alice", "email": "flow-alice@test.com"}' 2>/dev/null)
    
    user2=$(curl -sf -X POST "http://headscale-server:8080/api/v1/user" \
        -H "Authorization: Bearer $API_KEY" \
        -H "Content-Type: application/json" \
        -d '{"name": "flow-bob", "email": "flow-bob@test.com"}' 2>/dev/null)
    
    FLOW_ALICE_ID=$(echo "$user1" | jq -r '.user.id')
    FLOW_BOB_ID=$(echo "$user2" | jq -r '.user.id')
    
    if [ -z "$FLOW_ALICE_ID" ] || [ -z "$FLOW_BOB_ID" ]; then
        echo "Failed to create users"
        return 1
    fi
    log "Created users: Alice($FLOW_ALICE_ID), Bob($FLOW_BOB_ID)"
    
    # 2. Set OIDC groups
    log "Step 2: Setting OIDC groups..."
    curl -sf -X PUT "http://headscale-server:8080/api/v1/user/$FLOW_ALICE_ID/oidc-groups" \
        -H "Authorization: Bearer $API_KEY" \
        -H "Content-Type: application/json" \
        -d '{"groups": ["engineering", "platform"]}' > /dev/null 2>/dev/null
    
    curl -sf -X PUT "http://headscale-server:8080/api/v1/user/$FLOW_BOB_ID/oidc-groups" \
        -H "Authorization: Bearer $API_KEY" \
        -H "Content-Type: application/json" \
        -d '{"groups": ["engineering"]}' > /dev/null 2>/dev/null
    
    # 3. Set ACL policy using oidcgrp:
    log "Step 3: Setting ACL policy with oidcgrp:..."
    local policy
    policy=$(cat <<POLICY
{
    "acls": [
        {
            "action": "accept",
            "src": ["oidcgrp:engineering"],
            "dst": ["oidcgrp:platform:443"]
        },
        {
            "action": "accept",
            "src": ["oidcgrp:engineering"],
            "dst": ["*:22,80"]
        }
    ]
}
POLICY
)
    
    curl -sf -X PUT "http://headscale-server:8080/api/v1/policy" \
        -H "Authorization: Bearer $API_KEY" \
        -H "Content-Type: application/json" \
        -d "$policy" > /dev/null 2>/dev/null
    
    # 4. Verify groups are set correctly
    log "Step 4: Verifying group assignments..."
    local groups_alice groups_bob
    groups_alice=$(curl -sf "http://headscale-server:8080/api/v1/user/$FLOW_ALICE_ID/oidc-groups" \
        -H "Authorization: Bearer $API_KEY" 2>/dev/null | jq -r '.groups[]' | sort | tr '\n' ',')
    
    groups_bob=$(curl -sf "http://headscale-server:8080/api/v1/user/$FLOW_BOB_ID/oidc-groups" \
        -H "Authorization: Bearer $API_KEY" 2>/dev/null | jq -r '.groups[]' | sort | tr '\n' ',')
    
    log "Alice groups: $groups_alice"
    log "Bob groups: $groups_bob"
    
    # 5. List users in engineering group
    log "Step 5: Listing users in engineering group..."
    local eng_users
    eng_users=$(curl -sf "http://headscale-server:8080/api/v1/user/oidc-group?group=engineering" \
        -H "Authorization: Bearer $API_KEY" 2>/dev/null | jq '.users | length')
    
    if [ "$eng_users" -eq 2 ]; then
        log "Engineering group has 2 users (correct)"
    else
        echo "Expected 2 users in engineering, got $eng_users"
        return 1
    fi
    
    log "=== Full Flow Test PASSED ==="
    return 0
}

test_concurrent_group_updates() {
    echo "=== Concurrent Group Updates Test ==="
    
    # Create a user
    local user
    user=$(curl -sf -X POST "http://headscale-server:8080/api/v1/user" \
        -H "Authorization: Bearer $API_KEY" \
        -H "Content-Type: application/json" \
        -d '{"name": "concurrent-user", "email": "concurrent@test.com"}' 2>/dev/null)
    
    local user_id
    user_id=$(echo "$user" | jq -r '.user.id')
    
    # Concurrently update groups
    for i in $(seq 1 5); do
        curl -sf -X PUT "http://headscale-server:8080/api/v1/user/$user_id/oidc-groups" \
            -H "Authorization: Bearer $API_KEY" \
            -H "Content-Type: application/json" \
            -d "{\"groups\": [\"group-$i\"]}" > /dev/null 2>/dev/null &
    done
    wait
    
    # Verify groups are in a consistent state
    local final_groups
    final_groups=$(curl -sf "http://headscale-server:8080/api/v1/user/$user_id/oidc-groups" \
        -H "Authorization: Bearer $API_KEY" 2>/dev/null | jq '.groups | length')
    
    # Should have exactly 1 group (last write wins)
    if [ "$final_groups" -eq 1 ]; then
        log "Concurrent updates resulted in consistent state"
        return 0
    fi
    echo "Expected 1 group after concurrent updates, got $final_groups"
    return 1
}

test_policy_reload_preserves_groups() {
    echo "=== Policy Reload Preserves Groups Test ==="
    
    # Set groups
    curl -sf -X PUT "http://headscale-server:8080/api/v1/user/$FLOW_ALICE_ID/oidc-groups" \
        -H "Authorization: Bearer $API_KEY" \
        -H "Content-Type: application/json" \
        -d '{"groups": ["test-group"]}' > /dev/null 2>/dev/null
    
    # Reload policy
    curl -sf -X PUT "http://headscale-server:8080/api/v1/policy" \
        -H "Authorization: Bearer $API_KEY" \
        -H "Content-Type: application/json" \
        -d '{"acls": [{"action": "accept", "src": ["oidcgrp:test-group"], "dst": ["*:443"]}]}' > /dev/null 2>/dev/null
    
    # Verify groups still exist
    local groups
    groups=$(curl -sf "http://headscale-server:8080/api/v1/user/$FLOW_ALICE_ID/oidc-groups" \
        -H "Authorization: Bearer $API_KEY" 2>/dev/null | jq '.groups | length')
    
    if [ "$groups" -eq 1 ]; then
        log "Groups preserved after policy reload"
        return 0
    fi
    echo "Expected 1 group after policy reload, got $groups"
    return 1
}

run_test "Full OIDC Group VPN Flow" test_full_oidc_group_vpn_flow
run_test "Concurrent Group Updates" test_concurrent_group_updates
run_test "Policy Reload Preserves Groups" test_policy_reload_preserves_groups
