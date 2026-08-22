#!/bin/bash
# Test 6: Full End-to-End Flow

test_full_oidc_group_flow() {
    echo "=== Full OIDC Group Flow Test ==="
    
    local flow_alice_id flow_bob_id
    flow_alice_id=$(get_user_id flow-alice)
    flow_bob_id=$(get_user_id flow-bob)
    
    if [ -z "$flow_alice_id" ] || [ -z "$flow_bob_id" ]; then
        echo "flow-alice or flow-bob not found"
        return 1
    fi
    
    # Set OIDC groups
    curl -s -o /dev/null -X PUT "http://headscale-server:8080/api/v1/user/$flow_alice_id/oidc-groups" \
        -H "Authorization: Bearer $API_KEY" \
        -H "Content-Type: application/json" \
        -d '{"groups": ["engineering", "platform"]}'
    
    curl -s -o /dev/null -X PUT "http://headscale-server:8080/api/v1/user/$flow_bob_id/oidc-groups" \
        -H "Authorization: Bearer $API_KEY" \
        -H "Content-Type: application/json" \
        -d '{"groups": ["engineering"]}'
    
    # Verify groups
    local groups_alice groups_bob
    groups_alice=$(curl -sf "http://headscale-server:8080/api/v1/user/$flow_alice_id/oidc-groups" \
        -H "Authorization: Bearer $API_KEY" 2>/dev/null | jq -r '.groups[]' | sort | tr '\n' ',')
    groups_bob=$(curl -sf "http://headscale-server:8080/api/v1/user/$flow_bob_id/oidc-groups" \
        -H "Authorization: Bearer $API_KEY" 2>/dev/null | jq -r '.groups[]' | sort | tr '\n' ',')
    
    log "Alice groups: $groups_alice"
    log "Bob groups: $groups_bob"
    
    # Verify engineering group has users
    local eng_users
    eng_users=$(curl -sf "http://headscale-server:8080/api/v1/user/oidc-group?group=engineering" \
        -H "Authorization: Bearer $API_KEY" 2>/dev/null | jq '.users | length')
    
    if [ "$eng_users" -ge 2 ]; then
        log "Engineering group has $eng_users users (OK)"
    else
        echo "Expected >= 2 users in engineering, got $eng_users"
        return 1
    fi
    
    log "=== Full Flow Test PASSED ==="
    return 0
}

test_concurrent_group_updates() {
    echo "=== Concurrent Group Updates Test ==="
    
    local user_id
    user_id=$(get_user_id concurrent-user)
    
    if [ -z "$user_id" ]; then
        echo "concurrent-user not found"
        return 1
    fi
    
    # Launch 5 concurrent updates
    for i in $(seq 1 5); do
        curl -s -o /dev/null -X PUT "http://headscale-server:8080/api/v1/user/$user_id/oidc-groups" \
            -H "Authorization: Bearer $API_KEY" \
            -H "Content-Type: application/json" \
            -d "{\"groups\": [\"group-$i\"]}" &
    done
    wait
    
    # Verify final state has exactly 1 group
    local final_groups
    final_groups=$(curl -sf "http://headscale-server:8080/api/v1/user/$user_id/oidc-groups" \
        -H "Authorization: Bearer $API_KEY" 2>/dev/null | jq '.groups | length')
    
    if [ "$final_groups" = "1" ]; then
        log "Concurrent updates resulted in consistent state"
        return 0
    fi
    echo "Expected 1 group after concurrent updates, got $final_groups"
    return 1
}

test_policy_reload_preserves_groups() {
    echo "=== Policy Reload Preserves Groups Test ==="
    
    local user_id
    user_id=$(get_user_id refresh-test-user)
    
    if [ -z "$user_id" ]; then
        echo "refresh-test-user not found"
        return 1
    fi
    
    # Set groups
    curl -s -o /dev/null -X PUT "http://headscale-server:8080/api/v1/user/$user_id/oidc-groups" \
        -H "Authorization: Bearer $API_KEY" \
        -H "Content-Type: application/json" \
        -d '{"groups": ["test-group"]}'
    
    # Reload policy
    local body
    body=$(echo '{"acls":[{"action":"accept","src":["oidcgrp:test-group"],"dst":["*:443"]}]}' | jq -c '{policy: .}')
    curl -s -o /dev/null -X PUT "http://headscale-server:8080/api/v1/policy" \
        -H "Authorization: Bearer $API_KEY" \
        -H "Content-Type: application/json" \
        -d "$body"
    
    # Verify groups still there
    local groups
    groups=$(curl -sf "http://headscale-server:8080/api/v1/user/$user_id/oidc-groups" \
        -H "Authorization: Bearer $API_KEY" 2>/dev/null | jq '.groups | length')
    
    if [ "$groups" = "1" ]; then
        log "Groups preserved after policy reload"
        return 0
    fi
    echo "Expected 1 group after policy reload, got $groups"
    return 1
}

run_test "Full OIDC Group Flow" test_full_oidc_group_flow
run_test "Concurrent Group Updates" test_concurrent_group_updates
run_test "Policy Reload Preserves Groups" test_policy_reload_preserves_groups
