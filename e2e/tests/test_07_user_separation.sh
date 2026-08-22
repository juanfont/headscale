#!/bin/bash
# Test 7: User Separation via OIDC Groups

test_set_users_and_groups() {
    # Ensure test users exist
    for name in e2e-alice e2e-bob e2e-charlie; do
        curl -s -X POST "http://headscale-server:8080/api/v1/user" \
            -H "Authorization: Bearer $API_KEY" \
            -H "Content-Type: application/json" \
            -d "{\"name\": \"$name\", \"email\": \"${name}@headscale.local\"}" > /dev/null 2>&1 || true
    done
    
    E2E_ALICE_ID=$(get_user_id e2e-alice)
    E2E_BOB_ID=$(get_user_id e2e-bob)
    E2E_CHARLIE_ID=$(get_user_id e2e-charlie)
    
    if [ -z "$E2E_ALICE_ID" ] || [ -z "$E2E_BOB_ID" ] || [ -z "$E2E_CHARLIE_ID" ]; then
        echo "Missing users: alice=$E2E_ALICE_ID bob=$E2E_BOB_ID charlie=$E2E_CHARLIE_ID"
        return 1
    fi
    
    # Set OIDC groups
    curl -s -o /dev/null -X PUT "http://headscale-server:8080/api/v1/user/$E2E_ALICE_ID/oidc-groups" \
        -H "Authorization: Bearer $API_KEY" \
        -H "Content-Type: application/json" \
        -d '{"groups": ["engineering", "admins"]}'
    
    curl -s -o /dev/null -X PUT "http://headscale-server:8080/api/v1/user/$E2E_BOB_ID/oidc-groups" \
        -H "Authorization: Bearer $API_KEY" \
        -H "Content-Type: application/json" \
        -d '{"groups": ["engineering"]}'
    
    curl -s -o /dev/null -X PUT "http://headscale-server:8080/api/v1/user/$E2E_CHARLIE_ID/oidc-groups" \
        -H "Authorization: Bearer $API_KEY" \
        -H "Content-Type: application/json" \
        -d '{"groups": ["platform"]}'
    
    return 0
}

test_alice_bob_same_group() {
    E2E_ALICE_ID=$(get_user_id e2e-alice)
    E2E_BOB_ID=$(get_user_id e2e-bob)
    
    local alice_groups bob_groups
    alice_groups=$(curl -sf "http://headscale-server:8080/api/v1/user/$E2E_ALICE_ID/oidc-groups" \
        -H "Authorization: Bearer $API_KEY" 2>/dev/null | jq -r '.groups[]' | sort | tr '\n' ',')
    bob_groups=$(curl -sf "http://headscale-server:8080/api/v1/user/$E2E_BOB_ID/oidc-groups" \
        -H "Authorization: Bearer $API_KEY" 2>/dev/null | jq -r '.groups[]' | sort | tr '\n' ',')
    
    local alice_has_eng bob_has_eng
    alice_has_eng=$(echo "$alice_groups" | grep -c "engineering" || true)
    bob_has_eng=$(echo "$bob_groups" | grep -c "engineering" || true)
    
    if [ "$alice_has_eng" -gt 0 ] && [ "$bob_has_eng" -gt 0 ]; then
        return 0
    fi
    echo "alice=$alice_groups bob=$bob_groups"
    return 1
}

test_charlie_different_group() {
    E2E_CHARLIE_ID=$(get_user_id e2e-charlie)
    
    local charlie_groups
    charlie_groups=$(curl -sf "http://headscale-server:8080/api/v1/user/$E2E_CHARLIE_ID/oidc-groups" \
        -H "Authorization: Bearer $API_KEY" 2>/dev/null | jq -r '.groups[]' | sort | tr '\n' ',')
    
    local charlie_has_eng
    charlie_has_eng=$(echo "$charlie_groups" | grep -c "engineering" || true)
    
    if [ "$charlie_has_eng" -eq 0 ]; then
        return 0
    fi
    echo "charlie should not be in engineering but has: $charlie_groups"
    return 1
}

test_alice_is_admin() {
    E2E_ALICE_ID=$(get_user_id e2e-alice)
    
    local alice_groups
    alice_groups=$(curl -sf "http://headscale-server:8080/api/v1/user/$E2E_ALICE_ID/oidc-groups" \
        -H "Authorization: Bearer $API_KEY" 2>/dev/null | jq -r '.groups[]')
    
    if echo "$alice_groups" | grep -q "^admins$"; then
        return 0
    fi
    echo "alice groups: $alice_groups"
    return 1
}

test_bob_not_admin() {
    E2E_BOB_ID=$(get_user_id e2e-bob)
    
    local bob_groups
    bob_groups=$(curl -sf "http://headscale-server:8080/api/v1/user/$E2E_BOB_ID/oidc-groups" \
        -H "Authorization: Bearer $API_KEY" 2>/dev/null | jq -r '.groups[]')
    
    if echo "$bob_groups" | grep -q "^admins$"; then
        echo "bob should not be admin but has: $bob_groups"
        return 1
    fi
    return 0
}

test_engineering_group_count() {
    local response count
    response=$(curl -sf "http://headscale-server:8080/api/v1/user/oidc-group?group=engineering" \
        -H "Authorization: Bearer $API_KEY" 2>/dev/null)
    count=$(echo "$response" | jq '.users | length' 2>/dev/null)
    
    if [ "$count" -ge 2 ]; then
        return 0
    fi
    echo "Expected >= 2 in engineering, got $count"
    return 1
}

test_platform_group_count() {
    local response count
    response=$(curl -sf "http://headscale-server:8080/api/v1/user/oidc-group?group=platform" \
        -H "Authorization: Bearer $API_KEY" 2>/dev/null)
    count=$(echo "$response" | jq '.users | length' 2>/dev/null)
    
    if [ "$count" -ge 1 ]; then
        return 0
    fi
    echo "Expected >= 1 in platform, got $count"
    return 1
}

run_test "Set Users and Groups" test_set_users_and_groups
run_test "Alice & Bob Same Group (engineering)" test_alice_bob_same_group
run_test "Charlie Different Group (platform)" test_charlie_different_group
run_test "Alice Is Admin" test_alice_is_admin
run_test "Bob Not Admin" test_bob_not_admin
run_test "Engineering Group Count >= 2" test_engineering_group_count
run_test "Platform Group Count >= 1" test_platform_group_count
