#!/bin/bash
# Test 8: OIDC Group Refresh Monitor

test_oidc_groups_exist() {
    local response
    response=$(curl -sf "http://headscale-server:8080/api/v1/user" \
        -H "Authorization: Bearer $API_KEY" 2>/dev/null)
    
    if [ $? -eq 0 ]; then
        local count
        count=$(echo "$response" | jq '.users | length' 2>/dev/null)
        log "Users found: $count"
        return 0
    fi
    return 1
}

test_set_and_verify_groups() {
    local user_id
    user_id=$(get_user_id refresh-test-user)
    
    if [ -z "$user_id" ]; then
        echo "refresh-test-user not found"
        return 1
    fi
    
    local code
    code=$(curl -s -o /dev/null -w "%{http_code}" -X PUT "http://headscale-server:8080/api/v1/user/$user_id/oidc-groups" \
        -H "Authorization: Bearer $API_KEY" \
        -H "Content-Type: application/json" \
        -d '{"groups": ["refresh-group-a", "refresh-group-b"]}')
    if [ "$code" != "200" ]; then
        echo "Failed to set groups: HTTP $code"
        return 1
    fi
    
    local groups
    groups=$(curl -sf "http://headscale-server:8080/api/v1/user/$user_id/oidc-groups" \
        -H "Authorization: Bearer $API_KEY" 2>/dev/null | jq '.groups | length' 2>/dev/null)
    
    if [ "$groups" = "2" ]; then
        log "Groups correctly set to 2"
        return 0
    fi
    echo "Expected 2 groups, got $groups"
    return 1
}

test_group_membership_persists() {
    local user_id
    user_id=$(get_user_id refresh-test-user)
    
    if [ -z "$user_id" ]; then
        echo "refresh-test-user not found"
        return 1
    fi
    
    local groups
    groups=$(curl -sf "http://headscale-server:8080/api/v1/user/$user_id/oidc-groups" \
        -H "Authorization: Bearer $API_KEY" 2>/dev/null | jq -r '.groups[]' 2>/dev/null | sort | tr '\n' ',')
    
    if echo "$groups" | grep -q "refresh-group-a" && echo "$groups" | grep -q "refresh-group-b"; then
        log "Groups persisted correctly: $groups"
        return 0
    fi
    echo "Groups not found: $groups"
    return 1
}

test_group_update_atomic() {
    local user_id
    user_id=$(get_user_id refresh-test-user)
    
    if [ -z "$user_id" ]; then
        echo "refresh-test-user not found"
        return 1
    fi
    
    curl -s -o /dev/null -X PUT "http://headscale-server:8080/api/v1/user/$user_id/oidc-groups" \
        -H "Authorization: Bearer $API_KEY" \
        -H "Content-Type: application/json" \
        -d '{"groups": ["refresh-group-c"]}'
    
    local count has_old
    count=$(curl -sf "http://headscale-server:8080/api/v1/user/$user_id/oidc-groups" \
        -H "Authorization: Bearer $API_KEY" 2>/dev/null | jq '.groups | length' 2>/dev/null)
    has_old=$(curl -sf "http://headscale-server:8080/api/v1/user/$user_id/oidc-groups" \
        -H "Authorization: Bearer $API_KEY" 2>/dev/null | jq -r '.groups[]' 2>/dev/null | grep -c "refresh-group-a" || true)
    
    if [ "$count" = "1" ] && [ "$has_old" = "0" ]; then
        log "Groups atomically replaced"
        return 0
    fi
    echo "Expected 1 group (refresh-group-c), got $count groups"
    return 1
}

test_list_users_in_group() {
    local user2_id
    user2_id=$(get_user_id refresh-test-user-2)
    
    if [ -z "$user2_id" ]; then
        echo "refresh-test-user-2 not found"
        return 1
    fi
    
    curl -s -o /dev/null -X PUT "http://headscale-server:8080/api/v1/user/$user2_id/oidc-groups" \
        -H "Authorization: Bearer $API_KEY" \
        -H "Content-Type: application/json" \
        -d '{"groups": ["refresh-group-c"]}'
    
    local count
    count=$(curl -sf "http://headscale-server:8080/api/v1/user/oidc-group?group=refresh-group-c" \
        -H "Authorization: Bearer $API_KEY" 2>/dev/null | jq '.users | length' 2>/dev/null)
    
    if [ "$count" -ge 1 ]; then
        log "Found $count user(s) in refresh-group-c"
        return 0
    fi
    echo "Expected >= 1 user in group, got $count"
    return 1
}

test_refresh_clears_old_groups() {
    local user_id
    user_id=$(get_user_id refresh-test-user)
    
    if [ -z "$user_id" ]; then
        echo "refresh-test-user not found"
        return 1
    fi
    
    curl -s -o /dev/null -X PUT "http://headscale-server:8080/api/v1/user/$user_id/oidc-groups" \
        -H "Authorization: Bearer $API_KEY" \
        -H "Content-Type: application/json" \
        -d '{"groups": []}'
    
    local count
    count=$(curl -sf "http://headscale-server:8080/api/v1/user/$user_id/oidc-groups" \
        -H "Authorization: Bearer $API_KEY" 2>/dev/null | jq '.groups | length' 2>/dev/null)
    
    if [ "$count" = "0" ]; then
        log "Groups successfully cleared"
        return 0
    fi
    echo "Expected 0 groups after clear, got $count"
    return 1
}

run_test "OIDC Groups Exist" test_oidc_groups_exist
run_test "Set and Verify Groups" test_set_and_verify_groups
run_test "Group Membership Persists" test_group_membership_persists
run_test "Group Update Atomic" test_group_update_atomic
run_test "List Users in Group" test_list_users_in_group
run_test "Refresh Clears Old Groups" test_refresh_clears_old_groups
