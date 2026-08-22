#!/bin/bash
# Test 2: OIDC Groups - API and Policy Resolution

test_set_oidc_groups() {
    ALICE_ID=$(get_user_id alice)
    BOB_ID=$(get_user_id bob)
    CHARLIE_ID=$(get_user_id charlie)
    
    if [ -z "$ALICE_ID" ] || [ -z "$BOB_ID" ] || [ -z "$CHARLIE_ID" ]; then
        echo "Could not find test users: alice=$ALICE_ID bob=$BOB_ID charlie=$CHARLIE_ID"
        return 1
    fi
    
    # Alice: engineering, platform
    local code
    code=$(curl -s -o /dev/null -w "%{http_code}" -X PUT "http://headscale-server:8080/api/v1/user/$ALICE_ID/oidc-groups" \
        -H "Authorization: Bearer $API_KEY" \
        -H "Content-Type: application/json" \
        -d '{"groups": ["engineering", "platform"]}')
    if [ "$code" != "200" ]; then
        echo "Set alice groups failed: HTTP $code"
        return 1
    fi
    
    # Bob: engineering
    code=$(curl -s -o /dev/null -w "%{http_code}" -X PUT "http://headscale-server:8080/api/v1/user/$BOB_ID/oidc-groups" \
        -H "Authorization: Bearer $API_KEY" \
        -H "Content-Type: application/json" \
        -d '{"groups": ["engineering"]}')
    if [ "$code" != "200" ]; then
        echo "Set bob groups failed: HTTP $code"
        return 1
    fi
    
    # Charlie: admins
    code=$(curl -s -o /dev/null -w "%{http_code}" -X PUT "http://headscale-server:8080/api/v1/user/$CHARLIE_ID/oidc-groups" \
        -H "Authorization: Bearer $API_KEY" \
        -H "Content-Type: application/json" \
        -d '{"groups": ["admins"]}')
    if [ "$code" != "200" ]; then
        echo "Set charlie groups failed: HTTP $code"
        return 1
    fi
    
    return 0
}

test_get_user_oidc_groups() {
    local user_id groups
    user_id=$(get_user_id alice)
    
    groups=$(curl -sf "http://headscale-server:8080/api/v1/user/$user_id/oidc-groups" \
        -H "Authorization: Bearer $API_KEY" 2>/dev/null | jq -r '.groups[]' | sort | tr '\n' ',')
    local expected
    expected=$(echo -e "engineering,platform,")
    
    if [ "$groups" = "$expected" ]; then
        return 0
    fi
    echo "Expected: $expected"
    echo "Got: $groups"
    return 1
}

test_list_users_by_oidc_group() {
    local response count
    response=$(curl -sf "http://headscale-server:8080/api/v1/user/oidc-group?group=engineering" \
        -H "Authorization: Bearer $API_KEY" 2>/dev/null)
    count=$(echo "$response" | jq '.users | length')
    
    if [ "$count" -ge 2 ]; then
        return 0
    fi
    echo "Expected >= 2 users in engineering, got $count"
    return 1
}

test_oidc_group_update() {
    local user_id
    user_id=$(get_user_id alice)
    
    local code
    code=$(curl -s -o /dev/null -w "%{http_code}" -X PUT "http://headscale-server:8080/api/v1/user/$user_id/oidc-groups" \
        -H "Authorization: Bearer $API_KEY" \
        -H "Content-Type: application/json" \
        -d '{"groups": ["engineering", "security"]}')
    if [ "$code" != "200" ]; then
        echo "Update alice groups failed: HTTP $code"
        return 1
    fi
    
    # Verify
    local groups
    groups=$(curl -sf "http://headscale-server:8080/api/v1/user/$user_id/oidc-groups" \
        -H "Authorization: Bearer $API_KEY" 2>/dev/null | jq -r '.groups[]' | sort | tr '\n' ',')
    local expected
    expected=$(echo -e "engineering,security,")
    
    if [ "$groups" = "$expected" ]; then
        return 0
    fi
    echo "Expected: $expected"
    echo "Got: $groups"
    return 1
}

test_oidc_group_clear() {
    local user_id
    user_id=$(get_user_id charlie)
    
    local code
    code=$(curl -s -o /dev/null -w "%{http_code}" -X PUT "http://headscale-server:8080/api/v1/user/$user_id/oidc-groups" \
        -H "Authorization: Bearer $API_KEY" \
        -H "Content-Type: application/json" \
        -d '{"groups": []}')
    if [ "$code" != "200" ]; then
        echo "Clear charlie groups failed: HTTP $code"
        return 1
    fi
    
    local count
    count=$(curl -sf "http://headscale-server:8080/api/v1/user/$user_id/oidc-groups" \
        -H "Authorization: Bearer $API_KEY" 2>/dev/null | jq '.groups | length')
    
    if [ "$count" = "0" ]; then
        return 0
    fi
    echo "Expected 0 groups, got $count"
    return 1
}

run_test "Set OIDC Groups" test_set_oidc_groups
run_test "Get User OIDC Groups" test_get_user_oidc_groups
run_test "List Users by OIDC Group" test_list_users_by_oidc_group
run_test "Update OIDC Groups" test_oidc_group_update
run_test "Clear OIDC Groups" test_oidc_group_clear
