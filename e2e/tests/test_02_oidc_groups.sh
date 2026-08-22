#!/bin/bash
# Test 2: OIDC Groups - API and Policy Resolution

test_create_users() {
    # Create test users
    local user1 user2 user3
    user1=$(curl -sf -X POST "http://headscale-server:8080/api/v1/user" \
        -H "Authorization: Bearer $API_KEY" \
        -H "Content-Type: application/json" \
        -d '{"name": "alice", "email": "alice@test.com"}' 2>/dev/null)
    
    user2=$(curl -sf -X POST "http://headscale-server:8080/api/v1/user" \
        -H "Authorization: Bearer $API_KEY" \
        -H "Content-Type: application/json" \
        -d '{"name": "bob", "email": "bob@test.com"}' 2>/dev/null)
    
    user3=$(curl -sf -X POST "http://headscale-server:8080/api/v1/user" \
        -H "Authorization: Bearer $API_KEY" \
        -H "Content-Type: application/json" \
        -d '{"name": "charlie", "email": "charlie@test.com"}' 2>/dev/null)
    
    if [ $? -eq 0 ]; then
        ALICE_ID=$(echo "$user1" | jq -r '.user.id')
        BOB_ID=$(echo "$user2" | jq -r '.user.id')
        CHARLIE_ID=$(echo "$user3" | jq -r '.user.id')
        return 0
    fi
    return 1
}

test_set_oidc_groups() {
    # Set OIDC groups for users
    local response
    
    # Alice: engineering, platform
    response=$(curl -sf -X PUT "http://headscale-server:8080/api/v1/user/$ALICE_ID/oidc-groups" \
        -H "Authorization: Bearer $API_KEY" \
        -H "Content-Type: application/json" \
        -d '{"groups": ["engineering", "platform"]}' 2>/dev/null)
    
    if [ $? -ne 0 ]; then
        return 1
    fi
    
    # Bob: engineering
    response=$(curl -sf -X PUT "http://headscale-server:8080/api/v1/user/$BOB_ID/oidc-groups" \
        -H "Authorization: Bearer $API_KEY" \
        -H "Content-Type: application/json" \
        -d '{"groups": ["engineering"]}' 2>/dev/null)
    
    if [ $? -ne 0 ]; then
        return 1
    fi
    
    # Charlie: admins
    response=$(curl -sf -X PUT "http://headscale-server:8080/api/v1/user/$CHARLIE_ID/oidc-groups" \
        -H "Authorization: Bearer $API_KEY" \
        -H "Content-Type: application/json" \
        -d '{"groups": ["admins"]}' 2>/dev/null)
    
    if [ $? -eq 0 ]; then
        return 0
    fi
    return 1
}

test_get_user_oidc_groups() {
    # Verify Alice's groups
    local response
    response=$(curl -sf "http://headscale-server:8080/api/v1/user/$ALICE_ID/oidc-groups" \
        -H "Authorization: Bearer $API_KEY" 2>/dev/null)
    
    if [ $? -ne 0 ]; then
        return 1
    fi
    
    local groups
    groups=$(echo "$response" | jq -r '.groups[]' | sort)
    local expected
    expected=$(echo -e "engineering\nplatform" | sort)
    
    if [ "$groups" = "$expected" ]; then
        return 0
    fi
    echo "Expected: $expected"
    echo "Got: $groups"
    return 1
}

test_list_users_by_oidc_group() {
    # List users in engineering group
    local response
    response=$(curl -sf "http://headscale-server:8080/api/v1/user/oidc-group?group=engineering" \
        -H "Authorization: Bearer $API_KEY" 2>/dev/null)
    
    if [ $? -ne 0 ]; then
        return 1
    fi
    
    local count
    count=$(echo "$response" | jq '.users | length')
    
    # Should have 2 users (alice + bob)
    if [ "$count" -eq 2 ]; then
        return 0
    fi
    echo "Expected 2 users, got $count"
    return 1
}

test_oidc_group_update() {
    # Update Alice's groups - remove platform, add security
    local response
    response=$(curl -sf -X PUT "http://headscale-server:8080/api/v1/user/$ALICE_ID/oidc-groups" \
        -H "Authorization: Bearer $API_KEY" \
        -H "Content-Type: application/json" \
        -d '{"groups": ["engineering", "security"]}' 2>/dev/null)
    
    if [ $? -ne 0 ]; then
        return 1
    fi
    
    # Verify the update
    response=$(curl -sf "http://headscale-server:8080/api/v1/user/$ALICE_ID/oidc-groups" \
        -H "Authorization: Bearer $API_KEY" 2>/dev/null)
    
    local groups
    groups=$(echo "$response" | jq -r '.groups[]' | sort)
    local expected
    expected=$(echo -e "engineering\nsecurity" | sort)
    
    if [ "$groups" = "$expected" ]; then
        return 0
    fi
    echo "Expected: $expected"
    echo "Got: $groups"
    return 1
}

test_oidc_group_clear() {
    # Clear Charlie's groups
    local response
    response=$(curl -sf -X PUT "http://headscale-server:8080/api/v1/user/$CHARLIE_ID/oidc-groups" \
        -H "Authorization: Bearer $API_KEY" \
        -H "Content-Type: application/json" \
        -d '{"groups": []}' 2>/dev/null)
    
    if [ $? -ne 0 ]; then
        return 1
    fi
    
    # Verify groups are empty
    response=$(curl -sf "http://headscale-server:8080/api/v1/user/$CHARLIE_ID/oidc-groups" \
        -H "Authorization: Bearer $API_KEY" 2>/dev/null)
    
    local count
    count=$(echo "$response" | jq '.groups | length')
    
    if [ "$count" -eq 0 ]; then
        return 0
    fi
    echo "Expected 0 groups, got $count"
    return 1
}

run_test "Create Test Users" test_create_users
run_test "Set OIDC Groups" test_set_oidc_groups
run_test "Get User OIDC Groups" test_get_user_oidc_groups
run_test "List Users by OIDC Group" test_list_users_by_oidc_group
run_test "Update OIDC Groups" test_oidc_group_update
run_test "Clear OIDC Groups" test_oidc_group_clear
