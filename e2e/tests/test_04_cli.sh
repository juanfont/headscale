#!/bin/bash
# Test 4: API-based tests (replaces CLI tests since CLI needs unix socket)
# These test the same functionality the CLI commands would test

test_api_user_create() {
    local response code
    response=$(curl -s -w "\n%{http_code}" -X POST "http://headscale-server:8080/api/v1/user" \
        -H "Authorization: Bearer $API_KEY" \
        -H "Content-Type: application/json" \
        -d '{"name": "dave", "email": "dave@test.com"}')
    code=$(echo "$response" | tail -1)
    if [ "$code" = "200" ] || [ "$code" = "201" ]; then
        return 0
    fi
    # 409 conflict means user already exists, still counts as working
    if [ "$code" = "409" ]; then
        return 0
    fi
    echo "Create user failed: HTTP $code"
    echo "$response" | head -1
    return 1
}

test_api_user_list_has_alice() {
    local response
    response=$(curl -sf "http://headscale-server:8080/api/v1/user" \
        -H "Authorization: Bearer $API_KEY" 2>/dev/null)
    if [ $? -eq 0 ] && echo "$response" | jq -e '.users[] | select(.name == "alice")' > /dev/null 2>&1; then
        return 0
    fi
    return 1
}

test_api_node_list() {
    local response code
    response=$(curl -s -w "\n%{http_code}" "http://headscale-server:8080/api/v1/node" \
        -H "Authorization: Bearer $API_KEY")
    code=$(echo "$response" | tail -1)
    if [ "$code" = "200" ]; then
        return 0
    fi
    echo "Node list failed: HTTP $code"
    return 1
}

test_api_preauth_key() {
    # Create a preauth key for test user via the v1 API
    local response code
    response=$(curl -s -w "\n%{http_code}" -X POST "http://headscale-server:8080/api/v1/preauthkey" \
        -H "Authorization: Bearer $API_KEY" \
        -H "Content-Type: application/json" \
        -d "{\"user\": \"$TEST_USER_ID\", \"reusable\": true}")
    code=$(echo "$response" | tail -1)
    if [ "$code" = "200" ] || [ "$code" = "201" ]; then
        return 0
    fi
    echo "Preauth key failed: HTTP $code"
    echo "$response" | head -1
    return 1
}

test_api_health_json() {
    local response
    response=$(curl -sf "http://headscale-server:8080/health" 2>/dev/null)
    if [ $? -eq 0 ]; then
        local status
        status=$(echo "$response" | jq -r '.status' 2>/dev/null)
        if [ "$status" = "pass" ] || [ "$response" = "OK" ]; then
            return 0
        fi
    fi
    return 1
}

run_test "API Health (JSON)" test_api_health_json
run_test "API List Users (has alice)" test_api_user_list_has_alice
run_test "API Create User" test_api_user_create
run_test "API List Nodes" test_api_node_list
run_test "API Create Preauth Key" test_api_preauth_key
