#!/bin/bash
# Test 1: API Health and Basic Connectivity

test_api_health() {
    local response
    response=$(curl -sf "http://headscale-server:8080/health" 2>/dev/null)
    if [ $? -eq 0 ]; then
        # Health may return "OK" or {"status":"pass"} depending on version
        if [ "$response" = "OK" ] || echo "$response" | jq -e '.status' > /dev/null 2>&1; then
            return 0
        fi
    fi
    return 1
}

test_api_user_list() {
    local response
    response=$(curl -sf "http://headscale-server:8080/api/v1/user" \
        -H "Authorization: Bearer $API_KEY" 2>/dev/null)
    if [ $? -eq 0 ] && echo "$response" | jq -e '.users' > /dev/null 2>&1; then
        return 0
    fi
    return 1
}

test_api_user_count() {
    local response
    response=$(curl -sf "http://headscale-server:8080/api/v1/user" \
        -H "Authorization: Bearer $API_KEY" 2>/dev/null)
    local count
    count=$(echo "$response" | jq '.users | length')
    if [ "$count" -gt 0 ] 2>/dev/null; then
        return 0
    fi
    return 1
}

run_test "API Health Check" test_api_health
run_test "API List Users" test_api_user_list
run_test "API User Count > 0" test_api_user_count
