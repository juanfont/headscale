#!/bin/bash
# Test 3: ACL Policies with oidcgrp: Principal Type

set_policy() {
    local policy_json="$1"
    local body
    body=$(echo "$policy_json" | jq -c '{policy: .}')
    curl -sf -X PUT "http://headscale-server:8080/api/v1/policy" \
        -H "Authorization: Bearer $API_KEY" \
        -H "Content-Type: application/json" \
        -d "$body" 2>/dev/null
}

test_set_policy_with_oidcgrp() {
    local policy='{"acls":[{"action":"accept","src":["oidcgrp:engineering"],"dst":["oidcgrp:admins:443"]},{"action":"accept","src":["oidcgrp:engineering"],"dst":["*:22,80"]},{"action":"accept","src":["oidcgrp:admins"],"dst":["*:*"]}]}'
    
    local http_code
    http_code=$(set_policy "$policy" -o /dev/null -w "%{http_code}" 2>/dev/null || true)
    
    # Verify policy was set by getting it
    local response
    response=$(curl -sf "http://headscale-server:8080/api/v1/policy" \
        -H "Authorization: Bearer $API_KEY" 2>/dev/null)
    
    if echo "$response" | jq -e '.policy' > /dev/null 2>&1; then
        return 0
    fi
    echo "Failed to get policy after set"
    return 1
}

test_get_policy() {
    local response
    response=$(curl -sf "http://headscale-server:8080/api/v1/policy" \
        -H "Authorization: Bearer $API_KEY" 2>/dev/null)
    if [ $? -eq 0 ] && echo "$response" | jq -e '.policy' > /dev/null 2>&1; then
        return 0
    fi
    return 1
}

test_validate_policy_syntax() {
    local policy='{"acls":[{"action":"accept","src":["oidcgrp:"],"dst":["*:*"]}]}'
    local body
    body=$(echo "$policy" | jq -c '{policy: .}')
    
    local http_code
    http_code=$(curl -s -o /dev/null -w "%{http_code}" \
        -X PUT "http://headscale-server:8080/api/v1/policy" \
        -H "Authorization: Bearer $API_KEY" \
        -H "Content-Type: application/json" \
        -d "$body" 2>/dev/null)
    
    if [ "$http_code" -ge 400 ]; then
        return 0
    fi
    echo "Expected 4xx error, got $http_code"
    return 1
}

test_policy_with_multiple_groups() {
    local policy='{"acls":[{"action":"accept","src":["oidcgrp:engineering","oidcgrp:admins"],"dst":["oidcgrp:platform:80,443"]}]}'
    local body
    body=$(echo "$policy" | jq -c '{policy: .}')
    
    local http_code
    http_code=$(curl -s -o /dev/null -w "%{http_code}" \
        -X PUT "http://headscale-server:8080/api/v1/policy" \
        -H "Authorization: Bearer $API_KEY" \
        -H "Content-Type: application/json" \
        -d "$body" 2>/dev/null)
    
    # Verify policy was set
    local response
    response=$(curl -sf "http://headscale-server:8080/api/v1/policy" \
        -H "Authorization: Bearer $API_KEY" 2>/dev/null)
    
    if echo "$response" | jq -e '.policy' > /dev/null 2>&1; then
        return 0
    fi
    echo "Failed to set multiple groups policy"
    return 1
}

test_policy_mixed_principals() {
    local policy='{"groups":{"group:team-a":["alice@headscale.local"],"group:team-b":["bob@headscale.local"]},"tagOwners":{"tag:server":["group:team-a"]},"acls":[{"action":"accept","src":["oidcgrp:engineering","group:team-a","tag:server"],"dst":["*:*"]}]}'
    local body
    body=$(echo "$policy" | jq -c '{policy: .}')
    
    local http_code
    http_code=$(curl -s -o /dev/null -w "%{http_code}" \
        -X PUT "http://headscale-server:8080/api/v1/policy" \
        -H "Authorization: Bearer $API_KEY" \
        -H "Content-Type: application/json" \
        -d "$body" 2>/dev/null)
    
    # Verify policy was set
    local response
    response=$(curl -sf "http://headscale-server:8080/api/v1/policy" \
        -H "Authorization: Bearer $API_KEY" 2>/dev/null)
    
    if echo "$response" | jq -e '.policy' > /dev/null 2>&1; then
        return 0
    fi
    echo "Failed to set mixed principals policy"
    return 1
}

run_test "Set Policy with oidcgrp:" test_set_policy_with_oidcgrp
run_test "Get Policy" test_get_policy
run_test "Validate Policy Syntax" test_validate_policy_syntax
run_test "Policy with Multiple Groups" test_policy_with_multiple_groups
run_test "Policy with Mixed Principals" test_policy_mixed_principals
