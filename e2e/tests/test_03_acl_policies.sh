#!/bin/bash
# Test 3: ACL Policies with oidcgrp: Principal Type

test_set_policy_with_oidcgrp() {
    # Set a policy that uses oidcgrp: sources
    local policy
    policy=$(cat <<'POLICY'
{
    "acls": [
        {
            "action": "accept",
            "src": ["oidcgrp:engineering"],
            "dst": ["oidcgrp:admins:443"]
        },
        {
            "action": "accept",
            "src": ["oidcgrp:engineering"],
            "dst": ["*:22,80"]
        },
        {
            "action": "accept",
            "src": ["oidcgrp:admins"],
            "dst": ["*:*"]
        }
    ]
}
POLICY
)
    
    local response
    response=$(curl -sf -X PUT "http://headscale-server:8080/api/v1/policy" \
        -H "Authorization: Bearer $API_KEY" \
        -H "Content-Type: application/json" \
        -d "$policy" 2>/dev/null)
    
    if [ $? -eq 0 ]; then
        return 0
    fi
    echo "Failed to set policy: $response"
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
    # Set an invalid policy and expect failure
    local policy
    policy=$(cat <<'POLICY'
{
    "acls": [
        {
            "action": "accept",
            "src": ["oidcgrp:"],
            "dst": ["*:*"]
        }
    ]
}
POLICY
)
    
    local http_code
    http_code=$(curl -s -o /dev/null -w "%{http_code}" \
        -X PUT "http://headscale-server:8080/api/v1/policy" \
        -H "Authorization: Bearer $API_KEY" \
        -H "Content-Type: application/json" \
        -d "$policy" 2>/dev/null)
    
    # Should return 4xx error for invalid oidcgrp:
    if [ "$http_code" -ge 400 ]; then
        return 0
    fi
    echo "Expected 4xx error, got $http_code"
    return 1
}

test_policy_with_multiple_groups() {
    # Set a policy with multiple oidcgrp: sources
    local policy
    policy=$(cat <<'POLICY'
{
    "acls": [
        {
            "action": "accept",
            "src": ["oidcgrp:engineering", "oidcgrp:admins"],
            "dst": ["oidcgrp:platform:80,443"]
        }
    ]
}
POLICY
)
    
    local response
    response=$(curl -sf -X PUT "http://headscale-server:8080/api/v1/policy" \
        -H "Authorization: Bearer $API_KEY" \
        -H "Content-Type: application/json" \
        -d "$policy" 2>/dev/null)
    
    if [ $? -eq 0 ]; then
        return 0
    fi
    echo "Failed to set policy: $response"
    return 1
}

test_policy_mixed_principals() {
    # Set a policy mixing oidcgrp: with other principal types
    local policy
    policy=$(cat <<'POLICY'
{
    "groups": {
        "group:team-a": ["alice@test.com"],
        "group:team-b": ["bob@test.com"]
    },
    "tagOwners": {
        "tag:server": ["group:team-a"]
    },
    "acls": [
        {
            "action": "accept",
            "src": ["oidcgrp:engineering", "group:team-a", "tag:server"],
            "dst": ["*:*"]
        }
    ]
}
POLICY
)
    
    local response
    response=$(curl -sf -X PUT "http://headscale-server:8080/api/v1/policy" \
        -H "Authorization: Bearer $API_KEY" \
        -H "Content-Type: application/json" \
        -d "$policy" 2>/dev/null)
    
    if [ $? -eq 0 ]; then
        return 0
    fi
    echo "Failed to set policy: $response"
    return 1
}

run_test "Set Policy with oidcgrp:" test_set_policy_with_oidcgrp
run_test "Get Policy" test_get_policy
run_test "Validate Policy Syntax" test_validate_policy_syntax
run_test "Policy with Multiple Groups" test_policy_with_multiple_groups
run_test "Policy with Mixed Principals" test_policy_mixed_principals
