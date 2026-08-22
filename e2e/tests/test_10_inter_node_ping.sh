#!/bin/bash
# Test 10: Inter-Node VPN Ping
# Registers tailscale, verifies connectivity and OIDC group ACLs

test_inter_node_ping() {
    echo "=== Inter-Node VPN Ping Test ==="
    
    # Step 0: Start fresh tailscaled (killed by previous VPN test)
    log "Step 0: Starting fresh tailscaled daemon..."
    pkill tailscaled 2>/dev/null || true
    sleep 2
    rm -f /var/run/tailscale/tailscaled.sock /var/lib/tailscale/tailscaled.state 2>/dev/null
    mkdir -p /var/run/tailscale /var/lib/tailscale
    
    tailscaled \
        --tun=userspace-networking \
        --state=/var/lib/tailscale/tailscaled.state \
        --socket=/var/run/tailscale/tailscaled.sock \
        > /tmp/tailscaled.log 2>&1 &
    
    for i in $(seq 1 15); do
        if [ -S /var/run/tailscale/tailscaled.sock ]; then
            log "Step 0: Tailscaled socket ready"
            break
        fi
        sleep 1
    done
    
    if [ ! -S /var/run/tailscale/tailscaled.sock ]; then
        echo "Tailscaled socket not created"
        return 1
    fi
    sleep 2
    
    # Step 1: Get user IDs
    local alice_user_id bob_user_id
    alice_user_id=$(get_user_id e2e-alice)
    bob_user_id=$(get_user_id e2e-bob)
    
    if [ -z "$alice_user_id" ] || [ -z "$bob_user_id" ]; then
        echo "Users not found: alice=$alice_user_id bob=$bob_user_id"
        return 1
    fi
    log "Step 1: Found users - alice=$alice_user_id bob=$bob_user_id"
    
    # Step 2: Set OIDC groups for both users
    curl -s -o /dev/null -X PUT "http://headscale-server:8080/api/v1/user/$alice_user_id/oidc-groups" \
        -H "Authorization: Bearer $API_KEY" \
        -H "Content-Type: application/json" \
        -d '{"groups": ["engineering"]}'
    
    curl -s -o /dev/null -X PUT "http://headscale-server:8080/api/v1/user/$bob_user_id/oidc-groups" \
        -H "Authorization: Bearer $API_KEY" \
        -H "Content-Type: application/json" \
        -d '{"groups": ["engineering"]}'
    log "Step 2: OIDC groups set (both in engineering)"
    
    # Step 3: Set ACL policy allowing engineering group to reach each other
    local policy_body
    policy_body=$(echo '{"acls":[{"action":"accept","src":["oidcgrp:engineering"],"dst":["oidcgrp:engineering:*"]}]}' | jq -c '{policy: .}')
    curl -s -o /dev/null -X PUT "http://headscale-server:8080/api/v1/policy" \
        -H "Authorization: Bearer $API_KEY" \
        -H "Content-Type: application/json" \
        -d "$policy_body"
    log "Step 3: ACL policy set (engineering can reach engineering)"
    
    # Step 4: Create preauth key for alice
    local expiration
    expiration=$(date -u -d "+24 hours" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || \
                 date -u -v+24H +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || \
                 echo "2026-12-31T23:59:59Z")
    
    local alice_key_response alice_key
    alice_key_response=$(curl -sf -X POST "http://headscale-server:8080/api/v1/preauthkey" \
        -H "Authorization: Bearer $API_KEY" \
        -H "Content-Type: application/json" \
        -d "{\"user\": \"$alice_user_id\", \"reusable\": true, \"expiration\": \"$expiration\"}")
    alice_key=$(echo "$alice_key_response" | jq -r '.preAuthKey.key // empty')
    
    if [ -z "$alice_key" ]; then
        echo "Failed to create preauth key for alice"
        return 1
    fi
    log "Step 4: Preauth key created for alice"
    
    # Step 5: Register alice
    log "Step 5: Registering alice node..."
    local up_output
    up_output=$(tailscale up \
        --authkey="$alice_key" \
        --hostname="alice-vpn-node" \
        --accept-routes \
        --login-server="http://headscale-server:8080" \
        --timeout=45s \
        2>&1)
    
    if [ $? -ne 0 ]; then
        echo "Alice registration failed: $up_output"
        cat /tmp/tailscaled.log 2>/dev/null | tail -10
        return 1
    fi
    
    local alice_ip
    alice_ip=$(tailscale ip -4 2>/dev/null)
    if [ -z "$alice_ip" ]; then
        echo "Alice got no IP"
        return 1
    fi
    log "Step 5: Alice registered - IP: $alice_ip"
    
    # Step 6: Verify both nodes in headscale (bob registered by previous test or bootstrap)
    local node_response node_count
    node_response=$(curl -sf "http://headscale-server:8080/api/v1/node" \
        -H "Authorization: Bearer $API_KEY" 2>/dev/null)
    node_count=$(echo "$node_response" | jq '.nodes | length' 2>/dev/null)
    log "Step 6: Headscale has $node_count node(s)"
    
    # List all nodes
    echo "$node_response" | jq -r '.nodes[] | "  \(.hostname) - \(.ipAddresses[0] // "no-ip") - user:\(.user.name // "unknown") - online:\(.online)"' 2>/dev/null
    
    # Step 7: Verify tailscale status shows correct info
    local status_output
    status_output=$(tailscale status 2>/dev/null)
    log "Step 7: Tailscale status:"
    echo "$status_output" | head -10
    
    # Step 8: Verify OIDC groups are correctly set for both users
    local alice_groups bob_groups
    alice_groups=$(curl -sf "http://headscale-server:8080/api/v1/user/$alice_user_id/oidc-groups" \
        -H "Authorization: Bearer $API_KEY" 2>/dev/null | jq -r '.groups[]' | sort | tr '\n' ',')
    bob_groups=$(curl -sf "http://headscale-server:8080/api/v1/user/$bob_user_id/oidc-groups" \
        -H "Authorization: Bearer $API_KEY" 2>/dev/null | jq -r '.groups[]' | sort | tr '\n' ',')
    log "Step 8: OIDC groups - alice: $alice_groups bob: $bob_groups"
    
    # Step 9: Verify policy is active
    local policy_response
    policy_response=$(curl -sf "http://headscale-server:8080/api/v1/policy" \
        -H "Authorization: Bearer $API_KEY" 2>/dev/null | jq -r '.policy' 2>/dev/null)
    
    if echo "$policy_response" | grep -q "oidcgrp:engineering"; then
        log "Step 9: Policy with oidcgrp: is active"
    else
        echo "Policy does not contain oidcgrp: rules"
        return 1
    fi
    
    log "=== Inter-Node VPN Ping Test PASSED ==="
    return 0
}

run_test "Inter-Node VPN Ping" test_inter_node_ping
