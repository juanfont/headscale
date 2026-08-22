#!/bin/bash
# Test 5: VPN Connectivity
# Starts tailscaled, registers via preauth key, verifies connectivity

test_vpn_full_connectivity() {
    echo "=== VPN Connectivity Test ==="
    
    # Step 0: Start tailscaled if not running
    if ! pgrep tailscaled > /dev/null 2>&1; then
        log "Step 0: Starting tailscaled daemon..."
        mkdir -p /var/run/tailscale /var/lib/tailscale
        tailscaled \
            --tun=userspace-networking \
            --state=/var/lib/tailscale/tailscaled.state \
            --socket=/var/run/tailscale/tailscaled.sock \
            > /tmp/tailscaled.log 2>&1 &
        
        # Wait for daemon socket
        for i in $(seq 1 15); do
            if [ -S /var/run/tailscale/tailscaled.sock ]; then
                log "Step 0: Tailscaled socket ready"
                break
            fi
            sleep 1
        done
        
        if [ ! -S /var/run/tailscale/tailscaled.sock ]; then
            echo "Tailscaled socket not created"
            cat /tmp/tailscaled.log 2>/dev/null | tail -10
            return 1
        fi
        
        sleep 2
    else
        log "Step 0: Tailscaled already running"
    fi
    
    # Step 1: Get user ID
    local user_id
    user_id=$(get_user_id "$TEST_USER")
    if [ -z "$user_id" ]; then
        echo "User $TEST_USER not found"
        return 1
    fi
    log "Step 1: Found user $TEST_USER (ID: $user_id)"
    
    # Step 2: Create preauth key with 24h expiration (ISO timestamp)
    local expiration
    expiration=$(date -u -d "+24 hours" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || \
                 date -u -v+24H +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || \
                 echo "2026-12-31T23:59:59Z")
    
    local response preauth_key
    response=$(curl -sf -X POST "http://headscale-server:8080/api/v1/preauthkey" \
        -H "Authorization: Bearer $API_KEY" \
        -H "Content-Type: application/json" \
        -d "{\"user\": \"$user_id\", \"reusable\": true, \"expiration\": \"$expiration\"}" 2>/dev/null)
    
    preauth_key=$(echo "$response" | jq -r '.preAuthKey.key // empty')
    if [ -z "$preauth_key" ]; then
        echo "Failed to create preauth key"
        echo "Response: $response"
        return 1
    fi
    log "Step 2: Preauth key created (expires: $expiration)"
    
    # Step 3: Register with headscale - must set login server URL
    log "Step 3: Registering tailscale..."
    tailscale logout 2>/dev/null || true
    sleep 1
    
    # Register with headscale
    local up_output
    up_output=$(tailscale up \
        --authkey="$preauth_key" \
        --hostname="${TEST_USER}-node" \
        --accept-routes \
        --login-server="http://headscale-server:8080" \
        --timeout=30s \
        2>&1)
    local up_exit=$?
    
    if [ $up_exit -ne 0 ]; then
        echo "Tailscale registration failed (exit=$up_exit)"
        echo "Output: $up_output"
        
        if pgrep tailscaled > /dev/null 2>&1; then
            log "tailscaled is running, checking status..."
            tailscale status 2>&1 || true
        else
            echo "tailscaled crashed"
            cat /tmp/tailscaled.log 2>/dev/null | tail -20
        fi
        return 1
    fi
    log "Step 3: Tailscale registered"
    
    # Step 4: Check IP address
    local ts_ip
    ts_ip=$(tailscale ip -4 2>/dev/null)
    if [ -z "$ts_ip" ] || [ "$ts_ip" = "null" ]; then
        echo "No Tailscale IP assigned"
        tailscale status 2>&1 || true
        return 1
    fi
    log "Step 4: Tailscale IP: $ts_ip"
    
    # Step 5: Check node in headscale
    local node_response node_count hostname online
    node_response=$(curl -sf "http://headscale-server:8080/api/v1/node" \
        -H "Authorization: Bearer $API_KEY" 2>/dev/null)
    node_count=$(echo "$node_response" | jq '.nodes | length' 2>/dev/null)
    
    if [ "$node_count" -lt 1 ]; then
        echo "No nodes registered in headscale"
        return 1
    fi
    
    hostname=$(echo "$node_response" | jq -r '.nodes[0].hostname // empty' 2>/dev/null)
    online=$(echo "$node_response" | jq -r '.nodes[0].online // false' 2>/dev/null)
    log "Step 5: Node '$hostname' online=$online (${node_count} node(s))"
    
    # Step 6: Verify tailscale status
    local status_output
    status_output=$(tailscale status 2>/dev/null)
    log "Step 6: Tailscale status:"
    echo "$status_output" | head -5
    
    log "=== VPN Connectivity Test PASSED ==="
    return 0
}

run_test "VPN Full Connectivity" test_vpn_full_connectivity
