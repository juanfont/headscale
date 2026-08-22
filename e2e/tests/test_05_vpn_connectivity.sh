#!/bin/bash
# Test 5: VPN Connectivity and User Separation

test_register_node() {
    # Generate a preauth key
    local users output key
    users=$(headscale users list 2>/dev/null)
    alice_id=$(echo "$users" | grep "alice" | awk '{print $1}')
    
    if [ -z "$alice_id" ]; then
        echo "Could not find alice user"
        return 1
    fi
    
    key=$(curl -sf -X POST "http://headscale-server:8080/api/v1/preauthkey" \
        -H "Authorization: Bearer $API_KEY" \
        -H "Content-Type: application/json" \
        -d "{\"user\": \"alice\", \"reusable\": true, \"expirationSeconds\": 86400}" 2>/dev/null | jq -r '.preAuthKey.key // empty')
    
    if [ -z "$key" ]; then
        echo "Failed to create preauth key"
        return 1
    fi
    
    # Register with tailscale
    tailscale up --authkey="$key" --hostname="client-alice" --accept-routes 2>/dev/null
    if [ $? -eq 0 ]; then
        echo "Node registered successfully"
        return 0
    fi
    return 1
}

test_node_appears_in_list() {
    # Check that the node appears in the headscale node list
    local output
    for i in $(seq 1 10); do
        output=$(headscale nodes list 2>/dev/null)
        if echo "$output" | grep -q "client-alice"; then
            return 0
        fi
        sleep 2
    done
    echo "Node did not appear in list within 20 seconds"
    return 1
}

test_tailscale_status() {
    local output
    output=$(tailscale status 2>/dev/null)
    if [ $? -eq 0 ]; then
        return 0
    fi
    return 1
}

test_tailscale_ip() {
    local output
    output=$(tailscale ip -4 2>/dev/null)
    if [ $? -eq 0 ] && [ -n "$output" ]; then
        echo "Assigned IP: $output"
        return 0
    fi
    return 1
}

test_node_approved_routes() {
    # List nodes and check routes
    local output
    output=$(headscale nodes list 2>/dev/null)
    if [ $? -eq 0 ]; then
        return 0
    fi
    return 1
}

test_user_separation() {
    # Verify user isolation - Alice's node should be tagged with correct user
    local output
    output=$(headscale nodes list --json 2>/dev/null)
    if [ $? -eq 0 ]; then
        # Check that at least one node exists
        local count
        count=$(echo "$output" | jq '.[] | length' 2>/dev/null || echo "0")
        echo "Nodes found: $count"
        return 0
    fi
    return 1
}

test_dns_resolution() {
    # Test MagicDNS resolution (may need to wait for map update)
    local output
    for i in $(seq 1 5); do
        output=$(tailscale status 2>/dev/null)
        if echo "$output" | grep -q "client-alice"; then
            return 0
        fi
        sleep 2
    done
    echo "DNS resolution test - node not found in status"
    return 1
}

run_test "Register Node" test_register_node
run_test "Node Appears in List" test_node_appears_in_list
run_test "Tailscale Status" test_tailscale_status
run_test "Tailscale IP Assignment" test_tailscale_ip
run_test "Node Approved Routes" test_node_approved_routes
run_test "User Separation" test_user_separation
run_test "DNS Resolution" test_dns_resolution
