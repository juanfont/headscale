#!/bin/bash
# Test 9: Long-running OIDC Group Refresh Monitor
# Monitors the 15-minute refresh cycle by checking groups periodically
# Run with: docker exec -e TEST_DURATION=180 client-alice bash /tests/test_09_refresh_monitor_long.sh

TEST_DURATION="${TEST_DURATION:-180}"  # Default 3 minutes
CHECK_INTERVAL="${CHECK_INTERVAL:-15}" # Check every 15 seconds

log() { echo -e "\033[0;32m[MONITOR]\033[0m $(date '+%H:%M:%S') $1"; }
warn() { echo -e "\033[0;33m[WARN]\033[0m $(date '+%H:%M:%S') $1"; }
err() { echo -e "\033[0;31m[ERROR]\033[0m $(date '+%H:%M:%S') $1"; }

# Setup test data
setup_test_groups() {
    local user_id
    user_id=$(get_user_id refresh-test-user)
    
    if [ -z "$user_id" ]; then
        err "refresh-test-user not found"
        return 1
    fi
    
    # Set initial groups
    curl -s -o /dev/null -X PUT "http://headscale-server:8080/api/v1/user/$user_id/oidc-groups" \
        -H "Authorization: Bearer $API_KEY" \
        -H "Content-Type: application/json" \
        -d '{"groups": ["monitor-group-a", "monitor-group-b"]}'
    
    log "Initial groups set for refresh-test-user"
    return 0
}

# Check groups are consistent
check_groups() {
    local user_id
    user_id=$(get_user_id refresh-test-user)
    
    if [ -z "$user_id" ]; then
        err "refresh-test-user not found during check"
        return 1
    fi
    
    local groups count
    groups=$(curl -sf "http://headscale-server:8080/api/v1/user/$user_id/oidc-groups" \
        -H "Authorization: Bearer $API_KEY" 2>/dev/null | jq -r '.groups[]' 2>/dev/null | sort | tr '\n' ',')
    count=$(echo "$groups" | tr ',' '\n' | grep -c '.' || true)
    
    echo "$count:$groups"
}

# Check server health
check_server_health() {
    curl -sf "http://headscale-server:8080/health" > /dev/null 2>&1
    return $?
}

# Main monitoring loop
run_refresh_monitor() {
    log "=== OIDC Group Refresh Monitor ==="
    log "Duration: ${TEST_DURATION}s, Interval: ${CHECK_INTERVAL}s"
    
    # Setup
    if ! setup_test_groups; then
        return 1
    fi
    
    local start_time
    start_time=$(date +%s)
    local checks=0
    local passes=0
    local failures=0
    local last_groups=""
    local changes_detected=0
    
    log "Starting monitoring loop..."
    
    while true; do
        local now elapsed
        now=$(date +%s)
        elapsed=$((now - start_time))
        
        if [ "$elapsed" -ge "$TEST_DURATION" ]; then
            break
        fi
        
        checks=$((checks + 1))
        
        # Check server health
        if ! check_server_health; then
            warn "Server health check failed at ${elapsed}s"
            failures=$((failures + 1))
            sleep "$CHECK_INTERVAL"
            continue
        fi
        
        # Check groups
        local result count groups
        result=$(check_groups)
        count=$(echo "$result" | cut -d: -f1)
        groups=$(echo "$result" | cut -d: -f2)
        
        if [ "$count" -ge 2 ]; then
            passes=$((passes + 1))
            
            # Track changes
            if [ -n "$last_groups" ] && [ "$groups" != "$last_groups" ]; then
                changes_detected=$((changes_detected + 1))
                warn "Groups changed at ${elapsed}s: $last_groups -> $groups"
            fi
            last_groups="$groups"
        else
            warn "Groups check failed at ${elapsed}s: count=$count groups=$groups"
            failures=$((failures + 1))
        fi
        
        # Log progress every 60 seconds
        if [ $((elapsed % 60)) -eq 0 ] && [ "$elapsed" -gt 0 ]; then
            log "Progress: ${elapsed}/${TEST_DURATION}s - checks=$checks passes=$passes failures=$failures changes=$changes_detected"
        fi
        
        sleep "$CHECK_INTERVAL"
    done
    
    # Final summary
    local total_time
    total_time=$(($(date +%s) - start_time))
    
    log "=== Monitor Summary ==="
    log "Duration: ${total_time}s"
    log "Checks: $checks"
    log "Passes: $passes"
    log "Failures: $failures"
    log "Group changes detected: $changes_detected"
    
    if [ "$failures" -eq 0 ]; then
        log "=== Monitor PASSED ==="
        return 0
    else
        err "=== Monitor FAILED ($failures failures) ==="
        return 1
    fi
}

# Run if executed directly (not sourced)
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    # Source helpers if available
    if [ -f /tests/run_all.sh ]; then
        export API_KEY="${API_KEY:-}"
        if [ -z "$API_KEY" ] && [ -f /var/lib/headscale/.api_key ]; then
            API_KEY=$(cat /var/lib/headscale/.api_key)
        fi
        export HEADSCALE_URL="http://headscale-server:8080"
        export TEST_USER="${TEST_USER:-alice}"
        export TEST_USER_ID="${TEST_USER_ID:-1}"
        
        # Export get_user_id helper
        get_user_id() {
            local name="$1"
            curl -sf "http://headscale-server:8080/api/v1/user" \
                -H "Authorization: Bearer $API_KEY" 2>/dev/null | \
                jq -r --arg name "$name" '.users[] | select(.name == $name) | .id' | head -1
        }
        export -f get_user_id
    fi
    
    run_refresh_monitor
fi
