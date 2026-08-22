#!/bin/bash
set -eo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

PASSED=0
FAILED=0
TOTAL=0

log() { echo -e "${GREEN}[TEST]${NC} $1"; }
fail() { echo -e "${RED}[FAIL]${NC} $1"; FAILED=$((FAILED + 1)); }
pass() { echo -e "${GREEN}[PASS]${NC} $1"; PASSED=$((PASSED + 1)); }

run_test() {
    local test_name="$1"
    local test_func="$2"
    TOTAL=$((TOTAL + 1))
    echo ""
    echo "=========================================="
    log "Running: $test_name"
    echo "=========================================="
    if (set +e; set +u; "$test_func"); then
        pass "$test_name"
    else
        fail "$test_name"
    fi
}

# Helper: get user ID by name from API
get_user_id() {
    local name="$1"
    curl -sf "http://headscale-server:8080/api/v1/user" \
        -H "Authorization: Bearer $API_KEY" 2>/dev/null | \
        jq -r --arg name "$name" '.users[] | select(.name == $name) | .id' | head -1
}

# Wait for headscale to be ready
echo "Waiting for headscale server to be ready..."
for i in $(seq 1 30); do
    if curl -sf "http://headscale-server:8080/health" > /dev/null 2>&1; then
        log "Headscale is ready!"
        break
    fi
    if [ $i -eq 30 ]; then
        echo "Headscale failed to start within 30 seconds"
        exit 1
    fi
    sleep 1
done

# Read API key from the bootstrap file
echo "Reading API key..."
for i in $(seq 1 10); do
    if [ -f /var/lib/headscale/.api_key ]; then
        API_KEY=$(cat /var/lib/headscale/.api_key)
        if [ -n "$API_KEY" ]; then
            log "API key loaded"
            break
        fi
    fi
    sleep 1
done

if [ -z "${API_KEY:-}" ]; then
    echo "Failed to get API key"
    exit 1
fi

export API_KEY
export HEADSCALE_URL="http://headscale-server:8080"
export TEST_USER="${TEST_USER:-alice}"
export TEST_USER_ID="${TEST_USER_ID:-1}"
export -f get_user_id
log "Running as: $TEST_USER (ID: $TEST_USER_ID)"

# Source test files
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Run API and OIDC tests (only on client-alice to avoid duplicates)
if [ "$TEST_USER" = "alice" ]; then
    for test_file in "$SCRIPT_DIR"/test_0{1,2,3,6,8}_*.sh; do
        if [ -f "$test_file" ]; then
            source "$test_file"
        fi
    done
fi

# Run VPN connectivity test (each client registers its own node)
if [ -f "$SCRIPT_DIR/test_05_vpn_connectivity.sh" ]; then
    source "$SCRIPT_DIR/test_05_vpn_connectivity.sh"
fi

# Run inter-node ping test (both alice and bob run this)
if [ -f "$SCRIPT_DIR/test_10_inter_node_ping.sh" ]; then
    source "$SCRIPT_DIR/test_10_inter_node_ping.sh"
fi

# Run VPN/user separation tests (each client runs its own)
if [ -f "$SCRIPT_DIR/test_07_user_separation.sh" ]; then
    source "$SCRIPT_DIR/test_07_user_separation.sh"
fi

# Run API-based tests (only on client-alice)
if [ "$TEST_USER" = "alice" ]; then
    for test_file in "$SCRIPT_DIR"/test_04_*.sh; do
        if [ -f "$test_file" ]; then
            source "$test_file"
        fi
    done
fi

echo ""
echo "=========================================="
echo "           TEST RESULTS ($TEST_USER)"
echo "=========================================="
echo -e "Total:  $TOTAL"
echo -e "Passed: ${GREEN}$PASSED${NC}"
echo -e "Failed: ${RED}$FAILED${NC}"
echo "=========================================="

if [ $FAILED -gt 0 ]; then
    exit 1
fi
