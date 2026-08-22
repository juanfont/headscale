#!/bin/bash
set -euo pipefail

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
    if $test_func; then
        pass "$test_name"
    else
        fail "$test_name"
    fi
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

# Read API key from the bootstrap file (shared via volume)
echo "Reading API key..."
for i in $(seq 1 10); do
    if [ -f /var/lib/headscale/.api_key ]; then
        API_KEY=$(cat /var/lib/headscale/.api_key)
        if [ -n "$API_KEY" ]; then
            log "API key loaded from bootstrap"
            break
        fi
    fi
    sleep 1
done

if [ -z "${API_KEY:-}" ]; then
    echo "Failed to get API key from bootstrap"
    exit 1
fi

export API_KEY
export HEADSCALE_URL="http://headscale-server:8080"
log "API key: ${API_KEY:0:10}..."

# Source test files
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
for test_file in "$SCRIPT_DIR"/test_*.sh; do
    if [ -f "$test_file" ]; then
        source "$test_file"
    fi
done

echo ""
echo "=========================================="
echo "           TEST RESULTS"
echo "=========================================="
echo -e "Total:  $TOTAL"
echo -e "Passed: ${GREEN}$PASSED${NC}"
echo -e "Failed: ${RED}$FAILED${NC}"
echo "=========================================="

if [ $FAILED -gt 0 ]; then
    exit 1
fi
