#!/bin/bash
set -euo pipefail

BOOTSTRAP_FLAG="/var/lib/headscale/.bootstrapped"
SOCKET="/var/run/headscale/headscale.sock"

# Start headscale in the background
headscale serve --config /etc/headscale/config.yaml &
HS_PID=$!

# Wait for the unix socket to appear
echo "Waiting for headscale socket..."
for i in $(seq 1 30); do
    if [ -S "$SOCKET" ]; then
        echo "Socket ready!"
        break
    fi
    sleep 1
done

# Extra settle time
sleep 3

# Only bootstrap once
if [ ! -f "$BOOTSTRAP_FLAG" ]; then
    echo "Bootstrapping headscale..."
    
    # Create admin user
    headscale user create --name admin 2>&1 || true
    sleep 1
    
    # Create API key (no --user flag needed)
    for attempt in $(seq 1 5); do
        OUTPUT=$(headscale apikeys create --expiration 8760h 2>&1 || true)
        echo "API key output: $OUTPUT"
        
        # Extract the key - it's printed as the raw key value
        API_KEY=$(echo "$OUTPUT" | grep -oP '(?<=API key: ).*' || echo "$OUTPUT" | head -1)
        
        if [ -n "$API_KEY" ] && [ ${#API_KEY} -gt 20 ]; then
            echo "$API_KEY" > /var/lib/headscale/.api_key
            echo "Bootstrap complete. API key saved."
            break
        fi
        echo "API key attempt $attempt failed, retrying in 2s..."
        sleep 2
    done
    
    if [ ! -f /var/lib/headscale/.api_key ]; then
        echo "Warning: Could not create API key after 5 attempts"
        echo "$OUTPUT" > /var/lib/headscale/.api_key_debug
    fi
    
    touch "$BOOTSTRAP_FLAG"
fi

# Keep running
wait $HS_PID
