#!/bin/bash
set -x

KC_URL="http://keycloak:8080/auth"

echo "Waiting for Keycloak to be ready..."
for i in $(seq 1 40); do
    if curl -s "$KC_URL/realms/master" > /dev/null 2>&1; then
        echo "Keycloak is ready!"
        break
    fi
    echo "Waiting... attempt $i"
    sleep 3
done

echo "Getting admin token..."
TOKEN=""
for i in $(seq 1 10); do
    TOKEN=$(curl -s -X POST "$KC_URL/realms/master/protocol/openid-connect/token" \
        -d 'client_id=admin-cli' \
        -d 'username=admin' \
        -d 'password=admin' \
        -d 'grant_type=password' | jq -r '.access_token // empty')
    if [ -n "$TOKEN" ]; then
        echo "Got admin token!"
        break
    fi
    echo "Token attempt $i failed, retrying..."
    sleep 3
done

if [ -z "$TOKEN" ]; then
    echo "ERROR: Could not get admin token"
    exit 1
fi

echo "Creating headscale realm..."
curl -s -X POST "$KC_URL/admin/realms" \
    -H "Authorization: Bearer $TOKEN" \
    -H 'Content-Type: application/json' \
    -d '{"realm":"headscale","enabled":true}' || true

echo "Creating headscale client..."
curl -s -X POST "$KC_URL/admin/realms/headscale/clients" \
    -H "Authorization: Bearer $TOKEN" \
    -H 'Content-Type: application/json' \
    -d '{"clientId":"headscale","enabled":true,"directAccessGrantsEnabled":true,"publicClient":false,"secret":"headscale-secret","redirectUris":["http://headscale-server:8080/oidc/callback"]}' || true

echo "Creating groups..."
for group in admins engineering platform; do
    curl -s -X POST "$KC_URL/admin/realms/headscale/groups" \
        -H "Authorization: Bearer $TOKEN" \
        -H 'Content-Type: application/json' \
        -d "{\"name\":\"$group\"}" || true
done

echo "Getting group IDs..."
ADMINS_ID=$(curl -s "$KC_URL/admin/realms/headscale/groups" -H "Authorization: Bearer $TOKEN" | jq -r '.[] | select(.name=="admins") | .id')
ENG_ID=$(curl -s "$KC_URL/admin/realms/headscale/groups" -H "Authorization: Bearer $TOKEN" | jq -r '.[] | select(.name=="engineering") | .id')
PLAT_ID=$(curl -s "$KC_URL/admin/realms/headscale/groups" -H "Authorization: Bearer $TOKEN" | jq -r '.[] | select(.name=="platform") | .id')
echo "Groups: admins=$ADMINS_ID engineering=$ENG_ID platform=$PLAT_ID"

# Create alice (admins + engineering)
echo "Creating alice..."
curl -s -X POST "$KC_URL/admin/realms/headscale/users" \
    -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
    -d '{"username":"alice","email":"alice@headscale.local","enabled":true,"emailVerified":true}' || true
ALICE_ID=$(curl -s "$KC_URL/admin/realms/headscale/users?username=alice" -H "Authorization: Bearer $TOKEN" | jq -r '.[0].id')
curl -s -X PUT "$KC_URL/admin/realms/headscale/users/$ALICE_ID/reset-password" \
    -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
    -d '{"type":"password","value":"alice123","temporary":false}' || true
curl -s -X POST "$KC_URL/admin/realms/headscale/users/$ALICE_ID/groups/$ADMINS_ID" -H "Authorization: Bearer $TOKEN" -o /dev/null || true
curl -s -X POST "$KC_URL/admin/realms/headscale/users/$ALICE_ID/groups/$ENG_ID" -H "Authorization: Bearer $TOKEN" -o /dev/null || true

# Create bob (engineering only)
echo "Creating bob..."
curl -s -X POST "$KC_URL/admin/realms/headscale/users" \
    -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
    -d '{"username":"bob","email":"bob@headscale.local","enabled":true,"emailVerified":true}' || true
BOB_ID=$(curl -s "$KC_URL/admin/realms/headscale/users?username=bob" -H "Authorization: Bearer $TOKEN" | jq -r '.[0].id')
curl -s -X PUT "$KC_URL/admin/realms/headscale/users/$BOB_ID/reset-password" \
    -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
    -d '{"type":"password","value":"bob123","temporary":false}' || true
curl -s -X POST "$KC_URL/admin/realms/headscale/users/$BOB_ID/groups/$ENG_ID" -H "Authorization: Bearer $TOKEN" -o /dev/null || true

# Create charlie (platform only)
echo "Creating charlie..."
curl -s -X POST "$KC_URL/admin/realms/headscale/users" \
    -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
    -d '{"username":"charlie","email":"charlie@headscale.local","enabled":true,"emailVerified":true}' || true
CHARLIE_ID=$(curl -s "$KC_URL/admin/realms/headscale/users?username=charlie" -H "Authorization: Bearer $TOKEN" | jq -r '.[0].id')
curl -s -X PUT "$KC_URL/admin/realms/headscale/users/$CHARLIE_ID/reset-password" \
    -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
    -d '{"type":"password","value":"charlie123","temporary":false}' || true
curl -s -X POST "$KC_URL/admin/realms/headscale/users/$CHARLIE_ID/groups/$PLAT_ID" -H "Authorization: Bearer $TOKEN" -o /dev/null || true

echo ""
echo "=== Keycloak Init Complete ==="
echo "Users: alice(admins+engineering), bob(engineering), charlie(platform)"
echo "OIDC: $KC_URL/realms/headscale"
