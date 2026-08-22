#!/bin/bash
# Test 4: CLI Commands

export HEADSCALE_URL="http://headscale-server:8080"
export HEADSCALE_API_KEY="$API_KEY"

test_cli_version() {
    local output
    output=$(headscale version 2>/dev/null)
    if [ $? -eq 0 ] && echo "$output" | grep -q "headscale"; then
        return 0
    fi
    return 1
}

test_cli_list_users() {
    local output
    output=$(headscale users list 2>/dev/null)
    if [ $? -eq 0 ] && echo "$output" | grep -q "alice"; then
        return 0
    fi
    return 1
}

test_cli_create_user() {
    local output
    output=$(headscale users create --name "dave" --email "dave@test.com" 2>/dev/null)
    if [ $? -eq 0 ]; then
        return 0
    fi
    return 1
}

test_cli_rename_user() {
    local users output
    users=$(headscale users list 2>/dev/null)
    dave_id=$(echo "$users" | grep "dave" | awk '{print $1}')
    
    if [ -n "$dave_id" ]; then
        output=$(headscale users rename "$dave_id" "david" 2>/dev/null)
        if [ $? -eq 0 ]; then
            return 0
        fi
    fi
    return 1
}

test_cli_list_nodes() {
    # Nodes list should work even if empty
    local output
    output=$(headscale nodes list 2>/dev/null)
    if [ $? -eq 0 ]; then
        return 0
    fi
    return 1
}

test_cli_preauth_keys() {
    local output
    # List users to get an ID
    local users
    users=$(headscale users list 2>/dev/null)
    alice_id=$(echo "$users" | grep "alice" | awk '{print $1}')
    
    if [ -n "$alice_id" ]; then
        output=$(headscale preauthkeys create --user "$alice_id" --reusable 2>/dev/null)
        if [ $? -eq 0 ]; then
            # List the keys
            output=$(headscale preauthkeys list --user "$alice_id" 2>/dev/null)
            if [ $? -eq 0 ]; then
                return 0
            fi
        fi
    fi
    return 1
}

test_cli_status() {
    local output
    output=$(headscale status 2>/dev/null)
    # Status should return something (even if no nodes connected)
    if [ $? -eq 0 ] || echo "$output" | grep -q "Daemon"; then
        return 0
    fi
    return 1
}

run_test "CLI Version" test_cli_version
run_test "CLI List Users" test_cli_list_users
run_test "CLI Create User" test_cli_create_user
run_test "CLI Rename User" test_cli_rename_user
run_test "CLI List Nodes" test_cli_list_nodes
run_test "CLI Preauth Keys" test_cli_preauth_keys
run_test "CLI Status" test_cli_status
