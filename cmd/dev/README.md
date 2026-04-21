# cmd/dev -- Local Development Environment

Starts a headscale server on localhost with a pre-created user and
pre-auth key. Pair with `mts` to add real tailscale nodes.

## Quick start

```bash
# Terminal 1: start headscale
go run ./cmd/dev

# Terminal 2: start mts server
go tool mts server run

# Terminal 3: add and connect nodes
go tool mts server add node1
go tool mts server add node2

# Disable logtail (avoids startup delays, see "Known issues" below)
for n in node1 node2; do
  cat > ~/.config/multi-tailscale-dev/$n/env.txt << 'EOF'
TS_NO_LOGS_NO_SUPPORT=true
EOF
done

# Restart nodes so env.txt takes effect
go tool mts server stop node1 && go tool mts server start node1
go tool mts server stop node2 && go tool mts server start node2

# Connect to headscale (use the auth key printed by cmd/dev)
go tool mts node1 up --login-server=http://127.0.0.1:8080 --authkey=<KEY> --reset
go tool mts node2 up --login-server=http://127.0.0.1:8080 --authkey=<KEY> --reset

# Verify
go tool mts node1 status
```

## Flags

| Flag     | Default | Description                  |
| -------- | ------- | ---------------------------- |
| `--port` | 8080    | Headscale listen port        |
| `--keep` | false   | Keep state directory on exit |

The metrics/debug port is `port + 1010` (default 9090) and the gRPC
port is `port + 42363` (default 50443).

## What it does

1. Builds the headscale binary into a temp directory
2. Writes a minimal dev config (SQLite, public DERP, debug logging)
3. Starts `headscale serve` as a subprocess
4. Creates a "dev" user and a reusable 24h pre-auth key via the CLI
5. Prints a banner with server URL, auth key, and usage instructions
6. Blocks until Ctrl+C, then kills headscale

State lives in `/tmp/headscale-dev-*/`. Pass `--keep` to preserve it
across restarts (useful for inspecting the database or reusing keys).

## Useful endpoints

- `http://127.0.0.1:8080/health` -- health check
- `http://127.0.0.1:9090/debug/ping` -- interactive ping UI
- `http://127.0.0.1:9090/debug/ping?node=1` -- quick-ping a node
- `POST http://127.0.0.1:9090/debug/ping` with `node=<id>` -- trigger ping

## Managing headscale

The banner prints the full path to the built binary and config. Use it
for any headscale CLI command:

```bash
/tmp/headscale-dev-*/headscale -c /tmp/headscale-dev-*/config.yaml nodes list
/tmp/headscale-dev-*/headscale -c /tmp/headscale-dev-*/config.yaml users list
```

## Known issues

### Logtail delays on mts nodes

Freshly created `mts` instances may take 30+ seconds to start if
`~/.local/share/tailscale/` contains stale logtail cache from previous
tailscaled runs. The daemon blocks trying to upload old logs before
creating its socket.

Fix: write `TS_NO_LOGS_NO_SUPPORT=true` to each instance's `env.txt`
before starting (or restart after writing). See the quick start above.

### mts node cleanup

`mts` stores state in `~/.config/multi-tailscale-dev/`. Old instances
accumulate over time. Clean them with:

```bash
go tool mts server rm <name>
```
