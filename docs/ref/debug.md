# Debugging and troubleshooting

Headscale and Tailscale provide debug and introspection capabilities that can be helpful when things don't work as
expected. This page explains some debugging techniques to help pinpoint problems.

Please also have a look at [Tailscale's Troubleshooting guide](https://tailscale.com/kb/1023/troubleshooting). It offers
a many tips and suggestions to troubleshoot common issues.

## Tailscale

The Tailscale client itself offers many commands to introspect its state as well as the state of the network:

- [Check local network conditions](https://tailscale.com/kb/1080/cli#netcheck): `tailscale netcheck`
- [Get the client status](https://tailscale.com/kb/1080/cli#status): `tailscale status --json`
- [Get DNS status](https://tailscale.com/kb/1080/cli#dns): `tailscale dns status --all`
- Client logs: `tailscale debug daemon-logs`
- Client netmap: `tailscale debug netmap`
- Test DERP connection: `tailscale debug derp headscale`
- And many more, see: `tailscale debug --help`

Many of the commands are helpful when trying to understand differences between Headscale and Tailscale SaaS.

## Headscale

### Application logging

The log levels `debug` and `trace` can be useful to get more information from Headscale.

```yaml hl_lines="3"
log:
  # Valid log levels: panic, fatal, error, warn, info, debug, trace
  level: debug
```

### Database logging

The database debug mode logs all database queries. Enable it to see how Headscale interacts with its database. This also
requires the application log level to be set to either `debug` or `trace`.

```yaml hl_lines="3 7"
database:
  # Enable debug mode. This setting requires the log.level to be set to "debug" or "trace".
  debug: false

log:
  # Valid log levels: panic, fatal, error, warn, info, debug, trace
  level: debug
```

### Metrics and debug endpoint

Headscale provides a metrics and debug endpoint. It allows to introspect different aspects such as:

- Information about the Go runtime, memory usage and statistics
- Connected nodes and pending registrations
- Active ACLs, filters and SSH policy
- Current DERPMap
- Prometheus metrics

!!! warning "Keep the metrics and debug endpoint private"

    The listen address and port can be configured with the `metrics_listen_addr` variable in the [configuration
    file](./configuration.md). By default it listens on localhost, port 9090.

    Keep the metrics and debug endpoint private to your internal network and don't expose it to the Internet.

Query metrics via <http://localhost:9090/metrics> and get an overview of available debug information via
<http://localhost:9090/debug/>. Metrics may be queried from outside localhost but the debug interface is subject to
additional protection despite listening on all interfaces.

=== "Direct access"

    Access the debug interface directly on the server where Headscale is installed.

    ```console
    curl http://localhost:9090/debug/
    ```

=== "SSH port forwarding"

    Use SSH port forwarding to forward Headscale's metrics and debug port to your device.

    ```console
    ssh <HEADSCALE_SERVER> -L 9090:localhost:9090
    ```

    Access the debug interface on your device by opening <http://localhost:9090/debug/> in your web browser.

=== "Via debug key"

    The access control of the debug interface supports the use of a debug key. Traffic is accepted if the path to a
    debug key is set via the environment variable `TS_DEBUG_KEY_PATH` and the debug key sent as value for `debugkey`
    parameter with each request.

    ```console
    openssl rand -hex 32 | tee debugkey.txt
    export TS_DEBUG_KEY_PATH=debugkey.txt
    headscale serve
    ```

    Access the debug interface on your device by opening `http://<IP_OF_HEADSCALE>:9090/debug/?debugkey=<DEBUG_KEY>` in
    your web browser. The `debugkey` parameter must be sent with every request.

=== "Via debug IP address"

    The debug endpoint expects traffic from localhost. A different debug IP address may be configured by setting the
    `TS_ALLOW_DEBUG_IP` environment variable before starting Headscale. The debug IP address is ignored when the HTTP
    header `X-Forwarded-For` is present.

    ```console
    export TS_ALLOW_DEBUG_IP=192.168.0.10       # IP address of your device
    headscale serve
    ```

    Access the debug interface on your device by opening `http://<IP_OF_HEADSCALE>:9090/debug/` in your web browser.
