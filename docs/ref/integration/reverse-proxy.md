# Running Headscale behind a reverse proxy

!!! warning "Community documentation"

    This page is not actively maintained by the Headscale authors and is
    written by community members. It is _not_ verified by Headscale developers.

    **It might be outdated and it might miss necessary steps**.

Running Headscale behind a reverse proxy is useful when running multiple applications on the same server, and you want
to reuse the same external IP and port - usually tcp/443 for HTTPS.

Please see [limitations](#limitations) for known issues and limitations.

## Configuration

The configuration depends on the set of Headscale features you intend to use. Please have a look at the
[requirements](../../setup/requirements.md) and especially the [ports in use](../../setup/requirements.md#ports-in-use)
section to learn what a Tailscale clients expects.

The configuration examples in this documentation are basic and cover only HTTP and HTTPS traffic. Other features such as
STUN for Headscale's [embedded DERP server](../derp.md) are expected to be exposed directly or to be only available on
localhost.

### WebSocket

Tailscale clients are using a custom protocol (Tailscale Control Protocol) to communicate with a control server such as
Headscale. The reverse proxy **must** be configured to support WebSockets in order to communicate with Tailscale clients
and it needs to handle two peculiarities of the Tailscale Control Protocol:

- The POST method is used to upgrade the WebSocket connection.
- The value for the `Upgrade` header is `tailscale-control-protocol`.

### TLS

Headscale can be configured not to use TLS, leaving it to the reverse proxy to handle. Add the following configuration
values to your Headscale [configuration file](../configuration.md):

```yaml title="config.yaml" hl_lines="1"
server_url: https://<SERVER_NAME>
tls_cert_path: ""
tls_key_path: ""
```

Headscale logs `WRN listening without TLS but ServerURL does not start with http://` during startup. This is expected
and indicates that the reverse proxy is in charge of terminating TLS.

### Trusted proxies

Headscale ignores `True-Client-IP`, `X-Real-IP` and `X-Forwarded-For` headers unless the request's TCP peer matches the
`trusted_proxies` configuration option. Set this to the CIDR(s) your reverse proxy connects from so the real client IP
appears in access logs.

```yaml title="config.yaml"
trusted_proxies:
  - 127.0.0.1/32
  - ::1/128
```

The reverse proxy is responsible to replace any client-supplied `True-Client-IP`, `X-Real-IP`, `X-Forwarded-For` headers
on inbound requests with sanitized values. Headscale picks the first valid IP address supplied by headers in this order:

- `True-Client-IP`
- `X-Real-IP`
- `X-Forwarded-For`

## Limitations

- A reverse proxy adds another layer of complexity that needs to be able to handle the [Tailscale Control
  Protocol](#websocket) properly. Be sure to test your setup without a reverse proxy before raising an issue.
- STUN (used along with the [embedded DERP server](../derp.md)) requires udp/3478 to be served publicly.

## Reverse proxy specific configuration

!!! warning "Third-party software and services"

    This section of the documentation is specific for third-party software and services. We recommend users read the
    third-party documentation for a secure configuration.

This following Headscale configuration may be used as base for the various reverse proxy examples below. The following
is [assumed](../../setup/requirements.md):

- Service for Tailscale clients is served via HTTPS on port 443.
- The reverse proxy redirects HTTP to HTTPS and is terminating TLS.
- Both Headscale and the reverse proxy are running on the same host.
- [Metrics](../debug.md#metrics-and-debug-endpoint) are not proxied, those are available via localhost.

```yaml title="config.yaml" hl_lines="1"
server_url: https://<SERVER_NAME>
listen_addr: 127.0.0.1:8080
metrics_listen_addr: 127.0.0.1:9090
trusted_proxies:
  - 127.0.0.1/32
  - ::1/128
tls_cert_path: ""
tls_key_path: ""
```

### Apache

The following basic Apache configuration works with the Headscale configuration [as shown
above](#reverse-proxy-specific-configuration). Substitute placeholders and adjust the configuration as needed:

- `<SERVER_NAME>`: The server name for your instance, e.g. `headscale.example.com`
- `<PATH_TO_TLS_CERT>`: Absolute path to your TLS certificate
- `<PATH_TO_TLS_KEY>`: Absolute path to your TLS private key

```apache title="apache.conf" hl_lines="2 7 11 14-15"
<VirtualHost *:80>
  ServerName <SERVER_NAME>

  # Tailscale captive portal detection
  RedirectMatch 204 ^/generate_204$

  RedirectMatch permanent "^/(.*)$" "https://<SERVER_NAME>/$1"
</VirtualHost>

<VirtualHost *:443>
  ServerName <SERVER_NAME>

  SSLEngine On
  SSLCertificateFile <PATH_TO_TLS_CERT>
  SSLCertificateKeyFile <PATH_TO_TLS_KEY>

  RequestHeader set True-Client-IP "%{REMOTE_ADDR}s"
  RequestHeader set X-Real-IP "%{REMOTE_ADDR}s"

  ProxyPreserveHost On
  ProxyPass / http://127.0.0.1:8080/ upgrade=any
</VirtualHost>
```

Note that `upgrade=any` is required as a parameter for `ProxyPass` so that WebSocket traffic whose `Upgrade` header
value is not equal to `WebSocket` (i. e. Tailscale Control Protocol) is forwarded correctly. See the [Apache
docs](https://httpd.apache.org/docs/current/mod/mod_proxy.html#upgrade) for more information on this.

### Caddy

The following basic Caddyfile works with the Headscale configuration [as shown
above](#reverse-proxy-specific-configuration). Substitute placeholders and adjust the configuration as needed:

- `<SERVER_NAME>`: The server name for your instance, e.g. `headscale.example.com`

```none title="Caddyfile" hl_lines="1 12"
http://<SERVER_NAME> {
	# Tailscale captive portal detection
	handle /generate_204 {
		respond 204
	}

	handle * {
		redir https://{host}{uri}
	}
}

<SERVER_NAME> {
	reverse_proxy 127.0.0.1:8080 {
		header_up True-Client-IP {remote_host}
		header_up X-Real-IP {remote_host}
	}
}
```

Caddy will [automatically](https://caddyserver.com/docs/automatic-https) provision a certificate for your
domain/subdomain, force HTTPS, and proxy WebSocket connections.

### Cloudflare

Running Headscale behind a Cloudflare Proxy or Cloudflare Tunnel is not supported and will not work as Cloudflare does
not support [WebSocket POSTs as required by the Tailscale protocol](#websocket). See [issue
1468](https://github.com/juanfont/headscale/issues/1468) for more information.

### Envoy

You need to add a new upgrade_type named `tailscale-control-protocol`. [See
details](https://www.envoyproxy.io/docs/envoy/latest/api-v3/extensions/filters/network/http_connection_manager/v3/http_connection_manager.proto#extensions-filters-network-http-connection-manager-v3-httpconnectionmanager-upgradeconfig).

### Istio

Same as [envoy](#envoy), we can use `EnvoyFilter` to add a new upgrade_type named `tailscale-control-protocol`.

```yaml
apiVersion: networking.istio.io/v1alpha3
kind: EnvoyFilter
metadata:
  name: headscale-behind-istio-ingress
  namespace: istio-system
spec:
  configPatches:
    - applyTo: NETWORK_FILTER
      match:
        listener:
          filterChain:
            filter:
              name: envoy.filters.network.http_connection_manager
      patch:
        operation: MERGE
        value:
          typed_config:
            "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
            upgrade_configs:
              - upgrade_type: tailscale-control-protocol
```

### Nginx

The following basic Nginx configuration works with the Headscale configuration [as shown
above](#reverse-proxy-specific-configuration). Substitute placeholders and adjust the configuration as needed:

- `<SERVER_NAME>`: The server name for your instance, e.g. `headscale.example.com`
- `<PATH_TO_TLS_CERT>`: Absolute path to your TLS certificate
- `<PATH_TO_TLS_KEY>`: Absolute path to your TLS private key

```nginx title="nginx.conf" hl_lines="19 37 39-40"
# headscale
upstream headscale {
  zone upstreams 64K;
  server 127.0.0.1:8080 max_fails=1 fail_timeout=5s;
  keepalive 2;
}

# websocket
map $http_upgrade $connection_upgrade {
  default keep-alive;
  ''      close;
}

# http
server {
  listen 80;
  listen [::]:80;

  server_name <SERVER_NAME>;

  # Tailscale captive portal detection
  location = /generate_204 {
    return 204;
  }

  location / {
    return 301 https://$server_name$request_uri;
  }
}

# https
server {
  listen 443 ssl;
  listen [::]:443 ssl;
  http2 on;

  server_name <SERVER_NAME>;

  ssl_certificate <PATH_TO_TLS_CERT>;
  ssl_certificate_key <PATH_TO_TLS_KEY>;

  location / {
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection $connection_upgrade;
    proxy_set_header Host $host;
    proxy_set_header True-Client-IP $remote_addr;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_buffering off;
    proxy_pass http://headscale;
  }
}
```
