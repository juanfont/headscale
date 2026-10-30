# Running the service via TLS (optional)

## Bring your own certificate

Headscale can be configured to expose its web service via TLS. To configure the certificate and key file manually, set the `tls.cert_path` and `tls.key_path` configuration parameters. If the path is relative, it will be interpreted as relative to the directory the configuration file was read from.

```yaml title="config.yaml"
tls:
  cert_path: ""
  key_path: ""
```

The certificate should contain the full chain, else some clients, like the Tailscale Android client, will reject it.

### Reloading the certificate

Headscale reads the certificate and key again when it receives a SIGHUP signal, so a renewed certificate takes effect without a restart. Either reload Headscale via its systemd service (`sudo systemctl reload headscale`) or send the signal directly (`sudo kill -HUP $(pidof headscale)`). The same signal also [reloads the policy](policy.md). New connections get the new certificate; open connections stay as they are.

If the files cannot be loaded, or the certificate is expired or not yet valid, Headscale logs an error and keeps serving the previous certificate. `systemctl reload` reports success either way, because it only delivers the signal. Look for `TLS certificate reloaded` in the log, or [check the served certificate](#checking-certificate-expiry).

## Let's Encrypt / ACME

To get a certificate automatically via [Let's Encrypt](https://letsencrypt.org/), set `tls.acme.hostname` to the desired certificate hostname. This name must resolve to the IP address(es) headscale is reachable on (i.e., it must correspond to the `server_url` configuration parameter). The certificate and Let's Encrypt account credentials will be stored in the directory configured in `tls.acme.cache_dir`. If the path is relative, it will be interpreted as relative to the directory the configuration file was read from.

```yaml title="config.yaml"
tls:
  acme:
    hostname: ""
    http_listen: ":http"
    cache_dir: /var/lib/headscale/cache
    challenge_type: HTTP-01
```

### Challenge types

Headscale supports three values for `tls.acme.challenge_type`: `HTTP-01` (default), `TLS-ALPN-01` and `DNS-01`. `DNS-01` publishes the challenge through the DNS provider in `dns.challenge.provider`.

#### HTTP-01

For `HTTP-01`, headscale must be reachable on port 80 for the Let's Encrypt automated validation, in addition to whatever port is configured in `listen_addr`. By default, headscale listens on port 80 on all local IPs for Let's Encrypt automated validation.

!!! warning "`listen_addr` cannot also be port 80"

    `listen_addr` and `tls.acme.http_listen` must not bind the same TCP socket. A common mistake is setting `listen_addr: 0.0.0.0:80` together with `tls.acme.hostname` — both endpoints try to claim port 80, and the second bind fails with `address already in use` even though no other process is involved. Headscale validates this at startup and refuses to launch with a `Fatal config error: listen_addr and tls.acme.http_listen would bind the same TCP socket` message. Use `listen_addr: 0.0.0.0:443` (or any non-80 port) when HTTP-01 is enabled.

If you need to change the ip and/or port used by headscale for the Let's Encrypt validation process, set `tls.acme.http_listen` to the appropriate value. This can be handy if you are running headscale as a non-root user (or can't run `setcap`). Keep in mind, however, that Let's Encrypt will _only_ connect to port 80 for the validation callback, so if you change `tls.acme.http_listen` you will also need to configure something else (e.g. a firewall rule) to forward the traffic from port 80 to the ip:port combination specified in `tls.acme.http_listen`.

#### TLS-ALPN-01

For `TLS-ALPN-01`, headscale listens on the ip:port combination defined in `listen_addr`. Let's Encrypt will _only_ connect to port 443 for the validation callback, so if `listen_addr` is not set to port 443, something else (e.g. a firewall rule) will be required to forward the traffic from port 443 to the ip:port combination specified in `listen_addr`.

### Technical description

Headscale uses [CertMagic](https://github.com/caddyserver/certmagic), a Golang library providing [ACME protocol](https://en.wikipedia.org/wiki/Automatic_Certificate_Management_Environment) verification, to facilitate certificate renewals via [Let's Encrypt](https://letsencrypt.org/about/). Certificates will be renewed automatically, and the following can be expected:

- Certificates provided from Let's Encrypt have a validity of 3 months from date issued.
- Renewals start when a third of the validity remains.
- Renewal checks run every 10 minutes.
- Log lines from the library are logged with `logger=acme`.

#### Checking certificate expiry

If you want to validate that certificate renewal completed successfully, this can be done either manually, or through external monitoring software. Two examples of doing this manually:

1. Open the URL for your headscale server in your browser of choice, and manually inspecting the expiry date of the certificate you receive.
1. Or, check remotely from CLI using `openssl`:

```console
$ openssl s_client -servername [hostname] -connect [hostname]:443 | openssl x509 -noout -dates
(...)
notBefore=Feb  8 09:48:26 2024 GMT
notAfter=May  8 09:48:25 2024 GMT
```
