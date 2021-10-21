# Running the service via TLS (optional)

```yaml
tls_letsencrypt_hostname: ""
tls_letsencrypt_listen: ":http"
tls_letsencrypt_cache_dir: ".cache"
tls_letsencrypt_challenge_type: HTTP-01
```

To get a certificate automatically via [Let's Encrypt](https://letsencrypt.org/), set `tls_letsencrypt_hostname` to the desired certificate hostname. This name must resolve to the IP address(es) headscale is reachable on (i.e., it must correspond to the `server_url` configuration parameter). The certificate and Let's Encrypt account credentials will be stored in the directory configured in `tls_letsencrypt_cache_dir`. If the path is relative, it will be interpreted as relative to the directory the configuration file was read from. The certificate will automatically be renewed as needed.

```yaml
tls_cert_path: ""
tls_key_path: ""
```

headscale can also be configured to expose its web service via TLS. To configure the certificate and key file manually, set the `tls_cert_path` and `tls_cert_path` configuration parameters. If the path is relative, it will be interpreted as relative to the directory the configuration file was read from.

## Challenge type HTTP-01

The default challenge type `HTTP-01` requires that headscale is reachable on port 80 for the Let's Encrypt automated validation, in addition to whatever port is configured in `listen_addr`. By default, headscale listens on port 80 on all local IPs for Let's Encrypt automated validation.

If you need to change the ip and/or port used by headscale for the Let's Encrypt validation process, set `tls_letsencrypt_listen` to the appropriate value. This can be handy if you are running headscale as a non-root user (or can't run `setcap`). Keep in mind, however, that Let's Encrypt will _only_ connect to port 80 for the validation callback, so if you change `tls_letsencrypt_listen` you will also need to configure something else (e.g. a firewall rule) to forward the traffic from port 80 to the ip:port combination specified in `tls_letsencrypt_listen`.

## Challenge type TLS-ALPN-01

Alternatively, `tls_letsencrypt_challenge_type` can be set to `TLS-ALPN-01`. In this configuration, headscale listens on the ip:port combination defined in `listen_addr`. Let's Encrypt will _only_ connect to port 443 for the validation callback, so if `listen_addr` is not set to port 443, something else (e.g. a firewall rule) will be required to forward the traffic from port 443 to the ip:port combination specified in `listen_addr`.
