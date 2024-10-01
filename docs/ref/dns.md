# DNS

Headscale supports [most DNS features](../about/features.md) from Tailscale and DNS releated settings can be configured
in the [configuration file](./configuration.md) within the `dns` section.

## Setting custom DNS records

!!! warning "Community documentation"

    This page is not actively maintained by the headscale authors and is
    written by community members. It is _not_ verified by `headscale` developers.

    **It might be outdated and it might miss necessary steps**.

Headscale allows to set custom DNS records which are made available via
[MagicDNS](https://tailscale.com/kb/1081/magicdns). An example use case is to serve multiple apps on the same host via a
reverse proxy like NGINX, in this case a Prometheus monitoring stack. This allows to nicely access the service with
"http://grafana.myvpn.example.com" instead of the hostname and port combination
"http://hostname-in-magic-dns.myvpn.example.com:3000".

!!! warning "Limitations"

    [Not all types of records are supported](https://github.com/tailscale/tailscale/blob/6edf357b96b28ee1be659a70232c0135b2ffedfd/ipn/ipnlocal/local.go#L2989-L3007), especially no CNAME records.

1.  Update the [configuration file](./configuration.md) to contain the desired records like so:

    ```yaml
    dns:
      ...
      extra_records:
        - name: "prometheus.myvpn.example.com"
          type: "A"
          value: "100.64.0.3"

        - name: "grafana.myvpn.example.com"
          type: "A"
          value: "100.64.0.3"
      ...
    ```

1.  Restart your headscale instance.

1.  Verify that DNS records are properly set using the DNS querying tool of your choice:

    === "Query with dig"

        ```shell
        dig +short grafana.myvpn.example.com
        100.64.0.3
        ```

    === "Query with drill"

        ```shell
        drill -Q grafana.myvpn.example.com
        100.64.0.3
        ```

1.  Optional: Setup the reverse proxy

    The motivating example here was to be able to access internal monitoring services on the same host without
    specifying a port, depicted as NGINX configuration snippet:

    ```
    server {
        listen 80;
        listen [::]:80;

        server_name grafana.myvpn.example.com;

        location / {
            proxy_pass http://localhost:3000;
            proxy_set_header Host $http_host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
        }

    }
    ```
