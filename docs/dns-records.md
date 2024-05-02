# Setting custom DNS records

!!! warning "Community documentation"

    This page is not actively maintained by the headscale authors and is
    written by community members. It is _not_ verified by `headscale` developers.

    **It might be outdated and it might miss necessary steps**.

## Goal

This documentation has the goal of showing how a user can set custom DNS records with `headscale`s magic dns.
An example use case is to serve apps on the same host via a reverse proxy like NGINX, in this case a Prometheus monitoring stack. This allows to nicely access the service with "http://grafana.myvpn.example.com" instead of the hostname and portnum combination "http://hostname-in-magic-dns.myvpn.example.com:3000".

## Setup

### 1. Change the configuration

1. Change the `config.yaml` to contain the desired records like so:

    ```yaml
    dns_config:
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

1. Restart your headscale instance.

    !!! warning

        Beware of the limitations listed later on!

### 2. Verify that the records are set

You can use a DNS querying tool of your choice on one of your hosts to verify that your newly set records are actually available in MagicDNS, here we used [`dig`](https://man.archlinux.org/man/dig.1.en):

```
$ dig grafana.myvpn.example.com

; <<>> DiG 9.18.10 <<>> grafana.myvpn.example.com
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 44054
;; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 65494
;; QUESTION SECTION:
;grafana.myvpn.example.com.         IN      A

;; ANSWER SECTION:
grafana.myvpn.example.com.  593     IN      A       100.64.0.3

;; Query time: 0 msec
;; SERVER: 127.0.0.53#53(127.0.0.53) (UDP)
;; WHEN: Sat Dec 31 11:46:55 CET 2022
;; MSG SIZE  rcvd: 66
```

### 3. Optional: Setup the reverse proxy

The motivating example here was to be able to access internal monitoring services on the same host without specifying a port:

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

## Limitations

[Not all types of records are supported](https://github.com/tailscale/tailscale/blob/6edf357b96b28ee1be659a70232c0135b2ffedfd/ipn/ipnlocal/local.go#L2989-L3007), especially no CNAME records.
