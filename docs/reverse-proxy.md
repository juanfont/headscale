# Running behind a reverse proxy

Running Headscale behind a reverse proxy is suitable for container-based deployments. This is especially useful on a server were port 443 is already being used for other web services.

Headscale can be configured not to use TLS, leaving it to the reverse proxy to handle. Add the following configuration values to your headscale config file.

```yaml
server_url: https://<YOUR_SERVER_NAME> # This should be the FQDN at which headscale will be served
listen_addr: 0.0.0.0:8080
metrics_listen_addr: 0.0.0.0:9090
tls_cert_path: ""
tls_key_path: ""
```

## nginx
The following example configuration can be used in your nginx setup, substituting values as necessary. `<IP:PORT>` should be the IP address and port where headscale is running. In most cases, this will be `http://localhost:8080`.

```Nginx
server {
    listen 80;
	listen [::]:80;

	listen 443      ssl http2;
	listen [::]:443 ssl http2;

    server_name <YOUR_SERVER_NAME>;

    ssl_certificate <PATH_TO_CERT>;
    ssl_certificate_key <PATH_CERT_KEY>;
    ssl_protocols TLSv1.2 TLSv1.3;

    map $http_upgrade $connection_upgrade { 
        default      keep-alive;
        'websocket'  upgrade; 
        ''           close;
    }

    location / {
        proxy_pass http://<IP:PORT>;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection $connection_upgrade;
        proxy_set_header Host $server_name;
        proxy_redirect http:// https://;
        proxy_buffering off;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $http_x_forwarded_proto;
        add_header Strict-Transport-Security "max-age=15552000; includeSubDomains" always;
    }
}
```
