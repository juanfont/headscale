# DNS

Headscale 支持来自 Tailscale 的 [大多数 DNS 功能](../about/features.md)。与 DNS 相关的设置可以在 [配置文件](configuration.md) 的 `dns` 部分进行配置。

## 设置额外的 DNS 记录

Headscale 允许设置额外的 DNS 记录，这些记录可以通过 [MagicDNS](https://tailscale.com/kb/1081/magicdns) 提供。额外的 DNS 记录可以通过配置文件中的静态条目或 Headscale 持续监视其更改的 JSON 文件进行配置：

* 使用 [配置文件](configuration.md) 中的 `dns.extra_records` 选项来添加静态条目，这些条目在 Headscale 运行期间不会更改。这些条目在 Headscale 启动时处理，配置的更改需要重启 Headscale。
* 对于在 Headscale 运行期间可能添加、更新或删除的动态 DNS 记录，或者由脚本生成的 DNS 记录，使用 [配置文件](configuration.md) 中的 `dns.extra_records_path` 选项。将其设置为包含 DNS 记录的 JSON 文件的绝对路径，Headscale 会在检测到更改时处理该文件。

一个示例用例是通过 NGINX 等反向代理在同一主机上服务多个应用，这里以 Prometheus 监控堆栈为例。这样可以通过 "http://grafana.myvpn.example.com" 优雅地访问服务，而不是使用 "http://hostname-in-magic-dns.myvpn.example.com:3000" 的主机名和端口组合。

!!! warning "限制"

当前，Tailscale [仅处理 A 和 AAAA 记录](https://github.com/tailscale/tailscale/blob/v1.78.3/ipn/ipnlocal/local.go#L4461-L4479)。

1. 使用可用的配置选项配置额外的 DNS 记录：

=== "静态条目，通过 `dns.extra_records`"

```yaml title="config.yaml"
dns:
 ...
 extra_records:
 - name: "grafana.myvpn.example.com"
   type: "A"
   value: "100.64.0.3"

 - name: "prometheus.myvpn.example.com"
   type: "A"
   value: "100.64.0.3"
 ...
```

重启您的 Headscale 实例。

=== "动态条目，通过 `dns.extra_records_path`"

```json title="extra-records.json"
[
 {
   "name": "grafana.myvpn.example.com",
   "type": "A",
   "value": "100.64.0.3"
 },
 {
   "name": "prometheus.myvpn.example.com",
   "type": "A",
   "value": "100.64.0.3"
 }
]
```

Headscale 会自动获取上述 JSON 文件的更改。

!!! tip "注意事项"

* [配置文件](./configuration.md) 中的 `dns.extra_records_path` 选项需要引用包含额外 DNS 记录的 JSON 文件。
* 如果您使用脚本生成 JSON 文件，请确保“排序键”并生成稳定输出。Headscale 使用校验和来检测文件的更改，而稳定的输出可以避免不必要的处理。

1. 使用您选择的 DNS 查询工具验证 DNS 记录是否正确设置：

=== "使用 dig 查询"

```shell
dig +short grafana.myvpn.example.com
100.64.0.3
```

=== "使用 drill 查询"

```shell
drill -Q grafana.myvpn.example.com
100.64.0.3
```

1. 可选：设置反向代理

这里的一个主要示例是能够访问同一主机上的内部监控服务，而不需要指定端口，下面是 NGINX 配置片段：

```nginx title="nginx.conf"
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