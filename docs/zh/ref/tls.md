# 通过 TLS 运行服务（可选）

## 自带证书

Headscale 可以配置通过 TLS 暴露其网络服务。要手动配置证书和密钥文件，请设置 `tls_cert_path` 和 `tls_key_path` 配置参数。如果路径是相对的，它将被解释为相对于读取配置文件的目录。

```yaml title="config.yaml"
tls_cert_path: ""
tls_key_path: ""
```

证书应包含完整的链，否则某些客户端（如 Tailscale Android 客户端）将拒绝它。

## Let's Encrypt / ACME

要通过 [Let's Encrypt](https://letsencrypt.org/) 自动获取证书，请将 `tls_letsencrypt_hostname` 设置为所需的证书主机名。此名称必须解析到 Headscale 可访问的 IP 地址（即，它必须与 `server_url` 配置参数相对应）。证书和 Let's Encrypt 账户凭据将存储在 `tls_letsencrypt_cache_dir` 中配置的目录中。如果路径是相对的，它将被解释为相对于读取配置文件的目录。

```yaml title="config.yaml"
tls_letsencrypt_hostname: ""
tls_letsencrypt_listen: ":http"
tls_letsencrypt_cache_dir: ".cache"
tls_letsencrypt_challenge_type: HTTP-01
```

### 挑战类型

Headscale 仅支持两种值作为 `tls_letsencrypt_challenge_type`：`HTTP-01`（默认）和 `TLS-ALPN-01`。

#### HTTP-01

对于 `HTTP-01`，Headscale 必须在端口 80 上可访问，以便进行 Let's Encrypt 的自动验证，此外，还要配置在 `listen_addr` 中的端口。默认情况下，Headscale 在所有本地 IP 的端口 80 上监听，以进行 Let's Encrypt 的自动验证。

如果您需要更改 Headscale 用于 Let's Encrypt 验证过程的 IP 和/或端口，请将 `tls_letsencrypt_listen` 设置为适当的值。这在您以非 root 用户身份运行 Headscale（或无法运行 `setcap`）时很有用。然而，请记住，Let's Encrypt **仅**会连接到端口 80 进行验证回调，因此如果您更改了 `tls_letsencrypt_listen`，您还需要配置其他东西（例如防火墙规则）来将流量从端口 80 转发到 `tls_letsencrypt_listen` 中指定的 ip:port 组合。

#### TLS-ALPN-01

对于 `TLS-ALPN-01`，Headscale 在 `listen_addr` 中定义的 ip:port 组合上监听。Let's Encrypt **仅**会在端口 443 上连接以进行验证回调，因此如果 `listen_addr` 没有设置为端口 443，则需要其他配置（例如防火墙规则）以将流量从端口 443 转发到在 `listen_addr` 中指定的 ip:port 组合。

### 技术描述

Headscale 使用 [autocert](https://pkg.go.dev/golang.org/x/crypto/acme/autocert)库，提供 [ACME 协议](https://en.wikipedia.org/wiki/Automatic_Certificate_Management_Environment) 验证，以 facilitar通过 [Let's Encrypt](https://letsencrypt.org/about/) 自动续订证书。证书将自动续订，您可以期待以下结果：

- Let’s Encrypt 提供的证书自签发之日起有效期为 3 个月。
- 只有当证书的有效期剩余 30 天或更少时，Headscale 才会尝试续订。
- `autocert` 的续订尝试将在 30-60 分钟的随机间隔内触发。
- 跳过续订或续订成功时不会生成日志输出。

#### 检查证书过期

如果您想验证证书续订是否成功，可以手动检查，或通过外部监控软件进行监控。这是手动执行的两个示例：

1. 在您喜欢的浏览器中打开 Headscale 服务器的 URL，并手动检查收到的证书的过期日期。
2. 或者，通过 CLI 使用 `openssl` 远程检查：

```bash
$ openssl s_client -servername [hostname] -connect [hostname]:443 | openssl x509 -noout -dates
(...)
notBefore=2024年2月8日 09:48:26 GMT
notAfter=2024年5月8日 09:48:25 GMT
```

#### autocert 库的日志输出

由于这些日志行来自 autocert 库，所以并非严格由 Headscale 本身生成。

```plaintext
acme/autocert: missing server name
```

可能是由于一个未指定主机名的传入连接引起的，例如直接针对服务器 IP 的 `curl` 请求，或意外的主机名。

```plaintext
acme/autocert: host "[foo]" not configured in HostWhitelist
```

类似于上面的情况，这可能表示对错误主机名的无效传入请求，通常是仅使用 IP 本身。

autocert 的源代码可以在 [这里](https://cs.opensource.google/go/x/crypto/+/refs/tags/v0.19.0:acme/autocert/autocert.go) 找到。
