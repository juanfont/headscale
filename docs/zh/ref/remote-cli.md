# 使用远程 CLI 控制 Headscale

本文件旨在向用户展示如何通过 `headscale` 命令行工具从远程计算机控制 Headscale 实例。

## 前提条件

- 一台用于运行 `headscale` 的工作站（任何支持的平台，例如 Linux）。
- 一台启用 gRPC 的 Headscale 服务器。
- 允许连接到 gRPC 端口（默认：`50443`）。
- 远程访问要求通过 TLS 加密连接。
- 一个 API 密钥用于与 Headscale 服务器进行身份验证。

## 创建 API 密钥

我们需要创建一个 API 密钥，以便在从工作站使用远程 Headscale 服务器时进行身份验证。

要创建 API 密钥，请登录到您的 Headscale 服务器并生成一个密钥：

```shell
headscale apikeys create --expiration 90d
```

复制命令的输出并为稍后保存。请注意，密钥一旦丢失无法再次检索，您需要使旧的密钥失效，并创建新的密钥。

要列出当前与服务器关联的密钥，请使用：

```shell
headscale apikeys list
```

要使密钥失效：

```shell
headscale apikeys expire --prefix "<PREFIX>"
```

## 下载并配置 Headscale

1. 从 [GitHub 的发布页面](https://github.com/juanfont/headscale/releases) 下载 [`headscale` 二进制文件](https://github.com/juanfont/headscale/releases)。确保版本与服务器上的相同。

2. 将二进制文件放在您的 `PATH` 中，例如 `/usr/local/bin/headscale`。

3. 使 `headscale` 可执行：

```shell
chmod +x /usr/local/bin/headscale
```

4. 通过一个最小的 YAML 配置文件或环境变量提供远程 Headscale 服务器的连接参数：

=== "最小 YAML 配置文件"

```yaml title="config.yaml"
cli:
  address: <HEADSCALE_ADDRESS>:<PORT>
  api_key: <API_KEY_FROM_PREVIOUS_STEP>
```

=== "环境变量"

```shell
export HEADSCALE_CLI_ADDRESS="<HEADSCALE_ADDRESS>:<PORT>"
export HEADSCALE_CLI_API_KEY="<API_KEY_FROM_PREVIOUS_STEP>"
```

!!! bug

Headscale 目前需要至少有一个空的配置文件才能使用环境变量指定连接详细信息。请参见 [第2193号问题](https://github.com/juanfont/headscale/issues/2193) 了解更多信息。

这将指示 `headscale` 二进制文件连接到位于 `<HEADSCALE_ADDRESS>:<PORT>` 的远程实例，而不是连接到本地实例。

5. 测试连接

让我们运行 Headscale 命令来验证我们是否能够通过列出节点来进行连接：

```shell
headscale nodes list
```

您现在应该能够从工作站看到节点列表，并可以从您的工作站控制 Headscale 服务器。

## 通过代理

可以在反向代理后运行 gRPC 远程端点，比如 Nginx，并让它运行在与 Headscale 相同的端口上。

虽然这不是一个受支持的功能，但 [这上面有一个在 NixOS 上如何设置的示例](https://github.com/kradalby/dotfiles/blob/4489cdbb19cddfbfae82cd70448a38fde5a76711/machines/headscale.oracldn/headscale.nix#L61-L91)。

## 故障排除

- 确保服务器和工作站上运行的 Headscale 版本相同。
- 确保允许连接到 gRPC 端口。
- 验证您的 TLS 证书是否有效且受信任。
- 如果您没有访问受信任证书的权限（例如 Let's Encrypt 的证书），请：
  - 将您的自签名证书添加到操作系统的信任存储中 _或_
  - 通过在配置文件中设置 `cli.insecure: true` 或通过设置环境变量 `HEADSCALE_CLI_INSECURE=1` 禁用证书验证。我们**不**推荐禁用证书验证。