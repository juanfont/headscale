# 入门指南

本页面将帮助你开始使用 Headscale，并提供一些 `headscale` 命令行工具的使用示例。

!!! note "前置条件"

*   Headscale 已安装并作为系统服务运行。请阅读 [设置部分](../setup/requirements.md) 获取安装说明。
*   配置文件已存在并已根据你的环境进行调整，详细信息请参阅 [配置](../ref/configuration.md)。
*   Headscale 可以从互联网访问。 通过在浏览器中打开特定于客户端的设置说明来验证这一点，例如 [headscale.example.com](https://headscale.example.com)/windows
*   已安装 Tailscale 客户端，更多信息请参阅 [客户端和操作系统支持](../about/clients.md)。

## 获取帮助

`headscale` 命令行工具提供了内置帮助。 要显示可用命令及其参数和选项，请运行：

=== "Native"

```shell
# 显示帮助
headscale help

# 显示特定命令的帮助
headscale <COMMAND> --help
```

=== "Container"

```shell
# 显示帮助
docker exec -it headscale \
headscale help

# 显示特定命令的帮助
docker exec -it headscale \
headscale <COMMAND> --help
```

## 管理 Headscale 用户

在 Headscale 中，节点（也称为机器或设备）始终分配给 Headscale 用户。 这样的 Headscale 用户可以拥有分配给他们的多个节点，并且可以使用 `headscale users` 命令进行管理。 调用内置帮助以获取更多信息：`headscale users --help`。

### 创建 Headscale 用户

=== "Native"

```shell
headscale users create <USER>
```

=== "Container"

```shell
docker exec -it headscale \
headscale users create <USER>
```

### 列出现有的 Headscale 用户

=== "Native"

```shell
headscale users list
```

=== "Container"

```shell
docker exec -it headscale \
headscale users list
```

## 注册节点

必须先注册节点，才能使用 Headscale 与 Tailscale 进行协调。 以下示例适用于 Linux/BSD 操作系统上的 Tailscale 客户端。 或者，按照说明连接 [Android](connect/android.md)、[Apple](connect/apple.md) 或 [Windows](connect/windows.md) 设备。

### 常规交互式登录

在客户端机器上，运行 `tailscale up` 命令，并将你的 Headscale 实例的 FQDN 作为参数提供：

```shell
tailscale up --login-server <YOUR_HEADSCALE_URL>
```

通常，会打开一个包含进一步说明的浏览器窗口，其中包含 `<YOUR_MACHINE_KEY>` 的值。 在你的 Headscale 服务器上批准并注册该节点：

=== "Native"

```shell
headscale nodes register --user <USER> --key <YOUR_MACHINE_KEY>
```

=== "Container"

```shell
docker exec -it headscale \
headscale nodes register --user <USER> --key <YOUR_MACHINE_KEY>
```

### 使用预授权密钥

也可以生成预授权密钥并以非交互方式注册节点。 首先，在 Headscale 实例上生成预授权密钥。 默认情况下，该密钥有效期为一个小时，并且只能使用一次（有关其他选项，请参阅 `headscale preauthkeys --help`）：

=== "Native"

```shell
headscale preauthkeys create --user <USER>
```

=== "Container"

```shell
docker exec -it headscale \
headscale preauthkeys create --user <USER>
```

该命令成功后会返回预授权密钥，该密钥用于通过 `tailscale up` 命令将节点连接到 Headscale 实例：

```shell
tailscale up --login-server <YOUR_HEADSCALE_URL> --authkey <YOUR_AUTH_KEY>
```
 