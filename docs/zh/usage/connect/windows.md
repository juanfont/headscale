# 连接 Windows 客户端

本文档旨在说明用户如何将官方 Windows [Tailscale](https://tailscale.com) 客户端与 Headscale 结合使用。

!!! info "Headscale 实例上的说明"

关于如何连接你的 Windows 设备的信息终结点也可以在你的运行实例上的 `/windows` 处获得。

## 安装

下载 [官方 Windows 客户端](https://tailscale.com/download/windows) 并安装它。

## 配置 Headscale URL

打开命令提示符或 Powershell，并使用 Tailscale 的登录命令连接到你的 Headscale 实例（例如 `https://headscale.example.com`）：

```
tailscale login --login-server <YOUR_HEADSCALE_URL>
```

按照打开的浏览器窗口中的说明完成配置。

## 故障排除

### 无人值守模式

默认情况下，Tailscale 的 Windows 客户端仅在用户登录时运行。 如果你希望 Tailscale 始终运行，请启用 “无人值守模式 (Unattended mode)”:

- 单击 Tailscale 托盘图标，然后选择 “首选项 (Preferences)”。
- 启用 “无人值守运行 (Run unattended)”。
- 确认 “无人值守模式 (Unattended mode)” 消息。

另请参阅 [当我不登录到我的计算机时，保持 Tailscale 运行](https://tailscale.com/kb/1088/run-unattended)。

### 节点注册失败

如果你在 Headscale 输出中看到重复的消息，例如：

```
[GIN] 2022/02/10 - 16:39:34 | 200 | 1.105306ms | 127.0.0.1 | POST "/machine/redacted"
```

打开 `DEBUG` 日志记录并查找：

```
2022-02-11T00:59:29Z DBG Machine registration has expired. Sending a authurl to register machine=redacted
```

这通常意味着上面的注册表项未正确设置。

要重置并重试，请务必执行以下操作：

1. 关闭 Tailscale 服务（或在托盘中运行的客户端）。
2. 删除 Tailscale 应用程序数据文件夹，该文件夹位于 `C:\Users\<USERNAME>\AppData\Local\Tailscale`，然后尝试重新连接。
3. 确保 Windows 节点已从 Headscale 中删除（以确保全新设置）。
4. 在 Windows 计算机上启动 Tailscale 并重试登录。
 