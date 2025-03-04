# 连接 Apple 客户端

本文档旨在说明用户如何将官方 iOS 和 macOS [Tailscale](https://tailscale.com) 客户端与 Headscale 结合使用。

!!! info "Headscale 实例上的说明"

关于如何连接你的 Apple 设备的信息终结点也可以在你的运行实例上的 `/apple` 处获得。

## iOS

### 安装

从 [App Store](https://apps.apple.com/app/tailscale/id1470499037) 安装官方 Tailscale iOS 客户端。

### 配置 Headscale URL

- 打开 Tailscale 应用
- 点击右上角的帐户图标，然后选择 “登录… (Log in…)”。
- 点击右上角的选项菜单按钮，然后选择 “使用自定义协调服务器 (Use custom coordination server)”。
- 输入你的实例 URL（例如 `https://headscale.example.com`）。
- 输入你的凭据并登录。 Headscale 现在应该可以在你的 iOS 设备上使用了。

## macOS

### 安装

选择一个可用的 [macOS Tailscale 客户端](https://tailscale.com/kb/1065/macos-variants) 并安装它。

### 配置 Headscale URL

#### 命令行

使用 Tailscale 的登录命令连接到你的 Headscale 实例（例如 `https://headscale.example.com`）：

```
tailscale login --login-server <YOUR_HEADSCALE_URL>
```

#### GUI

- Option + 单击菜单中的 Tailscale 图标，并将鼠标悬停在 “调试 (Debug)” 菜单上。
- 在 “自定义登录服务器 (Custom Login Server)” 下，选择 “添加帐户… (Add Account…)”。
- 输入你的 Headscale 实例的 URL（例如 `https://headscale.example.com`），然后按 “添加帐户 (Add Account)”。
- 按照浏览器中的登录步骤操作。

## tvOS

### 安装

从 [App Store](https://apps.apple.com/app/tailscale/id1470499037) 安装官方 Tailscale tvOS 客户端。

!!! danger

**安装后不要打开 Tailscale 应用！**

### 配置 Headscale URL

- 打开 “设置 (Settings)”（Apple tvOS 设置）> “应用 (Apps)” > “Tailscale”。
- 在 “备用协调服务器 URL (ALTERNATE COORDINATION SERVER URL)” 下，选择 “URL”。
- 输入你的 Headscale 实例的 URL（例如 `https://headscale.example.com`），然后按 “确定 (OK)”。
- 返回 tvOS 主屏幕。
- 打开 Tailscale。
- 点击 “安装 VPN 配置 (Install VPN configuration)” 按钮，然后点击 “允许 (Allow)” 按钮确认出现的弹出窗口。
- 扫描二维码，然后按照登录步骤操作。
 