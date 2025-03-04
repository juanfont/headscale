以下是您提供的英文内容翻译为中文：

---

# 官方版本

Headscale 的官方版本提供多种平台的二进制文件以及适用于 Debian 和 Ubuntu 的 DEB 包。两者均可在 [GitHub 发布页面](https://github.com/juanfont/headscale/releases) 获取。

## 使用 Debian/Ubuntu 软件包（推荐）

推荐在基于 Debian 的系统上使用我们的 DEB 包来安装 Headscale，因为这些软件包会配置一个本地用户来运行 Headscale，提供默认配置文件，并附带 systemd 服务文件。支持的发行版包括 Ubuntu 20.04 或更新版本，以及 Debian 11 或更新版本。

1. 下载适用于您平台的最新 [Headscale 软件包](https://github.com/juanfont/headscale/releases/latest)（Ubuntu 和 Debian 使用 `.deb` 文件）。

   ```shell
   HEADSCALE_VERSION="" # 参见上方链接获取最新版本号，例如 "X.Y.Z"（注意：不要添加 "v" 前缀！）
   HEADSCALE_ARCH="" # 您的系统架构，例如 "amd64"
   wget --output-document=headscale.deb \
   "https://github.com/juanfont/headscale/releases/download/v${HEADSCALE_VERSION}/headscale_${HEADSCALE_VERSION}_linux_${HEADSCALE_ARCH}.deb"
   ```

2. 安装 Headscale：

   ```shell
   sudo apt install ./headscale.deb
   ```

3. [编辑配置文件以配置 Headscale](../../../en/ref/configuration.md)：

   ```shell
   sudo nano /etc/headscale/config.yaml
   ```

4. 启用并启动 Headscale 服务：

   ```shell
   sudo systemctl enable --now headscale
   ```

5. 验证 Headscale 是否正常运行：

   ```shell
   sudo systemctl status headscale
   ```

## 使用独立二进制文件（高级）

!!! warning "高级"

   此安装方法被认为是高级的，因为用户需要自行管理本地用户和 systemd 服务。如果可能，请使用 [DEB 软件包](#使用-debianubuntu-软件包推荐) 或 [社区包](community.md)。

本节介绍根据 [要求和假设](../requirements.md#假设) 安装 Headscale 的步骤。Headscale 由专用本地用户运行，服务本身由 systemd 管理。

1. 从 [GitHub 发布页面](https://github.com/juanfont/headscale/releases) 下载最新的 `headscale` 二进制文件：

   ```shell
   sudo wget --output-document=/usr/local/bin/headscale \
   https://github.com/juanfont/headscale/releases/download/v<HEADSCALE 版本>/headscale_<HEADSCALE 版本>_linux_<架构>
   ```

2. 使 `headscale` 可执行：

   ```shell
   sudo chmod +x /usr/local/bin/headscale
   ```

3. 添加一个专用的本地用户来运行 Headscale：

   ```shell
   sudo useradd \
   --create-home \
   --home-dir /var/lib/headscale/ \
   --system \
   --user-group \
   --shell /usr/sbin/nologin \
   headscale
   ```

4. 下载所需版本的示例配置文件并保存为 `/etc/headscale/config.yaml`。根据本地环境调整配置。详情请参见 [配置文件](../../../en/ref/configuration.md)。

   ```shell
   sudo mkdir -p /etc/headscale
   sudo nano /etc/headscale/config.yaml
   ```

5. 将 [Headscale 的 systemd 服务文件](../../../en/packaging/headscale.systemd.service) 复制到 `/etc/systemd/system/headscale.service` 并根据本地设置进行调整。以下参数可能需要修改： `ExecStart`、`WorkingDirectory`、`ReadWritePaths`。

6. 在 `/etc/headscale/config.yaml` 中，将默认的 `headscale` Unix 套接字路径替换为可由 `headscale` 用户或组写入的路径：

   ```yaml title="config.yaml"
   unix_socket: /var/run/headscale/headscale.sock
   ```

7. 重新加载 systemd 以加载新配置文件：

   ```shell
   systemctl daemon-reload
   ```

8. 启用并启动新的 Headscale 服务：

   ```shell
   systemctl enable --now headscale
   ```

9. 验证 Headscale 是否正常运行：

   ```shell
   systemctl status headscale
   ```

---

