# 在容器中运行 Headscale

!!! 警告 "社区文档"

    本页面并非由 Headscale 官方维护，而是由社区成员编写。Headscale 开发者**未验证**其内容。

    **内容可能已过时或缺少必要步骤**。

本文档旨在指导用户如何在容器中设置和运行 Headscale。虽然以 [Docker](https://www.docker.com) 作为参考容器实现，但同样适用于其他容器工具，如 [Podman](https://podman.io)。Headscale 的 Docker 镜像可以在 Docker Hub 上找到：[这里](https://hub.docker.com/r/headscale/headscale)。

## 配置并运行 Headscale

1. **准备主机目录**  
   在 Docker 主机上选择一个目录，用于存放 Headscale 的配置文件和 [SQLite](https://www.sqlite.org/) 数据库：

   ```shell
   mkdir -p ./headscale/config
   cd ./headscale
   ```

2. **下载并调整配置文件**  
   下载适合你版本的示例配置文件，并保存为 `/etc/headscale/config.yaml`。根据你的环境调整配置。详情请参考 [配置文档](../../../en/ref/configuration.md)。

   ```shell
   sudo mkdir -p /etc/headscale
   sudo nano /etc/headscale/config.yaml
   ```

   或者，你可以通过添加 `--volume $(pwd)/lib:/var/lib/headscale` 和 `--volume $(pwd)/run:/var/run/headscale` 来挂载主机的 `/var/lib` 和 `/var/run` 目录。

3. **启动 Headscale 服务**  
   在主机 Headscale 目录下运行以下命令：

   ```shell
   docker run \
     --name headscale \
     --detach \
     --volume $(pwd)/config:/etc/headscale/ \
     --publish 127.0.0.1:8080:8080 \
     --publish 127.0.0.1:9090:9090 \
     headscale/headscale:<VERSION> \
     serve
   ```

   注意：如果你希望外部访问容器，可以将 `127.0.0.1:8080:8080` 改为 `0.0.0.0:8080:8080`。

   此命令会将 `config/` 挂载到 `/etc/headscale`，将容器的 8080 端口映射到主机，使 Headscale 服务可用，并在后台运行。

   **示例 `docker-compose.yaml` 文件**：

   ```yaml
   version: "3.7"

   services:
     headscale:
       image: headscale/headscale:<VERSION>
       restart: unless-stopped
       container_name: headscale
       ports:
         - "127.0.0.1:8080:8080"
         - "127.0.0.1:9090:9090"
       volumes:
         # 请将 <CONFIG_PATH> 替换为你刚创建的配置文件夹的完整路径
         - <CONFIG_PATH>:/etc/headscale
       command: serve
   ```

4. **验证 Headscale 是否正常运行**  
   查看容器日志：

   ```shell
   docker logs --follow headscale
   ```

   查看正在运行的容器：

   ```shell
   docker ps
   ```

   验证 Headscale 是否可用：

   ```shell
   curl http://127.0.0.1:9090/metrics
   ```

5. **创建 Headscale 用户**  
   在容器中执行以下命令创建用户：

   ```shell
   docker exec -it headscale \
     headscale users create myfirstuser
   ```

### 注册设备（普通登录）

在客户端设备上执行以下命令：

```shell
tailscale up --login-server YOUR_HEADSCALE_URL
```

如果 Headscale 运行在容器中，可以通过以下命令注册设备：

```shell
docker exec -it headscale \
  headscale nodes register --user myfirstuser --key <YOUR_MACHINE_KEY>
```

### 使用预认证密钥注册设备

生成预认证密钥：

```shell
docker exec -it headscale \
  headscale preauthkeys create --user myfirstuser --reusable --expiration 24h
```

这将返回一个预认证密钥，可以在 `tailscale` 命令中使用：

```shell
tailscale up --login-server <YOUR_HEADSCALE_URL> --authkey <YOUR_AUTH_KEY>
```

## 调试运行在 Docker 中的 Headscale

`headscale/headscale` Docker 容器基于“无发行版”镜像，不包含 shell 或其他调试工具。如果需要调试，可以使用 `-debug` 变体，例如 `headscale/headscale:x.x.x-debug`。

### 运行调试容器

使用与普通容器相同的命令，但将 `headscale/headscale:x.x.x` 替换为 `headscale/headscale:x.x.x-debug`（`x.x.x` 是 Headscale 版本）。两个容器兼容，可以交替使用。

### 在调试容器中执行命令

调试容器的默认命令是运行 Headscale，路径为 `/ko-app/headscale`。

此外，调试容器包含一个极简的 Busybox shell。

启动容器的 shell：

```shell
docker run -it headscale/headscale:x.x.x-debug sh
```

也可以直接执行命令，例如列出 `/ko-app` 目录：

```shell
docker run headscale/headscale:x.x.x-debug ls /ko-app
```

使用 `docker exec -it` 可以在现有容器中运行命令。