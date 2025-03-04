# 配置

- Headscale 从 YAML 文件加载其配置。
- 它会在以下路径中搜索 `config.yaml`：
  - `/etc/headscale`
  - `$HOME/.headscale`
  - 当前工作目录
- 使用命令行标志 `-c` 或 `--config` 从其他路径加载配置。
- 使用命令：`headscale configtest` 验证配置文件。

!!! example "获取 [GitHub 存储库中的示例配置](https://github.com/juanfont/headscale/blob/main/config-example.yaml)"

始终选择与您使用的发布版本相同的 [GitHub 标签](https://github.com/juanfont/headscale/tags)，以确保您拥有正确的示例配置。`main` 分支可能包含尚未发布的更改。

=== "在 GitHub 上查看"

- 开发版：<https://github.com/juanfont/headscale/blob/main/config-example.yaml>
- 版本 {{ headscale.version }}：<https://github.com/juanfont/headscale/blob/v{{ headscale.version }}/config-example.yaml>

=== "使用 `wget` 下载"

```shell
# 开发版
wget -O config.yaml https://raw.githubusercontent.com/juanfont/headscale/main/config-example.yaml

# 版本 {{ headscale.version }}
wget -O config.yaml https://raw.githubusercontent.com/juanfont/headscale/v{{ headscale.version }}/config-example.yaml
```

=== "使用 `curl` 下载"

```shell
# 开发版
curl -o config.yaml https://raw.githubusercontent.com/juanfont/headscale/main/config-example.yaml

# 版本 {{ headscale.version }}
curl -o config.yaml https://raw.githubusercontent.com/juanfont/headscale/v{{ headscale.version }}/config-example.yaml
```
