# 从源码构建

!!! 警告 "社区文档"

    本页面并非由 Headscale 官方维护，而是由社区成员编写。Headscale 开发者**未验证**其内容。

    **内容可能已过时或缺少必要步骤**。

Headscale 可以通过最新版本的 [Go](https://golang.org) 和 [Buf](https://buf.build)（Protobuf 生成器）从源码构建。更多信息请参考 [GitHub README 中的贡献部分](https://github.com/juanfont/headscale#contributing)。

## OpenBSD

### 从源码安装

```shell
# 安装依赖
pkg_add go

# 克隆 Headscale 仓库
git clone https://github.com/juanfont/headscale.git

cd headscale

# 可选：切换到某个发布版本
# 选项 a. 你可以在 https://github.com/juanfont/headscale/releases/latest 找到官方发布版本
# 选项 b. 获取最新的标签，可能是测试版
latestTag=$(git describe --tags `git rev-list --tags --max-count=1`)

git checkout $latestTag

# 构建 Headscale
go build -ldflags="-s -w -X github.com/juanfont/headscale/hscontrol/types.Version=$latestTag" -X github.com/juanfont/headscale/hscontrol/types.GitCommitHash=HASH" github.com/juanfont/headscale

# 赋予可执行权限
chmod a+x headscale

# 复制到 /usr/local/sbin
cp headscale /usr/local/sbin
```

### 通过交叉编译从源码安装

```shell
# 安装依赖
# 1. go v1.20+：Headscale 0.21 以上版本需要 Go 1.20+ 才能编译
# 2. gmake：Headscale 仓库中的 Makefile 使用 GNU make 语法

# 克隆 Headscale 仓库
git clone https://github.com/juanfont/headscale.git

cd headscale

# 可选：切换到某个发布版本
# 选项 a. 你可以在 https://github.com/juanfont/headscale/releases/latest 找到官方发布版本
# 选项 b. 获取最新的标签，可能是测试版
latestTag=$(git describe --tags `git rev-list --tags --max-count=1`)

git checkout $latestTag

# 交叉编译
make build GOOS=openbsd

# 将编译好的 headscale 复制到 OpenBSD 机器，并放到 /usr/local/sbin
```