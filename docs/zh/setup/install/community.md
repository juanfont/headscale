# 社区提供的安装包

一些 Linux 发行版和社区成员为 Headscale 提供了安装包。这些包可以作为 Headscale 维护者提供的 [官方版本](official.md) 的替代方案。这些包通常能更好地集成到目标操作系统中，并且通常会：

- 创建一个专用的本地用户来运行 Headscale
- 提供默认的配置文件
- 将 Headscale 安装为系统服务

!!! 警告 "社区包可能已过时"

    本页提到的包可能已经过时或不再维护。建议使用 [官方版本](./official.md) 来获取最新的稳定版本或测试预发布版本。

    [![打包状态](https://repology.org/badge/vertical-allrepos/headscale.svg)](https://repology.org/project/headscale/versions)

## Arch Linux

Arch Linux 提供了 Headscale 的安装包，可以通过以下命令安装：

```shell
pacman -S headscale
```

如果你想安装最新的开发版本，可以使用 [AUR 包 `headscale-git`](https://aur.archlinux.org/packages/headscale-git)。

## Fedora, RHEL, CentOS

针对基于 RPM 的发行版，可以在以下地址找到第三方仓库：  
<https://copr.fedorainfracloud.org/coprs/jonathanspw/headscale/>  
该网站提供了详细的设置和安装说明。

## Nix, NixOS

Nix 提供了一个名为 `headscale` 的包。安装细节可以参考 [NixOS 包页面](https://search.nixos.org/packages?show=headscale)。

## Gentoo

可以通过以下命令安装 Headscale：

```shell
emerge --ask net-vpn/headscale
```

Gentoo 的具体文档可以在 [这里](https://wiki.gentoo.org/wiki/User:Maffblaster/Drafts/Headscale) 找到。

## OpenBSD

Headscale 已经包含在 OpenBSD 的 ports 中。安装时会通过 `rc.d` 将 Headscale 设置为系统服务，并在安装完成后提供使用说明。

```shell
pkg_add headscale
```