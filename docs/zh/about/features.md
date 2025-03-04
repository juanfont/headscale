# 功能

Headscale 旨在实现一个自托管的开源替代方案，作为 Tailscale 控制服务器。Headscale 的目标是为自托管者和爱好者提供一个可以用于他们项目和实验室的开源服务器。此页面提供了 headscale 功能及其与 Tailscale 控制服务器兼容性的概述：

- [x] 完整的 Tailscale 功能“基础”支持
- [x] 节点注册
    - [x] 交互式
    - [x] 预认证密钥
- [x] [DNS](https://tailscale.com/kb/1054/dns)
    - [x] [MagicDNS](https://tailscale.com/kb/1081/magicdns)
    - [x] [全局和受限名称服务器（分割 DNS）](https://tailscale.com/kb/1054/dns#nameservers)
    - [x] [搜索域](https://tailscale.com/kb/1054/dns#search-domains)
    - [x] [额外 DNS 记录（仅限 headscale）](../ref/dns.md#setting-extra-dns-records)
- [x] [Taildrop（文件共享）](https://tailscale.com/kb/1106/taildrop)
- [x] 路由广告（包括出口节点）
- [x] 双栈（IPv4 和 IPv6）
- [x] 瞬态节点
- [x] 嵌入式 [DERP 服务器](https://tailscale.com/kb/1232/derp-servers)
- [x] 访问控制列表（[GitHub 标签 "policy"](https://github.com/juanfont/headscale/labels/policy%20%F0%9F%93%9D)）
    - [x] 通过 API 管理 ACL
    - [x] `autogroup:internet`
    - [ ] `autogroup:self`
    - [ ] `autogroup:member`
* [ ] 使用单点登录（OpenID Connect）进行节点注册（[GitHub 标签 "OIDC"](https://github.com/juanfont/headscale/labels/OIDC)）
    - [x] 基本注册
    - [x] 从身份提供者更新用户资料
    - [ ] 动态 ACL 支持
    - [ ] OIDC 组不能在 ACL 中使用
- [ ] [Funnel](https://tailscale.com/kb/1223/funnel) （[#1040](https://github.com/juanfont/headscale/issues/1040)）
- [ ] [Serve](https://tailscale.com/kb/1312/serve) （[#1234](https://github.com/juanfont/headscale/issues/1921)）