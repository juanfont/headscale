# 常见问题解答

## headscale 的设计目标是什么？

Headscale 旨在实现一个自托管的开源替代方案，作为 [Tailscale](https://tailscale.com/) 控制服务器。Headscale 的目标是为自托管者和爱好者提供一个可以用于他们项目和实验室的开源服务器。它实现了一个狭窄的范围，一个 _单一_ 的 Tailscale 网络（tailnet），适合个人使用或小型开源组织。

## 我该如何贡献？

Headscale 是“开源，认可贡献”，这意味着任何贡献都必须在提交之前与维护者讨论。

请参见 [贡献](contributing.md) 以获取更多信息。

## 为什么选择“认可贡献”作为模型？

两位维护者都有全职工作和家庭，我们希望避免疲惫。我们也希望避免贡献者在他们的 PR 未被接受时感到沮丧。

在提交 PR 之前，我们非常乐意通过电子邮件交流，或进行专门的电话会议。

## 功能 X 何时/为什么会被实现？

我们不知道。我们可能正在进行相关工作。如果您有兴趣贡献，请发布关于该功能的请求。

请注意，我们可能不接受特定贡献的原因有很多：

- 以自托管环境的方式实现该功能是不可能的。
- 鉴于我们正在逆向工程 Tailscale 以满足自己的好奇心，我们可能会对自己实现该功能感兴趣。
- 您没有随之发送单元测试和集成测试。

## 你们支持 Y 种部署 headscale 的方法吗？

我们目前支持使用我们的二进制文件和 DEB 包部署 headscale。有关更多信息，请访问我们的 [使用官方发布的安装指南](../setup/install/official.md)。

此外，您可以使用社区提供的包或发行版中的包。有关更多信息，请查看 [使用社区包的安装指南](../setup/install/community.md)。

为了方便起见，我们还 [构建了带有 headscale 的 Docker 镜像](../setup/install/container.md)。但 **请注意，我们不正式支持使用 Docker 部署 headscale**。在我们的 [Discord 服务器](https://discord.gg/c84AZQhmpx) 上，我们有一个“docker-issues”频道，您可以在这里向社区寻求 Docker 相关的帮助。

## 我应该使用哪个数据库？

我们推荐使用 SQLite 作为 headscale 的数据库：

- SQLite 设置简单，易于使用
- 它适合 headscale 的所有用例
- 开发和测试主要在 SQLite 上进行
- PostgreSQL 仍然受支持，但被认为处于“维护模式”

headscale 项目本身不提供从 PostgreSQL 迁移到 SQLite 的工具。请查看 [相关工具文档](../ref/integration/tools.md)，以获取社区提供的迁移工具。

## 为什么我的反向代理与 headscale 不兼容？

我们不知道。我们自己不使用反向代理与 headscale，因此没有相关经验。我们有 [社区文档](../ref/integration/reverse-proxy.md) 介绍如何配置各种反向代理，并在我们的 [Discord 服务器](https://discord.gg/c84AZQhmpx) 上有一个专门的“reverse-proxy-issues”频道，您可以在这里向社区寻求帮助。

## 我可以在同一台机器上使用 headscale 和 tailscale 吗？

在同一台机器上运行 headscale，同时该机器也在 tailnet 中，可能会导致子网路由器、流量中继节点和 MagicDNS 的问题。它可能会工作，但不被支持。