# 出口节点

## 在节点上操作

注册节点并使其宣布自己为出口节点：

```console
$ sudo tailscale up --login-server https://headscale.example.com --advertise-exit-node
```

如果节点已经注册，可以通过以下命令宣布其出口能力：

```console
$ sudo tailscale set --advertise-exit-node
```

要将节点用作出口节点，必须在节点上启用 IP 转发。请参考官方 [Tailscale 文档](https://tailscale.com/kb/1019/subnets/?tab=linux#enable-ip-forwarding) 了解如何启用 IP 转发。

## 在控制服务器上操作

```console
$ headscale nodes list-routes
ID | Hostname           | Approved | Available       | Serving
1  | ts-head-ruqsg8     |          | 0.0.0.0/0, ::/0 |
2  | ts-unstable-fq7ob4 |          | 0.0.0.0/0, ::/0 |

# 注意：对于出口节点，只需批准 IPv4 或 IPv6 路由之一，另一个会自动添加。
$ headscale nodes approve-routes --identifier 1 --routes 0.0.0.0/0
Node updated

$ headscale nodes list-routes
ID | Hostname           | Approved        | Available       | Serving
1  | ts-head-ruqsg8     | 0.0.0.0/0, ::/0 | 0.0.0.0/0, ::/0 | 0.0.0.0/0, ::/0
2  | ts-unstable-fq7ob4 |                 | 0.0.0.0/0, ::/0 |
```

## 在客户端上操作

现在可以使用出口节点：

```console
$ sudo tailscale set --exit-node phobos
```

请参考官方 [Tailscale 文档](https://tailscale.com/kb/1103/exit-nodes#use-the-exit-node) 了解如何在你的设备上设置出口节点。