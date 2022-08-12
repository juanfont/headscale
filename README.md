# headscale

![ci](https://github.com/juanfont/headscale/actions/workflows/test.yml/badge.svg)

An open source, self-hosted implementation of the Tailscale control server.

Join our [Discord](https://discord.gg/c84AZQhmpx) server for a chat.

**Note:** Always select the same GitHub tag as the released version you use
to ensure you have the correct example configuration and documentation.
The `main` branch might contain unreleased changes.

## What is Tailscale

Tailscale is [a modern VPN](https://tailscale.com/) built on top of
[Wireguard](https://www.wireguard.com/).
It [works like an overlay network](https://tailscale.com/blog/how-tailscale-works/)
between the computers of your networks - using
[NAT traversal](https://tailscale.com/blog/how-nat-traversal-works/).

Everything in Tailscale is Open Source, except the GUI clients for proprietary OS
(Windows and macOS/iOS), and the control server.

The control server works as an exchange point of Wireguard public keys for the
nodes in the Tailscale network. It assigns the IP addresses of the clients,
creates the boundaries between each user, enables sharing machines between users,
and exposes the advertised routes of your nodes.

A [Tailscale network (tailnet)](https://tailscale.com/kb/1136/tailnet/) is private
network which Tailscale assigns to a user in terms of private users or an
organisation.

## Design goal

`headscale` aims to implement a self-hosted, open source alternative to the Tailscale
control server. `headscale` has a narrower scope and an instance of `headscale`
implements a _single_ Tailnet, which is typically what a single organisation, or
home/personal setup would use.

`headscale` uses terms that maps to Tailscale's control server, consult the
[glossary](./docs/glossary.md) for explainations.

## Support

If you like `headscale` and find it useful, there is a sponsorship and donation
buttons available in the repo.

If you would like to sponsor features, bugs or prioritisation, reach out to
one of the maintainers.

## Features

- Full "base" support of Tailscale's features
- Configurable DNS
  - [Split DNS](https://tailscale.com/kb/1054/dns/#using-dns-settings-in-the-admin-console)
- Node registration
  - Single-Sign-On (via Open ID Connect)
  - Pre authenticated key
- Taildrop (File Sharing)
- [Access control lists](https://tailscale.com/kb/1018/acls/)
- [MagicDNS](https://tailscale.com/kb/1081/magicdns)
- Support for multiple IP ranges in the tailnet
- Dual stack (IPv4 and IPv6)
- Routing advertising (including exit nodes)
- Ephemeral nodes
- Embedded [DERP server](https://tailscale.com/blog/how-tailscale-works/#encrypted-tcp-relays-derp)

## Client OS support

| OS      | Supports headscale                                        |
| ------- | --------------------------------------------------------- |
| Linux   | Yes                                                       |
| OpenBSD | Yes                                                       |
| FreeBSD | Yes                                                       |
| macOS   | Yes (see `/apple` on your headscale for more information) |
| Windows | Yes [docs](./docs/windows-client.md)                      |
| Android | Yes [docs](./docs/android-client.md)                      |
| iOS     | Not yet                                                   |

## Running headscale

Please have a look at the documentation under [`docs/`](docs/).

## Disclaimer

1. We have nothing to do with Tailscale, or Tailscale Inc.
2. The purpose of Headscale is maintaining a working, self-hosted Tailscale control panel.

## Contributing

To contribute to headscale you would need the lastest version of [Go](https://golang.org)
and [Buf](https://buf.build)(Protobuf generator).

We recommend using [Nix](https://nixos.org/) to setup a development environment. This can
be done with `nix develop`, which will install the tools and give you a shell.
This guarantees that you will have the same dev env as `headscale` maintainers.

PRs and suggestions are welcome.

### Code style

To ensure we have some consistency with a growing number of contributions,
this project has adopted linting and style/formatting rules:

The **Go** code is linted with [`golangci-lint`](https://golangci-lint.run) and
formatted with [`golines`](https://github.com/segmentio/golines) (width 88) and
[`gofumpt`](https://github.com/mvdan/gofumpt).
Please configure your editor to run the tools while developing and make sure to
run `make lint` and `make fmt` before committing any code.

The **Proto** code is linted with [`buf`](https://docs.buf.build/lint/overview) and
formatted with [`clang-format`](https://clang.llvm.org/docs/ClangFormat.html).

The **rest** (Markdown, YAML, etc) is formatted with [`prettier`](https://prettier.io).

Check out the `.golangci.yaml` and `Makefile` to see the specific configuration.

### Install development tools

- Go
- Buf
- Protobuf tools

Install and activate:

```shell
nix develop
```

### Testing and building

Some parts of the project require the generation of Go code from Protobuf
(if changes are made in `proto/`) and it must be (re-)generated with:

```shell
make generate
```

**Note**: Please check in changes from `gen/` in a separate commit to make it easier to review.

To run the tests:

```shell
make test
```

To build the program:

```shell
nix build
```

or

```shell
make build
```

## Contributors

<table>
<tr>
    <td align="center" style="word-wrap: break-word; width: 150.0; height: 150.0">
        <a href=https://github.com/kradalby>
            <img src=https://avatars.githubusercontent.com/u/98431?v=4 width="100;"  style="border-radius:50%;align-items:center;justify-content:center;overflow:hidden;padding-top:10px" alt=Kristoffer Dalby/>
            <br />
            <sub style="font-size:14px"><b>Kristoffer Dalby</b></sub>
        </a>
    </td>
    <td align="center" style="word-wrap: break-word; width: 150.0; height: 150.0">
        <a href=https://github.com/juanfont>
            <img src=https://avatars.githubusercontent.com/u/181059?v=4 width="100;"  style="border-radius:50%;align-items:center;justify-content:center;overflow:hidden;padding-top:10px" alt=Juan Font/>
            <br />
            <sub style="font-size:14px"><b>Juan Font</b></sub>
        </a>
    </td>
    <td align="center" style="word-wrap: break-word; width: 150.0; height: 150.0">
        <a href=https://github.com/restanrm>
            <img src=https://avatars.githubusercontent.com/u/4344371?v=4 width="100;"  style="border-radius:50%;align-items:center;justify-content:center;overflow:hidden;padding-top:10px" alt=Adrien Raffin-Caboisse/>
            <br />
            <sub style="font-size:14px"><b>Adrien Raffin-Caboisse</b></sub>
        </a>
    </td>
    <td align="center" style="word-wrap: break-word; width: 150.0; height: 150.0">
        <a href=https://github.com/cure>
            <img src=https://avatars.githubusercontent.com/u/149135?v=4 width="100;"  style="border-radius:50%;align-items:center;justify-content:center;overflow:hidden;padding-top:10px" alt=Ward Vandewege/>
            <br />
            <sub style="font-size:14px"><b>Ward Vandewege</b></sub>
        </a>
    </td>
    <td align="center" style="word-wrap: break-word; width: 150.0; height: 150.0">
        <a href=https://github.com/huskyii>
            <img src=https://avatars.githubusercontent.com/u/5499746?v=4 width="100;"  style="border-radius:50%;align-items:center;justify-content:center;overflow:hidden;padding-top:10px" alt=Jiang Zhu/>
            <br />
            <sub style="font-size:14px"><b>Jiang Zhu</b></sub>
        </a>
    </td>
    <td align="center" style="word-wrap: break-word; width: 150.0; height: 150.0">
        <a href=https://github.com/reynico>
            <img src=https://avatars.githubusercontent.com/u/715768?v=4 width="100;"  style="border-radius:50%;align-items:center;justify-content:center;overflow:hidden;padding-top:10px" alt=Nico/>
            <br />
            <sub style="font-size:14px"><b>Nico</b></sub>
        </a>
    </td>
</tr>
<tr>
    <td align="center" style="word-wrap: break-word; width: 150.0; height: 150.0">
        <a href=https://github.com/e-zk>
            <img src=https://avatars.githubusercontent.com/u/58356365?v=4 width="100;"  style="border-radius:50%;align-items:center;justify-content:center;overflow:hidden;padding-top:10px" alt=e-zk/>
            <br />
            <sub style="font-size:14px"><b>e-zk</b></sub>
        </a>
    </td>
    <td align="center" style="word-wrap: break-word; width: 150.0; height: 150.0">
        <a href=https://github.com/arch4ngel>
            <img src=https://avatars.githubusercontent.com/u/11574161?v=4 width="100;"  style="border-radius:50%;align-items:center;justify-content:center;overflow:hidden;padding-top:10px" alt=Justin Angel/>
            <br />
            <sub style="font-size:14px"><b>Justin Angel</b></sub>
        </a>
    </td>
    <td align="center" style="word-wrap: break-word; width: 150.0; height: 150.0">
        <a href=https://github.com/ItalyPaleAle>
            <img src=https://avatars.githubusercontent.com/u/43508?v=4 width="100;"  style="border-radius:50%;align-items:center;justify-content:center;overflow:hidden;padding-top:10px" alt=Alessandro (Ale) Segala/>
            <br />
            <sub style="font-size:14px"><b>Alessandro (Ale) Segala</b></sub>
        </a>
    </td>
    <td align="center" style="word-wrap: break-word; width: 150.0; height: 150.0">
        <a href=https://github.com/unreality>
            <img src=https://avatars.githubusercontent.com/u/352522?v=4 width="100;"  style="border-radius:50%;align-items:center;justify-content:center;overflow:hidden;padding-top:10px" alt=unreality/>
            <br />
            <sub style="font-size:14px"><b>unreality</b></sub>
        </a>
    </td>
    <td align="center" style="word-wrap: break-word; width: 150.0; height: 150.0">
        <a href=https://github.com/mpldr>
            <img src=https://avatars.githubusercontent.com/u/33086936?v=4 width="100;"  style="border-radius:50%;align-items:center;justify-content:center;overflow:hidden;padding-top:10px" alt=Moritz Poldrack/>
            <br />
            <sub style="font-size:14px"><b>Moritz Poldrack</b></sub>
        </a>
    </td>
    <td align="center" style="word-wrap: break-word; width: 150.0; height: 150.0">
        <a href=https://github.com/ohdearaugustin>
            <img src=https://avatars.githubusercontent.com/u/14001491?v=4 width="100;"  style="border-radius:50%;align-items:center;justify-content:center;overflow:hidden;padding-top:10px" alt=ohdearaugustin/>
            <br />
            <sub style="font-size:14px"><b>ohdearaugustin</b></sub>
        </a>
    </td>
</tr>
<tr>
    <td align="center" style="word-wrap: break-word; width: 150.0; height: 150.0">
        <a href=https://github.com/Niek>
            <img src=https://avatars.githubusercontent.com/u/213140?v=4 width="100;"  style="border-radius:50%;align-items:center;justify-content:center;overflow:hidden;padding-top:10px" alt=Niek van der Maas/>
            <br />
            <sub style="font-size:14px"><b>Niek van der Maas</b></sub>
        </a>
    </td>
    <td align="center" style="word-wrap: break-word; width: 150.0; height: 150.0">
        <a href=https://github.com/negbie>
            <img src=https://avatars.githubusercontent.com/u/20154956?v=4 width="100;"  style="border-radius:50%;align-items:center;justify-content:center;overflow:hidden;padding-top:10px" alt=Eugen Biegler/>
            <br />
            <sub style="font-size:14px"><b>Eugen Biegler</b></sub>
        </a>
    </td>
    <td align="center" style="word-wrap: break-word; width: 150.0; height: 150.0">
        <a href=https://github.com/qbit>
            <img src=https://avatars.githubusercontent.com/u/68368?v=4 width="100;"  style="border-radius:50%;align-items:center;justify-content:center;overflow:hidden;padding-top:10px" alt=Aaron Bieber/>
            <br />
            <sub style="font-size:14px"><b>Aaron Bieber</b></sub>
        </a>
    </td>
    <td align="center" style="word-wrap: break-word; width: 150.0; height: 150.0">
        <a href=https://github.com/iSchluff>
            <img src=https://avatars.githubusercontent.com/u/1429641?v=4 width="100;"  style="border-radius:50%;align-items:center;justify-content:center;overflow:hidden;padding-top:10px" alt=Anton Schubert/>
            <br />
            <sub style="font-size:14px"><b>Anton Schubert</b></sub>
        </a>
    </td>
    <td align="center" style="word-wrap: break-word; width: 150.0; height: 150.0">
        <a href=https://github.com/fdelucchijr>
            <img src=https://avatars.githubusercontent.com/u/69133647?v=4 width="100;"  style="border-radius:50%;align-items:center;justify-content:center;overflow:hidden;padding-top:10px" alt=Fernando De Lucchi/>
            <br />
            <sub style="font-size:14px"><b>Fernando De Lucchi</b></sub>
        </a>
    </td>
    <td align="center" style="word-wrap: break-word; width: 150.0; height: 150.0">
        <a href=https://github.com/GrigoriyMikhalkin>
            <img src=https://avatars.githubusercontent.com/u/3637857?v=4 width="100;"  style="border-radius:50%;align-items:center;justify-content:center;overflow:hidden;padding-top:10px" alt=GrigoriyMikhalkin/>
            <br />
            <sub style="font-size:14px"><b>GrigoriyMikhalkin</b></sub>
        </a>
    </td>
</tr>
<tr>
    <td align="center" style="word-wrap: break-word; width: 150.0; height: 150.0">
        <a href=https://github.com/hdhoang>
            <img src=https://avatars.githubusercontent.com/u/12537?v=4 width="100;"  style="border-radius:50%;align-items:center;justify-content:center;overflow:hidden;padding-top:10px" alt=Hoàng Đức Hiếu/>
            <br />
            <sub style="font-size:14px"><b>Hoàng Đức Hiếu</b></sub>
        </a>
    </td>
    <td align="center" style="word-wrap: break-word; width: 150.0; height: 150.0">
        <a href=https://github.com/bravechamp>
            <img src=https://avatars.githubusercontent.com/u/48980452?v=4 width="100;"  style="border-radius:50%;align-items:center;justify-content:center;overflow:hidden;padding-top:10px" alt=bravechamp/>
            <br />
            <sub style="font-size:14px"><b>bravechamp</b></sub>
        </a>
    </td>
    <td align="center" style="word-wrap: break-word; width: 150.0; height: 150.0">
        <a href=https://github.com/deonthomasgy>
            <img src=https://avatars.githubusercontent.com/u/150036?v=4 width="100;"  style="border-radius:50%;align-items:center;justify-content:center;overflow:hidden;padding-top:10px" alt=Deon Thomas/>
            <br />
            <sub style="font-size:14px"><b>Deon Thomas</b></sub>
        </a>
    </td>
    <td align="center" style="word-wrap: break-word; width: 150.0; height: 150.0">
        <a href=https://github.com/ChibangLW>
            <img src=https://avatars.githubusercontent.com/u/22293464?v=4 width="100;"  style="border-radius:50%;align-items:center;justify-content:center;overflow:hidden;padding-top:10px" alt=ChibangLW/>
            <br />
            <sub style="font-size:14px"><b>ChibangLW</b></sub>
        </a>
    </td>
    <td align="center" style="word-wrap: break-word; width: 150.0; height: 150.0">
        <a href=https://github.com/mevansam>
            <img src=https://avatars.githubusercontent.com/u/403630?v=4 width="100;"  style="border-radius:50%;align-items:center;justify-content:center;overflow:hidden;padding-top:10px" alt=Mevan Samaratunga/>
            <br />
            <sub style="font-size:14px"><b>Mevan Samaratunga</b></sub>
        </a>
    </td>
    <td align="center" style="word-wrap: break-word; width: 150.0; height: 150.0">
        <a href=https://github.com/dragetd>
            <img src=https://avatars.githubusercontent.com/u/3639577?v=4 width="100;"  style="border-radius:50%;align-items:center;justify-content:center;overflow:hidden;padding-top:10px" alt=Michael G./>
            <br />
            <sub style="font-size:14px"><b>Michael G.</b></sub>
        </a>
    </td>
</tr>
<tr>
    <td align="center" style="word-wrap: break-word; width: 150.0; height: 150.0">
        <a href=https://github.com/ptman>
            <img src=https://avatars.githubusercontent.com/u/24669?v=4 width="100;"  style="border-radius:50%;align-items:center;justify-content:center;overflow:hidden;padding-top:10px" alt=Paul Tötterman/>
            <br />
            <sub style="font-size:14px"><b>Paul Tötterman</b></sub>
        </a>
    </td>
    <td align="center" style="word-wrap: break-word; width: 150.0; height: 150.0">
        <a href=https://github.com/samson4649>
            <img src=https://avatars.githubusercontent.com/u/12725953?v=4 width="100;"  style="border-radius:50%;align-items:center;justify-content:center;overflow:hidden;padding-top:10px" alt=Samuel Lock/>
            <br />
            <sub style="font-size:14px"><b>Samuel Lock</b></sub>
        </a>
    </td>
    <td align="center" style="word-wrap: break-word; width: 150.0; height: 150.0">
        <a href=https://github.com/majst01>
            <img src=https://avatars.githubusercontent.com/u/410110?v=4 width="100;"  style="border-radius:50%;align-items:center;justify-content:center;overflow:hidden;padding-top:10px" alt=Stefan Majer/>
            <br />
            <sub style="font-size:14px"><b>Stefan Majer</b></sub>
        </a>
    </td>
    <td align="center" style="word-wrap: break-word; width: 150.0; height: 150.0">
        <a href=https://github.com/artemklevtsov>
            <img src=https://avatars.githubusercontent.com/u/603798?v=4 width="100;"  style="border-radius:50%;align-items:center;justify-content:center;overflow:hidden;padding-top:10px" alt=Artem Klevtsov/>
            <br />
            <sub style="font-size:14px"><b>Artem Klevtsov</b></sub>
        </a>
    </td>
    <td align="center" style="word-wrap: break-word; width: 150.0; height: 150.0">
        <a href=https://github.com/cmars>
            <img src=https://avatars.githubusercontent.com/u/23741?v=4 width="100;"  style="border-radius:50%;align-items:center;justify-content:center;overflow:hidden;padding-top:10px" alt=Casey Marshall/>
            <br />
            <sub style="font-size:14px"><b>Casey Marshall</b></sub>
        </a>
    </td>
    <td align="center" style="word-wrap: break-word; width: 150.0; height: 150.0">
        <a href=https://github.com/pvinis>
            <img src=https://avatars.githubusercontent.com/u/100233?v=4 width="100;"  style="border-radius:50%;align-items:center;justify-content:center;overflow:hidden;padding-top:10px" alt=Pavlos Vinieratos/>
            <br />
            <sub style="font-size:14px"><b>Pavlos Vinieratos</b></sub>
        </a>
    </td>
</tr>
<tr>
    <td align="center" style="word-wrap: break-word; width: 150.0; height: 150.0">
        <a href=https://github.com/SilverBut>
            <img src=https://avatars.githubusercontent.com/u/6560655?v=4 width="100;"  style="border-radius:50%;align-items:center;justify-content:center;overflow:hidden;padding-top:10px" alt=Silver Bullet/>
            <br />
            <sub style="font-size:14px"><b>Silver Bullet</b></sub>
        </a>
    </td>
    <td align="center" style="word-wrap: break-word; width: 150.0; height: 150.0">
        <a href=https://github.com/lachy2849>
            <img src=https://avatars.githubusercontent.com/u/98844035?v=4 width="100;"  style="border-radius:50%;align-items:center;justify-content:center;overflow:hidden;padding-top:10px" alt=lachy2849/>
            <br />
            <sub style="font-size:14px"><b>lachy2849</b></sub>
        </a>
    </td>
    <td align="center" style="word-wrap: break-word; width: 150.0; height: 150.0">
        <a href=https://github.com/t56k>
            <img src=https://avatars.githubusercontent.com/u/12165422?v=4 width="100;"  style="border-radius:50%;align-items:center;justify-content:center;overflow:hidden;padding-top:10px" alt=thomas/>
            <br />
            <sub style="font-size:14px"><b>thomas</b></sub>
        </a>
    </td>
    <td align="center" style="word-wrap: break-word; width: 150.0; height: 150.0">
        <a href=https://github.com/aberoham>
            <img src=https://avatars.githubusercontent.com/u/586805?v=4 width="100;"  style="border-radius:50%;align-items:center;justify-content:center;overflow:hidden;padding-top:10px" alt=Abraham Ingersoll/>
            <br />
            <sub style="font-size:14px"><b>Abraham Ingersoll</b></sub>
        </a>
    </td>
    <td align="center" style="word-wrap: break-word; width: 150.0; height: 150.0">
        <a href=https://github.com/apognu>
            <img src=https://avatars.githubusercontent.com/u/3017182?v=4 width="100;"  style="border-radius:50%;align-items:center;justify-content:center;overflow:hidden;padding-top:10px" alt=Antoine POPINEAU/>
            <br />
            <sub style="font-size:14px"><b>Antoine POPINEAU</b></sub>
        </a>
    </td>
    <td align="center" style="word-wrap: break-word; width: 150.0; height: 150.0">
        <a href=https://github.com/aofei>
            <img src=https://avatars.githubusercontent.com/u/5037285?v=4 width="100;"  style="border-radius:50%;align-items:center;justify-content:center;overflow:hidden;padding-top:10px" alt=Aofei Sheng/>
            <br />
            <sub style="font-size:14px"><b>Aofei Sheng</b></sub>
        </a>
    </td>
</tr>
<tr>
    <td align="center" style="word-wrap: break-word; width: 150.0; height: 150.0">
        <a href=https://github.com/awoimbee>
            <img src=https://avatars.githubusercontent.com/u/22431493?v=4 width="100;"  style="border-radius:50%;align-items:center;justify-content:center;overflow:hidden;padding-top:10px" alt=Arthur Woimbée/>
            <br />
            <sub style="font-size:14px"><b>Arthur Woimbée</b></sub>
        </a>
    </td>
    <td align="center" style="word-wrap: break-word; width: 150.0; height: 150.0">
        <a href=https://github.com/stensonb>
            <img src=https://avatars.githubusercontent.com/u/933389?v=4 width="100;"  style="border-radius:50%;align-items:center;justify-content:center;overflow:hidden;padding-top:10px" alt=Bryan Stenson/>
            <br />
            <sub style="font-size:14px"><b>Bryan Stenson</b></sub>
        </a>
    </td>
    <td align="center" style="word-wrap: break-word; width: 150.0; height: 150.0">
        <a href=https://github.com/yangchuansheng>
            <img src=https://avatars.githubusercontent.com/u/15308462?v=4 width="100;"  style="border-radius:50%;align-items:center;justify-content:center;overflow:hidden;padding-top:10px" alt= Carson Yang/>
            <br />
            <sub style="font-size:14px"><b> Carson Yang</b></sub>
        </a>
    </td>
    <td align="center" style="word-wrap: break-word; width: 150.0; height: 150.0">
        <a href=https://github.com/kundel>
            <img src=https://avatars.githubusercontent.com/u/10158899?v=4 width="100;"  style="border-radius:50%;align-items:center;justify-content:center;overflow:hidden;padding-top:10px" alt=kundel/>
            <br />
            <sub style="font-size:14px"><b>kundel</b></sub>
        </a>
    </td>
    <td align="center" style="word-wrap: break-word; width: 150.0; height: 150.0">
        <a href=https://github.com/fkr>
            <img src=https://avatars.githubusercontent.com/u/51063?v=4 width="100;"  style="border-radius:50%;align-items:center;justify-content:center;overflow:hidden;padding-top:10px" alt=Felix Kronlage-Dammers/>
            <br />
            <sub style="font-size:14px"><b>Felix Kronlage-Dammers</b></sub>
        </a>
    </td>
    <td align="center" style="word-wrap: break-word; width: 150.0; height: 150.0">
        <a href=https://github.com/felixonmars>
            <img src=https://avatars.githubusercontent.com/u/1006477?v=4 width="100;"  style="border-radius:50%;align-items:center;justify-content:center;overflow:hidden;padding-top:10px" alt=Felix Yan/>
            <br />
            <sub style="font-size:14px"><b>Felix Yan</b></sub>
        </a>
    </td>
</tr>
<tr>
    <td align="center" style="word-wrap: break-word; width: 150.0; height: 150.0">
        <a href=https://github.com/JJGadgets>
            <img src=https://avatars.githubusercontent.com/u/5709019?v=4 width="100;"  style="border-radius:50%;align-items:center;justify-content:center;overflow:hidden;padding-top:10px" alt=JJGadgets/>
            <br />
            <sub style="font-size:14px"><b>JJGadgets</b></sub>
        </a>
    </td>
    <td align="center" style="word-wrap: break-word; width: 150.0; height: 150.0">
        <a href=https://github.com/madjam002>
            <img src=https://avatars.githubusercontent.com/u/679137?v=4 width="100;"  style="border-radius:50%;align-items:center;justify-content:center;overflow:hidden;padding-top:10px" alt=Jamie Greeff/>
            <br />
            <sub style="font-size:14px"><b>Jamie Greeff</b></sub>
        </a>
    </td>
    <td align="center" style="word-wrap: break-word; width: 150.0; height: 150.0">
        <a href=https://github.com/jimt>
            <img src=https://avatars.githubusercontent.com/u/180326?v=4 width="100;"  style="border-radius:50%;align-items:center;justify-content:center;overflow:hidden;padding-top:10px" alt=Jim Tittsler/>
            <br />
            <sub style="font-size:14px"><b>Jim Tittsler</b></sub>
        </a>
    </td>
    <td align="center" style="word-wrap: break-word; width: 150.0; height: 150.0">
        <a href=https://github.com/piec>
            <img src=https://avatars.githubusercontent.com/u/781471?v=4 width="100;"  style="border-radius:50%;align-items:center;justify-content:center;overflow:hidden;padding-top:10px" alt=Pierre Carru/>
            <br />
            <sub style="font-size:14px"><b>Pierre Carru</b></sub>
        </a>
    </td>
    <td align="center" style="word-wrap: break-word; width: 150.0; height: 150.0">
        <a href=https://github.com/rcursaru>
            <img src=https://avatars.githubusercontent.com/u/16259641?v=4 width="100;"  style="border-radius:50%;align-items:center;justify-content:center;overflow:hidden;padding-top:10px" alt=rcursaru/>
            <br />
            <sub style="font-size:14px"><b>rcursaru</b></sub>
        </a>
    </td>
    <td align="center" style="word-wrap: break-word; width: 150.0; height: 150.0">
        <a href=https://github.com/renovate-bot>
            <img src=https://avatars.githubusercontent.com/u/25180681?v=4 width="100;"  style="border-radius:50%;align-items:center;justify-content:center;overflow:hidden;padding-top:10px" alt=WhiteSource Renovate/>
            <br />
            <sub style="font-size:14px"><b>WhiteSource Renovate</b></sub>
        </a>
    </td>
</tr>
<tr>
    <td align="center" style="word-wrap: break-word; width: 150.0; height: 150.0">
        <a href=https://github.com/ryanfowler>
            <img src=https://avatars.githubusercontent.com/u/2668821?v=4 width="100;"  style="border-radius:50%;align-items:center;justify-content:center;overflow:hidden;padding-top:10px" alt=Ryan Fowler/>
            <br />
            <sub style="font-size:14px"><b>Ryan Fowler</b></sub>
        </a>
    </td>
    <td align="center" style="word-wrap: break-word; width: 150.0; height: 150.0">
        <a href=https://github.com/shaananc>
            <img src=https://avatars.githubusercontent.com/u/2287839?v=4 width="100;"  style="border-radius:50%;align-items:center;justify-content:center;overflow:hidden;padding-top:10px" alt=Shaanan Cohney/>
            <br />
            <sub style="font-size:14px"><b>Shaanan Cohney</b></sub>
        </a>
    </td>
    <td align="center" style="word-wrap: break-word; width: 150.0; height: 150.0">
        <a href=https://github.com/m-tanner-dev0>
            <img src=https://avatars.githubusercontent.com/u/97977342?v=4 width="100;"  style="border-radius:50%;align-items:center;justify-content:center;overflow:hidden;padding-top:10px" alt=Tanner/>
            <br />
            <sub style="font-size:14px"><b>Tanner</b></sub>
        </a>
    </td>
    <td align="center" style="word-wrap: break-word; width: 150.0; height: 150.0">
        <a href=https://github.com/Teteros>
            <img src=https://avatars.githubusercontent.com/u/5067989?v=4 width="100;"  style="border-radius:50%;align-items:center;justify-content:center;overflow:hidden;padding-top:10px" alt=Teteros/>
            <br />
            <sub style="font-size:14px"><b>Teteros</b></sub>
        </a>
    </td>
    <td align="center" style="word-wrap: break-word; width: 150.0; height: 150.0">
        <a href=https://github.com/gitter-badger>
            <img src=https://avatars.githubusercontent.com/u/8518239?v=4 width="100;"  style="border-radius:50%;align-items:center;justify-content:center;overflow:hidden;padding-top:10px" alt=The Gitter Badger/>
            <br />
            <sub style="font-size:14px"><b>The Gitter Badger</b></sub>
        </a>
    </td>
    <td align="center" style="word-wrap: break-word; width: 150.0; height: 150.0">
        <a href=https://github.com/tianon>
            <img src=https://avatars.githubusercontent.com/u/161631?v=4 width="100;"  style="border-radius:50%;align-items:center;justify-content:center;overflow:hidden;padding-top:10px" alt=Tianon Gravi/>
            <br />
            <sub style="font-size:14px"><b>Tianon Gravi</b></sub>
        </a>
    </td>
</tr>
<tr>
    <td align="center" style="word-wrap: break-word; width: 150.0; height: 150.0">
        <a href=https://github.com/woudsma>
            <img src=https://avatars.githubusercontent.com/u/6162978?v=4 width="100;"  style="border-radius:50%;align-items:center;justify-content:center;overflow:hidden;padding-top:10px" alt=Tjerk Woudsma/>
            <br />
            <sub style="font-size:14px"><b>Tjerk Woudsma</b></sub>
        </a>
    </td>
    <td align="center" style="word-wrap: break-word; width: 150.0; height: 150.0">
        <a href=https://github.com/y0ngb1n>
            <img src=https://avatars.githubusercontent.com/u/25719408?v=4 width="100;"  style="border-radius:50%;align-items:center;justify-content:center;overflow:hidden;padding-top:10px" alt=Yang Bin/>
            <br />
            <sub style="font-size:14px"><b>Yang Bin</b></sub>
        </a>
    </td>
    <td align="center" style="word-wrap: break-word; width: 150.0; height: 150.0">
        <a href=https://github.com/zekker6>
            <img src=https://avatars.githubusercontent.com/u/1367798?v=4 width="100;"  style="border-radius:50%;align-items:center;justify-content:center;overflow:hidden;padding-top:10px" alt=Zakhar Bessarab/>
            <br />
            <sub style="font-size:14px"><b>Zakhar Bessarab</b></sub>
        </a>
    </td>
    <td align="center" style="word-wrap: break-word; width: 150.0; height: 150.0">
        <a href=https://github.com/Bpazy>
            <img src=https://avatars.githubusercontent.com/u/9838749?v=4 width="100;"  style="border-radius:50%;align-items:center;justify-content:center;overflow:hidden;padding-top:10px" alt=Ziyuan Han/>
            <br />
            <sub style="font-size:14px"><b>Ziyuan Han</b></sub>
        </a>
    </td>
    <td align="center" style="word-wrap: break-word; width: 150.0; height: 150.0">
        <a href=https://github.com/derelm>
            <img src=https://avatars.githubusercontent.com/u/465155?v=4 width="100;"  style="border-radius:50%;align-items:center;justify-content:center;overflow:hidden;padding-top:10px" alt=derelm/>
            <br />
            <sub style="font-size:14px"><b>derelm</b></sub>
        </a>
    </td>
    <td align="center" style="word-wrap: break-word; width: 150.0; height: 150.0">
        <a href=https://github.com/nning>
            <img src=https://avatars.githubusercontent.com/u/557430?v=4 width="100;"  style="border-radius:50%;align-items:center;justify-content:center;overflow:hidden;padding-top:10px" alt=henning mueller/>
            <br />
            <sub style="font-size:14px"><b>henning mueller</b></sub>
        </a>
    </td>
</tr>
<tr>
    <td align="center" style="word-wrap: break-word; width: 150.0; height: 150.0">
        <a href=https://github.com/ignoramous>
            <img src=https://avatars.githubusercontent.com/u/852289?v=4 width="100;"  style="border-radius:50%;align-items:center;justify-content:center;overflow:hidden;padding-top:10px" alt=ignoramous/>
            <br />
            <sub style="font-size:14px"><b>ignoramous</b></sub>
        </a>
    </td>
    <td align="center" style="word-wrap: break-word; width: 150.0; height: 150.0">
        <a href=https://github.com/lion24>
            <img src=https://avatars.githubusercontent.com/u/1382102?v=4 width="100;"  style="border-radius:50%;align-items:center;justify-content:center;overflow:hidden;padding-top:10px" alt=lion24/>
            <br />
            <sub style="font-size:14px"><b>lion24</b></sub>
        </a>
    </td>
    <td align="center" style="word-wrap: break-word; width: 150.0; height: 150.0">
        <a href=https://github.com/pernila>
            <img src=https://avatars.githubusercontent.com/u/12460060?v=4 width="100;"  style="border-radius:50%;align-items:center;justify-content:center;overflow:hidden;padding-top:10px" alt=pernila/>
            <br />
            <sub style="font-size:14px"><b>pernila</b></sub>
        </a>
    </td>
    <td align="center" style="word-wrap: break-word; width: 150.0; height: 150.0">
        <a href=https://github.com/Wakeful-Cloud>
            <img src=https://avatars.githubusercontent.com/u/38930607?v=4 width="100;"  style="border-radius:50%;align-items:center;justify-content:center;overflow:hidden;padding-top:10px" alt=Wakeful-Cloud/>
            <br />
            <sub style="font-size:14px"><b>Wakeful-Cloud</b></sub>
        </a>
    </td>
    <td align="center" style="word-wrap: break-word; width: 150.0; height: 150.0">
        <a href=https://github.com/xpzouying>
            <img src=https://avatars.githubusercontent.com/u/3946563?v=4 width="100;"  style="border-radius:50%;align-items:center;justify-content:center;overflow:hidden;padding-top:10px" alt=zy/>
            <br />
            <sub style="font-size:14px"><b>zy</b></sub>
        </a>
    </td>
</tr>
</table>
