# Development builds

!!! warning

    Development builds are created automatically from the latest `main` branch
    and are **not versioned releases**. They may contain incomplete features,
    breaking changes, or bugs. Use them for testing only.

Each push to `main` produces container images and cross-compiled binaries.
Container images are multi-arch (amd64, arm64) and use the same distroless
base image as official releases.

## Container images

Images are available from both Docker Hub and GitHub Container Registry, tagged
with the short commit hash of the build (e.g. `main-abc1234`):

- Docker Hub: `docker.io/headscale/headscale:main-<sha>`
- GitHub Container Registry: `ghcr.io/juanfont/headscale:main-<sha>`

To find the latest available tag, check the
[GitHub Actions workflow](https://github.com/juanfont/headscale/actions/workflows/container-main.yml)
or the [GitHub Container Registry package page](https://github.com/juanfont/headscale/pkgs/container/headscale).

For example, to run a specific development build:

```shell
docker run \
  --name headscale \
  --detach \
  --read-only \
  --tmpfs /var/run/headscale \
  --volume "$(pwd)/config:/etc/headscale:ro" \
  --volume "$(pwd)/lib:/var/lib/headscale" \
  --publish 127.0.0.1:8080:8080 \
  --publish 127.0.0.1:9090:9090 \
  --health-cmd "CMD headscale health" \
  docker.io/headscale/headscale:main-<sha> \
  serve
```

See [Running headscale in a container](./container.md) for full container setup instructions.

## Binaries

Pre-built binaries from the latest successful build on `main` are available
via [nightly.link](https://nightly.link/juanfont/headscale/workflows/container-main/main):

| OS    | Arch  | Download                                                                                                                   |
| ----- | ----- | -------------------------------------------------------------------------------------------------------------------------- |
| Linux | amd64 | [headscale-linux-amd64](https://nightly.link/juanfont/headscale/workflows/container-main/main/headscale-linux-amd64.zip)   |
| Linux | arm64 | [headscale-linux-arm64](https://nightly.link/juanfont/headscale/workflows/container-main/main/headscale-linux-arm64.zip)   |
| macOS | amd64 | [headscale-darwin-amd64](https://nightly.link/juanfont/headscale/workflows/container-main/main/headscale-darwin-amd64.zip) |
| macOS | arm64 | [headscale-darwin-arm64](https://nightly.link/juanfont/headscale/workflows/container-main/main/headscale-darwin-arm64.zip) |

After downloading, make the binary executable and follow the
[standalone binary installation](./official.md#using-standalone-binaries-advanced)
instructions for setting up the service.
