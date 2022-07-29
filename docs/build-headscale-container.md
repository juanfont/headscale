# Build docker from scratch

The Dockerfiles included in the repository are using the [buildx plugin](https://docs.docker.com/buildx/working-with-buildx/). This plugin is includes in docker newer than Docker-ce CLI 19.03.2. The plugin is used to be able to build different container arches. Building the Dockerfiles without buildx is not possible.

# Build native

To build the container on the native arch you can just use:
```
$ sudo docker buildx build -t headscale:custom-arch .
```

For example: This will build a amd64(x86_64) container if your hostsystem is amd64(x86_64). Or a arm64 container on a arm64 hostsystem (raspberry pi4).

# Build cross platform

To build a arm64 container on a amd64 hostsystem you could use:
```
$ sudo docker buildx build --platform linux/arm64 -t headscale:custom-arm64 .

```

**Import: Currently arm32 build are not supported as there is a problem with a library used by headscale. Hopefully this will be fixed soon.**

# Build multiple arches

To build multiple archres you could use:

```
$ sudo docker buildx create --use
$ sudo docker buildx build --platform linux/amd64,linux/arm64 .

```
