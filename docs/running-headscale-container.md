# Running headscale in a container

**Note:** the container documentation is maintained by the _community_ and there is no guarentee
it is up to date, or working.

## Goal

This documentation has the goal of showing a user how-to set up and run `headscale` in a container.
[Docker](https://www.docker.com) is used as the reference container implementation, but there is no reason that it should
not work with alternatives like [Podman](https://podman.io).

## Configure and run `headscale`

1. Prepare a direction to hold `headscale` configuration and the [SQLite](https://www.sqlite.org/) database:

```shell
mkdir config
```

2. Create an empty SQlite datebase:

```shell
touch config/db.sqlite
```

3. Create a `headscale` configuration:

```shell
touch config/config.yaml
```

It is **strongly recommended** to copy the [example configuration](../config.yaml) from the [headscale repository](../)

4. Start the headscale server:

```shell
docker run \
  --name headscale \
  --detach \
  --rm \
  --volume $(pwd)/config:/etc/headscale/ \
  --publish 127.0.0.1:8080:8080 \
  headscale/headscale:<VERSION> \
  headscale serve

```

This command will mount `config/` under `/etc/headscale`, forward port 8080 out of the container so the
`headscale` instance becomes available and then detach so headscale runs in the background.

5. Verify `headscale` is running:

Follow the container logs:

```shell
docker logs --follow headscale
```

Verify running containers:

```shell
docker ps
```

Verify `headscale` is available:

```shell
curl http://127.0.0.1:8080/metrics
```

6. Create a namespace ([tailnet](https://tailscale.com/kb/1136/tailnet/)):

```shell
docker exec headscale -- headscale namespaces create myfirstnamespace
```

### Register a machine (normal login)

On a client machine, execute the `tailscale` login command:

```shell
tailscale up --login-server YOUR_HEADSCALE_URL
```

To register a machine when running `headscale` in a container, take the headscale command and pass it to the container:

```shell
docker exec headscale -- \
  headscale --namespace myfirstnamespace nodes register --key <YOU_+MACHINE_KEY>
```

### Register machine using a pre authenticated key

Generate a key using the command line:

```shell
docker exec headscale -- \
  headscale --namespace myfirstnamespace preauthkeys create --reusable --expiration 24h
```

This will return a pre-authenticated key that can be used to connect a node to `headscale` during the `tailscale` command:

```shell
tailscale up --login-server <YOUR_HEADSCALE_URL> --authkey <YOUR_AUTH_KEY>
```

## Debugging headscale running in Docker

The `headscale/headscale` Docker container is based on a "distroless" image that does not contain a shell or any other debug tools. If you need to debug your application running in the Docker container, you can use the `-debug` variant, for example `headscale/headscale:x.x.x-debug`.

### Running the debug Docker container

To run the debug Docker container, use the exact same commands as above, but replace `headscale/headscale:x.x.x` with `headscale/headscale:x.x.x-debug` (`x.x.x` is the version of headscale). The two containers are compatible with each other, so you can alternate between them.

### Executing commands in the debug container

The default command in the debug container is to run `headscale`, which is located at `/bin/headscale` inside the container.

Additionally, the debug container includes a minimalist Busybox shell.

To launch a shell in the container, use:

```
docker run -it headscale/headscale:x.x.x-debug sh
```

You can also execute commands directly, such as `ls /bin` in this example:

```
docker run headscale/headscale:x.x.x-debug ls /bin
```

Using `docker exec` allows you to run commands in an existing container.
