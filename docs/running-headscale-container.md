# Running headscale in a container

!!! warning "Community documentation"

    This page is not actively maintained by the headscale authors and is
    written by community members. It is _not_ verified by `headscale` developers.

    **It might be outdated and it might miss necessary steps**.

## Goal

This documentation has the goal of showing a user how-to set up and run `headscale` in a container.
[Docker](https://www.docker.com) is used as the reference container implementation, but there is no reason that it should
not work with alternatives like [Podman](https://podman.io). The Docker image can be found on Docker Hub [here](https://hub.docker.com/r/headscale/headscale).

## Configure and run `headscale`

1. Prepare a directory on the host Docker node in your directory of choice, used to hold `headscale` configuration and the [SQLite](https://www.sqlite.org/) database:

    ```shell
    mkdir -p ./headscale/config
    cd ./headscale
    ```

1. Create an empty SQlite datebase in the headscale directory:

    ```shell
    touch ./config/db.sqlite
    ```

1. **(Strongly Recommended)** Download a copy of the [example configuration](https://github.com/juanfont/headscale/blob/main/config-example.yaml) from the headscale repository.

    - Using `wget`:

        ```shell
        wget -O ./config/config.yaml https://raw.githubusercontent.com/juanfont/headscale/main/config-example.yaml
        ```

    - Using `curl`:

        ```shell
        curl https://raw.githubusercontent.com/juanfont/headscale/main/config-example.yaml -o ./config/config.yaml
        ```

    - **(Advanced)** If you would like to hand craft a config file **instead** of downloading the example config file, create a blank `headscale` configuration in the headscale directory to edit:

        ```shell
        touch ./config/config.yaml
        ```

        Modify the config file to your preferences before launching Docker container.
        Here are some settings that you likely want:

        ```yaml
        # Change to your hostname or host IP
        server_url: http://your-host-name:8080
        # Listen to 0.0.0.0 so it's accessible outside the container
        metrics_listen_addr: 0.0.0.0:9090
        # The default /var/lib/headscale path is not writable in the container
        noise:
          private_key_path: /etc/headscale/noise_private.key
        # The default /var/lib/headscale path is not writable in the container
        derp:
          private_key_path: /etc/headscale/private.key
        # The default /var/run/headscale path is not writable  in the container
        unix_socket: /etc/headscale/headscale.sock
        # The default /var/lib/headscale path is not writable  in the container
        database.type: sqlite3
        database.sqlite.path: /etc/headscale/db.sqlite
        ```

        Alternatively, you can mount `/var/lib` and `/var/run` from your host system by adding
        `--volume $(pwd)/lib:/var/lib/headscale` and `--volume $(pwd)/run:/var/run/headscale`
        in the next step.

1. Start the headscale server while working in the host headscale directory:

    ```shell
    docker run \
      --name headscale \
      --detach \
      --volume $(pwd)/config:/etc/headscale/ \
      --publish 127.0.0.1:8080:8080 \
      --publish 127.0.0.1:9090:9090 \
      headscale/headscale:<VERSION> \
      headscale serve
    ```

    Note: use `0.0.0.0:8080:8080` instead of `127.0.0.1:8080:8080` if you want to expose the container externally.

    This command will mount `config/` under `/etc/headscale`, forward port 8080 out of the container so the
    `headscale` instance becomes available and then detach so headscale runs in the background.

    Example `docker-compose.yaml`

      ```yaml
      version: "3.7"
      
      services:
        headscale:
          image: headscale/headscale:0.22.3
          restart: unless-stopped
          container_name: headscale
          ports:
            - "127.0.0.1:8080:8080"
            - "127.0.0.1:9090:9090"
          volumes:
            # pls change [config_path] to the fullpath of the config folder just created
            - [config_path]:/etc/headscale
          command: headscale serve
      ```

1. Verify `headscale` is running:
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
    curl http://127.0.0.1:9090/metrics
    ```

1. Create a user ([tailnet](https://tailscale.com/kb/1136/tailnet/)):

    ```shell
    docker exec headscale \
    headscale users create myfirstuser
    ```

### Register a machine (normal login)

On a client machine, execute the `tailscale` login command:

```shell
tailscale up --login-server YOUR_HEADSCALE_URL
```

To register a machine when running `headscale` in a container, take the headscale command and pass it to the container:

```shell
docker exec headscale \
  headscale --user myfirstuser nodes register --key <YOU_+MACHINE_KEY>
```

### Register machine using a pre authenticated key

Generate a key using the command line:

```shell
docker exec headscale \
  headscale --user myfirstuser preauthkeys create --reusable --expiration 24h
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
