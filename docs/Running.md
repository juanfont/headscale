# Running headscale

## Server configuration
1. Download the headscale binary https://github.com/juanfont/headscale/releases, and place it somewhere in your $PATH or use the docker container

   ```shell
   docker pull headscale/headscale:x.x.x
   ```

   <!--
    or
    ```shell
    docker pull ghrc.io/juanfont/headscale:x.x.x
    ``` -->

2. When running headscale in a docker container, prepare a directory to hold all configuration

   ```shell
   mkdir config
   ```
   
3. Get yourself a DB

   a) Get a Postgres DB running in docker
   ```shell
   docker run --name headscale \
     -e POSTGRES_DB=headscale
     -e POSTGRES_USER=foo \
     -e POSTGRES_PASSWORD=bar \
     -p 5432:5432 \
     -d postgres
   ```
   or b) Prepare a SQLite DB file
   ```shell
   touch config/db.sqlite
   ```

4. Create a WireGuard private key, headscale configuration, and a DERP map file. Refer to [tailscale sample](https://raw.githubusercontent.com/tailscale/tailscale/main/net/dnsfallback/dns-fallback-servers.json) for more guidance.

   ```shell
   wg genkey > config/private.key

   cp config.yaml.[sqlite|postgres].example config/config.yaml
   
   cp derp-example.yaml config/derp.yaml
   ```

5. Create a namespace

   ```shell
   headscale namespaces create myfirstnamespace
   ```

   or docker:

   ```shell
   docker run \
     -v $(pwd)/config:/etc/headscale/ \
     -p 127.0.0.1:8080:8080 \
     headscale/headscale:x.x.x \
     headscale namespaces create myfirstnamespace
   ```

   or if your server is already running in docker:

   ```shell
   docker exec <container_name> headscale namespaces create myfirstnamespace
   ```

6. Run the server

   ```shell
   headscale serve
   ```

   or docker:

   ```shell
   docker run \
     -v $(pwd)/config:/etc/headscale/ \
     -p 127.0.0.1:8080:8080 \
     headscale/headscale:x.x.x headscale serve
   ```
## Nodes configuration

If you used tailscale.com before in your nodes, make sure you clear the tailscaled data folder

   ```shell
   systemctl stop tailscaled
   rm -fr /var/lib/tailscale
   systemctl start tailscaled
   ```
### Adding node based on MACHINEKEY
1. Add your first machine

   ```shell
   tailscale up --login-server YOUR_HEADSCALE_URL
   ```

2. Navigate to the URL returned by `tailscale up`, where you'll find your machine key.

3. In the server, register your machine to a namespace with the CLI
   ```shell
   headscale -n myfirstnamespace nodes register YOURMACHINEKEY
   ```
   or docker:
   ```shell
   docker run \
     -v $(pwd)/config:/etc/headscale/ \
     headscale/headscale:x.x.x \
     headscale -n myfirstnamespace nodes register YOURMACHINEKEY
   ```
   or if your server is already running in docker:
   ```shell
   docker exec <container_name> headscale -n myfirstnamespace nodes register YOURMACHINEKEY
   ```

### Alternative: adding node with AUTHKEY

1. Create an authkey

   ```shell
   headscale -n myfirstnamespace preauthkeys create --reusable --expiration 24h
   ```

   or docker:

   ```shell
   docker run \
     -v $(pwd)/config:/etc/headscale/ \
     headscale/headscale:x.x.x \
     headscale -n myfirstnamespace preauthkeys create --reusable --expiration 24h
   ```

   or if your server is already running in docker:

   ```shell
   docker exec <container_name> headscale -n myfirstnamespace preauthkeys create --reusable --expiration 24h
   ```

2. Use the authkey on your node to register it
   ```shell
   tailscale up --login-server YOUR_HEADSCALE_URL --authkey YOURAUTHKEY
   ```

If you create an authkey with the `--ephemeral` flag, that key will create ephemeral nodes. This implies that `--reusable` is true.

Please bear in mind that all headscale commands support adding `-o json` or `-o json-line` to get nicely JSON-formatted output.
