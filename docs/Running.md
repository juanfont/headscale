# Running headscale

1. Download the headscale binary https://github.com/juanfont/headscale/releases, and place it somewhere in your $PATH or use the docker container

   ```shell
   docker pull headscale/headscale:x.x.x
   ```

   <!--
    or
    ```shell
    docker pull ghrc.io/juanfont/headscale:x.x.x
    ``` -->

2. (Optional, you can also use SQLite) Get yourself a PostgreSQL DB running

   ```shell
   docker run --name headscale -e POSTGRES_DB=headscale -e \
     POSTGRES_USER=foo -e POSTGRES_PASSWORD=bar -p 5432:5432 -d postgres
   ```

3. Create a WireGuard private key and headscale configuration

   ```shell
   wg genkey > private.key

   cp config.yaml.example config.yaml
   ```

4. Create a namespace

   ```shell
   headscale namespaces create myfirstnamespace
   ```

   or docker:

   the db.sqlite mount is only needed if you use sqlite

   ```shell
   touch db.sqlite
   docker run \
     -v $(pwd)/private.key:/private.key \
     -v $(pwd)/config.json:/config.json \
     -v $(pwd)/derp.yaml:/derp.yaml \
     -v $(pwd)/db.sqlite:/db.sqlite \
     -p 127.0.0.1:8080:8080 \
     headscale/headscale:x.x.x \
     headscale namespaces create myfirstnamespace
   ```

   or if your server is already running in docker:

   ```shell
   docker exec <container_name> headscale create myfirstnamespace
   ```

5. Run the server

   ```shell
   headscale serve
   ```

   or docker:

   the db.sqlite mount is only needed if you use sqlite

   ```shell
   docker run \
     -v $(pwd)/private.key:/private.key \
     -v $(pwd)/config.json:/config.json \
     -v $(pwd)/derp.yaml:/derp.yaml \
     -v $(pwd)/db.sqlite:/db.sqlite \
     -p 127.0.0.1:8080:8080 \
     headscale/headscale:x.x.x headscale serve
   ```

6. If you used tailscale.com before in your nodes, make sure you clear the tailscaled data folder

   ```shell
   systemctl stop tailscaled
   rm -fr /var/lib/tailscale
   systemctl start tailscaled
   ```

7. Add your first machine

   ```shell
   tailscale up --login-server YOUR_HEADSCALE_URL
   ```

8. Navigate to the URL you will get with `tailscale up`, where you'll find your machine key.

9. In the server, register your machine to a namespace with the CLI
   ```shell
   headscale -n myfirstnamespace nodes register YOURMACHINEKEY
   ```
   or docker:
   ```shell
   docker run \
     -v $(pwd)/private.key:/private.key \
     -v $(pwd)/config.json:/config.json \
     -v $(pwd)/derp.yaml:/derp.yaml \
     headscale/headscale:x.x.x \
     headscale -n myfirstnamespace nodes register YOURMACHINEKEY
   ```
   or if your server is already running in docker:
   ```shell
   docker exec <container_name> headscale -n myfirstnamespace nodes register YOURMACHINEKEY
   ```

Alternatively, you can use Auth Keys to register your machines:

1. Create an authkey

   ```shell
   headscale -n myfirstnamespace preauthkeys create --reusable --expiration 24h
   ```

   or docker:

   ```shell
   docker run \
     -v $(pwd)/private.key:/private.key \
     -v $(pwd)/config.json:/config.json \
     -v$(pwd)/derp.yaml:/derp.yaml \
     -v $(pwd)/db.sqlite:/db.sqlite \
     headscale/headscale:x.x.x \
     headscale -n myfirstnamespace preauthkeys create --reusable --expiration 24h
   ```

   or if your server is already running in docker:

   ```shell
   docker exec <container_name> headscale -n myfirstnamespace preauthkeys create --reusable --expiration 24h
   ```

2. Use the authkey from your machine to register it
   ```shell
   tailscale up --login-server YOUR_HEADSCALE_URL --authkey YOURAUTHKEY
   ```

If you create an authkey with the `--ephemeral` flag, that key will create ephemeral nodes. This implies that `--reusable` is true.

Please bear in mind that all headscale commands support adding `-o json` or `-o json-line` to get nicely JSON-formatted output.