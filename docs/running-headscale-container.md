# Running headscale in a container

!!! warning "Community documentation"

    This page is not actively maintained by the headscale authors and is
    written by community members. It is _not_ verified by `headscale` developers.

    **It might be outdated and it might miss necessary steps**.
    
    Last update : 01/05/2023 - Headscale 0.22.1
 
## Goal

This documentation has the goal of showing a user how-to set up and run `headscale` in a [Docker](https://www.docker.com) container.

The Docker image can be found on Docker Hub [here](https://hub.docker.com/r/headscale/headscale).

## Configure and run `headscale`

# 1. Prepare a directory on the host Docker node in your directory of choice, used to hold `headscale` files. 

```shell
mkdir -p ./headscale/config && cd ./headscale/config
``` 
    
!!! info "Database"
    
    This tutorial uses SQLite for simplicity reasons, in a large environnement, it's recommended to use Postgres,  
    please refer the configuration file
    
# 2. Create an empty [SQLite](https://www.sqlite.org/) datebase in the headscale directory:

```shell
touch ./config/db.sqlite
```

# 3. Create an ACL file in the headscale directory:

```shell
touch ./config/ACL.json
```

Edit the file and put a base ACL in it :

```json
{
    "acls": [
      { "action": "accept", "src": ["*:*"], "dst": ["*:*"] }
    ]
}  
```

# 4. Download a copy of the [example configuration][config-example.yaml](https://github.com/juanfont/headscale/blob/main/config-example.yaml) from the headscale repository and place it at ./config/config.yaml

```shell
wget -O ./config/config.yaml https://raw.githubusercontent.com/juanfont/headscale/main/config-example.yaml || curl https://raw.githubusercontent.com/juanfont/headscale/main/config-example.yaml -o ./config/config.yaml
```

Modify the config file to your preferences before launching Docker container.
Here are some settings that you likely want to change:

Change `Headscale's` server url to your hostname or host IP

```yaml
server_url: http://your-host-name:8080
```

Listen to 0.0.0.0 so the services are accessible outside the container

```yaml
listen_addr: 0.0.0.0:8080 #For Headscale
metrics_listen_addr: 0.0.0.0:9090 #For the metrics 
```

Bind the ACL file we created above:

```yaml
acl_policy_path: "/etc/headscale/ACL.json"
```

!!! warning "/var/lib isn't an editable path in the container"

    Because /var/lib isn't an editable path in the container, we will need to replace
    in the config file all those /var/lib paths to /etc.
    
    Example :
    ```yaml
    # The default /var/lib path is not writable in the container
    private_key_path: /etc/headscale/private.key
    ```

# 5. Start the headscale server while working in the host headscale directory:

Replace <VERSION> with the current version, and your good to go !

```shell
docker run \
  --name headscale \
  --detach \
  --restart unless-stopped \
  --volume $(pwd)/config:/etc/headscale/ \
  --publish 127.0.0.1:8080:8080 \
  --publish 127.0.0.1:9090:9090 \
  headscale/headscale:<VERSION> \
  headscale serve

```

!!! note "About the docker run command"
    
    Use `0.0.0.0:8080:8080` instead of `127.0.0.1:8080:8080` if you want to expose the container externally.

    This command will mount `config/` (outside the container) under `/etc/headscale` (inside the container), 
    forward port 8080 out of the container so the `headscale` instance becomes available and then detach so 
    headscale runs in the background.
    
    The restart flag will made the instance restart unless if you stopped it manually

# 6. Verify `headscale` is running:

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

# 7. Launch command in the container :
 
```shell    
docker exec headscale <COMMAND>
```
    
!!! note "Debugging & using a shell with Headscale"

    The `headscale/headscale` Docker container does not contain a shell or any other debug tools. 
    If you need to debug your application running in the Docker container, you can use the 
    `-debug` variant, for example `headscale/headscale:0.22.1-debug`.


    To run the debug Docker container, use the exact same run command as above, but replace         
    `headscale/headscale:<VERSION>` with `headscale/headscale:<VERSION>-debug`. The two 
    containers are compatible with each other, so you can alternate between them.


    To launch a shell in the container, use:

    ```
    docker run -it headscale sh
    ```
