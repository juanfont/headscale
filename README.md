# Headscale
An open source implementation of the Tailscale coordination server.


## Status

- [x] Basic functionality (nodes can communicate with each other)
- [x] Node registration through the web flow
- [x] Network changes are relied to the nodes
- [x] ~~Multiuser~~ Namespace support
- [x] Basic routing (advertise & accept) 
- [ ] Share nodes between ~~users~~ namespaces
- [ ] Node registration via pre-auth keys
- [ ] ACLs
- [ ] DNS

... and probably lots of stuff missing

## Roadmap 🤷

Basic multiuser support (multinamespace, actually) is now implemented. No node sharing or ACLs between namespaces yet though...

Pre-auth keys should also be feasible.

Suggestions/PRs welcomed!



## Running it

1. Compile the headscale binary
  ```shell
  go build cmd/headscale/headscale.go 
  ```
  
2. Get youself a PostgreSQL DB running (yes, [I know](https://tailscale.com/blog/an-unlikely-database-migration/))

  ```shell 
  docker run --name headscale -e POSTGRES_DB=headscale -e \
    POSTGRES_USER=foo -e POSTGRES_PASSWORD=bar -p 5432:5432 -d postgres
  ```

3. Sort some stuff up (headscale Wireguard keys & the config.json file)
  ```shell
  wg genkey > private.key
  wg pubkey < private.key > public.key  # not needed 
  cp config.json.example config.json
  ```

4. Create a namespace (equivalent to a user in tailscale.com)
  ```shell
  ./headscale namespace create myfirstnamespace
  ```

5. Run the server
  ```shell
  ./headscale serve
  ```
  
6. Add your first machine
  ```shell
  tailscale up -login-server YOUR_HEADSCALE_URL
  ```

7. Navigate to the URL you will get with `tailscale up`, where you'll find your machine key.

8. In the server, register your machine to a namespace with the CLI
  ```shell
  ./headscale register YOURMACHINEKEY myfirstnamespace
  ```


## Disclaimer

1. I have nothing to do with Tailscale, or Tailscale Inc. 
2. The purpose of writing this was to learn how Tailscale works.
3. I don't use Headscale myself.

