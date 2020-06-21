# headscale
An open source implementation of the Tailscale coordination server.


## Disclaimer

1. I have nothing to do with Tailscale, or Tailscale Inc. Just a fan of their tech.
2. The purpose of writing this was to learn a bit how Tailscale works. Hence the emojis in the log messages and other terrible code.
3. I don't use Headscale myself (their Solo plan + DERP infra is way more convenient).
4. Headscale adds all the machines under the same user. Be careful!


## Running it

1. Compile the headscale binary
  ```
  go build cmd/headscale/headscale.go 
  ```
  
2. Get youself a PostgreSQL DB running. 

  ``` 
  docker run --name headscale -e POSTGRES_DB=headscale -e \
    POSTGRES_USER=foo -e POSTGRES_PASSWORD=bar -p 5432:5432 -d postgres
  ```

3. Sort some stuff up (headscale Wireguard keys & the config.json file)
  ```
  wg genkey > private.key
  wg pubkey < private.key > public.key
  cp config.json.example config.json
  ```

4. Run it
  ```
  ./headcale
  ```
  
5. Add your first machine
  ```
  tailscale up -login-server YOUR_HEADSCALE_URL
  ```
