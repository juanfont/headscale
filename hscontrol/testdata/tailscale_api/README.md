# Raw Tailscale API recordings

Transcripts of calls against the live Tailscale API, made on the tscap test
tailnet with disposable nodes and keys that each probe deleted again. They are
not in tscap's step format and no test reads them; the `/api/v2` tests cite
their row IDs (`probe-U U5k`) in the comments that explain why Headscale
answers as it does.

Each file states its own time and setup in its first lines. Secrets are cut to
`…-REDACTED`, the public IP to `REDACTED-IP`, and the tailnet owner's login to
`REDACTED-USER`. Keep every file as it is; a new recording is a new file.

| File      | What it records                                                  |
| --------- | ---------------------------------------------------------------- |
| `probe-A` | auth keys with tags in and out of the policy, admin API key      |
| `probe-G` | key and OAuth client errors, delete and read-after-delete        |
| `probe-J` | device calls: tags, authorized, attributes, delete               |
| `probe-N` | one exit prefix enabled, as the node sees it                     |
| `probe-P` | one exit prefix enabled, as a peer sees it                       |
| `probe-Q` | an OAuth token deleting its own client                           |
| `probe-R` | tags of a new OAuth client, admin API key                        |
| `probe-T` | keys, OAuth clients, descriptions, listing with `all=true`       |
| `probe-U` | OAuth token rules: tags, scopes, refusals by scope, key listing  |
| `probe-V` | devices by token scope; tag writes by tagged tokens              |
| `probe-W` | keys in use, joins with ended keys, description characters       |
