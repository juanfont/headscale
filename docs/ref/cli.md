<!-- Generated from the command specs by `headscale generate cli-reference`; do not edit. -->

# Command line reference

!!! note "Generated page"

    This page is generated from the command specs in `cmd/headscale` by `headscale generate cli-reference`.
    Edit the specs, not this page. `man headscale` shows the same.

## Command tree

```text
headscale is an open source implementation of the Tailscale control server

Local commands (no server needed):

  serve                               Run the control server
  version                             Print the version
  check config [file]                 Check a config file
  check policy <file>                 Check a policy file and run its tests
  check derp-map <file>               Check a DERP map file
  check extra-records <file>          Check an extra records file
  check all [config-file]             Check the config and every file it points at
  generate private-key                Print a new private key
  generate config                     Print a configuration file with every key
  generate nixos-options              Print the NixOS options for services.headscale.settings
  generate cli-reference              Print the reference page of the command line
  generate man                        Print the man page
  completion <shell>                  Print the completion script of a shell

Server commands (talk to a running headscale):

  nodes list                          List the nodes (alias: ls)
  nodes get <node>                    Show one node
  nodes set <node>                    Change the name or expiry of a node
  nodes expire <node>                 Log a node out
  nodes delete <node>                 Delete a node (alias: rm)
  nodes update-client <node>          Ask a node to update its Tailscale client
  nodes routes list [node]            List routes (alias: ls)
  nodes routes set <node> <routes>    Replace the enabled routes of a node (alias: approve)
  nodes routes clear <node>           Remove all enabled routes of a node
  nodes tags list [node]              List tags and their nodes (alias: ls)
  nodes tags set <node> <tags>        Replace the tags of a node
  users list                          List the users (alias: ls)
  users get <user>                    Show one user
  users create <name>                 Create a local user
  users set <user>                    Change a local user
  users delete <user>                 Delete a user with its keys (alias: rm)
  auth register <auth-id> <user>      Register a node that waits to join
  auth approve <auth-id>              Let an SSH check pass
  auth reject <auth-id>               Refuse a registration or an SSH check
  auth keys list                      List the auth keys (alias: ls)
  auth keys get <key>                 Show one auth key
  auth keys create <owner>            Create an auth key
  auth keys delete <key>              Revoke an auth key (alias: rm)
  api whoami                          Show who the server sees calling
  api keys list                       List the API keys (alias: ls)
  api keys get <key>                  Show one API key
  api keys create                     Create an API key
  api keys delete <key>               Revoke an API key (alias: rm)
  api oauth-clients list              List the OAuth clients (alias: ls)
  api oauth-clients get <client>      Show one OAuth client
  api oauth-clients create <scopes>   Create an OAuth client
  api oauth-clients delete <client>   Revoke an OAuth client (alias: rm)
  policy get                          Print the policy
  policy set <file>                   Replace the policy
  policy reload                       Read the policy again from where it is kept

Debug:

  debug health                        Check that the server is healthy
  debug create-node                   Make a registration of a made-up node, for tests
  debug mockoidc                      Run a mock OIDC server for tests

Server commands take -o json, which prints the API object.
See `headscale <command> --help` for examples.
```

## Global flags

| Flag        | Short | On                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| ----------- | ----- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `--output`  | `-o`  | `version`, `nodes list`, `nodes get`, `nodes set`, `nodes expire`, `nodes delete`, `nodes update-client`, `nodes routes list`, `nodes routes set`, `nodes routes clear`, `nodes tags list`, `nodes tags set`, `users list`, `users get`, `users create`, `users set`, `users delete`, `auth register`, `auth approve`, `auth reject`, `auth keys list`, `auth keys get`, `auth keys create`, `auth keys delete`, `api whoami`, `api keys list`, `api keys get`, `api keys create`, `api keys delete`, `api oauth-clients list`, `api oauth-clients get`, `api oauth-clients create`, `api oauth-clients delete`, `policy get`, `policy set`, `policy reload`, `debug health` |
| `--config`  | `-c`  | every server command, and `serve`, `version`, `check config`, `check all`, `generate config`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| `--help`    | `-h`  | every command                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| `--version` |       | `headscale` alone                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |

## Short flags

A short flag has one meaning in the whole CLI. Every other flag is long only.

| Short | Long            | On                                                 |
| ----- | --------------- | -------------------------------------------------- |
| `-c`  | `--config`      | see [Global flags](#global-flags)                  |
| `-d`  | `--description` | `auth keys create`, `api oauth-clients create`     |
| `-e`  | `--expiry`      | `nodes set`, `auth keys create`, `api keys create` |
| `-h`  | `--help`        | see [Global flags](#global-flags)                  |
| `-o`  | `--output`      | see [Global flags](#global-flags)                  |
| `-u`  | `--user`        | `api keys create`                                  |

## Aliases

| Alias     | Means    | On                                                                                                                              |
| --------- | -------- | ------------------------------------------------------------------------------------------------------------------------------- |
| `ls`      | `list`   | `nodes list`, `nodes routes list`, `nodes tags list`, `users list`, `auth keys list`, `api keys list`, `api oauth-clients list` |
| `rm`      | `delete` | `nodes delete`, `users delete`, `auth keys delete`, `api keys delete`, `api oauth-clients delete`                               |
| `approve` | `set`    | `nodes routes set`                                                                                                              |

## Commands

### headscale serve

Run the control server.

```text
Run the headscale control server until it gets SIGINT, SIGTERM or
SIGQUIT, and exit 0 then.

The configuration is the file that --config or HEADSCALE_CONFIG names, or
the first file found in /etc/headscale, $XDG_CONFIG_HOME/headscale,
headscale under each $XDG_CONFIG_DIRS entry, ~/.headscale and the working
directory, with the HEADSCALE_* variables of the environment. Each
directory is searched for config.json, config.toml, config.yaml,
config.yml, config.hujson, config.dotenv and config.env, in that order; a
.toml, .dotenv or .env file, a format of old releases, is an error, and the
search does not go past it. Without a file, the defaults and the
environment are the configuration, and the log says so.

The log goes to stderr, or to stdout as JSON with log.format: json. At
startup, serve checks GitHub for a newer release in the background and logs
one line when there is one; disable_check_updates turns this off.

serve exits 78 (EX_CONFIG) when the configuration file it loaded is wrong,
which a restart cannot fix, and 1 for every other failure. The systemd
units of headscale do not restart it on 78.

Usage:

  headscale serve [flags]

Examples:

  headscale serve
  headscale serve -c config.yaml

Flags:

  -c, --config string   Config file
  -h, --help            Show this help
```

### headscale version

Print the version.

```text
Print the version of headscale, and check GitHub for a newer release.

The hint about a newer release goes to stderr. The check has a short
timeout; when it fails, no hint is printed and the command still succeeds.
The config key disable_check_updates turns the check off. A build that is
not a release does not check.

With -o json the command prints the version with the keys Version, Commit,
BuildTime, Go and Dirty.

Usage:

  headscale version [flags]

Examples:

  headscale version
  headscale version -o json

Flags:

  -o, --output string   Output format: json
  -c, --config string   Config file
  -h, --help            Show this help
```

### headscale check config

Check a config file.

```text
Check the configuration: its syntax, its keys and its values.

Unknown and removed keys are errors. The files that the configuration names
are not checked; check all does that. Without a file, the command checks
the file that --config or HEADSCALE_CONFIG names, or the one that serve
finds, and the environment; with one, it does not look at --config or
HEADSCALE_CONFIG. The file - reads the configuration from stdin, as HuJSON
when it starts with { or [ after space and comments, and as YAML
otherwise; paths in it are relative to the working directory.

It prints one line to stdout when the configuration is valid. Otherwise it
prints the reason to stderr and exits 1. What the configuration warns about
goes to stderr either way, as "warning: ...".

It needs no server and no database, and it writes no file.

Usage:

  headscale check config [file] [flags]

  [file] is the config file, or - for stdin; by default the one --config names or serve finds.

Examples:

  headscale check config
  headscale check config config.yaml

Flags:

  -c, --config string   Config file
  -h, --help            Show this help
```

### headscale check policy

Check a policy file and run its tests.

```text
Check a policy file and run its "tests" and "sshTests".

The tests run against stand-in users and nodes built from the policy
itself, one for each user and tag it names, not against your tailnet. A
host alias or an IP address matches no stand-in, so an SSH test that names
one is always denied. To test a policy against the users and nodes of a
running server, use policy set --dry-run.

The file - reads the policy from stdin, as in
"generate-policy.sh | headscale check policy -".

It prints one line to stdout when the policy is valid and its tests pass.
Otherwise it prints the reason to stderr and exits 1. It needs no server,
no database and no config, and it writes no file.

Usage:

  headscale check policy <file> [flags]

  <file> is the file to check, or - for stdin.

Examples:

  headscale check policy policy.hujson

Flags:

  -h, --help   Show this help
```

### headscale check derp-map

Check a DERP map file.

```text
Check a DERP map file, as derp.paths names one: its format, its keys and
its regions. The extension names the format, .json, .hujson, .yaml or .yml;
stdin, the file -, is read as HuJSON when it starts with { or [ after space
and comments, and as YAML otherwise.

It prints one line to stdout when the file is valid. Otherwise it prints the
reason to stderr and exits 1. It needs no server and no config.

Usage:

  headscale check derp-map <file> [flags]

  <file> is the file to check, or - for stdin.

Examples:

  headscale check derp-map derp.yaml

Flags:

  -h, --help   Show this help
```

### headscale check extra-records

Check an extra records file.

```text
Check a file of extra DNS records, as dns.extra_records_path names one.
The extension names the format, .json, .hujson, .yaml or .yml; stdin, the
file -, is read as HuJSON when it starts with { or [ after space and
comments, and as YAML otherwise.

It prints one line to stdout when the file is valid. Otherwise it prints the
reason to stderr and exits 1. It needs no server and no config.

Usage:

  headscale check extra-records <file> [flags]

  <file> is the file to check, or - for stdin.

Examples:

  headscale check extra-records records.json

Flags:

  -h, --help   Show this help
```

### headscale check all

Check the config and every file it points at.

```text
Check the configuration, then each file it names: the policy, the DERP
maps, the extra records, the TLS certificate and key, and the private keys.

It prints its whole report to stdout, one line per file: ok, FAIL with the
error below it, or skip. Skip is a key file that startup creates when it is
missing, or a "file:<path>" secret, which no check reads. It exits 1 when a
line is FAIL. A derp.paths file that fails to parse is FAIL here, although
startup only skips it with a warning.

Without a file, the command checks the file that --config or
HEADSCALE_CONFIG names, or the one that serve finds; with one, it does not
look at --config or HEADSCALE_CONFIG. The file - reads the configuration
from stdin, as check config does. What the configuration warns about goes
to stderr, as "warning: ...". It needs no server and no database, and it
writes no file.

Usage:

  headscale check all [config-file] [flags]

  [config-file] is the config file, or - for stdin; by default the one --config names or serve finds.

Examples:

  headscale check all
  headscale check all config.yaml

Flags:

  -c, --config string   Config file
  -h, --help            Show this help
```

### headscale generate private-key

Print a new private key.

```text
Print a new private key for the headscale server, such as for
noise.private_key_path or derp.server.private_key_path, to stdout.

The key is printed alone. Headscale creates the key files that are missing
at startup; this is for a key made beforehand.

Usage:

  headscale generate private-key [flags]

Examples:

  headscale generate private-key

Flags:

  -h, --help   Show this help
```

### headscale generate config

Print a configuration file with every key.

```text
Print a YAML configuration with every key, its default and its
documentation as comments, as for "> /etc/headscale/config.yaml". Set the
keys marked "Required" before starting headscale. With --minimal, print only
those keys.

With --running, print instead the configuration of the running server,
without the client-only cli section: literal secrets, DNS provider settings
other than its name, and the credentials in URLs are removed, "file:"
references kept as written. --running asks the server, so it takes --config
and needs a server; the rest needs none.

Usage:

  headscale generate config [flags]

Examples:

  headscale generate config
  headscale generate config --minimal
  headscale generate config --running

Flags:

      --no-docs         Leave out the documentation comments
      --running         Print the running server's configuration, secrets removed, instead of the defaults
      --minimal         Print only the keys every server must set
  -c, --config string   Config file
  -h, --help            Show this help
```

### headscale generate nixos-options

Print the NixOS options for services.headscale.settings.

```text
Print the NixOS options for services.headscale.settings: one option per
configuration key, with its type, default, documentation and an example. The
output is a function of lib only, not a module:

    options = import ./options.generated.nix { inherit lib; };

With --release, its header names this binary's version and commit instead
of the development tree.

Usage:

  headscale generate nixos-options [flags]

Examples:

  headscale generate nixos-options

Flags:

      --release   Stamp the version and commit of this binary, which must be a clean build of a known commit
  -h, --help      Show this help
```

### headscale generate cli-reference

Print the reference page of the command line.

```text
Print the reference page of the command line, in Markdown: the command
tree, the flags that more than one command takes, the short flags, the
aliases, and the help of every command, with the columns of each list.

It is made from the command specs, as the help is, and committed as
docs/ref/cli.md. A check fails when the committed page is stale.

Usage:

  headscale generate cli-reference [flags]

Examples:

  headscale generate cli-reference

Flags:

  -h, --help   Show this help
```

### headscale generate man

Print the man page.

```text
Print the man page headscale(1), in roff: one page with the command tree
and every command, as the reference page has them.

It is made from the command specs, as the help is, and committed as
docs/ref/headscale.1, which a package installs. A check fails when the
committed page is stale.

Usage:

  headscale generate man [flags]

Examples:

  headscale generate man

Flags:

  -h, --help   Show this help
```

### headscale completion

Print the completion script of a shell.

```text
Print the completion script of a shell to stdout.

The script calls headscale itself to answer Tab, so it completes the
commands, the flags and their values of the binary that runs. Tab reads no
config and never calls the server. bash, zsh and fish are tested in real
shells; PowerShell gets a script too.

To load completions in the running shell:

  bash:        source <(headscale completion bash)
  zsh:         source <(headscale completion zsh)
  fish:        headscale completion fish | source
  PowerShell:  headscale completion powershell | Out-String | Invoke-Expression

Usage:

  headscale completion <shell> [flags]

  <shell> is bash, zsh, fish or powershell.

Examples:

  headscale completion bash
  headscale completion zsh
  headscale completion fish
  headscale completion powershell

Flags:

  -h, --help   Show this help
```

### headscale nodes list

List the nodes.

```text
List every node, with its owner, addresses, client and times.

OWNER is the user that owns the node, or its tags: a node is owned by one
or the other. --filter owner=alice finds the nodes of a user, named as
users get names one; --filter owner=tag:ci the nodes with that tag.
PROBLEMS names the health checks a node fails, which debug health counts.

With -o json the command prints an array of the nodes as the API gives
them; --filter and --sort apply to it as to the table.

Usage:

  headscale nodes list [flags]

Aliases: ls

Examples:

  headscale nodes list
  headscale nodes list --columns +os,+hostname --sort -last-seen
  headscale nodes list --filter owner=alice -o json
  headscale nodes ls --filter 'last-seen>30d'
  headscale nodes list --filter 'version<1.80'
  headscale nodes list --filter problems=node_expiry_invalid

Flags:

      --columns string   Columns to show: a list, or +name and -name to change the default
      --list-columns     List the columns, the API field behind each, and exit
      --filter string    Keep the rows that match, such as owner=alice; may be repeated
      --sort string      Column to sort by; -name sorts in reverse
  -o, --output string    Output format: json (the API object)
  -c, --config string    Config file
  -h, --help             Show this help
```

Columns:

```text
COLUMN             FIELD                           KIND     DEFAULT  DESCRIPTION
id                 id                              id       yes      Node ID
name               name                            text     yes      Name in headscale (MagicDNS uses it)
owner              owner                           owner    yes      Owning user, or the tags
ip                 addresses                       list     yes      Tailnet IP addresses
version            clientVersion                   version  yes      Tailscale client version
online             connectedToControl              bool     yes      Whether the node is connected
last-seen          lastSeen                        time     yes      Time of last contact
expiry             expiry                          time     yes      When the node key expires
hostname           hostname                        text     no       Hostname the node reports
os                 os                              text     no       Operating system
enabled-routes     enabledRoutes                   list     no       Routes the admin approved
advertised-routes  advertisedRoutes                list     no       Routes the node announces
serving-routes     servingRoutes                   list     no       Routes in use
public-ip          attributes["ip:publicAddress"]  text     no       Last seen public address
ephemeral          ephemeral                       bool     no       Whether the node is ephemeral
update-available   updateAvailable                 bool     no       Whether a newer Tailscale client exists
register-method    registerMethod                  text     no       How the node joined: authKey, cli or oidc
auth-key           authKeyId                       id       no       ID of the auth key the node joined with
machine-key        machineKey                      text     no       Machine key
node-key           nodeKey                         text     no       Node key
disco-key          discoKey                        text     no       Disco key
created            created                         time     no       When the node registered
problems           problems                        list     no       Health checks the node fails, by code, as debug health counts them
```

### headscale nodes get

Show one node.

```text
Show one node, with every column of nodes list and its attributes.

An ID wins, then a tailnet IP; the name and the hostname are searched
together, and a word that matches more than one node is an error that lists
them. Attributes are the node attributes of the server, under their
Tailscale names.

With -o json the command prints the node as the API gives it.

Usage:

  headscale nodes get <node> [flags]

  <node> is an ID, a tailnet IP, a name or a hostname.

Examples:

  headscale nodes get mynode
  headscale nodes get 12 -o json
  headscale nodes get 100.64.0.12

Flags:

  -o, --output string   Output format: json (the API object)
  -c, --config string   Config file
  -h, --help            Show this help
```

### headscale nodes set

Change the name or expiry of a node.

```text
Change the name of a node, the expiry of its key, or both.

A flag you do not pass leaves the field alone, and at least one is needed.
--name "" gives the node the name made from its hostname again. --expiry
takes a time (2999-08-27T10:00:00Z), a date (midnight UTC), a duration from
now (90d), now, which expires the node like nodes expire, or never. A time
in the past is an error. Both fields change in one call, or neither does.

With -o json the command prints the node after the change.

Usage:

  headscale nodes set <node> [flags]

  <node> is an ID, a tailnet IP, a name or a hostname.

Examples:

  headscale nodes set mynode --name web-1
  headscale nodes set mynode --expiry 2999-08-27T10:00:00Z
  headscale nodes set mynode --expiry 2999-08-27
  headscale nodes set mynode --expiry 90d
  headscale nodes set mynode --expiry now
  headscale nodes set mynode --expiry never
  headscale nodes set mynode --name web-1 --expiry never
  headscale nodes set 12 --name web-1 -o json | jq -r .name

Flags:

      --name string     New name of the node
  -e, --expiry string   New expiry of the node key
  -o, --output string   Output format: json (the API object)
  -c, --config string   Config file
  -h, --help            Show this help
```

### headscale nodes expire

Log a node out.

```text
Expire the key of a node now: the node is logged out and must log in
again. It keeps its record, so this can be undone by a new login. It does
the same as nodes set --expiry now, at the server's clock.

With -o json the command prints the node after the change.

Usage:

  headscale nodes expire <node> [flags]

  <node> is an ID, a tailnet IP, a name or a hostname.

Examples:

  headscale nodes expire mynode

Flags:

  -o, --output string   Output format: json (the API object)
  -c, --config string   Config file
  -h, --help            Show this help
```

### headscale nodes delete

Delete a node.

```text
Delete a node and its record. It cannot be undone: the node must be
registered again. The command asks first; --force does not ask.

With -o json the command prints nothing; the exit code says it worked.

Usage:

  headscale nodes delete <node> [flags]

  <node> is an ID, a tailnet IP, a name or a hostname.

Aliases: rm

Examples:

  headscale nodes delete mynode
  headscale nodes delete 12 --force

Flags:

  -o, --output string   Output format: json (the API object)
  -c, --config string   Config file
      --force           Do not ask
  -h, --help            Show this help
```

### headscale nodes update-client

Ask a node to update its Tailscale client.

```text
Ask a connected node to update its Tailscale client. The command ends
when the node started the update, not when it is done.

A node can refuse: when it is not connected, when it does not allow remote
updates (tailscale set --auto-update allows them), when its client refuses,
with the client's text, or when it does not answer in time.

With -o json the command prints the node.

Usage:

  headscale nodes update-client <node> [flags]

  <node> is an ID, a tailnet IP, a name or a hostname.

Examples:

  headscale nodes update-client mynode

Flags:

  -o, --output string   Output format: json (the API object)
  -c, --config string   Config file
  -h, --help            Show this help
```

### headscale nodes routes list

List routes.

```text
List the nodes that have routes, with three route columns. ENABLED is
what the admin approved, ADVERTISED what the node announces, SERVING what is
in use. exit stands for the two exit routes, 0.0.0.0/0 and ::/0.

A node that has no enabled, advertised or serving route is left out. A
node argument shows that node alone. The view has every column of
nodes list.

With -o json the command prints an array of the nodes as the API gives
them.

Usage:

  headscale nodes routes list [node] [flags]

  <node> narrows the list to one node: an ID, a tailnet IP, a name or a hostname.

Aliases: ls

Examples:

  headscale nodes routes list
  headscale nodes routes list mynode
  headscale nodes routes ls --filter enabled-routes=exit

Flags:

      --columns string   Columns to show: a list, or +name and -name to change the default
      --list-columns     List the columns, the API field behind each, and exit
      --filter string    Keep the rows that match, such as enabled-routes=exit; may be repeated
      --sort string      Column to sort by; -name sorts in reverse
  -o, --output string    Output format: json (the API object)
  -c, --config string    Config file
  -h, --help             Show this help
```

Columns:

```text
COLUMN             FIELD                           KIND     DEFAULT  DESCRIPTION
id                 id                              id       yes      Node ID
name               name                            text     yes      Name in headscale (MagicDNS uses it)
owner              owner                           owner    no       Owning user, or the tags
ip                 addresses                       list     no       Tailnet IP addresses
version            clientVersion                   version  no       Tailscale client version
online             connectedToControl              bool     no       Whether the node is connected
last-seen          lastSeen                        time     no       Time of last contact
expiry             expiry                          time     no       When the node key expires
hostname           hostname                        text     no       Hostname the node reports
os                 os                              text     no       Operating system
enabled-routes     enabledRoutes                   list     yes      Routes the admin approved
advertised-routes  advertisedRoutes                list     yes      Routes the node announces
serving-routes     servingRoutes                   list     yes      Routes in use
public-ip          attributes["ip:publicAddress"]  text     no       Last seen public address
ephemeral          ephemeral                       bool     no       Whether the node is ephemeral
update-available   updateAvailable                 bool     no       Whether a newer Tailscale client exists
register-method    registerMethod                  text     no       How the node joined: authKey, cli or oidc
auth-key           authKeyId                       id       no       ID of the auth key the node joined with
machine-key        machineKey                      text     no       Machine key
node-key           nodeKey                         text     no       Node key
disco-key          discoKey                        text     no       Disco key
created            created                         time     no       When the node registered
problems           problems                        list     no       Health checks the node fails, by code, as debug health counts them
```

### headscale nodes routes set

Replace the enabled routes of a node.

```text
Replace the enabled routes of a node with the given list. It does not
add: a route left out is no longer enabled. routes clear removes them all.

exit is the pair 0.0.0.0/0 and ::/0, an exit node, and mixes with subnet
routes. The server enables both when given one of them.

With -o json the command prints the node after the change.

Usage:

  headscale nodes routes set <node> <routes> [flags]

  <node> is an ID, a tailnet IP, a name or a hostname.

  <routes> are IP prefixes, comma separated; exit is 0.0.0.0/0 and ::/0.

Aliases: approve

Examples:

  headscale nodes routes set 12 10.0.0.0/8,192.168.0.0/24
  headscale nodes routes approve 12 10.0.0.0/8,192.168.0.0/24
  headscale nodes routes set 14 exit
  headscale nodes routes set 14 10.0.0.0/8,exit
  headscale nodes routes set 14 0.0.0.0/0

Flags:

  -o, --output string   Output format: json (the API object)
  -c, --config string   Config file
  -h, --help            Show this help
```

### headscale nodes routes clear

Remove all enabled routes of a node.

```text
Remove every enabled route of a node, the exit routes included. The
node keeps advertising its routes, so they can be enabled again.

With -o json the command prints the node after the change.

Usage:

  headscale nodes routes clear <node> [flags]

  <node> is an ID, a tailnet IP, a name or a hostname.

Examples:

  headscale nodes routes clear 12

Flags:

  -o, --output string   Output format: json (the API object)
  -c, --config string   Config file
  -h, --help            Show this help
```

### headscale nodes tags list

List tags and their nodes.

```text
List every tag that the policy names or that a node has, one row per
tag: a tag no node has counts 0, and a tag that is gone from the policy
but still on a node is not in the policy.

A node argument keeps the rows of the tags that node has; COUNT and NODES
still cover every node.

NODES is truncated to fit your terminal. For all nodes of a tag:

  headscale nodes list --filter owner=tag:ci -o json | jq -r '.[].name'

With -o json the command prints an array of the tags as the API gives
them.

Usage:

  headscale nodes tags list [node] [flags]

  <node> narrows the list to one node: an ID, a tailnet IP, a name or a hostname.

Aliases: ls

Examples:

  headscale nodes tags list
  headscale nodes tags list builder
  headscale nodes tags list builder -o json
  headscale nodes tags ls --filter in-policy=no

Flags:

      --columns string   Columns to show: a list, or +name and -name to change the default
      --list-columns     List the columns, the API field behind each, and exit
      --filter string    Keep the rows that match, such as in-policy=no; may be repeated
      --sort string      Column to sort by; -name sorts in reverse
  -o, --output string    Output format: json (the API object)
  -c, --config string    Config file
  -h, --help             Show this help
```

Columns:

```text
COLUMN     FIELD      KIND    DEFAULT  DESCRIPTION
tag        tag        text    yes      Tag
count      nodeCount  number  yes      Nodes that have the tag
in-policy  inPolicy   bool    yes      Whether tagOwners of the policy names the tag
nodes      nodes      list    yes      Names of the nodes that have the tag
```

### headscale nodes tags set

Replace the tags of a node.

```text
Replace the tags of a node with the given list. A tag that tagOwners of
the policy does not name is refused.

A node is owned by a user or by its tags. Tagging a node that a user owns
ends that ownership for good, so the command asks first; --force does not
ask. A tagged node needs at least one tag.

With -o json the command prints the node after the change.

Usage:

  headscale nodes tags set <node> <tags> [flags]

  <node> is an ID, a tailnet IP, a name or a hostname.

  <tags> are the tags, comma separated, each named in tagOwners of the policy.

Examples:

  headscale nodes tags set 13 tag:ci,tag:build,tag:test
  headscale nodes tags set mynode tag:server --force

Flags:

  -o, --output string   Output format: json (the API object)
  -c, --config string   Config file
      --force           Do not ask
  -h, --help            Show this help
```

### headscale users list

List the users.

```text
List every user, local and from OIDC, with the nodes each one owns.

NAME is the stored username; a user from OIDC can have none. COUNT and
NODES are the nodes the user owns; a tagged node is owned by its tags and
is in neither.

NODES is truncated to fit your terminal. For all nodes of a user:

  headscale users get carol -o json | jq -r '.nodes[].name'

With -o json the command prints an array of the users as the API gives
them; --filter and --sort apply to it as to the table.

Usage:

  headscale users list [flags]

Aliases: ls

Examples:

  headscale users list
  headscale users list --filter provider=oidc --sort -count
  headscale users ls --columns +login-name,-nodes
  headscale users list --filter email=carol@example.com -o json

Flags:

      --columns string   Columns to show: a list, or +name and -name to change the default
      --list-columns     List the columns, the API field behind each, and exit
      --filter string    Keep the rows that match, such as provider=oidc; may be repeated
      --sort string      Column to sort by; -name sorts in reverse
  -o, --output string    Output format: json (the API object)
  -c, --config string    Config file
  -h, --help             Show this help
```

Columns:

```text
COLUMN           FIELD          KIND    DEFAULT  DESCRIPTION
id               id             id      yes      User ID
name             name           text    yes      Username; empty for some users from OIDC
display-name     displayName    text    yes      Display name
email            email          text    yes      Email address
provider         provider       text    yes      Where the user comes from: local or oidc
count            nodeCount      number  yes      Nodes the user owns, tagged nodes not counted
nodes            nodes          list    yes      Names of the nodes the user owns
login-name       loginName      text    no       What headscale shows for the user: the email, else the username, else the provider identifier
profile-pic-url  profilePicUrl  text    no       URL of the profile picture
provider-id      providerId     text    no       Identifier at the identity provider
created          created        time    no       When the user was created
```

### headscale users get

Show one user.

```text
Show one user, with every column of users list.

An ID wins; the email, the username and the provider identifier are
searched together, and a word that matches more than one user is an error
that lists them.

With -o json the command prints the user as the API gives it.

Usage:

  headscale users get <user> [flags]

  <user> is an ID, an email, a username or a provider identifier.

Examples:

  headscale users get alice
  headscale users get carol@example.com -o json

Flags:

  -o, --output string   Output format: json (the API object)
  -c, --config string   Config file
  -h, --help            Show this help
```

### headscale users create

Create a local user.

```text
Create a local user with a username.

The server checks the values: the username, --email as one address, and
--picture-url as an absolute http or https URL. A username or an email
that equals the username, the email or the provider identifier of another
user, in any case, is refused: a policy names a user by these texts.

With -o json the command prints the new user.

Usage:

  headscale users create <name> [flags]

Examples:

  headscale users create dave
  headscale users create dave --display-name "Dave D" --email dave@example.com

Flags:

      --display-name string   Display name
      --email string          Email address
      --picture-url string    Profile picture: an absolute http or https URL
  -o, --output string         Output format: json (the API object)
  -c, --config string         Config file
  -h, --help                  Show this help
```

### headscale users set

Change a local user.

```text
Change any field of a local user, the username included.

A flag you do not pass leaves the field alone, and at least one is needed.
An empty value clears the field; a user needs a username, so --name ""
is refused. The server checks the values as for users create. All given
fields change in one call, or none do. An OAuth access token cannot change
the username or the email; an API key can.

A user from OIDC is refused: the identity provider owns its fields, and the
next login would overwrite them.

With -o json the command prints the user after the change.

Usage:

  headscale users set <user> [flags]

  <user> is an ID, an email, a username or a provider identifier.

Examples:

  headscale users set alice --display-name "Alice A" --email a@b.c
  headscale users set alice --name alice2
  headscale users set 3 --name alice2 --email a@b.c
  headscale users set alice --picture-url ""

Flags:

      --name string           New username
      --display-name string   New display name; "" clears it
      --email string          New email address; "" clears it
      --picture-url string    New profile picture URL; "" clears it
  -o, --output string         Output format: json (the API object)
  -c, --config string         Config file
  -h, --help                  Show this help
```

### headscale users delete

Delete a user with its keys.

```text
Delete a user together with its auth keys and its API keys, revoked and
expired ones too, so the counts may be more than the lists show by default.
Tagged keys and OAuth clients the user made stay.

A user who still owns nodes is refused; --with-nodes deletes the nodes too.
It is one step on the server: all of it, or nothing.

The command asks the server first what the delete would remove, and shows
it: the nodes by name, and the keys counted. The delete then removes only
what was shown. When that changed in between, nothing is removed, and the
command asks again with what is there now; with --force it tries once more
without asking. A second change is an error. A node or a key that comes or
goes is a change; a rename, an expiry or a revoke is not.

With -o json the command prints what was removed.

Usage:

  headscale users delete <user> [flags]

  <user> is an ID, an email, a username or a provider identifier.

Aliases: rm

Examples:

  headscale users delete bob
  headscale users delete alice --with-nodes
  headscale users delete alice --with-nodes --force

Flags:

      --with-nodes      Delete the nodes of the user too
  -o, --output string   Output format: json (the API object)
  -c, --config string   Config file
      --force           Do not ask
  -h, --help            Show this help
```

### headscale auth register

Register a node that waits to join.

```text
Answer a registration: the node that shows the auth ID joins the tailnet,
owned by the user. A node that asked for tags the user may give joins
tagged instead.

The auth ID is a secret: whoever holds it can put that machine into the
tailnet. The command sends it to the server and prints it nowhere. A
request that timed out or was answered already is gone. An SSH check is
answered with auth approve, not here.

With -o json the command prints the new node. In the examples, $id holds
the auth ID.

Usage:

  headscale auth register <auth-id> <user> [flags]

  <auth-id> is the ID the node shows, hskey-authreq- and the rest, as at the end of its URL.

  <user> is an ID, an email, a username or a provider identifier.

Examples:

  headscale auth register "$id" alice
  headscale auth register "$id" 3 -o json

Flags:

  -o, --output string   Output format: json (the API object)
  -c, --config string   Config file
  -h, --help            Show this help
```

### headscale auth approve

Let an SSH check pass.

```text
Answer an SSH check with yes: the SSH connection that waits for it goes on.

The command reads the request first, so its message says which nodes the
check is between. The auth ID is a secret, which the command sends to the
server and prints nowhere. A registration is answered with auth register,
not here. A request that timed out or was answered already is gone.

With -o json the command prints nothing; the exit code says it worked. In
the example, $id holds the auth ID.

Usage:

  headscale auth approve <auth-id> [flags]

  <auth-id> is the ID the node shows, hskey-authreq- and the rest, as at the end of its URL.

Examples:

  headscale auth approve "$id"

Flags:

  -o, --output string   Output format: json (the API object)
  -c, --config string   Config file
  -h, --help            Show this help
```

### headscale auth reject

Refuse a registration or an SSH check.

```text
Answer an auth request with no: a node that waits to join must start
again, and an SSH connection that waits for a check is refused.

The command reads the request first and asks, with what it is; --force
does not ask. The auth ID is a secret, which the command sends to the
server and prints nowhere. A request that timed out or was answered
already is gone.

With -o json the command prints nothing; the exit code says it worked. In
the examples, $id holds the auth ID.

Usage:

  headscale auth reject <auth-id> [flags]

  <auth-id> is the ID the node shows, hskey-authreq- and the rest, as at the end of its URL.

Examples:

  headscale auth reject "$id"
  headscale auth reject "$id" --force

Flags:

  -o, --output string   Output format: json (the API object)
  -c, --config string   Config file
      --force           Do not ask
  -h, --help            Show this help
```

### headscale auth keys list

List the auth keys.

```text
List the auth keys that work: the ones in the state valid.

A key that is used (single-use, and a node joined with it), expired or
revoked is hidden; --all shows every key and adds the STATE column, and a
filter on state shows the keys it names. A revoked key is listed until the
server removes its record. No list shows the secret of a key; only auth
keys create prints it, once.

--filter owner=alice finds the keys of a user, named as users get names
one; --filter owner=tag:ci the keys for that tag.

With -o json the command prints an array of the keys as the API gives
them, the hidden ones left out as in the table.

Usage:

  headscale auth keys list [flags]

Aliases: ls

Examples:

  headscale auth keys list
  headscale auth keys list --all
  headscale auth keys list --filter owner=tag:ci
  headscale auth keys list --filter state=expired
  headscale auth keys ls --filter 'expiry<7d' -o json

Flags:

      --columns string   Columns to show: a list, or +name and -name to change the default
      --list-columns     List the columns, the API field behind each, and exit
      --filter string    Keep the rows that match, such as owner=tag:ci; may be repeated
      --sort string      Column to sort by; -name sorts in reverse
      --all              Show every row, not only state=valid
  -o, --output string    Output format: json (the API object)
  -c, --config string    Config file
  -h, --help             Show this help
```

Columns:

```text
COLUMN       FIELD        KIND   DEFAULT  DESCRIPTION
id           id           id     yes      Auth key ID
prefix       prefix       text   yes      The part of the key that is not secret
owner        owner        owner  yes      The user, or the tags, that a node joining with the key gets
state        state        text   no       valid, used, expired or revoked; the list shows only state=valid, --all every row and this column
reusable     reusable     bool   yes      Whether more than one node may join with the key
ephemeral    ephemeral    bool   yes      Whether a node that joins is removed some time after it disconnects
expiry       expiry       time   yes      When the key stops working
created      created      time   yes      When the key was made
description  description  text   no       What the key is for
```

### headscale auth keys get

Show one auth key.

```text
Show the stored details of one auth key, in any state, with every column
of auth keys list. It never shows the secret: the server keeps only a hash
of it.

An ID wins over a prefix.

With -o json the command prints the key as the API gives it, with who made
it (createdBy), when it was revoked and when its record is removed.

Usage:

  headscale auth keys get <key> [flags]

  <key> is an ID or a prefix; hskey-auth-<prefix>-*** names the key too.

Examples:

  headscale auth keys get ab12cd345678
  headscale auth keys get 7 -o json

Flags:

  -o, --output string   Output format: json (the API object)
  -c, --config string   Config file
  -h, --help            Show this help
```

### headscale auth keys create

Create an auth key.

```text
Create a key that lets a node join the tailnet. A node that joins with it
is owned by the owner of the key: a user, or tags, never both. A tag must
be in tagOwners of the policy.

--expiry says when the key expires, its default under Flags: a time
(2999-08-27T10:00:00Z), a date (midnight UTC) or a duration from now (90d).
A key must expire; there is no upper limit. A time in the past is an
error.

The key is printed on stdout, alone, so a script can capture it:

  KEY=$(headscale auth keys create tag:ci)

Its ID, owner and expiry go to stderr. This is the only time the key is
shown: the server keeps only a hash of it.

With -o json the command prints the new key as the API gives it, the
secret in the field key.

Usage:

  headscale auth keys create <owner> [flags]

  <owner> is a user (an ID, an email, a username or a provider identifier), or tags, comma separated, each named in tagOwners of the policy.

Examples:

  headscale auth keys create alice
  headscale auth keys create alice --reusable --expiry 24h
  headscale auth keys create tag:ci,tag:build --ephemeral -d "CI runners"
  headscale auth keys create tag:ci --expiry 2999-08-27
  headscale auth keys create tag:ci -o json | jq -r .key

Flags:

      --reusable             Let more than one node join with the key
      --ephemeral            Remove a node that joined with the key some time after it disconnects
  -e, --expiry string        When the key stops working: a time, a date or a duration from now (default 1h)
  -d, --description string   What the key is for, shown by list and get
  -o, --output string        Output format: json (the API object)
  -c, --config string        Config file
  -h, --help                 Show this help
```

### headscale auth keys delete

Revoke an auth key.

```text
Revoke an auth key: it stops working at once. Nodes that joined with it
are not touched. The command asks first; --force does not ask.

The record stays, in the state revoked, so that list --all and get show
what was stopped. The server removes it after the retention time,
credentials.revoked_retention; a retention of 0 keeps
it, and so does a node that still refers to the key. Deleting a revoked key
succeeds and changes nothing, and does not ask.

With -o json the command prints the revoked key as the API gives it, with
removal, the time its record is removed; nothing when that read fails.

Usage:

  headscale auth keys delete <key> [flags]

  <key> is an ID or a prefix; hskey-auth-<prefix>-*** names the key too.

Aliases: rm

Examples:

  headscale auth keys delete 7
  headscale auth keys rm ab12cd345678 --force
  headscale auth keys delete 7 --force -o json | jq -r .removal

Flags:

  -o, --output string   Output format: json (the API object)
  -c, --config string   Config file
      --force           Do not ask
  -h, --help            Show this help
```

### headscale api whoami

Show who the server sees calling.

```text
Show who the server sees calling: who or what the call is from (the
principal), how the call is proven (the credential), and what the server
lets it do.

The key owner is not who is calling: it is the user recorded on the API
key. "Tags: any" means that tags do not limit the caller; a token shows the
tags it may give out, and none when it may give no tag. A line that does
not apply is left out: the socket has no credential.

With -o json the command prints the answer of GET /me as it is.

Usage:

  headscale api whoami [flags]

Examples:

  headscale api whoami
  headscale api whoami -o json

Flags:

  -o, --output string   Output format: json (the API object)
  -c, --config string   Config file
  -h, --help            Show this help
```

### headscale api keys list

List the API keys.

```text
List the API keys that work: the ones in the state valid.

An expired or revoked key is hidden; --all shows every key and adds the
STATE column, and a filter on state shows the keys it names. A revoked key
is listed until the server removes its record. No list shows the secret
of a key; only api keys create prints it, once.

OWNER is the user recorded on the key, - for none; every API key may do
everything, with or without an owner. LAST SEEN is when the key was last
used, to the minute.

With -o json the command prints an array of the keys as the API gives
them, the hidden ones left out as in the table.

Usage:

  headscale api keys list [flags]

Aliases: ls

Examples:

  headscale api keys list
  headscale api keys list --all
  headscale api keys list --filter owner=alice
  headscale api keys ls --filter 'last-seen>30d' -o json

Flags:

      --columns string   Columns to show: a list, or +name and -name to change the default
      --list-columns     List the columns, the API field behind each, and exit
      --filter string    Keep the rows that match, such as owner=alice; may be repeated
      --sort string      Column to sort by; -name sorts in reverse
      --all              Show every row, not only state=valid
  -o, --output string    Output format: json (the API object)
  -c, --config string    Config file
  -h, --help             Show this help
```

Columns:

```text
COLUMN     FIELD     KIND   DEFAULT  DESCRIPTION
id         id        id     yes      API key ID
prefix     prefix    text   yes      The part of the key that is not secret
owner      owner     owner  yes      The user recorded on the key; it does not limit what the key may do
state      state     text   no       valid, expired or revoked; the list shows only state=valid, --all every row and this column
expiry     expiry    time   yes      When the key stops working
created    created   time   yes      When the key was made
last-seen  lastSeen  time   yes      When the key was last used, to the minute
```

### headscale api keys get

Show one API key.

```text
Show the stored details of one API key, in any state, with every column
of api keys list. It never shows the secret: the server keeps only a hash
of it.

An ID wins over a prefix.

With -o json the command prints the key as the API gives it, with when it
was revoked and when its record is removed.

Usage:

  headscale api keys get <key> [flags]

  <key> is an ID or a prefix; hskey-api-<prefix>-*** names the key too.

Examples:

  headscale api keys get 2
  headscale api keys get f0e1d2c3b4a5 -o json

Flags:

  -o, --output string   Output format: json (the API object)
  -c, --config string   Config file
  -h, --help            Show this help
```

### headscale api keys create

Create an API key.

```text
Create an API key. Every API key may do everything that the API allows,
with or without an owner: keep it as a password of the server.

--user gives the key an owner. The owner does not limit the key; the key
is deleted with its user, and the Tailscale API (/api/v2) makes the auth
keys that this key asks for owned by that user.

--expiry says when the key expires, its default under Flags: a time
(2999-08-27T10:00:00Z), a date (midnight UTC) or a duration from now (30d).
A key must expire; there is no upper limit. A time in the past is an
error.

The key is printed on stdout, alone, so a script can capture it:

  KEY=$(headscale api keys create)

Its ID, owner and expiry go to stderr. This is the only time the key is
shown: the server keeps only a hash of it. Only an API key or the socket
can make one; an OAuth access token cannot.

With -o json the command prints the new key as the API gives it, the
secret in the field key.

Usage:

  headscale api keys create [flags]

Examples:

  headscale api keys create
  headscale api keys create --expiry 30d
  headscale api keys create --user alice --expiry 90d
  headscale api keys create -u alice -o json | jq -r .key

Flags:

  -u, --user string     The owner of the key: a user, named as users get names one. It does not limit what the key may do
  -e, --expiry string   When the key stops working: a time, a date or a duration from now (default 90d)
  -o, --output string   Output format: json (the API object)
  -c, --config string   Config file
  -h, --help            Show this help
```

### headscale api keys delete

Revoke an API key.

```text
Revoke an API key: it stops working at once. The command asks first;
--force does not ask. When the key is the one this CLI calls with, the
question says so, and so does the error when no terminal can answer: the
delete works, and every later call with the key is refused.

The record stays, in the state revoked, so that list --all and get show
what was stopped. The server removes it after the retention time,
credentials.revoked_retention; a retention of 0 keeps
it. Deleting a revoked key succeeds and changes nothing, and does not ask.

With -o json the command prints the revoked key as the API gives it, with
removal, the time its record is removed; nothing when that read fails, as
it does after the CLI revoked the key it calls with.

Usage:

  headscale api keys delete <key> [flags]

  <key> is an ID or a prefix; hskey-api-<prefix>-*** names the key too.

Aliases: rm

Examples:

  headscale api keys delete f0e1d2c3b4a5
  headscale api keys rm 2 --force
  headscale api keys delete 2 --force -o json | jq -r .removal

Flags:

  -o, --output string   Output format: json (the API object)
  -c, --config string   Config file
      --force           Do not ask
  -h, --help            Show this help
```

### headscale api oauth-clients list

List the OAuth clients.

```text
List the OAuth clients that work: the ones in the state valid, in the
order they were made.

A revoked client is hidden; --all shows every client and adds the STATE
column, and a filter on state shows the clients it names. A revoked client
is listed until the server removes its record. No list shows the secret of
a client; only api oauth-clients create prints it, once.

An OAuth client has no expiry. Its ID is no number: it sorts as text, and
a filter compares it with = and :, never with < or >.

With -o json the command prints an array of the clients as the API gives
them, with who made each (createdBy), the hidden ones left out as in the
table.

Usage:

  headscale api oauth-clients list [flags]

Aliases: ls

Examples:

  headscale api oauth-clients list
  headscale api oauth-clients list --all
  headscale api oauth-clients ls --filter tags=tag:ci -o json

Flags:

      --columns string   Columns to show: a list, or +name and -name to change the default
      --list-columns     List the columns, the API field behind each, and exit
      --filter string    Keep the rows that match, such as tags=tag:ci; may be repeated
      --sort string      Column to sort by; -name sorts in reverse
      --all              Show every row, not only state=valid
  -o, --output string    Output format: json (the API object)
  -c, --config string    Config file
  -h, --help             Show this help
```

Columns:

```text
COLUMN       FIELD        KIND  DEFAULT  DESCRIPTION
id           id           text  yes      OAuth client ID, which is no number
scopes       scopes       list  yes      The scopes the client may give its tokens
tags         tags         list  yes      The tags the client may give its tokens
description  description  text  yes      What the client is for
created      created      time  yes      When the client was made
state        state        text  no       valid or revoked; the list shows only state=valid, --all every row and this column
```

### headscale api oauth-clients get

Show one OAuth client.

```text
Show the stored details of one OAuth client, in any state, with every
column of api oauth-clients list. A client is named by its ID only. It
never shows the secret: the server keeps only a hash of it.

With -o json the command prints the client as the API gives it, with who
made it (createdBy), when it was revoked and when its record is removed.

Usage:

  headscale api oauth-clients get <client> [flags]

  <client> is the ID of the client.

Examples:

  headscale api oauth-clients get c9f2aa000001
  headscale api oauth-clients get c9f2aa000001 -o json

Flags:

  -o, --output string   Output format: json (the API object)
  -c, --config string   Config file
  -h, --help            Show this help
```

### headscale api oauth-clients create

Create an OAuth client.

```text
Create an OAuth client: an ID and a secret that a program trades at
POST /api/v2/oauth/token for short-lived access tokens, with the scopes and
the tags of the client. Scopes are required; the scopes devices:core and
auth_keys need at least one tag. A tag must be in tagOwners of the policy.

An OAuth client has no expiry. It works until it is deleted.

The secret is printed on stdout, alone, so a script can capture it:

  SECRET=$(headscale api oauth-clients create devices:core --tags tag:ci)

The client ID, its scopes and its tags go to stderr. This is the only time
the secret is shown: the server keeps only a hash of it. An OAuth access
token makes a client with only scopes it holds and tags it owns.

With -o json the command prints the new client as the API gives it, the
secret in the field key.

Usage:

  headscale api oauth-clients create <scopes> [flags]

  <scopes> are the scopes the client may give its tokens, comma separated, such as devices:core,auth_keys; devices:core and auth_keys need --tags.

Examples:

  headscale api oauth-clients create devices:core:read
  headscale api oauth-clients create devices:core,auth_keys --tags tag:ci
  headscale api oauth-clients create devices:core --tags tag:ci -d "CI"
  headscale api oauth-clients create devices:core --tags tag:ci -o json | jq -r '.id, .key'

Flags:

      --tags string          The tags the client may give its tokens, comma separated, each named in tagOwners of the policy
  -d, --description string   What the client is for, shown by list and get
  -o, --output string        Output format: json (the API object)
  -c, --config string        Config file
  -h, --help                 Show this help
```

### headscale api oauth-clients delete

Revoke an OAuth client.

```text
Revoke an OAuth client: it stops working at once, and every access token
it gave is refused from its next request. The command asks first, and
names the client with its description; --force does not ask. When the CLI
calls with a token of the client, the question says so, and so does the
error when no terminal can answer.

The record stays, in the state revoked, so that list --all and get show
what was stopped. The server removes it after the retention time,
credentials.revoked_retention; a retention of 0 keeps
it. Deleting a revoked client succeeds and changes nothing, and does not
ask.

With -o json the command prints the revoked client as the API gives it,
with removal, the time its record is removed; nothing when that read
fails.

Usage:

  headscale api oauth-clients delete <client> [flags]

  <client> is the ID of the client.

Aliases: rm

Examples:

  headscale api oauth-clients delete c9f2aa000001
  headscale api oauth-clients rm c9f2aa000001 --force
  headscale api oauth-clients delete c9f2aa000001 --force -o json | jq -r .removal

Flags:

  -o, --output string   Output format: json (the API object)
  -c, --config string   Config file
      --force           Do not ask
  -h, --help            Show this help
```

### headscale policy get

Print the policy.

```text
Print the policy in force exactly as it is stored, comments, tabs and
line ends included, so that policy get > file and policy set file give the
same policy back. In file mode it is the file the server last took. With
none in force it prints nothing, and says so on stderr.

With -o json the command prints the policy object of the API: policy,
updated, mode and path.

With --bypass-server-and-access-database-directly the command does not talk
to the server: it reads the policy the server would start with, from the
database (or the policy file in file mode) that the config names. It needs
the server's full config, and asks first, since the server must be
stopped; --force answers.

Usage:

  headscale policy get [flags]

Examples:

  headscale policy get > policy.hujson
  headscale policy get -o json | jq -r .updated
  headscale policy get --bypass-server-and-access-database-directly > p.hujson

Flags:

      --bypass-server-and-access-database-directly   Open the database of a stopped server, with no server: the rescue path when a policy keeps it from starting
  -o, --output string                                Output format: json (the API object)
  -c, --config string                                Config file
      --force                                        Do not ask
  -h, --help                                         Show this help
```

### headscale policy set

Replace the policy.

```text
Replace the whole policy with a file, sent as it is. It does not ask:
you hold the file, and the server refuses a policy that is not valid and
keeps the one in force. A refusal names each problem and each failed test,
at its line of the file. A file of - is read from stdin.

--dry-run runs every check of set against the users and nodes of the
server, the tests of the policy included, and changes nothing. In file mode
set is refused, and --dry-run still works.

With -o json the command prints the policy object of the API.

With --bypass-server-and-access-database-directly the command does not talk
to the server: it runs the same checks against the users and nodes in the
database that the config names, and stores the policy there. It needs the
server's full config, and asks first, since the server must be stopped;
--force answers, and stdin as the file needs it.

Usage:

  headscale policy set <file> [flags]

  <file> is the policy, HuJSON; - reads it from stdin.

Examples:

  headscale policy set policy.hujson
  headscale policy set policy.hujson --dry-run
  generate-policy.sh | headscale policy set -
  headscale policy set p.hujson --dry-run --bypass-server-and-access-database-directly
  headscale policy set p.hujson --bypass-server-and-access-database-directly

Flags:

      --dry-run                                      Run every check of set against the users and nodes, and change nothing
      --bypass-server-and-access-database-directly   Open the database of a stopped server, with no server: the rescue path when a policy keeps it from starting
  -o, --output string                                Output format: json (the API object)
  -c, --config string                                Config file
      --force                                        Do not ask
  -h, --help                                         Show this help
```

### headscale policy reload

Read the policy again from where it is kept.

```text
Ask the server to read the policy again from where it is kept, the
policy file or the database, and put it in force. The server reads the
file by itself when it is saved; reload is for knowing at once whether it
took it. A policy it refuses leaves the one in force, and the refusal names
each problem at its line.

With -o json the command prints the policy object of the API, as it is in
force now.

Usage:

  headscale policy reload [flags]

Examples:

  headscale policy reload

Flags:

  -o, --output string   Output format: json (the API object)
  -c, --config string   Config file
  -h, --help            Show this help
```

### headscale debug health

Check that the server is healthy.

```text
Ask the running server whether it is healthy.

It prints healthy and exits 0, or prints the reasons on stderr and exits 1.
A container healthcheck relies on the exit code.

A warning is something an admin should know that does not stop the
server, such as a node whose stored data is not valid. Each warning is
printed on stderr, a warning about nodes with the nodes list command that
shows them, and the command still exits 0, so a healthcheck does not
restart the server over one.

With -o json the command prints the answer of GET /health, warnings
included, and writes no warning on stderr.

Usage:

  headscale debug health [flags]

Examples:

  headscale debug health
  headscale debug health -o json

Flags:

  -o, --output string   Output format: json (the API object)
  -c, --config string   Config file
  -h, --help            Show this help
```

### headscale debug create-node

Make a registration of a made-up node, for tests.

```text
Make a registration that waits under the auth ID given with --key, as a
node that wants to join would. auth register answers it with a user; the
node never connects. It is a test tool: it is unstable, and it prints one
fixed sentence, with no -o json.

The auth ID is yours: hskey-authreq- and 24 lower-case hex digits. The
command does not print it back, and the help shows an ID it holds as
hskey-authreq-***, so keep it for auth register:

  id="hskey-authreq-$(openssl rand -hex 12)"
  headscale debug create-node --name fake-1 --key "$id"
  headscale auth register "$id" alice

Usage:

  headscale debug create-node [flags]

Examples:

  headscale debug create-node --name fake-1 --key "$id"
  headscale debug create-node --name fake-2 --key "$id" --route 10.0.0.0/8,192.168.0.0/24

Flags:

      --name string     The hostname of the made-up node; required
      --key string      The auth ID it waits under, hskey-authreq- and the rest; required
      --route string    Routes it advertises once it is registered, comma separated
  -c, --config string   Config file
  -h, --help            Show this help
```

### headscale debug mockoidc

Run a mock OIDC server for tests.

```text
Run a mock OpenID Connect server until it gets SIGINT or SIGTERM. It is a
test tool for the integration tests: unstable, and outside the rules of the
rest of the CLI.

It reads no headscale config. The environment sets it up: MOCKOIDC_ADDR and
MOCKOIDC_PORT where it listens, MOCKOIDC_CLIENT_ID and
MOCKOIDC_CLIENT_SECRET, MOCKOIDC_USERS (a JSON list of users, served in
order), and MOCKOIDC_ACCESS_TTL (a Go duration, with a default when unset).

Usage:

  headscale debug mockoidc [flags]

Examples:

  MOCKOIDC_ADDR=127.0.0.1 MOCKOIDC_PORT=10000 MOCKOIDC_CLIENT_ID=superclient MOCKOIDC_CLIENT_SECRET=supersecret MOCKOIDC_USERS='[]' headscale debug mockoidc

Flags:

  -h, --help   Show this help
```
