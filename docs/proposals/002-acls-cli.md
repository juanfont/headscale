# ACLs API proposal

In order to manage the ACLs it would be very nice to have an API that would
allow to consult and modify the ACL's. The advantages of this solution would be
to allow ACL's manipulation from the API and not the filesystem. Manipulation
of the ACL's via API would allow to change the ACL's via the command line, test
the ACL's file before loading it. These actions would also be possible via a
Web user interface.

As a side effect, the file would not be the primary source of truth. We could
still maintain this behavior with a switch in the configuration stating that we
want to load the ACL's from a configured file if it exists. Also it's still
possible to apply configuration as code like terraform is doing with static
configuration loaded to destination with the API.

## API

As a base of reflection, we used Tailscale's API definition from
[here](https://github.com/tailscale/tailscale/blob/main/api.md).

| Method | Path                 | Short Description                                                                              |
| ------ | -------------------- | ---------------------------------------------------------------------------------------------- |
| GET    | /api/v1/acl          | Retrieve ACL configuration file                                                                |
| POST   | /api/v1/acl          | Send ACL configuration. This could reject configuration if invalid                             |
| POST   | /api/v1/acl/preview  | Preview the ACLs for a user. It would return what can be accessed from this user point of view |
| POST   | /api/v1/acl/validate | This endpoint would run the given tests on the current ACLs                                    |

For the preview and validate method it would be interesting to develop the
hability to run tests of the ACLs configuration like it's done in tailscale.

### GET ACL

The GET request would be exactly the same as the tailscale one (path excepted).
It would be great to have the HuJSON as default so we can keep the comments
that the users would want to put in the rules to better understand them.

The ETAG could be a SHA1 or a SHA256 optionnaly put in the POST request. The
server could refuse the update if the ETAG in the request isn't equal to the
SHA of the current configuration to intercept race-condition on modifications.

### POST ACL

The POST request is also the same as tailscale's API. Obviously if the content
is uploaded as JSON, the comments in the file would not be available for the
next retrieval of the ACL's.

### POST ACL preview

The preview endpoint would be of great use when building new ACL's, it could
allow to propose a new ACL file and ask for the behavior on a specific user or
port. To do this, we may have to rethink some part of the code.

As an improvement on the tailscale version, we could preview the user or
ip+port against the current ACL's file (it is suggested as an improvement
because it's not described in the API documentation).

### POST ACL validate

The validate endpoint has 2 modes of functionning in tailscale. One is to
consider content of the request to be tests that are ran against the current
configuration. The second is to provide a full ACL file with optional tests. If
the file has no syntax error a 200 response message is sent. If the tests
failed, a 200 response message is sent with details explaining why the tests
failed in the response.

## CLI

### acl subcommand

The CLI commands could be like the following

```console
headscale acl --help
Manage the ACLs of Headscale

Usage:
  headscale acl [command]

Aliases:
  acls

Available Commands:
  get         Print the current ACL file.
  preview     Preview will return the lines of the ACL that matches a user or an IP+port in the request
  set         Set the ACLs with a given content
  validate    Validate the ACLs with a given ACL file or test to run agains current configuration

Flags:
  -h, --help   help for nodes

Global Flags:
  -c, --config string   config file (default is /etc/headscale/config.yaml)
      --force           Disable prompts and forces the execution
  -o, --output string   Output format. Empty for human-readable, 'json', 'json-line' or 'yaml'

Use "headscale acl [command] --help" for more information about a command.
```

### acl get subcommand

```console headscale acl get --help Get will retrieve the ACLs currently loaded
in Headscale. Use the `-o json` option to retrieve a JSON version of the ACL's
or `-o yaml` to retrieve a YAML version, default is HuJSON

Usage:
  headscale acl get [flags]

Aliases:
  read

Flags:
  -h, --help   help for nodes

Global Flags:
  -c, --config string   config file (default is /etc/headscale/config.yaml)
      --force           Disable prompts and forces the execution
  -o, --output string   Output format. Empty for human-readable, 'json', 'json-line' or 'yaml'
```

### acl set subcommand

```console
headscale acl set --help
Set will update the current ACL's with the provided ones.

Usage:
  headscale acl set file [flags]

Aliases:
  put, write

Flags:
  -h, --help   help for nodes
  -e, --etag   SHA of the configuration retrieved previously retrieved. If set and the configuration has changed, the update will not be made.

Global Flags:
  -c, --config string   config file (default is /etc/headscale/config.yaml)
      --force           Disable prompts and forces the execution
  -o, --output string   Output format. Empty for human-readable, 'json', 'json-line' or 'yaml'
```

### acl preview subcommand

```console
headscale acl preview --help
Preview allows you to ask for the rules that matches a user or a couple IP+port.

Usage:
  headscale acl preview [flags]

Flags:
  -h, --help         help for nodes
  -t, --type         Type of the preview to be done. It will be automatically guessed if not provided. Type can be either `user` or `ipport`.
  -p, --preview-for  Preview-For is the value to run the preview against.
  -f, --file         ACL file to run the preview against, if not provided, the currently loaded ACL's will be used.

Global Flags:
  -c, --config string   config file (default is /etc/headscale/config.yaml)
      --force           Disable prompts and forces the execution
  -o, --output string   Output format. Empty for human-readable, 'json', 'json-line' or 'yaml'
```

### acl validate subcommand

```console
headscale acl validate --help
Validate will check if the ACL file contains error. This will not modify the currently loaded ACL's.

Usage:
  headscale acl validate [flags]

Flags:
  -h, --help   help for nodes
  -t, --tests  Tests that have to be ran against the currently loaded ACL's rules
  -f, --file   File to validate. The tests, if provided in the file, would be ran.

Global Flags:
  -c, --config string   config file (default is /etc/headscale/config.yaml)
      --force           Disable prompts and forces the execution
  -o, --output string   Output format. Empty for human-readable, 'json', 'json-line' or 'yaml'
```
