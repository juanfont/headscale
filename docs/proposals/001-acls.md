# ACLs

A key component of tailscale is the notion of Tailnet. This notion is hidden
but the implications that it have on how to use tailscale are not.

For tailscale an [tailnet](https://tailscale.com/kb/1136/tailnet/) is the
following:

> For personal users, you are a tailnet of many devices and one person. Each
> device gets a private Tailscale IP address in the CGNAT range and every
> device can talk directly to every other device, wherever they are on the
> internet.
>
> For businesses and organizations, a tailnet is many devices and many users.
> It can be based on your Microsoft Active Directory, your Google Workspace, a
> GitHub organization, Okta tenancy, or other identity provider namespace. All
> of the devices and users in your tailnet can be seen by the tailnet
> administrators in the Tailscale admin console. There you can apply
> tailnet-wide configuration, such as ACLs that affect visibility of devices
> inside your tailnet, DNS settings, and more.

## Current implementation and issues

Currently in headscale, the namespaces are used both as tailnet and users. The
issue is that if we want to use the ACL's we can't use both at the same time.

Tailnet's cannot communicate with each others. So we can't have an ACL that
authorize tailnet (namespace) A to talk to tailnet (namespace) B.

We also can't write ACLs based on the users (namespaces in headscale) since all
devices belong to the same user.

With the current implementation the only ACL that we can user is to associate
each headscale IP to a host manually then write the ACLs according to this
manual mapping.

```json
{
  "hosts": {
    "host1": "100.64.0.1",
    "server": "100.64.0.2"
  },
  "acls": [
    { "action": "accept", "users": ["host1"], "ports": ["host2:80,443"] }
  ]
}
```

While this works, it requires a lot of manual editing on the configuration and
to keep track of all devices IP address.

## Proposition for a next implementation

In order to ease the use of ACL's we need to split the tailnet and users
notion.

A solution could be to consider a headscale server (in it's entirety) as a
tailnet.

For personal users the default behavior could either allow all communications
between all namespaces (like tailscale) or dissallow all communications between
namespaces (current behavior).

For businesses and organisations, viewing a headscale instance a single tailnet
would allow users (namespace) to talk to each other with the ACLs. As described
in tailscale's documentation [[1]], a server should be tagged and personnal
devices should be tied to a user. Translated in headscale's terms each user can
have multiple devices and all those devices should be in the same namespace.
The servers should be tagged and used as such.

This implementation would render useless the sharing feature that is currently
implemented since an ACL could do the same. Simplifying to only one user
interface to do one thing is easier and less confusing for the users.

To better suit the ACLs in this proposition, it's advised to consider that each
namespaces belong to one person. This person can have multiple devices, they
will all be considered as the same user in the ACLs. OIDC feature wouldn't need
to map people to namespace, just create a namespace if the person isn't
registered yet.

As a sidenote, users would like to write ACLs as YAML. We should offer users
the ability to rules in either format (HuJSON or YAML).

[1]: https://tailscale.com/kb/1068/acl-tags/

## Example

Let's build an example use case for a small business (It may be the place where
ACL's are the most useful).

We have a small company with a boss, an admin, two developper and an intern.

The boss should have access to all servers but not to the users hosts. Admin
should also have access to all hosts except that their permissions should be
limited to maintaining the hosts (for example purposes). The developers can do
anything they want on dev hosts, but only watch on productions hosts. Intern
can only interact with the development servers.

Each user have at least a device connected to the network and we have some
servers.

- database.prod
- database.dev
- app-server1.prod
- app-server1.dev
- billing.internal

### Current headscale implementation

Let's create some namespaces

```bash
headscale namespaces create prod
headscale namespaces create dev
headscale namespaces create internal
headscale namespaces create users

headscale nodes register -n users boss-computer
headscale nodes register -n users admin1-computer
headscale nodes register -n users dev1-computer
headscale nodes register -n users dev1-phone
headscale nodes register -n users dev2-computer
headscale nodes register -n users intern1-computer

headscale nodes register -n prod database
headscale nodes register -n prod app-server1

headscale nodes register -n dev database
headscale nodes register -n dev app-server1

headscale nodes register -n internal billing

headscale nodes list
ID  | Name              | Namespace | IP address
1   | boss-computer     | users     | 100.64.0.1
2   | admin1-computer   | users     | 100.64.0.2
3   | dev1-computer     | users     | 100.64.0.3
4   | dev1-phone        | users     | 100.64.0.4
5   | dev2-computer     | users     | 100.64.0.5
6   | intern1-computer  | users     | 100.64.0.6
7   | database          | prod      | 100.64.0.7
8   | app-server1       | prod      | 100.64.0.8
9   | database          | dev       | 100.64.0.9
10  | app-server1       | dev       | 100.64.0.10
11  | internal          | internal  | 100.64.0.11
```

In order to only allow the communications related to our description above we
need to add the following ACLs

```json
{
  "hosts": {
    "boss-computer": "100.64.0.1",
    "admin1-computer": "100.64.0.2",
    "dev1-computer": "100.64.0.3",
    "dev1-phone": "100.64.0.4",
    "dev2-computer": "100.64.0.5",
    "intern1-computer": "100.64.0.6",
    "prod-app-server1": "100.64.0.8"
  },
  "groups": {
    "group:dev": ["dev1-computer", "dev1-phone", "dev2-computer"],
    "group:admin": ["admin1-computer"],
    "group:boss": ["boss-computer"],
    "group:intern": ["intern1-computer"]
  },
  "acls": [
    // boss have access to all servers but no users hosts
    {
      "action": "accept",
      "users": ["group:boss"],
      "ports": ["prod:*", "dev:*", "internal:*"]
    },

    // admin have access to adminstration port (lets only consider port 22 here)
    {
      "action": "accept",
      "users": ["group:admin"],
      "ports": ["prod:22", "dev:22", "internal:22"]
    },

    // dev can do anything on dev servers and check access on prod servers
    {
      "action": "accept",
      "users": ["group:dev"],
      "ports": ["dev:*", "prod-app-server1:80,443"]
    },

    // interns only have access to port 80 and 443 on dev servers (lame internship)
    { "action": "accept", "users": ["group:intern"], "ports": ["dev:80,443"] },

    // users can access their own devices
    {
      "action": "accept",
      "users": ["dev1-computer"],
      "ports": ["dev1-phone:*"]
    },
    {
      "action": "accept",
      "users": ["dev1-phone"],
      "ports": ["dev1-computer:*"]
    },

    // internal namespace communications should still be allowed within the namespace
    { "action": "accept", "users": ["dev"], "ports": ["dev:*"] },
    { "action": "accept", "users": ["prod"], "ports": ["prod:*"] },
    { "action": "accept", "users": ["internal"], "ports": ["internal:*"] }
  ]
}
```

Since communications between namespace isn't possible we also have to share the
devices between the namespaces.

```bash

// add boss host to prod, dev and internal network
headscale nodes share -i 1 -n prod
headscale nodes share -i 1 -n dev
headscale nodes share -i 1 -n internal

// add admin computer to prod, dev and internal network
headscale nodes share -i 2 -n prod
headscale nodes share -i 2 -n dev
headscale nodes share -i 2 -n internal

// add all dev to prod and dev network
headscale nodes share -i 3 -n dev
headscale nodes share -i 4 -n dev
headscale nodes share -i 3 -n prod
headscale nodes share -i 4 -n prod
headscale nodes share -i 5 -n dev
headscale nodes share -i 5 -n prod

headscale nodes share -i 6 -n dev
```

This fake network have not been tested but it should work. Operating it could
be quite tedious if the company grows. Each time a new user join we have to add
it to a group, and share it to the correct namespaces. If the user want
multiple devices we have to allow communication to each of them one by one. If
business conduct a change in the organisations we may have to rewrite all acls
and reorganise all namespaces.

If we add servers in production we should also update the ACLs to allow dev
access to certain category of them (only app servers for example).

### example based on the proposition in this document

Let's create the namespaces

```bash
headscale namespaces create boss
headscale namespaces create admin1
headscale namespaces create dev1
headscale namespaces create dev2
headscale namespaces create intern1
```

We don't need to create namespaces for the servers because the servers will be
tagged. When registering the servers we will need to add the flag
`--advertised-tags=tag:<tag1>,tag:<tag2>`, and the user (namespace) that is
registering the server should be allowed to do it. Since anyone can add tags to
a server they can register, the check of the tags is done on headscale server
and only valid tags are applied. A tag is valid if the namespace that is
registering it is allowed to do it.

Here are the ACL's to implement the same permissions as above:

```json
{
  // groups are simpler and only list the namespaces name
  "groups": {
    "group:boss": ["boss"],
    "group:dev": ["dev1", "dev2"],
    "group:admin": ["admin1"],
    "group:intern": ["intern1"]
  },
  "tagOwners": {
    // the administrators can add servers in production
    "tag:prod-databases": ["group:admin"],
    "tag:prod-app-servers": ["group:admin"],

    // the boss can tag any server as internal
    "tag:internal": ["group:boss"],

    // dev can add servers for dev purposes as well as admins
    "tag:dev-databases": ["group:admin", "group:dev"],
    "tag:dev-app-servers": ["group:admin", "group:dev"]

    // interns cannot add servers
  },
  "acls": [
    // boss have access to all servers
    {
      "action": "accept",
      "users": ["group:boss"],
      "ports": [
        "tag:prod-databases:*",
        "tag:prod-app-servers:*",
        "tag:internal:*",
        "tag:dev-databases:*",
        "tag:dev-app-servers:*"
      ]
    },

    // admin have only access to administrative ports of the servers
    {
      "action": "accept",
      "users": ["group:admin"],
      "ports": [
        "tag:prod-databases:22",
        "tag:prod-app-servers:22",
        "tag:internal:22",
        "tag:dev-databases:22",
        "tag:dev-app-servers:22"
      ]
    },

    {
      "action": "accept",
      "users": ["group:dev"],
      "ports": [
        "tag:dev-databases:*",
        "tag:dev-app-servers:*",
        "tag:prod-app-servers:80,443"
      ]
    },

    // servers should be able to talk to database. Database should not be able to initiate connections to server
    {
      "action": "accept",
      "users": ["tag:dev-app-servers"],
      "ports": ["tag:dev-databases:5432"]
    },
    {
      "action": "accept",
      "users": ["tag:prod-app-servers"],
      "ports": ["tag:prod-databases:5432"]
    },

    // interns have access to dev-app-servers only in reading mode
    {
      "action": "accept",
      "users": ["group:intern"],
      "ports": ["tag:dev-app-servers:80,443"]
    },

    // we still have to allow internal namespaces communications since nothing guarantees that each user have their own namespaces. This could be talked over.
    { "action": "accept", "users": ["boss"], "ports": ["boss:*"] },
    { "action": "accept", "users": ["dev1"], "ports": ["dev1:*"] },
    { "action": "accept", "users": ["dev2"], "ports": ["dev2:*"] },
    { "action": "accept", "users": ["admin1"], "ports": ["admin1:*"] },
    { "action": "accept", "users": ["intern1"], "ports": ["intern1:*"] }
  ]
}
```

With this implementation, the sharing step is not necessary. Maintenance cost
of the ACL file is lower and less tedious (no need to map hostname and IP's
into it).
