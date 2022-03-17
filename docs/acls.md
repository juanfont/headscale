# ACLs use case example

Let's build an example use case for a small business (It may be the place where
ACL's are the most useful).

We have a small company with a boss, an admin, two developers and an intern.

The boss should have access to all servers but not to the user's hosts. Admin
should also have access to all hosts except that their permissions should be
limited to maintaining the hosts (for example purposes). The developers can do
anything they want on dev hosts but only watch on productions hosts. Intern
can only interact with the development servers.

There's an additional server that acts as a router, connecting the VPN users
to an internal network 10.20.0.0/16

Each user have at least a device connected to the network and we have some
servers.

- database.prod
- database.dev
- app-server1.prod
- app-server1.dev
- billing.internal
- router.internal

## Setup of the network

Let's create the namespaces. Each user should have his own namespace. The users
here are represented as namespaces.

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
  // groups are collections of users having a common scope. A user can be in multiple groups
  // groups cannot be composed of groups
  "groups": {
    "group:boss": ["boss"],
    "group:dev": ["dev1", "dev2"],
    "group:admin": ["admin1"],
    "group:intern": ["intern1"]
  },
  // tagOwners in tailscale is an association between a TAG and the people allowed to set this TAG on a server.
  // This is documented [here](https://tailscale.com/kb/1068/acl-tags#defining-a-tag)
  // and explained [here](https://tailscale.com/blog/rbac-like-it-was-meant-to-be/)
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

    // developers have access to databases servers and application servers on all ports
    // they can only view the applications servers in prod and have no access to databases servers in production
    {
      "action": "accept",
      "users": ["group:dev"],
      "ports": [
        "tag:dev-databases:*",
        "tag:dev-app-servers:*",
        "tag:prod-app-servers:80,443"
      ]
    },

    // servers should be able to talk to database. Database should not be able to initiate connections to
    // applications servers
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

    // We still have to allow internal namespaces communications since nothing guarantees that each user have
    // their own namespaces.
    { "action": "accept", "users": ["boss"], "ports": ["boss:*"] },
    { "action": "accept", "users": ["dev1"], "ports": ["dev1:*"] },
    { "action": "accept", "users": ["dev2"], "ports": ["dev2:*"] },
    { "action": "accept", "users": ["admin1"], "ports": ["admin1:*"] },
    { "action": "accept", "users": ["intern1"], "ports": ["intern1:*"] }
  ]
}
```
