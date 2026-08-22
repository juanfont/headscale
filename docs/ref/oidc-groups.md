# OIDC Groups in ACL Policies

Headscale supports using OIDC group memberships as a principal type in ACL policies.
This allows you to write policies that grant access based on group memberships from your
OIDC identity provider (e.g., Keycloak, Authentik, Okta, Azure AD, Google Workspace).

## Prerequisites

- OIDC authentication must be configured in your Headscale config
- Your OIDC provider must include a `groups` claim in the ID token or userinfo response
- The `groups` scope must be requested (add `"groups"` to the `scope` list in your OIDC config)

## Syntax

Use `oidcgrp:<group-name>` as a source or destination in your ACL policy:

```json
{
  "acls": [
    {
      "action": "accept",
      "src": ["oidcgrp:engineering"],
      "dst": ["oidcgrp:admins:443"]
    }
  ]
}
```

This grants all users in the `engineering` group access to all users in the `admins` group
on port 443.

### Examples

Allow engineers to access all internal services:

```json
{
  "acls": [
    {
      "action": "accept",
      "src": ["oidcgrp:engineering"],
      "dst": ["*:*"]
    }
  ]
}
```

Restrict database access to the DBA team:

```json
{
  "acls": [
    {
      "action": "accept",
      "src": ["oidcgrp:dba"],
      "dst": ["tag:database:5432"]
    }
  ]
}
```

Combine OIDC groups with other principal types:

```json
{
  "acls": [
    {
      "action": "accept",
      "src": ["oidcgrp:engineering", "tag:ops"],
      "dst": ["oidcgrp:platform:80,443"]
    }
  ]
}
```

## How It Works

1. **Login**: When a user authenticates via OIDC, Headscale fetches their group memberships
   from the `groups` claim in the ID token or userinfo response.

2. **Storage**: Group memberships are stored in the `user_oidc_groups` database table,
   linked to the user by their user ID.

3. **Policy Resolution**: When a policy uses `oidcgrp:<group-name>`, Headscale looks up
   all users in that group and resolves them to their node IP addresses.

4. **Refresh**: Group memberships are refreshed on each login. A background process also
   periodically clears stale group data so that removed memberships take effect at the
   user's next login.

## Group Name Format

Group names are case-sensitive and match exactly as provided by the OIDC provider.
For example, `oidcgrp:Engineering` and `oidcgrp:engineering` are different groups.

## Admin API

You can manage OIDC group memberships via the admin API:

### Get a user's OIDC groups

```
GET /api/v1/user/{id}/oidc-groups
```

Response:
```json
{
  "groups": ["engineering", "platform"]
}
```

### List users in an OIDC group

```
GET /api/v1/user/oidc-group?group=engineering
```

Response:
```json
{
  "users": [
    {"id": 1, "name": "alice", "email": "alice@example.com"},
    {"id": 2, "name": "bob", "email": "bob@example.com"}
  ]
}
```

### Set a user's OIDC groups

```
PUT /api/v1/user/{id}/oidc-groups
Content-Type: application/json

{
  "groups": ["engineering", "platform"]
}
```

## Limitations

- Group memberships are only refreshed on login or by the periodic background refresh
- The periodic refresh clears stale groups; fresh groups are populated on next login
- For immediate group updates, use the admin API to set groups manually
- Group names must not contain colons (`:`) as this conflicts with the alias parser
