# OIDC Groups in ACL Policies

Headscale supports using OIDC group memberships in ACL policies through the standard
Tailscale-compatible `group:<name>` principal. OIDC groups from any provider
(Keycloak, Authentik, Okta, Azure AD, Google Workspace, etc.) are merged with
policy-defined local groups under the same `group:<name>` syntax.

## Prerequisites

- OIDC authentication must be configured in your Headscale config
- Your OIDC provider must include a `groups` claim in the ID token or userinfo response
- The `groups` scope must be requested (add `"groups"` to the `scope` list in your OIDC config)

## Syntax

Use `group:<group-name>` as a source or destination in your ACL policy:

```json
{
  "acls": [
    {
      "action": "accept",
      "src": ["group:engineering"],
      "dst": ["group:admins:443"]
    }
  ]
}
```

This grants all users in the `engineering` group access to all users in the `admins` group
on port 443. The `engineering` group resolves through both:
- Policy-defined local group membership (from the `groups` section)
- OIDC provider group membership (from the `groups` claim in the OIDC token)

### Examples

Allow engineers to access all internal services:

```json
{
  "acls": [
    {
      "action": "accept",
      "src": ["group:engineering"],
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
      "src": ["group:dba"],
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
      "src": ["group:engineering", "tag:ops"],
      "dst": ["group:platform:80,443"]
    }
  ]
}
```

Mix local and OIDC groups:

```json
{
  "groups": {
    "group:local-team": ["bob@headscale.local", "alice@headscale.local"]
  },
  "acls": [
    {
      "action": "accept",
      "src": ["group:engineering"],
      "dst": ["*:*"]
    }
  ]
}
```

In this example, `group:engineering` might be defined only via OIDC, while
`group:local-team` is defined only in the policy. Both resolve through the
same `group:<name>` syntax.

## How It Works

1. **Login**: When a user authenticates via OIDC, Headscale fetches their group memberships
   from the `groups` claim in the ID token or userinfo response.

2. **Storage**: Group memberships are stored in the `user_oidc_groups` database table,
   linked to the user by their user ID.

3. **Policy Resolution**: When a policy uses `group:<group-name>`, Headscale resolves
   members from BOTH sources:
   - **Local groups**: Members defined in the policy's `groups` section
   - **OIDC groups**: Members from the `user_oidc_groups` table

4. **Deduplication**: If a user appears in both local and OIDC membership for the same
   group, they are counted once (no duplicate nodes or rules).

5. **Refresh**: OIDC group memberships are refreshed on each login. A background process
   also periodically clears stale OIDC group data so that removed memberships take effect
   at the user's next login. Local group memberships are never modified by OIDC refresh.

## Dual-Source Resolution

The same group name may exist in both systems:

- **Headscale local**: `bob -> engineering` (defined in the policy's `groups` section)
- **OIDC**: `alice -> engineering` (from the OIDC provider's `groups` claim)

Then `group:engineering` includes both `bob` and `alice`. The internal distinction
between local and OIDC membership is preserved:

- Policy-defined groups are stored in the policy's `groups` section and never modified
  by OIDC refresh
- OIDC memberships are stored in the `user_oidc_groups` table and never modified
  by local group changes
- The periodic OIDC refresh only modifies OIDC-derived memberships
- Removing a user from an OIDC group only removes their OIDC-derived authorization

## Group Name Format

Group names are case-sensitive and match exactly as provided by the OIDC provider.
For example, `group:Engineering` and `group:engineering` are different groups.

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

- OIDC group memberships are only refreshed on login or by the periodic background refresh
- The periodic refresh clears stale OIDC groups; fresh groups are populated on next login
- For immediate group updates, use the admin API to set groups manually
- Group names must not contain colons (`:`) as this conflicts with the alias parser
- Local group membership (defined in the policy's `groups` section) is managed separately
  and is not affected by OIDC refresh
