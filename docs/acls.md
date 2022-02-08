
# ACLs

A key component of tailscale is the notion of Tailnet. This notion is hidden but the implications that it have on how to use tailscale are not.

For tailscale an [tailnet](https://tailscale.com/kb/1136/tailnet/) is the following:

> For personal users, you are a tailnet of many devices and one person. Each device gets a private Tailscale IP address in the CGNAT range and every device can talk directly to every other device, wherever they are on the internet.
>
> For businesses and organizations, a tailnet is many devices and many users. It can be based on your Microsoft Active Directory, your Google Workspace, a GitHub organization, Okta tenancy, or other identity provider namespace. All of the devices and users in your tailnet can be seen by the tailnet administrators in the Tailscale admin console. There you can apply tailnet-wide configuration, such as ACLs that affect visibility of devices inside your tailnet, DNS settings, and more.

## Current implementation and issues

Currently in headscale, the namespaces are used both as tailnet and users. The issue is that if we want to use the ACL's we can't use both at the same time.

Tailnet's cannot communicate with each others. So we can't have an ACL that authorize tailnet (namespace) A to talk to tailnet (namespace) B.

We also can't write ACLs based on the users (namespaces in headscale) since all devices belong to the same user.

With the current implementation the only ACL that we can user is to associate each headscale IP to a host manually then write the ACLs according to this manual mapping.

```json
{
    "hosts":{
        "host1": "100.64.0.1",
        "server": "100.64.0.2"
    },
    "acls": [
        {"action": "accept", "users":["host1"], "ports":["host2:80,443"]}
    ]
}
```

While this works, it requires a lot of manual editing on the configuration and to keep track of all devices IP address.

## Proposition for a next implementation

In order to ease the use of ACL's we need to split the tailnet and users notion.

A solution could be to consider a headscale server (in it's entirety) as a tailnet.

For personal users the default behavior could either allow all communications between all namespaces (like tailscale) or dissallow all communications between namespaces (current behavior).

For businesses and organisations, viewing a headscale instance a single tailnet would allow users (namespace) to talk to each other with the ACLs. As described in tailscale's documentation [[1]], a server should be tagged and personnal devices should be tied to a user. Translated in headscale's terms each user can have multiple devices and all those devices should be in the same namespace. The servers should be tagged and used as such.

This implementation would render useless the sharing feature that is currently implemented since an ACL could do the same.

What could be improved would be to peer different headscale installation and allow `sharing`. This would raises issues about compatible network IPs range.

[1]: https://tailscale.com/kb/1068/acl-tags/


## Get the better of both worlds

If the current behavior has a lot of use cases we could maybe have a flag to trigger one behavior or the other. Or enabling the ACL's behavior if an ACL file is defined.
