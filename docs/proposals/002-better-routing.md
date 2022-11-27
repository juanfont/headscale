# Better route management

As of today, route management in Headscale is very basic and does not allow for much flexibility, including implementing subnet HA, 4via6 or more advanced features. We also have a number of bugs (e.g., routes exposed by ephemeral nodes)

This proposal aims to improve the route management.

## Current situation

Routes advertised by the nodes are read from the Hostinfo struct. If approved from the the CLI or via autoApprovers, the route is added to the EnabledRoutes field in `Machine`.

This means that the advertised routes are not persisted in the database, as Hostinfo is always replaced. In the same way, EnabledRoutes can get out of sync with the actual routes in the node.

In case of colliding routes (i.e., subnets that are exposed from multiple nodes), we are currently just sending all of them in `PrimaryRoutes`... and hope for the best. (`PrimaryRoutes` is the field in `Node` used for subnet failover).

## Proposal

The core part is to create a new `Route` struct (and DB table), with the following fields:

```go
type Route struct {
	ID          uint64 `gorm:"primary_key"`

    Machine     *Machine
    Prefix      IPPrefix

    Advertised  bool
    Enabled     bool
    IsPrimary   bool


    CreatedAt   *time.Time
    UpdatedAt   *time.Time
    DeletedAt   *time.Time
}
```

- The `Advertised` field is set to true if the route is being advertised by the node. It is set to false if the route is removed. This way we can indicate if a later enabled route has stopped being advertised. A similar behaviour happens in the Tailscale.com control panel.

- The `Enabled` field is set to true if the route is enabled - via CLI or autoApprovers.

- `IsPrimary` indicates if Headscale has selected this route as the primary route for that particular subnet. This allows us to implement subnet failover. This would be fully automatic if there is more than subnet routers advertising the same network - which is the behaviour of Tailscale.com.

## Stuff to bear in mind

- We need to make sure to migrate the current `EnabledRoutes` of `Machine` into the new table.
- When a node stops sharing a subnet, I reckon we should mark it both as not `Advertised` and not `Enabled`. Users should re-enable it if the node advertises it again.
- If only one subnet router is advertising a subnet, we should mark it as primary.
- Regarding subnet failover, the current behaviour of Tailscale.com is to perform the failover after 15 seconds from the node disconnecting from their control panel. I reckon we cannot do the same currently. Our maximum granularity is the keep alive period.
