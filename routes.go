package headscale

import (
	"fmt"

	"inet.af/netaddr"
)

const (
	errRouteIsNotAvailable = Error("route is not available")
)

// Deprecated: use machine function instead
// GetAdvertisedNodeRoutes returns the subnet routes advertised by a node (identified by
// namespace and node name).
func (h *Headscale) GetAdvertisedNodeRoutes(
	namespace string,
	nodeName string,
) (*[]netaddr.IPPrefix, error) {
	machine, err := h.GetMachine(namespace, nodeName)
	if err != nil {
		return nil, err
	}

	return &machine.HostInfo.RoutableIPs, nil
}

// Deprecated: use machine function instead
// GetEnabledNodeRoutes returns the subnet routes enabled by a node (identified by
// namespace and node name).
func (h *Headscale) GetEnabledNodeRoutes(
	namespace string,
	nodeName string,
) ([]netaddr.IPPrefix, error) {
	machine, err := h.GetMachine(namespace, nodeName)
	if err != nil {
		return nil, err
	}

	return machine.EnabledRoutes, nil
}

// Deprecated: use machine function instead
// IsNodeRouteEnabled checks if a certain route has been enabled.
func (h *Headscale) IsNodeRouteEnabled(
	namespace string,
	nodeName string,
	routeStr string,
) bool {
	route, err := netaddr.ParseIPPrefix(routeStr)
	if err != nil {
		return false
	}

	enabledRoutes, err := h.GetEnabledNodeRoutes(namespace, nodeName)
	if err != nil {
		return false
	}

	for _, enabledRoute := range enabledRoutes {
		if route == enabledRoute {
			return true
		}
	}

	return false
}

// Deprecated: use EnableRoute in machine.go
// EnableNodeRoute enables a subnet route advertised by a node (identified by
// namespace and node name).
func (h *Headscale) EnableNodeRoute(
	namespace string,
	nodeName string,
	routeStr string,
) error {
	machine, err := h.GetMachine(namespace, nodeName)
	if err != nil {
		return err
	}

	route, err := netaddr.ParseIPPrefix(routeStr)
	if err != nil {
		return err
	}

	availableRoutes, err := h.GetAdvertisedNodeRoutes(namespace, nodeName)
	if err != nil {
		return err
	}

	enabledRoutes, err := h.GetEnabledNodeRoutes(namespace, nodeName)
	if err != nil {
		return err
	}

	available := false
	for _, availableRoute := range *availableRoutes {
		// If the route is available, and not yet enabled, add it to the new routing table
		if route == availableRoute {
			available = true
			if !h.IsNodeRouteEnabled(namespace, nodeName, routeStr) {
				enabledRoutes = append(enabledRoutes, route)
			}
		}
	}

	if !available {
		return errRouteIsNotAvailable
	}

	machine.EnabledRoutes = enabledRoutes

	if err := h.db.Save(&machine).Error; err != nil {
		return fmt.Errorf("failed to update node routes in the database: %w", err)
	}

	return nil
}
