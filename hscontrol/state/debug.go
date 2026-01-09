package state

import (
	"fmt"
	"strings"
	"time"

	"github.com/juanfont/headscale/hscontrol/routes"
	"github.com/juanfont/headscale/hscontrol/types"
	"tailscale.com/tailcfg"
)

// DebugOverviewInfo represents the state overview information in a structured format.
type DebugOverviewInfo struct {
	Nodes struct {
		Total     int `json:"total"`
		Online    int `json:"online"`
		Expired   int `json:"expired"`
		Ephemeral int `json:"ephemeral"`
	} `json:"nodes"`
	Users      map[string]int `json:"users"` // username -> node count
	TotalUsers int            `json:"total_users"`
	Policy     struct {
		Mode string `json:"mode"`
		Path string `json:"path,omitempty"`
	} `json:"policy"`
	DERP struct {
		Configured bool `json:"configured"`
		Regions    int  `json:"regions"`
	} `json:"derp"`
	PrimaryRoutes int `json:"primary_routes"`
}

// DebugDERPInfo represents DERP map information in a structured format.
type DebugDERPInfo struct {
	Configured   bool                     `json:"configured"`
	TotalRegions int                      `json:"total_regions"`
	Regions      map[int]*DebugDERPRegion `json:"regions,omitempty"`
}

// DebugDERPRegion represents a single DERP region.
type DebugDERPRegion struct {
	RegionID   int              `json:"region_id"`
	RegionName string           `json:"region_name"`
	Nodes      []*DebugDERPNode `json:"nodes"`
}

// DebugDERPNode represents a single DERP node.
type DebugDERPNode struct {
	Name     string `json:"name"`
	HostName string `json:"hostname"`
	DERPPort int    `json:"derp_port"`
	STUNPort int    `json:"stun_port,omitempty"`
}

// DebugStringInfo wraps a debug string for JSON serialization.
type DebugStringInfo struct {
	Content string `json:"content"`
}

// DebugOverview returns a comprehensive overview of the current state for debugging.
func (s *State) DebugOverview() string {
	allNodes := s.nodeStore.ListNodes()
	users, _ := s.ListAllUsers()

	var sb strings.Builder

	sb.WriteString("=== Headscale State Overview ===\n\n")

	// Node statistics
	sb.WriteString(fmt.Sprintf("Nodes: %d total\n", allNodes.Len()))

	userNodeCounts := make(map[string]int)
	onlineCount := 0
	expiredCount := 0
	ephemeralCount := 0

	now := time.Now()
	for _, node := range allNodes.All() {
		if node.Valid() {
			userName := node.Owner().Name()
			userNodeCounts[userName]++

			if node.IsOnline().Valid() && node.IsOnline().Get() {
				onlineCount++
			}

			if node.Expiry().Valid() && node.Expiry().Get().Before(now) {
				expiredCount++
			}

			if node.AuthKey().Valid() && node.AuthKey().Ephemeral() {
				ephemeralCount++
			}
		}
	}

	sb.WriteString(fmt.Sprintf("  - Online: %d\n", onlineCount))
	sb.WriteString(fmt.Sprintf("  - Expired: %d\n", expiredCount))
	sb.WriteString(fmt.Sprintf("  - Ephemeral: %d\n", ephemeralCount))
	sb.WriteString("\n")

	// User statistics
	sb.WriteString(fmt.Sprintf("Users: %d total\n", len(users)))
	for userName, nodeCount := range userNodeCounts {
		sb.WriteString(fmt.Sprintf("  - %s: %d nodes\n", userName, nodeCount))
	}
	sb.WriteString("\n")

	// Policy information
	sb.WriteString("Policy:\n")
	sb.WriteString(fmt.Sprintf("  - Mode: %s\n", s.cfg.Policy.Mode))
	if s.cfg.Policy.Mode == types.PolicyModeFile {
		sb.WriteString(fmt.Sprintf("  - Path: %s\n", s.cfg.Policy.Path))
	}
	sb.WriteString("\n")

	// DERP information
	derpMap := s.derpMap.Load()
	if derpMap != nil {
		sb.WriteString(fmt.Sprintf("DERP: %d regions configured\n", len(derpMap.Regions)))
	} else {
		sb.WriteString("DERP: not configured\n")
	}
	sb.WriteString("\n")

	// Route information
	routeCount := len(strings.Split(strings.TrimSpace(s.primaryRoutes.String()), "\n"))
	if s.primaryRoutes.String() == "" {
		routeCount = 0
	}
	sb.WriteString(fmt.Sprintf("Primary Routes: %d active\n", routeCount))
	sb.WriteString("\n")

	// Registration cache
	sb.WriteString("Registration Cache: active\n")
	sb.WriteString("\n")

	return sb.String()
}

// DebugNodeStore returns debug information about the NodeStore.
func (s *State) DebugNodeStore() string {
	return s.nodeStore.DebugString()
}

// DebugDERPMap returns debug information about the DERP map configuration.
func (s *State) DebugDERPMap() string {
	derpMap := s.derpMap.Load()
	if derpMap == nil {
		return "DERP Map: not configured\n"
	}

	var sb strings.Builder

	sb.WriteString("=== DERP Map Configuration ===\n\n")

	sb.WriteString(fmt.Sprintf("Total Regions: %d\n\n", len(derpMap.Regions)))

	for regionID, region := range derpMap.Regions {
		sb.WriteString(fmt.Sprintf("Region %d: %s\n", regionID, region.RegionName))
		sb.WriteString(fmt.Sprintf("  - Nodes: %d\n", len(region.Nodes)))

		for _, node := range region.Nodes {
			sb.WriteString(fmt.Sprintf("    - %s (%s:%d)\n",
				node.Name, node.HostName, node.DERPPort))
			if node.STUNPort != 0 {
				sb.WriteString(fmt.Sprintf("      STUN: %d\n", node.STUNPort))
			}
		}
		sb.WriteString("\n")
	}

	return sb.String()
}

// DebugSSHPolicies returns debug information about SSH policies for all nodes.
func (s *State) DebugSSHPolicies() map[string]*tailcfg.SSHPolicy {
	nodes := s.nodeStore.ListNodes()

	sshPolicies := make(map[string]*tailcfg.SSHPolicy)

	for _, node := range nodes.All() {
		if !node.Valid() {
			continue
		}

		pol, err := s.SSHPolicy(node)
		if err != nil {
			// Store the error information
			continue
		}

		key := fmt.Sprintf("id:%d hostname:%s givenname:%s",
			node.ID(), node.Hostname(), node.GivenName())
		sshPolicies[key] = pol
	}

	return sshPolicies
}

// DebugRegistrationCache returns debug information about the registration cache.
func (s *State) DebugRegistrationCache() map[string]any {
	// The cache doesn't expose internal statistics, so we provide basic info
	result := map[string]any{
		"type":       "zcache",
		"expiration": registerCacheExpiration.String(),
		"cleanup":    registerCacheCleanup.String(),
		"status":     "active",
	}

	return result
}

// DebugConfig returns debug information about the current configuration.
func (s *State) DebugConfig() *types.Config {
	return s.cfg
}

// DebugPolicy returns the current policy data as a string.
func (s *State) DebugPolicy() (string, error) {
	switch s.cfg.Policy.Mode {
	case types.PolicyModeDB:
		p, err := s.GetPolicy()
		if err != nil {
			return "", err
		}

		return p.Data, nil
	case types.PolicyModeFile:
		pol, err := policyBytes(s.db, s.cfg)
		if err != nil {
			return "", err
		}

		return string(pol), nil
	default:
		return "", fmt.Errorf("unsupported policy mode: %s", s.cfg.Policy.Mode)
	}
}

// DebugFilter returns the current filter rules and matchers.
func (s *State) DebugFilter() ([]tailcfg.FilterRule, error) {
	filter, _ := s.Filter()
	return filter, nil
}

// DebugRoutes returns the current primary routes information as a structured object.
func (s *State) DebugRoutes() routes.DebugRoutes {
	return s.primaryRoutes.DebugJSON()
}

// DebugRoutesString returns the current primary routes information as a string.
func (s *State) DebugRoutesString() string {
	return s.PrimaryRoutesString()
}

// DebugPolicyManager returns the policy manager debug string.
func (s *State) DebugPolicyManager() string {
	return s.PolicyDebugString()
}

// PolicyDebugString returns a debug representation of the current policy.
func (s *State) PolicyDebugString() string {
	return s.polMan.DebugString()
}

// DebugOverviewJSON returns a structured overview of the current state for debugging.
func (s *State) DebugOverviewJSON() DebugOverviewInfo {
	allNodes := s.nodeStore.ListNodes()
	users, _ := s.ListAllUsers()

	info := DebugOverviewInfo{
		Users:      make(map[string]int),
		TotalUsers: len(users),
	}

	// Node statistics
	info.Nodes.Total = allNodes.Len()
	now := time.Now()

	for _, node := range allNodes.All() {
		if node.Valid() {
			userName := node.Owner().Name()
			info.Users[userName]++

			if node.IsOnline().Valid() && node.IsOnline().Get() {
				info.Nodes.Online++
			}

			if node.Expiry().Valid() && node.Expiry().Get().Before(now) {
				info.Nodes.Expired++
			}

			if node.AuthKey().Valid() && node.AuthKey().Ephemeral() {
				info.Nodes.Ephemeral++
			}
		}
	}

	// Policy information
	info.Policy.Mode = string(s.cfg.Policy.Mode)
	if s.cfg.Policy.Mode == types.PolicyModeFile {
		info.Policy.Path = s.cfg.Policy.Path
	}

	derpMap := s.derpMap.Load()
	if derpMap != nil {
		info.DERP.Configured = true
		info.DERP.Regions = len(derpMap.Regions)
	} else {
		info.DERP.Configured = false
		info.DERP.Regions = 0
	}

	// Route information
	routeCount := len(strings.Split(strings.TrimSpace(s.primaryRoutes.String()), "\n"))
	if s.primaryRoutes.String() == "" {
		routeCount = 0
	}
	info.PrimaryRoutes = routeCount

	return info
}

// DebugDERPJSON returns structured debug information about the DERP map configuration.
func (s *State) DebugDERPJSON() DebugDERPInfo {
	derpMap := s.derpMap.Load()

	info := DebugDERPInfo{
		Configured: derpMap != nil,
		Regions:    make(map[int]*DebugDERPRegion),
	}

	if derpMap == nil {
		return info
	}

	info.TotalRegions = len(derpMap.Regions)

	for regionID, region := range derpMap.Regions {
		debugRegion := &DebugDERPRegion{
			RegionID:   regionID,
			RegionName: region.RegionName,
			Nodes:      make([]*DebugDERPNode, 0, len(region.Nodes)),
		}

		for _, node := range region.Nodes {
			debugNode := &DebugDERPNode{
				Name:     node.Name,
				HostName: node.HostName,
				DERPPort: node.DERPPort,
				STUNPort: node.STUNPort,
			}
			debugRegion.Nodes = append(debugRegion.Nodes, debugNode)
		}

		info.Regions[regionID] = debugRegion
	}

	return info
}

// DebugNodeStoreJSON returns the actual nodes map from the current NodeStore snapshot.
func (s *State) DebugNodeStoreJSON() map[types.NodeID]types.Node {
	snapshot := s.nodeStore.data.Load()
	return snapshot.nodesByID
}

// DebugPolicyManagerJSON returns structured debug information about the policy manager.
func (s *State) DebugPolicyManagerJSON() DebugStringInfo {
	return DebugStringInfo{
		Content: s.polMan.DebugString(),
	}
}
