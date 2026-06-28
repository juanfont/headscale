package state

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"

	hsdb "github.com/juanfont/headscale/hscontrol/db"
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

// DebugRegistrationCacheInfo represents the registration cache in a JSON-safe
// format for the debug endpoint.
type DebugRegistrationCacheInfo struct {
	Type       string                        `json:"type"`
	Expiration string                        `json:"expiration"`
	MaxEntries int                           `json:"max_entries"`
	CurrentLen int                           `json:"current_len"`
	Status     string                        `json:"status"`
	Entries    []DebugRegistrationCacheEntry `json:"entries"`
}

// DebugRegistrationCacheEntry represents a pending auth cache entry without
// exposing internal channels or one-time secrets.
type DebugRegistrationCacheEntry struct {
	ID                  string                                     `json:"id"`
	Kind                string                                     `json:"kind"`
	Registration        *DebugRegistrationCacheRegistration        `json:"registration,omitempty"`
	SSHCheck            *DebugRegistrationCacheSSHCheck            `json:"ssh_check,omitempty"`
	PendingConfirmation *DebugRegistrationCachePendingConfirmation `json:"pending_confirmation,omitempty"`
}

// DebugRegistrationCacheRegistration represents a pending node registration.
type DebugRegistrationCacheRegistration struct {
	Hostname    string     `json:"hostname,omitempty"`
	HasHostinfo bool       `json:"has_hostinfo"`
	Endpoints   []string   `json:"endpoints,omitempty"`
	Expiry      *time.Time `json:"expiry,omitempty"`
}

// DebugRegistrationCacheSSHCheck represents a pending SSH check auth request.
type DebugRegistrationCacheSSHCheck struct {
	SrcNodeID types.NodeID `json:"src_node_id"`
	DstNodeID types.NodeID `json:"dst_node_id"`
}

// DebugRegistrationCachePendingConfirmation represents pending OIDC
// confirmation state without exposing the one-time CSRF token.
type DebugRegistrationCachePendingConfirmation struct {
	UserID     uint       `json:"user_id"`
	NodeExpiry *time.Time `json:"node_expiry,omitempty"`
	HasCSRF    bool       `json:"has_csrf"`
}

// DebugOverview returns a comprehensive overview of the current state for debugging.
func (s *State) DebugOverview() string {
	info := s.DebugOverviewJSON()

	var sb strings.Builder

	sb.WriteString("=== Headscale State Overview ===\n\n")

	// Node statistics
	fmt.Fprintf(&sb, "Nodes: %d total\n", info.Nodes.Total)
	fmt.Fprintf(&sb, "  - Online: %d\n", info.Nodes.Online)
	fmt.Fprintf(&sb, "  - Expired: %d\n", info.Nodes.Expired)
	fmt.Fprintf(&sb, "  - Ephemeral: %d\n", info.Nodes.Ephemeral)
	sb.WriteString("\n")

	// User statistics
	fmt.Fprintf(&sb, "Users: %d total\n", info.TotalUsers)

	for userName, nodeCount := range info.Users {
		fmt.Fprintf(&sb, "  - %s: %d nodes\n", userName, nodeCount)
	}

	sb.WriteString("\n")

	// Policy information
	sb.WriteString("Policy:\n")
	fmt.Fprintf(&sb, "  - Mode: %s\n", info.Policy.Mode)

	if info.Policy.Mode == string(types.PolicyModeFile) {
		fmt.Fprintf(&sb, "  - Path: %s\n", info.Policy.Path)
	}

	sb.WriteString("\n")

	// DERP information
	if info.DERP.Configured {
		fmt.Fprintf(&sb, "DERP: %d regions configured\n", info.DERP.Regions)
	} else {
		sb.WriteString("DERP: not configured\n")
	}

	sb.WriteString("\n")

	// Route information
	fmt.Fprintf(&sb, "Primary Routes: %d active\n", info.PrimaryRoutes)
	sb.WriteString("\n")

	// Registration cache
	sb.WriteString("Registration Cache: active\n")
	sb.WriteString("\n")

	return sb.String()
}

// DebugNodeStore returns debug information about the [NodeStore].
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

	fmt.Fprintf(&sb, "Total Regions: %d\n\n", len(derpMap.Regions))

	for regionID, region := range derpMap.Regions {
		fmt.Fprintf(&sb, "Region %d: %s\n", regionID, region.RegionName)
		fmt.Fprintf(&sb, "  - Nodes: %d\n", len(region.Nodes))

		for _, node := range region.Nodes {
			fmt.Fprintf(&sb, "    - %s (%s:%d)\n",
				node.Name, node.HostName, node.DERPPort)

			if node.STUNPort != 0 {
				fmt.Fprintf(&sb, "      STUN: %d\n", node.STUNPort)
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
func (s *State) DebugRegistrationCache() DebugRegistrationCacheInfo {
	keys := s.authCache.Keys()
	entries := make([]DebugRegistrationCacheEntry, 0, len(keys))

	for _, id := range keys {
		entry, ok := s.authCache.Peek(id)
		if !ok {
			continue
		}

		entries = append(entries, debugRegistrationCacheEntry(id, entry))
	}

	return DebugRegistrationCacheInfo{
		Type:       "expirable-lru",
		Expiration: registerCacheExpiration.String(),
		MaxEntries: defaultRegisterCacheMaxEntries,
		CurrentLen: s.authCache.Len(),
		Status:     "active",
		Entries:    entries,
	}
}

func debugRegistrationCacheEntry(
	id types.AuthID,
	request *types.AuthRequest,
) DebugRegistrationCacheEntry {
	entry := DebugRegistrationCacheEntry{
		ID:   id.String(),
		Kind: "unknown",
	}

	if request == nil {
		return entry
	}

	if request.IsRegistration() {
		registrationData := request.RegistrationData()
		endpoints := make([]string, 0, len(registrationData.Endpoints))
		for _, endpoint := range registrationData.Endpoints {
			endpoints = append(endpoints, endpoint.String())
		}

		entry.Kind = "registration"
		entry.Registration = &DebugRegistrationCacheRegistration{
			Hostname:    registrationData.Hostname,
			HasHostinfo: registrationData.Hostinfo != nil,
			Endpoints:   endpoints,
			Expiry:      registrationData.Expiry,
		}
	}

	if request.IsSSHCheck() {
		binding := request.SSHCheckBinding()
		entry.Kind = "ssh_check"
		entry.SSHCheck = &DebugRegistrationCacheSSHCheck{
			SrcNodeID: binding.SrcNodeID,
			DstNodeID: binding.DstNodeID,
		}
	}

	if pendingConfirmation := request.PendingConfirmation(); pendingConfirmation != nil {
		entry.PendingConfirmation = &DebugRegistrationCachePendingConfirmation{
			UserID:     pendingConfirmation.UserID,
			NodeExpiry: pendingConfirmation.NodeExpiry,
			HasCSRF:    pendingConfirmation.CSRF != "",
		}
	}

	return entry
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
		pol, err := hsdb.PolicyBytes(s.db.DB, s.cfg)
		if err != nil {
			return "", err
		}

		return string(pol), nil
	default:
		return "", fmt.Errorf("%w: %s", ErrUnsupportedPolicyMode, s.cfg.Policy.Mode)
	}
}

// DebugFilter returns the current filter rules and matchers.
func (s *State) DebugFilter() ([]tailcfg.FilterRule, error) {
	filter, _ := s.Filter()
	return filter, nil
}

// DebugRoutes returns the current primary routes information as a
// structured object built from the [NodeStore] snapshot.
func (s *State) DebugRoutes() types.DebugRoutes {
	debug := types.DebugRoutes{
		AvailableRoutes: make(map[types.NodeID][]netip.Prefix),
		PrimaryRoutes:   make(map[string]types.NodeID),
	}

	for _, nv := range s.nodeStore.ListNodes().All() {
		if !nv.Valid() {
			continue
		}

		online, known := nv.IsOnline().GetOk()
		if !known || !online {
			continue
		}

		approved := nv.AllApprovedRoutes()
		if len(approved) == 0 {
			continue
		}

		slices.SortFunc(approved, netip.Prefix.Compare)
		debug.AvailableRoutes[nv.ID()] = approved
	}

	for prefix, id := range s.nodeStore.PrimaryRoutes() {
		debug.PrimaryRoutes[prefix.String()] = id
	}

	var unhealthy []types.NodeID

	for _, nv := range s.nodeStore.ListNodes().All() {
		if !nv.Valid() {
			continue
		}

		if !s.nodeStore.IsNodeHealthy(nv.ID()) {
			unhealthy = append(unhealthy, nv.ID())
		}
	}

	if len(unhealthy) > 0 {
		slices.Sort(unhealthy)
		debug.UnhealthyNodes = unhealthy
	}

	return debug
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
	info.PrimaryRoutes = len(s.nodeStore.PrimaryRoutes())

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

// DebugNodeStoreJSON returns the actual nodes map from the current [NodeStore] snapshot.
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
