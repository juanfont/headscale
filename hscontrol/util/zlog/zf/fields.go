// Package zf provides zerolog field name constants for consistent logging.
//
// Using constants ensures typos are caught at compile time and enables
// easy refactoring. Import as:
//
//	import "github.com/juanfont/headscale/hscontrol/util/zlog/zf"
//
// Usage:
//
//	log.Info().Uint64(zf.NodeID, id).Str(zf.NodeName, name).Msg("...")
package zf

// Node fields.
const (
	NodeID       = "node.id"
	NodeName     = "node.name"
	NodeKey      = "node.key"
	NodeTags     = "node.tags"
	NodeIsTagged = "node.is_tagged"
	NodeOnline   = "node.online"
	NodeExpired  = "node.expired"
)

// Machine fields.
const (
	MachineKey = "machine.key"
)

// User fields.
const (
	UserID       = "user.id"
	UserName     = "user.name"
	UserDisplay  = "user.display"
	UserProvider = "user.provider"
	UserCount    = "user.count"
)

// PreAuthKey fields.
const (
	PAKID         = "pak.id"
	PAKPrefix     = "pak.prefix"
	PAKTags       = "pak.tags"
	PAKReusable   = "pak.reusable"
	PAKEphemeral  = "pak.ephemeral"
	PAKUsed       = "pak.used"
	PAKIsTagged   = "pak.is_tagged"
	PAKExpiration = "pak.expiration"
)

// APIKey fields.
const (
	APIKeyID         = "api_key.id"
	APIKeyPrefix     = "api_key.prefix"     //nolint:gosec // G101: not a credential
	APIKeyExpiration = "api_key.expiration" //nolint:gosec // G101: not a credential
	APIKeyLastSeen   = "api_key.last_seen"  //nolint:gosec // G101: not a credential
)

// Route fields.
const (
	RoutesAnnounced = "routes.announced"
	RoutesApproved  = "routes.approved"
)

// Request/Response fields.
const (
	OmitPeers      = "omit_peers"
	Stream         = "stream"
	Version        = "version"
	StatusCode     = "status_code"
	RegistrationID = "registration_id"
)

// Network fields.
const (
	EndpointsCount  = "endpoints_count"
	DERP            = "derp"
	Hostname        = "hostname"
	OS              = "os"
	RoutableIPCount = "routable_ips_count"
	RequestTags     = "request_tags"
	InvalidHostname = "invalid_hostname"
	NewHostname     = "new_hostname"
	URL             = "url"
	Path            = "path"
	PolicyChanged   = "policy.changed"
)

// Connection/Channel fields.
const (
	Chan            = "chan"
	ConnID          = "conn.id"
	ConnectionIndex = "connection_index"
)

// Worker/Processing fields.
const (
	WorkerID     = "worker.id"
	Reason       = "reason"
	Op           = "op"
	OK           = "ok"
	Changes      = "changes"
	Watching     = "watching"
	CleanedNodes = "cleaned_nodes"
)

// Duration fields.
const (
	TotalDuration   = "total.duration"
	TimeoutDuration = "timeout.duration"
)

// Database fields.
const (
	Table       = "table"
	MigrationID = "migration_id"
	Commit      = "commit"
	Records     = "records"
	Code        = "code"
	Got         = "got"
)

// Component field for sub-loggers.
const (
	Component = "component"
)
