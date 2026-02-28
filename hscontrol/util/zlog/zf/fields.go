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
	NodeID             = "node.id"
	NodeName           = "node.name"
	NodeKey            = "node.key"
	NodeKeyExisting    = "node.key.existing"
	NodeKeyRequest     = "node.key.request"
	NodeTags           = "node.tags"
	NodeIsTagged       = "node.is_tagged"
	NodeOnline         = "node.online"
	NodeExpired        = "node.expired"
	NodeHostname       = "node.hostname"
	ExistingNodeName   = "existing.node.name"
	ExistingNodeID     = "existing.node.id"
	CurrentHostname    = "current_hostname"
	RejectedHostname   = "rejected_hostname"
	OldHostname        = "old_hostname"
	NewHostnameField   = "new_hostname"
	OldGivenName       = "old_given_name"
	NewGivenName       = "new_given_name"
	NewName            = "new_name"
	GeneratedHostname  = "generated.hostname"
	RegistrationKey    = "registration_key" //nolint:gosec // G101: not a credential
	RegistrationMethod = "registrationMethod"
	ExpiresAt          = "expiresAt"
)

// Tag fields for reauth and tag operations.
const (
	CurrentTags      = "current.tags"
	RemovedTags      = "removed.tags"
	RejectedTags     = "rejected.tags"
	NewTags          = "new.tags"
	OldTags          = "old.tags"
	IsTagged         = "is.tagged"
	WasAuthKeyTagged = "was.authkey.tagged"
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
	OldUser      = "old.user"
	NewUser      = "new.user"
)

// PreAuthKey fields.
const (
	PAKID           = "pak.id"
	PAKPrefix       = "pak.prefix"
	PAKTags         = "pak.tags"
	PAKReusable     = "pak.reusable"
	PAKEphemeral    = "pak.ephemeral"
	PAKUsed         = "pak.used"
	PAKIsTagged     = "pak.is_tagged"
	PAKExpiration   = "pak.expiration"
	AuthKeyID       = "authkey.id"
	AuthKeyUsed     = "authkey.used"
	AuthKeyExpired  = "authkey.expired"
	AuthKeyReusable = "authkey.reusable"
	NodeKeyRotation = "nodekey.rotation"
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
	RoutesAnnounced    = "routes.announced"
	RoutesApproved     = "routes.approved"
	RoutesApprovedOld  = "routes.approved.old"
	RoutesApprovedNew  = "routes.approved.new"
	OldAnnouncedRoutes = "oldAnnouncedRoutes"
	NewAnnouncedRoutes = "newAnnouncedRoutes"
	ApprovedRoutes     = "approvedRoutes"
	OldApprovedRoutes  = "oldApprovedRoutes"
	NewApprovedRoutes  = "newApprovedRoutes"
	AutoApprovedRoutes = "autoApprovedRoutes"
	AllApprovedRoutes  = "allApprovedRoutes"
	RouteChanged       = "routeChanged"
	Prefix             = "prefix"
	FinalState         = "finalState"
	NewState           = "newState"
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
	ClientAddress   = "client_address"
	ClientVersion   = "client_version"
	MinimumVersion  = "minimum_version"
)

// Policy fields.
const (
	PolicyChanged      = "policy.changed"
	FilterHashOld      = "filter.hash.old"
	FilterHashNew      = "filter.hash.new"
	TagOwnerHashOld    = "tagOwner.hash.old"
	TagOwnerHashNew    = "tagOwner.hash.new"
	AutoApproveHashOld = "autoApprove.hash.old"
	AutoApproveHashNew = "autoApprove.hash.new"
	ExitSetHashOld     = "exitSet.hash.old"
	ExitSetHashNew     = "exitSet.hash.new"
)

// Connection/Channel fields.
const (
	Chan            = "chan"
	ConnID          = "conn.id"
	ConnectionIndex = "connection_index"
	Address         = "address"
)

// gRPC fields.
const (
	Client  = "client"
	Request = "request"
	Users   = "users"
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
	Method       = "method"
	Signal       = "signal"
	Func         = "func"
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
	Database    = "database"
	Index       = "index"
	Parent      = "parent"
	Type        = "type"
)

// Component field for sub-loggers.
const (
	Component = "component"
)

// Debug environment variable fields.
const (
	DebugDeadlock              = "HEADSCALE_DEBUG_DEADLOCK"
	DebugDERPUseIP             = "HEADSCALE_DEBUG_DERP_USE_IP"
	DebugDumpConfig            = "HEADSCALE_DEBUG_DUMP_CONFIG"
	DebugHighCardinalityMetric = "HEADSCALE_DEBUG_HIGH_CARDINALITY_METRICS"
	DebugProfilingEnabled      = "HEADSCALE_DEBUG_PROFILING_ENABLED"
	DebugTailSQLEnabled        = "HEADSCALE_DEBUG_TAILSQL_ENABLED"
)
