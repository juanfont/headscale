//go:generate go tool viewer --type=User,Node,PreAuthKey
package types

//go:generate go run tailscale.com/cmd/viewer --type=User,Node,PreAuthKey

import (
	"encoding/json"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"sync/atomic"
	"time"

	"github.com/juanfont/headscale/hscontrol/util"
	"tailscale.com/tailcfg"
)

const (
	SelfUpdateIdentifier = "self-update"
	DatabasePostgres     = "postgres"
	DatabaseSqlite       = "sqlite3"
)

// Common errors.
var (
	ErrCannotParsePrefix           = errors.New("cannot parse prefix")
	ErrInvalidAuthIDLength         = errors.New("auth ID has invalid length")
	ErrInvalidAuthIDPrefix         = errors.New("auth ID has invalid prefix")
	ErrRegistrationPayloadTooLarge = errors.New("registration payload exceeds size limit")
)

type StateUpdateType int

func (su StateUpdateType) String() string {
	switch su {
	case StateFullUpdate:
		return "StateFullUpdate"
	case StatePeerChanged:
		return "StatePeerChanged"
	case StatePeerChangedPatch:
		return "StatePeerChangedPatch"
	case StatePeerRemoved:
		return "StatePeerRemoved"
	case StateSelfUpdate:
		return "StateSelfUpdate"
	case StateDERPUpdated:
		return "StateDERPUpdated"
	}

	return "unknown state update type"
}

const (
	StateFullUpdate StateUpdateType = iota
	// StatePeerChanged is used for updates that needs
	// to be calculated with all peers and all policy rules.
	// This would typically be things that include tags, routes
	// and similar.
	StatePeerChanged
	StatePeerChangedPatch
	StatePeerRemoved
	// StateSelfUpdate is used to indicate that the node
	// has changed in control, and the client needs to be
	// informed.
	// The updated node is inside the ChangeNodes field
	// which should have a length of one.
	StateSelfUpdate
	StateDERPUpdated
)

// StateUpdate is an internal message containing information about
// a state change that has happened to the network.
// If type is [StateFullUpdate], all fields are ignored.
type StateUpdate struct {
	// The type of update
	Type StateUpdateType

	// ChangeNodes must be set when Type is StatePeerAdded
	// and [StatePeerChanged] and contains the full node
	// object for added nodes.
	ChangeNodes []NodeID

	// ChangePatches must be set when Type is [StatePeerChangedPatch]
	// and contains a populated [tailcfg.PeerChange] object.
	ChangePatches []*tailcfg.PeerChange

	// Removed must be set when Type is [StatePeerRemoved] and
	// contain a list of the nodes that has been removed from
	// the network.
	Removed []NodeID

	// DERPMap must be set when Type is [StateDERPUpdated] and
	// contain the new DERP Map.
	DERPMap *tailcfg.DERPMap

	// Additional message for tracking origin or what being
	// updated, useful for ambiguous updates like [StatePeerChanged].
	Message string
}

// Empty reports if there are any updates in the [StateUpdate].
func (su *StateUpdate) Empty() bool {
	switch su.Type {
	case StatePeerChanged:
		return len(su.ChangeNodes) == 0
	case StatePeerChangedPatch:
		return len(su.ChangePatches) == 0
	case StatePeerRemoved:
		return len(su.Removed) == 0
	case StateFullUpdate, StateSelfUpdate, StateDERPUpdated:
		// These update types don't have associated data to check,
		// so they are never considered empty.
		return false
	}

	return false
}

func UpdateFull() StateUpdate {
	return StateUpdate{
		Type: StateFullUpdate,
	}
}

func UpdateSelf(nodeID NodeID) StateUpdate {
	return StateUpdate{
		Type:        StateSelfUpdate,
		ChangeNodes: []NodeID{nodeID},
	}
}

func UpdatePeerChanged(nodeIDs ...NodeID) StateUpdate {
	return StateUpdate{
		Type:        StatePeerChanged,
		ChangeNodes: nodeIDs,
	}
}

func UpdatePeerPatch(changes ...*tailcfg.PeerChange) StateUpdate {
	return StateUpdate{
		Type:          StatePeerChangedPatch,
		ChangePatches: changes,
	}
}

func UpdatePeerRemoved(nodeIDs ...NodeID) StateUpdate {
	return StateUpdate{
		Type:    StatePeerRemoved,
		Removed: nodeIDs,
	}
}

func UpdateExpire(nodeID NodeID, expiry time.Time) StateUpdate {
	return StateUpdate{
		Type: StatePeerChangedPatch,
		ChangePatches: []*tailcfg.PeerChange{
			{
				NodeID:    nodeID.NodeID(),
				KeyExpiry: &expiry,
			},
		},
	}
}

const (
	authIDPrefix       = "hskey-authreq-"
	authIDRandomLength = 24
	// AuthIDLength is the total length of an AuthID: 14 (prefix) + 24 (random).
	AuthIDLength = 38
)

type AuthID string

func NewAuthID() (AuthID, error) {
	rid, err := util.GenerateRandomStringURLSafe(authIDRandomLength)
	if err != nil {
		return "", err
	}

	return AuthID(authIDPrefix + rid), nil
}

func MustAuthID() AuthID {
	rid, err := NewAuthID()
	if err != nil {
		panic(err)
	}

	return rid
}

func AuthIDFromString(str string) (AuthID, error) {
	r := AuthID(str)

	err := r.Validate()
	if err != nil {
		return "", err
	}

	return r, nil
}

func (r AuthID) String() string {
	return string(r)
}

func (r AuthID) Validate() error {
	if !strings.HasPrefix(string(r), authIDPrefix) {
		return fmt.Errorf(
			"%w: expected prefix %q",
			ErrInvalidAuthIDPrefix, authIDPrefix,
		)
	}

	if len(r) != AuthIDLength {
		return fmt.Errorf(
			"%w: expected %d, got %d",
			ErrInvalidAuthIDLength, AuthIDLength, len(r),
		)
	}

	return nil
}

// SSHCheckBinding identifies the (source, destination) node pair an SSH
// check-mode auth request is bound to. It is captured at HoldAndDelegate
// time so the follow-up request and OIDC callback can verify that no
// other (src, dst) pair has been substituted via tampered URL parameters.
type SSHCheckBinding struct {
	SrcNodeID NodeID
	DstNodeID NodeID
}

// PendingRegistrationConfirmation captures the server-side state needed
// to finalise a node registration after the user has confirmed it on
// the OIDC interstitial. The OIDC callback resolves the user identity
// and node expiry, stores them on the cached [AuthRequest], and renders
// a confirmation page; only when the user POSTs the confirmation form
// does the actual node registration run.
//
// CSRF is a one-shot per-session token that the OIDC callback set
// both as a cookie and as a hidden form field. The confirm POST
// handler refuses to proceed unless the cookie and form values match.
type PendingRegistrationConfirmation struct {
	UserID     uint
	NodeExpiry *time.Time
	CSRF       string
}

// AuthRequest represents a pending authentication request from a user or a
// node. It carries the minimum data needed to either complete a node
// registration (regData or regDataJSON populated) or an SSH check-mode auth (sshBinding
// populated), and signals the verdict via the finished channel. The closed
// flag guards [AuthRequest.FinishAuth] against double-close.
//
// [AuthRequest] is always handled by pointer so the channel and atomic flag
// have a single canonical instance even when stored in caches that
// internally copy values.
type AuthRequest struct {
	// regData holds the caller's registration payload until PrepareForCache
	// replaces it with owned serialized data and releases the original pointer.
	regData *RegistrationData

	// regDataJSON is immutable and bounded by MaxRegistrationPayloadBytes.
	// RegistrationData decodes a fresh copy without retaining the decoded graph.
	regDataJSON string

	// sshBinding is populated for SSH check-mode flows. It captures the
	// (src, dst) node pair the request was minted for so the follow-up
	// and OIDC callback can refuse to record a verdict for any other
	// pair.
	//
	// nil for non-SSH-check flows. Use [AuthRequest.SSHCheckBinding] to read it
	// safely.
	sshBinding *SSHCheckBinding

	// pendingConfirmation is populated by the OIDC callback for the
	// node-registration flow once the user identity has been resolved
	// but before the user has explicitly confirmed the registration on
	// the interstitial. The /register/confirm POST handler reads it to
	// finalise the registration without re-running the OIDC flow.
	pendingConfirmation *PendingRegistrationConfirmation

	finished chan AuthVerdict
	closed   *atomic.Bool

	// waiter is closed once a newer request parks on this session; see
	// [AuthRequest.Park].
	waiter atomic.Pointer[chan struct{}]
}

// NewAuthRequest creates a pending auth request with no payload, suitable
// for non-registration flows that only need a verdict channel.
func NewAuthRequest() *AuthRequest {
	return &AuthRequest{
		finished: make(chan AuthVerdict, 1),
		closed:   &atomic.Bool{},
	}
}

// NewRegisterAuthRequest creates a pending auth request carrying the
// minimal [RegistrationData] for a node-registration flow. The data is
// stored by pointer until [AuthRequest.PrepareForCache] detaches it; callers
// must not mutate it until preparation finishes.
func NewRegisterAuthRequest(data *RegistrationData) *AuthRequest {
	return &AuthRequest{
		regData:  data,
		finished: make(chan AuthVerdict, 1),
		closed:   &atomic.Bool{},
	}
}

// PrepareForCache replaces the registration payload with an owned serialized
// value of at most [MaxRegistrationPayloadBytes]. It must run before publishing
// the request to the cache. Serialization and size errors leave it unchanged;
// callers must reject admission on error. Repeated calls and non-registration
// requests are no-ops.
func (rn *AuthRequest) PrepareForCache() error {
	if rn.regData == nil {
		return nil
	}

	data, err := json.Marshal(rn.regData)
	if err != nil {
		return fmt.Errorf("serializing pending registration: %w", err)
	}

	if len(data) > MaxRegistrationPayloadBytes {
		return fmt.Errorf("%w: limit %d bytes", ErrRegistrationPayloadTooLarge, MaxRegistrationPayloadBytes)
	}

	rn.regDataJSON = string(data)
	rn.regData = nil

	return nil
}

// NewSSHCheckAuthRequest creates a pending auth request bound to a
// specific (src, dst) SSH check-mode pair. The follow-up handler and
// OIDC callback must verify their incoming request matches this binding
// before recording any verdict.
func NewSSHCheckAuthRequest(src, dst NodeID) *AuthRequest {
	return &AuthRequest{
		sshBinding: &SSHCheckBinding{
			SrcNodeID: src,
			DstNodeID: dst,
		},
		finished: make(chan AuthVerdict, 1),
		closed:   &atomic.Bool{},
	}
}

// RegistrationData returns the original registration payload before preparation,
// or a fresh decoded copy after [AuthRequest.PrepareForCache]. It panics if
// called on an [AuthRequest] that was not created via
// [NewRegisterAuthRequest].
func (rn *AuthRequest) RegistrationData() *RegistrationData {
	if rn.regData != nil {
		return rn.regData
	}

	if rn.regDataJSON == "" {
		panic("RegistrationData can only be used in registration requests")
	}

	var data RegistrationData

	err := json.Unmarshal([]byte(rn.regDataJSON), &data)
	if err != nil {
		panic(fmt.Sprintf("decoding prepared registration: %v", err))
	}

	return &data
}

// SSHCheckBinding returns the (src, dst) node pair an SSH check-mode
// auth request is bound to. It panics if called on an [AuthRequest] that
// was not created via [NewSSHCheckAuthRequest].
func (rn *AuthRequest) SSHCheckBinding() *SSHCheckBinding {
	if rn.sshBinding == nil {
		panic("SSHCheckBinding can only be used in SSH check-mode requests")
	}

	return rn.sshBinding
}

// IsRegistration reports whether this auth request carries registration
// data (i.e. it was created via [NewRegisterAuthRequest]).
func (rn *AuthRequest) IsRegistration() bool {
	return rn.regData != nil || rn.regDataJSON != ""
}

// IsSSHCheck reports whether this auth request is bound to an SSH
// check-mode (src, dst) pair (i.e. it was created via
// [NewSSHCheckAuthRequest]).
func (rn *AuthRequest) IsSSHCheck() bool {
	return rn.sshBinding != nil
}

// IsFinished reports whether a verdict has already resolved this request.
func (rn *AuthRequest) IsFinished() bool {
	return rn.closed.Load()
}

// SetPendingConfirmation marks this [AuthRequest] as having an
// OIDC-resolved user that is waiting to confirm the registration on
// the interstitial. The OIDC callback should call this and then render
// the confirmation page; the /register/confirm POST handler reads the
// stored UserID/NodeExpiry to finish the registration.
func (rn *AuthRequest) SetPendingConfirmation(p *PendingRegistrationConfirmation) {
	rn.pendingConfirmation = p
}

// PendingConfirmation returns the pending OIDC-resolved registration
// state captured by [AuthRequest.SetPendingConfirmation], or nil if no OIDC callback
// has yet resolved an identity for this [AuthRequest].
func (rn *AuthRequest) PendingConfirmation() *PendingRegistrationConfirmation {
	return rn.pendingConfirmation
}

func (rn *AuthRequest) FinishAuth(verdict AuthVerdict) {
	if rn.closed.Swap(true) {
		return
	}

	select {
	case rn.finished <- verdict:
	default:
	}

	close(rn.finished)
}

func (rn *AuthRequest) WaitForAuth() <-chan AuthVerdict {
	return rn.finished
}

// Park makes the caller the one request waiting on [AuthRequest.WaitForAuth]
// and returns a channel that is closed once a newer caller takes its place.
// [AuthRequest.FinishAuth] hands out one verdict, so a session needs one
// waiter. The newest wins, so a client that reconnected is not kept out by
// its own dead request. Parked requests are then bounded by the sessions in
// the auth cache, not by how many requests clients send.
func (rn *AuthRequest) Park() <-chan struct{} {
	waiter := make(chan struct{})

	if prev := rn.waiter.Swap(&waiter); prev != nil {
		close(*prev)
	}

	return waiter
}

type AuthVerdict struct {
	// Err is the error that occurred during the authentication process, if any.
	// If Err is nil, the authentication process has succeeded.
	// If Err is not nil, the authentication process has failed and the node should not be authenticated.
	Err error

	// Node is the node that has been authenticated.
	// Node is only valid if the auth request was a registration request
	// and the authentication process has succeeded.
	Node NodeView
}

func (v AuthVerdict) Accept() bool {
	return v.Err == nil
}

// DefaultBatcherWorkers returns the default number of batcher workers.
// Default to 3/4 of CPU cores, minimum 1, no maximum.
func DefaultBatcherWorkers() int {
	return DefaultBatcherWorkersFor(runtime.NumCPU())
}

// DefaultBatcherWorkersFor returns the default number of batcher workers for a given CPU count.
// Default to 3/4 of CPU cores, minimum 1, no maximum.
func DefaultBatcherWorkersFor(cpuCount int) int {
	const (
		workerNumerator   = 3
		workerDenominator = 4
	)

	defaultWorkers := max((cpuCount*workerNumerator)/workerDenominator, 1)

	return defaultWorkers
}
