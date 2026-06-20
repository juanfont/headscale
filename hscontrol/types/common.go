//go:generate go tool viewer --type=User,Node,PreAuthKey
package types

//go:generate go run tailscale.com/cmd/viewer --type=User,Node,PreAuthKey

import (
	"errors"
	"fmt"
	"runtime"
	"strings"
	"sync/atomic"
	"time"

	"tailscale.com/util/rands"
)

const (
	SelfUpdateIdentifier = "self-update"
	DatabasePostgres     = "postgres"
	DatabaseSqlite       = "sqlite3"
)

// Common errors.
var (
	ErrCannotParsePrefix   = errors.New("cannot parse prefix")
	ErrInvalidAuthIDLength = errors.New("auth ID has invalid length")
	ErrInvalidAuthIDPrefix = errors.New("auth ID has invalid prefix")
)

const (
	authIDPrefix       = "hskey-authreq-"
	authIDRandomLength = 24
	// AuthIDLength is the total length of an AuthID: 14 (prefix) + 24 (random).
	AuthIDLength = 38
)

type AuthID string

func NewAuthID() (AuthID, error) {
	return AuthID(authIDPrefix + rands.HexString(authIDRandomLength)), nil
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
// registration (regData populated) or an SSH check-mode auth (sshBinding
// populated), and signals the verdict via the finished channel. The closed
// flag guards [AuthRequest.FinishAuth] against double-close.
//
// [AuthRequest] is always handled by pointer so the channel and atomic flag
// have a single canonical instance even when stored in caches that
// internally copy values.
type AuthRequest struct {
	// regData is populated for node-registration flows (interactive web
	// or OIDC). It carries the cached registration payload that the
	// auth callback uses to promote this request into a real node.
	//
	// nil for non-registration flows. Use [AuthRequest.RegistrationData] to read it
	// safely.
	regData *RegistrationData

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
// stored by pointer; callers must not mutate it after handing it off.
func NewRegisterAuthRequest(data *RegistrationData) *AuthRequest {
	return &AuthRequest{
		regData:  data,
		finished: make(chan AuthVerdict, 1),
		closed:   &atomic.Bool{},
	}
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

// RegistrationData returns the cached registration payload. It panics if
// called on an [AuthRequest] that was not created via
// [NewRegisterAuthRequest].
func (rn *AuthRequest) RegistrationData() *RegistrationData {
	if rn.regData == nil {
		panic("RegistrationData can only be used in registration requests")
	}

	return rn.regData
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
	return rn.regData != nil
}

// IsSSHCheck reports whether this auth request is bound to an SSH
// check-mode (src, dst) pair (i.e. it was created via
// [NewSSHCheckAuthRequest]).
func (rn *AuthRequest) IsSSHCheck() bool {
	return rn.sshBinding != nil
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

	rn.finished <- verdict

	close(rn.finished)
}

func (rn *AuthRequest) WaitForAuth() <-chan AuthVerdict {
	return rn.finished
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
