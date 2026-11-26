package state

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	hsdb "github.com/juanfont/headscale/hscontrol/db"
	"github.com/juanfont/headscale/hscontrol/policy"
	policyv2 "github.com/juanfont/headscale/hscontrol/policy/v2"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/types/change"
	"github.com/rs/zerolog/log"
	"gorm.io/gorm"
)

// ErrInvalidPolicy is returned by [State.UpdatePolicy],
// [State.ValidatePolicy] and [State.ReloadPolicy] for a policy they refuse,
// as an [*InvalidPolicyError].
var ErrInvalidPolicy = errors.New("invalid policy")

// ErrPolicyPrecondition is returned by [State.UpdatePolicyIf] when the policy
// in force fails the caller's check.
var ErrPolicyPrecondition = errors.New("policy precondition failed")

// policyStoreTimeout bounds each read and write of the stored policy under
// the policy lock, which every login waits for.
var policyStoreTimeout = 10 * time.Second

// ErrPolicyFileUnreadable is a reload whose policy file cannot be read.
var ErrPolicyFileUnreadable = errors.New("the policy file cannot be read")

// ErrPolicySourceChanging is a reload whose last try saw the policy where it
// is kept change between two reads that both worked, and that has no tries
// left; the policy in force stays.
var ErrPolicySourceChanging = errors.New("the policy changed while it was read, and the tries ran out; the policy in force stays, reload again")

// errPolicySourceMoved is a reload whose locked read differs from the text
// it checked before the lock, both reads having worked.
var errPolicySourceMoved = errors.New("the policy changed while it was checked")

// errPolicyNotChecked is a reload whose read before the lock failed, so
// nothing was checked.
var errPolicyNotChecked = errors.New("the policy could not be read to check it")

// policyReloadAttempts bounds how often a reload checks a policy that
// changed under it, so a file rewritten in a loop cannot hold it for ever.
const policyReloadAttempts = 3

// InvalidPolicyError is a refused policy with its text, so that an answer
// can place each problem in it ([policyv2.Explain]). It reads as the reason,
// which the older APIs answer as is.
type InvalidPolicyError struct {
	// Policy is the refused text; nil when the file could not be read.
	Policy []byte
	Err    error

	// retry is whether the users can change the answer: the text parses, and
	// was refused for what it names, a user or a test.
	retry bool
}

func (e *InvalidPolicyError) Error() string { return e.Err.Error() }

func (e *InvalidPolicyError) Unwrap() []error { return []error{ErrInvalidPolicy, e.Err} }

// PolicyDocument is the policy in force and where it is kept.
type PolicyDocument struct {
	// Data is the text as it was read, "" when there is none.
	Data string
	// Updated is when the database stored it; nil in file mode and when
	// nothing is stored.
	Updated *time.Time
	Mode    types.PolicyMode
	// Path is the policy file, "" in database mode.
	Path string
}

// loadPolicy reads the policy from where cfg keeps it, with the time the
// database stored it. nil means none is configured or stored.
func loadPolicy(tx *gorm.DB, cfg *types.Config) ([]byte, time.Time, error) {
	if cfg.Policy.Mode != types.PolicyModeDB {
		if cfg.Policy.Path == "" {
			return nil, time.Time{}, nil
		}

		b, err := os.ReadFile(cfg.AbsPath(cfg.Policy.Path))
		if err != nil {
			return nil, time.Time{}, fmt.Errorf("%w: %w", ErrPolicyFileUnreadable, err)
		}

		return b, time.Time{}, nil
	}

	p, err := hsdb.GetPolicy(tx)
	if errors.Is(err, types.ErrPolicyNotFound) {
		return nil, time.Time{}, nil
	}

	if err != nil {
		return nil, time.Time{}, err
	}

	// An empty row is a policy source that is empty, as an empty file is.
	return append([]byte{}, p.Data...), p.UpdatedAt, nil
}

// documentOf is the document of data, read now from where the policy is kept.
func (s *State) documentOf(data []byte, updated time.Time) *PolicyDocument {
	d := &PolicyDocument{Data: string(data), Mode: s.cfg.Policy.Mode}

	switch {
	case s.cfg.Policy.Mode != types.PolicyModeDB:
		if s.cfg.Policy.Path != "" {
			d.Path = s.cfg.AbsPath(s.cfg.Policy.Path)
		}
	case !updated.IsZero():
		d.Updated = &updated
	}

	return d
}

// Policy is the policy in force. A policy the server refused where it is
// kept is not in force; [State.PolicySourceError] says why.
func (s *State) Policy() PolicyDocument {
	return *s.policyDoc.Load()
}

// PolicySourceError is why the policy kept now, the file or the stored
// row, cannot be used: it was refused, or the file cannot be read; nil when
// it can.
func (s *State) PolicySourceError() error {
	if err := s.policySourceErr.Load(); err != nil {
		return *err
	}

	return nil
}

// policyFacts is what the server knows of the policy where it is kept, the
// facts both warnings derive from in [State.settleWarnings] and nowhere
// else. Each read of the kept text, a write and a put-back that fails
// change them.
type policyFacts struct {
	// kept is the text last read where the policy is kept; nil for none.
	kept []byte
	// keptKnown is false after a write failed and the row could not be
	// read: the write may have landed, so what is kept is not known.
	keptKnown bool
	// refused is why kept cannot be used, nil when it can: the refusal of
	// that text, or a file that cannot be read.
	refused error
	// astray is set while the policy manager holds another policy than the
	// one in force says, after a put-back failed.
	astray bool
}

// settleWarnings derives both warnings of the policy from its facts and the
// policy in force: the source warning is that the kept policy cannot be
// used; policy_not_stored is that the policy in force may not be what a
// restart would install, for a reason the source warning does not give.
// The caller holds policyMu, or the State is not shared yet.
func (s *State) settleWarnings() {
	f := s.policyFacts

	// A refusal is of the text last read: while what is kept is not known,
	// it may be of a text that is gone, so it says nothing of what is kept.
	refused := f.refused
	if !f.keptKnown {
		refused = nil
	}

	if refused == nil {
		s.policySourceErr.Store(nil)
	} else {
		s.policySourceErr.Store(&refused)
	}

	invalid, ok := errors.AsType[*InvalidPolicyError](refused)
	s.policySourceRetry.Store(ok && invalid.retry)

	s.policyNotStored.Store(f.astray || !f.keptKnown || f.refused == nil && !sameText(f.kept, s.inForceText()))
}

// keptRead records text, read where the policy is kept, and why it cannot
// be used, nil when it can, and returns refused.
func (s *State) keptRead(text []byte, refused error) error {
	s.policyFacts.kept, s.policyFacts.keptKnown, s.policyFacts.refused = text, true, refused
	s.settleWarnings()

	return refused
}

// AmbiguousPolicyUsers is every user token of the policy in force that more
// than one user matches, so that it matches nobody.
func (s *State) AmbiguousPolicyUsers() []string {
	return s.polMan.AmbiguousUsers()
}

// PolicyNotStored reports that the policy in force may not be the one a
// restart would install, for a reason [State.PolicySourceError] does not
// give: a write failed and the row could not be read since, a put-back
// failed, or the text last read where the policy is kept is another one.
func (s *State) PolicyNotStored() bool {
	return s.policyNotStored.Load()
}

// PolicyFileRetry signals, at most once per wait, that the set of users
// changed while the policy file is refused for something the users can
// change.
func (s *State) PolicyFileRetry() <-chan struct{} {
	return s.policyFileRetry
}

// PreparedPolicy is a policy that passed every check of a write, tests
// included, ready for [State.WritePolicyIf].
type PreparedPolicy struct {
	data []byte
	p    *policyv2.PreparedPolicy
	// textErr is what [policyv2.CheckPolicyText] says of data, which
	// /api/v1 and /api/v2 store all the same.
	textErr error
}

// PreparePolicy runs every check of a write of pol against the users and
// nodes of now, tests included, holding no lock: tests run as long as the
// author of a policy makes them. It keeps a copy of pol, which the caller
// may reuse.
func (s *State) PreparePolicy(pol []byte) (*PreparedPolicy, error) {
	return s.prepare(pol, false)
}

// preparePolicyText is [State.PreparePolicy] that first refuses a text that
// is not an object, as start-up and a reload do ([policyv2.CheckPolicyText]).
func (s *State) preparePolicyText(pol []byte) (*PreparedPolicy, error) {
	return s.prepare(pol, true)
}

// prepare is [State.PreparePolicy], refusing a text that is not an object
// when text is set. Whatever an install needs to know of pol is worked out
// here, so nothing of it is parsed again under the lock.
func (s *State) prepare(pol []byte, text bool) (*PreparedPolicy, error) {
	if s.preparePolicyHook != nil {
		s.preparePolicyHook()
	}

	// Never nil: a text to store is never "none kept" ([sameText]).
	pol = append([]byte{}, pol...)

	textErr := policyv2.CheckPolicyText(pol)
	if text && textErr != nil {
		return nil, &InvalidPolicyError{Policy: pol, Err: textErr}
	}

	users, err := s.ListAllUsers()
	if err != nil {
		return nil, fmt.Errorf("loading users: %w", err)
	}

	p, err := policy.PreparePolicy(pol, users, s.ListNodes())
	if err != nil {
		_, perr := policyv2.ParsePolicy(pol)

		return nil, &InvalidPolicyError{Policy: pol, Err: err, retry: perr == nil}
	}

	return &PreparedPolicy{data: pol, p: p, textErr: textErr}, nil
}

// ValidatePolicy reports whether [State.UpdatePolicy] would accept pol; the
// policy in force is not touched.
func (s *State) ValidatePolicy(pol []byte) error {
	_, err := s.PreparePolicy(pol)

	return err
}

// ReloadPolicy reads the policy again from where it is kept and installs it.
// A policy it refuses leaves the one in force, and in file mode is kept for
// [State.PolicyFileError] until a file is installed.
//
// It approves no routes: auto-approval waits for a node's next change to
// its announced routes or its next node key rotation, as on Tailscale SaaS,
// so a reload cannot undo an admin's revoke.
func (s *State) ReloadPolicy() ([]change.Change, error) {
	var (
		changed, derpChanged bool
		err, readErr         error
	)

	// Read and checked before the lock, as a write is; read again under it,
	// and checked again, before the lock, when it moved meanwhile.
	for range policyReloadAttempts {
		data, _, lerr := loadPolicy(s.db.DB, s.cfg)
		if lerr != nil {
			lerr = fmt.Errorf("loading policy: %w", lerr)
		}

		readErr = lerr

		var (
			prep    *PreparedPolicy
			invalid error
		)

		if lerr == nil && data != nil {
			prep, invalid = s.preparePolicyText(data)

			// The users could not be read: no fault of the policy, so no
			// warning says so, and nothing changes.
			if _, refusal := errors.AsType[*InvalidPolicyError](invalid); invalid != nil && !refusal {
				err = fmt.Errorf("checking policy: %w", invalid)

				break
			}
		}

		changed, derpChanged, err = s.reloadPolicy(data, lerr, prep, invalid)
		if !errors.Is(err, errPolicySourceMoved) && !errors.Is(err, errPolicyNotChecked) {
			break
		}
	}

	// The last try answers: a change seen between two reads that both
	// worked is [ErrPolicySourceChanging], even after tries whose reads
	// failed; a read that failed is the storage's error, whatever the reads
	// under the lock found.
	switch {
	case errors.Is(err, errPolicySourceMoved):
		err = fmt.Errorf("%w: it changed between the two reads of the last of %d tries", ErrPolicySourceChanging, policyReloadAttempts)
	case errors.Is(err, errPolicyNotChecked):
		err = readErr
	}

	if changed {
		s.policyInstalled()
	}

	if err != nil {
		return nil, err
	}

	// Nodes whose CapMap shifted get their self refresh from
	// [State.DrainSelfRefreshes] when these changes are dispatched.
	changes := []change.Change{change.PolicyChange()}
	if derpChanged {
		changes = append(changes, change.DERPMap())
	}

	return changes, nil
}

// reloadPolicy is the locked part of [State.ReloadPolicy]: data is what was
// read before the lock, or readErr why it could not be, and prep and invalid
// what its check gave. A read before the lock that failed is
// [errPolicyNotChecked]; a source that is not data now is
// [errPolicySourceMoved]; either changes nothing.
func (s *State) reloadPolicy(data []byte, readErr error, prep *PreparedPolicy, invalid error) (bool, bool, error) {
	s.policyMu.Lock()
	defer s.policyMu.Unlock()

	pol, updated, err := s.loadPolicyBounded()
	if errors.Is(err, ErrPolicyFileUnreadable) {
		s.policyFacts.refused = &InvalidPolicyError{Err: err}
		s.settleWarnings()

		return false, false, s.policyFacts.refused
	}

	if err != nil {
		return false, false, fmt.Errorf("loading policy: %w", err)
	}

	switch {
	case readErr != nil:
		return false, false, errPolicyNotChecked
	case !sameText(pol, data):
		return false, false, errPolicySourceMoved
	case pol == nil:
		// None is kept: nothing to install.
		changed, err := s.settleNoneKept()

		return changed, s.applyPolicyDERPMap(), err
	case invalid != nil:
		return false, false, s.keptRead(pol, invalid)
	}

	// Nothing to store: it was read from where it is kept.
	changed, derpChanged, err := s.installLocked(prep, func() (*PolicyDocument, error) {
		return s.documentOf(pol, updated), nil
	})
	if _, refusal := errors.AsType[*InvalidPolicyError](err); refusal {
		return changed, false, s.keptRead(pol, err)
	}

	if err != nil {
		return changed, false, err
	}

	return changed, derpChanged, nil
}

// installLocked puts p in force and then stores it, the one way every
// policy comes into force while the server runs, so that what is in force
// is what is stored, or [State.PolicyNotStored] says it may not be.
// Installed first: the install checks p once more against the users of now,
// and a refusal then stores nothing. Every way out without a store that
// answered, an error or a panic, goes to [State.storeFailed]. It reports
// whether the policy in force changed, also when it was put back, so the
// caller brings the nodes to it again. The caller holds policyMu exclusive.
//
//nolint:nonamedreturns // the deferred settle of a failed store sets them
func (s *State) installLocked(p *PreparedPolicy, store func() (*PolicyDocument, error)) (changed, derpChanged bool, err error) {
	prev := s.polMan.PolicyInForce()

	var doc *PolicyDocument

	// Armed before the install, which may panic half done: a panic puts
	// back as a failed store does.
	changed = true

	defer func() {
		if doc == nil {
			changed, derpChanged, err = s.storeFailed(p, prev, changed, err)
		}
	}()

	changed, err = s.polMan.InstallPolicy(p.p)
	if err != nil {
		// Refused for the users of now, which can change.
		err = &InvalidPolicyError{Policy: p.data, Err: err, retry: true}

		return false, false, err
	}

	doc, err = store()
	if err != nil {
		doc = nil

		return changed, false, err
	}

	s.policyKept(doc, p)

	return changed, s.applyPolicyDERPMap(), nil
}

// policyKept records doc, of p, as in force and as what is kept, in the
// policy manager too.
func (s *State) policyKept(doc *PolicyDocument, p *PreparedPolicy) {
	s.policyDoc.Store(doc)
	s.policyFacts.astray = false

	// A write of /api/v1 or /api/v2 may store a text that is not an object,
	// which start-up and a reload refuse: say so as they would.
	var refused error
	if p.textErr != nil {
		refused = &InvalidPolicyError{Policy: p.data, Err: p.textErr}
	}

	_ = s.keptRead(p.data, refused)
}

// sameText reports whether a and b are the same policy text, nil being
// none kept. The text decides, byte for byte, not what it means: the text is
// what GET answers, what an ETag covers and what a restart reads, so two
// texts that differ in a comment are two policies here.
func sameText(a, b []byte) bool {
	return (a == nil) == (b == nil) && bytes.Equal(a, b)
}

// inForceText is the text of the policy in force as it is kept, nil when
// none is.
func (s *State) inForceText() []byte {
	doc := s.policyDoc.Load()
	if doc.Data == "" && doc.Updated == nil {
		return nil
	}

	return []byte(doc.Data)
}

// keptUnchecked records text, read where the policy is kept and not checked:
// it cannot be used if it is the text refused before, and it is not known
// to be refused otherwise.
func (s *State) keptUnchecked(text []byte) {
	refused := s.policyFacts.refused

	invalid, ok := errors.AsType[*InvalidPolicyError](refused)
	if !ok || invalid.Policy == nil || !sameText(text, invalid.Policy) {
		refused = nil
	}

	_ = s.keptRead(text, refused)
}

// settleNoneKept is a reload that found no policy kept. A policy manager
// astray with none in force is put back to none, which is then both in force
// and kept.
func (s *State) settleNoneKept() (bool, error) {
	var (
		changed bool
		err     error
	)

	if s.policyFacts.astray && s.inForceText() == nil {
		changed, err = s.polMan.RestorePolicy(&policyv2.PreparedPolicy{})
		if err != nil {
			err = fmt.Errorf("putting back no policy: %w", err)
		} else {
			s.policyFacts.astray = false
		}
	}

	_ = s.keptRead(nil, nil)

	return changed, err
}

// storeFailed settles what stays in force after an install whose store did
// not answer that it stored p: it failed, or the install or the store
// panicked. A store can fail on the client and still commit on the server,
// so the stored row decides: p stays in force if the row holds it, and
// otherwise the policy in force before, prev, is put back, compiled anew
// and not checked again, since the users may have changed under it. A row
// that cannot be read leaves prev in force and [State.PolicyNotStored] set.
func (s *State) storeFailed(p *PreparedPolicy, prev *policyv2.PreparedPolicy, changed bool, err error) (bool, bool, error) {
	// Refused by the install: nothing changed.
	if errors.Is(err, ErrInvalidPolicy) {
		return false, false, err
	}

	var (
		row  []byte
		read bool
	)

	if s.cfg.Policy.Mode == types.PolicyModeDB {
		r, updated, rerr := s.loadPolicyBounded()

		switch {
		case rerr != nil:
			s.policyFacts.keptKnown = false

			log.Error().Err(rerr).Msg("a policy write failed, and the stored policy cannot be read; the policy before it is in force and may not be the stored one")
		case sameText(r, p.data):
			s.policyKept(s.documentOf(p.data, updated), p)
			log.Warn().Err(err).Msg("storing the policy reported an error, but it is stored; it stays in force")

			return changed, s.applyPolicyDERPMap(), nil
		default:
			row, read = r, true
		}
	}

	_, perr := s.polMan.RestorePolicy(prev)
	if perr != nil {
		s.policyFacts.astray = true

		log.Error().Err(perr).Msg("a policy write was not stored, and the policy before it cannot be put back; the policy in force is not the stored one")
	}

	if read {
		s.keptUnchecked(row)
	}

	s.settleWarnings()

	// The nodes are brought to it again: one that changed in between was
	// given the other policy.
	return changed, false, err
}

// loadPolicyBounded is [loadPolicy] with a deadline, so a database that
// stalls does not hold the policy lock, and every login, for ever.
func (s *State) loadPolicyBounded() ([]byte, time.Time, error) {
	ctx, cancel := context.WithTimeout(context.Background(), policyStoreTimeout)
	defer cancel()

	return loadPolicy(s.db.DB.WithContext(ctx), s.cfg)
}

// StoredPolicy is [State.GetPolicy] with the deadline of every read of the
// stored policy under the policy lock, for a match of [State.WritePolicyIf]
// that reads the row.
func (s *State) StoredPolicy() (*types.Policy, error) {
	ctx, cancel := context.WithTimeout(context.Background(), policyStoreTimeout)
	defer cancel()

	return hsdb.GetPolicy(s.db.DB.WithContext(ctx))
}

// policyInstalled brings the peer maps up to a policy that changed. It runs
// after policyMu is released: the rebuild waits for a batch of the
// NodeStore's writer, and every check that reads the policy waits for the
// lock. The rebuild reads the policy in force when it runs, so a later
// install is never undone by an earlier rebuild.
//
// An unchanged policy leaves the matchers as they were, and the other
// inputs of the peer map rebuild it themselves (node writes in the
// [NodeStore], [State.updatePolicyManagerNodes] and
// [State.updatePolicyManagerUsers]), so the O(n^2) rebuild is skipped then.
func (s *State) policyInstalled() {
	// Stale approvals must not persist if checkPeriod rules are modified
	// or removed.
	s.ClearSSHCheckAuth()
	s.nodeStore.RebuildPeerMaps()
	log.Info().Msg("Policy reload completed with changes")
}

// UpdatePolicy validates, stores and installs pol; see
// [State.UpdatePolicyIf].
func (s *State) UpdatePolicy(pol []byte) (*types.Policy, []change.Change, error) {
	return s.UpdatePolicyIf(pol, nil)
}

// UpdatePolicyTextIf is [State.UpdatePolicyIf] that also refuses a text
// that is not an object, such as null, as start-up and a reload do; the
// older APIs keep taking it.
func (s *State) UpdatePolicyTextIf(pol []byte, match func(PolicyDocument) bool) (*types.Policy, []change.Change, error) {
	prep, invalid := s.preparePolicyText(pol)

	return s.writePolicyIf(prep, invalid, match)
}

// UpdatePolicyIf checks pol with [State.PreparePolicy] and writes it with
// [State.WritePolicyIf]; a false match is answered before pol is found
// invalid.
func (s *State) UpdatePolicyIf(pol []byte, match func(PolicyDocument) bool) (*types.Policy, []change.Change, error) {
	prep, invalid := s.PreparePolicy(pol)

	return s.writePolicyIf(prep, invalid, match)
}

// WritePolicyIf installs and stores p, after passing the policy in force to
// match under the lock of every policy write, so two writers cannot both
// pass a check against the same policy. A false match returns
// [ErrPolicyPrecondition]; a nil match always passes. A refused or unstored
// write leaves the policy in force as it was; the changes it returns with
// an error bring the nodes back to it.
func (s *State) WritePolicyIf(p *PreparedPolicy, match func(PolicyDocument) bool) (*types.Policy, []change.Change, error) {
	return s.writePolicyIf(p, nil, match)
}

func (s *State) writePolicyIf(p *PreparedPolicy, invalid error, match func(PolicyDocument) bool) (*types.Policy, []change.Change, error) {
	stored, changed, derpChanged, err := s.writePolicyLocked(p, invalid, match)

	var changes []change.Change

	// As on SaaS, a write that changes nothing sends clients nothing.
	if changed {
		s.policyInstalled()

		changes = append(changes, change.PolicyChange())
	}

	if derpChanged {
		changes = append(changes, change.DERPMap())
	}

	if err != nil {
		return nil, changes, err
	}

	return stored, changes, nil
}

// SetPreparePolicyHookForTesting runs hook as every policy is checked,
// before it is read; set it before the State is used concurrently.
func (s *State) SetPreparePolicyHookForTesting(hook func()) {
	s.preparePolicyHook = hook
}

// SetUpdatePolicyHookForTesting runs hook inside every policy write, under
// its lock, after its precondition passed and before it installs anything.
func (s *State) SetUpdatePolicyHookForTesting(hook func()) {
	s.policyMu.Lock()
	defer s.policyMu.Unlock()

	s.updatePolicyHook = hook
}

func (s *State) writePolicyLocked(p *PreparedPolicy, invalid error, match func(PolicyDocument) bool) (*types.Policy, bool, bool, error) {
	s.policyMu.Lock()
	defer s.policyMu.Unlock()

	if match != nil && !match(*s.policyDoc.Load()) {
		return nil, false, false, ErrPolicyPrecondition
	}

	if invalid != nil {
		return nil, false, false, invalid
	}

	if s.updatePolicyHook != nil {
		s.updatePolicyHook()
	}

	changed, derpChanged, err := s.installLocked(p, func() (*PolicyDocument, error) {
		ctx, cancel := context.WithTimeout(context.Background(), policyStoreTimeout)
		defer cancel()

		stored, err := s.storePolicy(ctx, string(p.data))
		if err != nil {
			return nil, fmt.Errorf("storing policy: %w", err)
		}

		return s.documentOf(p.data, stored.UpdatedAt), nil
	})
	if err != nil {
		return nil, changed, derpChanged, err
	}

	doc := s.policyDoc.Load()
	stored := &types.Policy{Data: doc.Data}
	stored.UpdatedAt = *doc.Updated

	return stored, changed, derpChanged, nil
}

// CheckPolicyIf answers what [State.UpdatePolicyTextIf] would answer for pol, and
// changes nothing. It takes no lock: match reads the policy in force as one
// value, and the write checks pol outside the lock too. Another write may
// change the answer of the real call a moment later.
func (s *State) CheckPolicyIf(pol []byte, match func(PolicyDocument) bool) error {
	if match != nil && !match(s.Policy()) {
		return ErrPolicyPrecondition
	}

	_, err := s.preparePolicyText(pol)

	return err
}
