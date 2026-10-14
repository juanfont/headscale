package dns

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/libdns/libdns"
	"github.com/rs/zerolog/log"
)

var (
	ErrTooManyChallenges = errors.New("too many pending ACME challenges for this node")
	ErrChallengeProvider = errors.New("DNS provider failed")
	ErrEmptyChallenge    = errors.New("empty ACME challenge value")
	ErrChallengesClosed  = errors.New("ACME challenges are shutting down")
)

const (
	// ChallengeTTL is the TTL of every challenge record headscale writes.
	ChallengeTTL = time.Minute
	// challengeLifetime outlives both authorizations of a wildcard order
	// and the CA's validation retries. A retry of the same order resends
	// the same value, which restarts the clock.
	challengeLifetime = 10 * time.Minute
	// maxChallengesPerNode covers a wildcard order (two values) racing a
	// plain order. It also bounds how many records one node can make
	// headscale write. The limit is per node, not per name: a node renames
	// itself by changing its hostname, and every new name would come with
	// fresh slots.
	maxChallengesPerNode = 4
	providerTimeout      = 30 * time.Second
	// caLookupDelay is how long after Present returns the CA may still
	// make its first lookup of the value.
	caLookupDelay = 5 * time.Second
)

// Challenges publishes ACME DNS-01 TXT values through a [Provider] and
// removes them again. Clients never ask for removal, so every value is
// deleted [challengeLifetime], plus the propagation timeout, after it was
// last published, or on [Challenges.Close]. Nothing is persisted: a crash,
// or a failed delete, leaves a few random TXT values behind.
type Challenges struct {
	provider Provider
	zone     string
	lifetime time.Duration
	wait     func(ctx context.Context, fqdn, value string) error

	// mu guards the fields below and is held across provider calls.
	// Providers that read-modify-write a record set lose a value when two
	// changes to one name overlap, and the changes can come from different
	// nodes: one renames away while its values are live, another takes the
	// name. Issuance is rare, so one lock for every name is enough.
	mu     sync.Mutex
	values map[challengeKey]*challengeValue
	// waiting counts each node's Present calls waiting for propagation, so
	// duplicate requests cannot pile up DNS queries.
	waiting map[uint64]int
	// closed refuses new values once Close has run. Noise connections
	// outlive the HTTP server's shutdown, so Present still gets called.
	closed bool
}

type challengeKey struct{ fqdn, value string }

type challengeValue struct {
	// owner is the node the value counts against.
	owner uint64
	// record is what the provider returned from AppendRecords; deleting
	// exactly it matters for providers that match on TTL or record ID.
	record libdns.Record
	timer  *time.Timer
	// expires moves on every use instead of resetting timer: a timer that
	// already fired, blocked on the lock behind that use, must not delete
	// the value.
	expires time.Time
	// shownAt is when Present returned, or will return, for this value.
	shownAt time.Time
}

// NewChallenges returns a [Challenges] writing into zone. Present waits up
// to propagationTimeout for the zone's nameservers, found through
// resolvers, to serve a value.
func NewChallenges(
	provider Provider,
	zone string,
	resolvers []string,
	propagationTimeout time.Duration,
) *Challenges {
	return &Challenges{
		provider: provider,
		zone:     fqdn(zone),
		// A value must outlive its own wait and hold, or it is deleted
		// while Present still waits on it, and its hold with it.
		lifetime: challengeLifetime + propagationTimeout,
		wait:     newTXTChecker(resolvers, propagationTimeout).wait,
		values:   make(map[challengeKey]*challengeValue),
		waiting:  make(map[uint64]int),
	}
}

// Present publishes value as a TXT record at name for the node owner and
// returns once the zone's nameservers serve it. Values are added next to
// existing ones, never replacing them, and publishing a value again is a
// no-op.
func (c *Challenges) Present(ctx context.Context, owner uint64, name, value string) error {
	if value == "" {
		return ErrEmptyChallenge
	}

	k := challengeKey{fqdn: fqdn(name), value: value}

	err := c.append(ctx, owner, k)
	if err != nil {
		return err
	}

	err = c.wait(ctx, k.fqdn, value)
	if err == nil {
		select {
		case <-ctx.Done():
			err = ctx.Err()
		case <-time.After(time.Until(c.show(k))):
		}
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	c.waiting[owner]--
	if c.waiting[owner] == 0 {
		delete(c.waiting, owner)
	}

	// A failed wait keeps the value until its lifetime ends: deleting it
	// at once would let a client that cancels requests in a loop make
	// headscale call the provider without bound. A success restarts the
	// lifetime, which is the CA's window to validate.
	if v, ok := c.values[k]; ok && err == nil {
		v.expires = time.Now().Add(c.lifetime)
	}

	return err
}

// append publishes k for owner unless it already is, and counts the caller
// as waiting.
func (c *Challenges) append(ctx context.Context, owner uint64, k challengeKey) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return ErrChallengesClosed
	}

	if c.waiting[owner] >= maxChallengesPerNode {
		return ErrTooManyChallenges
	}

	// A node that resends a value another node published, on a name it has
	// taken over, keeps that value alive, so the value moves to its count.
	v, ok := c.values[k]
	if (!ok || v.owner != owner) && c.count(owner) >= maxChallengesPerNode {
		return ErrTooManyChallenges
	}

	if ok {
		v.owner = owner
		v.expires = time.Now().Add(c.lifetime)
		c.waiting[owner]++

		return nil
	}

	record := libdns.TXT{
		Name: libdns.RelativeName(k.fqdn, c.zone),
		TTL:  ChallengeTTL,
		Text: k.value,
	}

	// The call must finish even if the client goes away, or a record
	// could be created that nothing tracks and deletes.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), providerTimeout)
	defer cancel()

	got, err := c.provider.AppendRecords(ctx, c.zone, []libdns.Record{record})
	if err != nil {
		return fmt.Errorf("%w: %w", ErrChallengeProvider, err)
	}

	stored := libdns.Record(record)
	if len(got) == 1 && got[0].RR().Type == "TXT" && got[0].RR().Data == k.value {
		stored = got[0]
	}

	c.values[k] = &challengeValue{
		owner:   owner,
		record:  stored,
		expires: time.Now().Add(c.lifetime),
		timer:   time.AfterFunc(c.lifetime, func() { c.expire(k) }), //nolint:contextcheck // outlives the request
	}
	c.waiting[owner]++

	return nil
}

// count returns how many values owner has published; c.mu must be held.
func (c *Challenges) count(owner uint64) int {
	n := 0

	for _, v := range c.values {
		if v.owner == owner {
			n++
		}
	}

	return n
}

// show reserves when Present may return for k. The client asks the CA to
// validate at once, and the CA's resolvers cache the record set they find
// for its TTL. A resolver that cached this name for an earlier value, such
// as the first of a wildcard order or one left by the node that had the
// name before, would not see a new one, so a new value is held back until
// that cache has expired. The hold counts from every other value on the name,
// so a resend cannot cut its own hold short. Another name, such as the
// node's name before a rename, is cached on its own.
func (c *Challenges) show(k challengeKey) time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()

	at := time.Now()

	for other, v := range c.values {
		expired := v.shownAt.Add(ChallengeTTL + caLookupDelay)
		if other.fqdn == k.fqdn && other != k && expired.After(at) {
			at = expired
		}
	}

	if v, ok := c.values[k]; ok {
		v.shownAt = at
	}

	return at
}

// expire removes k once it has gone unused for the lifetime.
func (c *Challenges) expire(k challengeKey) {
	c.mu.Lock()
	defer c.mu.Unlock()

	v, ok := c.values[k]
	if !ok {
		return
	}

	if d := time.Until(v.expires); d > 0 {
		v.timer.Reset(d)

		return
	}

	c.remove(k)
}

// remove deletes one tracked value from the provider; c.mu must be held.
// It never deletes by name alone: providers treat an empty value as
// "every record here", which would take out the operator's records and
// the other value of a wildcard order.
func (c *Challenges) remove(k challengeKey) {
	v := c.values[k]
	v.timer.Stop()
	delete(c.values, k)

	ctx, cancel := context.WithTimeout(context.Background(), providerTimeout)
	defer cancel()

	_, err := c.provider.DeleteRecords(ctx, c.zone, []libdns.Record{v.record})
	if err != nil {
		log.Warn().Err(err).Str("fqdn", k.fqdn).Msg("removing ACME challenge record")
	}
}

// Close deletes every pending value and refuses new ones.
func (c *Challenges) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.closed = true

	for k := range c.values {
		c.remove(k)
	}
}

func fqdn(name string) string {
	return strings.ToLower(strings.TrimSuffix(name, ".")) + "."
}
