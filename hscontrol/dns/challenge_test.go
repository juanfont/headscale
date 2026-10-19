package dns

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/juanfont/headscale/hscontrol/dns/dnstest"
	"github.com/libdns/libdns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testZone = "ts.example.com."
	testName = "_acme-challenge.node.ts.example.com."
	// renamedName is testName's node after it changed its hostname.
	renamedName = "_acme-challenge.renamed.ts.example.com."
	testOwner   = 1
	// operatorValue is a record headscale did not create and must keep.
	operatorValue = "operator-owned"
)

var errAPIDown = errors.New("api down")

func newTestChallenges(p *dnstest.Provider) *Challenges {
	return NewChallenges(p, "TS.example.com", nil, 0)
}

func TestChallengesAppendNotReplace(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p := &dnstest.Provider{}
		p.Add(testName, operatorValue)
		c := newTestChallenges(p)
		ctx := context.Background()

		// A wildcard order sends two values for one name, one after the other.
		require.NoError(t, c.Present(ctx, testOwner, testName, "value-1"))
		require.NoError(t, c.Present(ctx, testOwner, "_acme-challenge.NODE.ts.example.com", "value-2"))
		assert.ElementsMatch(t, []string{operatorValue, "value-1", "value-2"}, p.Values(testName))

		// A retry of the same order resends the same value.
		require.NoError(t, c.Present(ctx, testOwner, testName, "value-1"))
		assert.Len(t, p.Calls(), 2, "resent value must not be appended again")

		for _, call := range p.Calls() {
			assert.Equal(t, testZone, call.Zone)
		}

		time.Sleep(challengeLifetime) //nolint:forbidigo // synctest fake clock
		synctest.Wait()

		assert.Equal(t, []string{operatorValue}, p.Values(testName))
	})
}

// TestChallengesResendExtendsLifetime also pins that an expiry timer that
// fired just before a resend, and then waited for the lock, leaves the
// refreshed value alone.
func TestChallengesResendExtendsLifetime(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p := &dnstest.Provider{}
		c := newTestChallenges(p)
		ctx := context.Background()

		require.NoError(t, c.Present(ctx, testOwner, testName, "value"))
		time.Sleep(challengeLifetime - time.Minute) //nolint:forbidigo // synctest fake clock
		require.NoError(t, c.Present(ctx, testOwner, testName, "value"))

		c.expire(challengeKey{fqdn: testName, value: "value"})
		time.Sleep(2 * time.Minute) //nolint:forbidigo // synctest fake clock
		synctest.Wait()
		assert.Equal(t, []string{"value"}, p.Values(testName))

		time.Sleep(challengeLifetime) //nolint:forbidigo // synctest fake clock
		synctest.Wait()
		assert.Empty(t, p.Values(testName))
	})
}

func TestChallengesLimitPerNode(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p := &dnstest.Provider{}
		c := newTestChallenges(p)
		ctx := context.Background()

		for i := range maxChallengesPerNode {
			require.NoError(t, c.Present(ctx, testOwner, testName, "value-"+string(rune('a'+i))))
		}

		err := c.Present(ctx, testOwner, testName, "one-too-many")
		require.ErrorIs(t, err, ErrTooManyChallenges)

		// Renaming gives the node a new name, not new slots.
		err = c.Present(ctx, testOwner, renamedName, "value")
		require.ErrorIs(t, err, ErrTooManyChallenges)
		assert.Len(t, p.Calls(), maxChallengesPerNode)

		// Other nodes have their own limit.
		require.NoError(t, c.Present(ctx, testOwner+1, "_acme-challenge.other.ts.example.com", "value"))

		// A node that took the name over and resends a value there takes
		// over its slot.
		require.NoError(t, c.Present(ctx, testOwner+1, testName, "value-a"))
		require.NoError(t, c.Present(ctx, testOwner, renamedName, "value"))

		c.Close()
	})
}

// TestChallengesHoldsNewValueForCACache pins that a second value on a name
// is answered only once the CA's cache of the first has expired: the CA
// validates the second value of a wildcard order seconds after the first.
func TestChallengesHoldsNewValueForCACache(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c := newTestChallenges(&dnstest.Provider{})
		ctx := context.Background()
		start := time.Now()

		require.NoError(t, c.Present(ctx, testOwner, testName, "value-1"))
		assert.Equal(t, start, time.Now(), "first value is not held")

		require.NoError(t, c.Present(ctx, testOwner, renamedName, "value-2"))
		assert.Equal(t, start, time.Now(), "other names, such as after a rename, are not held")

		require.NoError(t, c.Present(ctx, testOwner, testName, "value-2"))
		assert.Equal(t, start.Add(ChallengeTTL+caLookupDelay), time.Now())

		shown := time.Now()

		require.NoError(t, c.Present(ctx, testOwner, testName, "value-2"))
		assert.Equal(t, shown, time.Now(), "a resent value is not held")

		require.NoError(t, c.Present(ctx, testOwner+1, testName, "value-3"))
		assert.Equal(t, shown.Add(ChallengeTTL+caLookupDelay), time.Now(), "a node that took the name over is held too")

		ctx, cancel := context.WithCancel(ctx)
		cancel()
		require.ErrorIs(t, c.Present(ctx, testOwner, testName, "value-4"), context.Canceled)

		c.Close()
	})
}

// TestChallengesResendKeepsHold pins that resending a value while its hold
// is pending does not cut the hold short.
func TestChallengesResendKeepsHold(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c := newTestChallenges(&dnstest.Provider{})
		ctx := context.Background()
		start := time.Now()

		require.NoError(t, c.Present(ctx, testOwner, testName, "value-1"))

		go func() { _ = c.Present(ctx, testOwner, testName, "value-2") }()

		time.Sleep(time.Second) //nolint:forbidigo // synctest fake clock
		require.NoError(t, c.Present(ctx, testOwner, testName, "value-2"))
		assert.Equal(t, start.Add(ChallengeTTL+caLookupDelay), time.Now())

		c.Close()
	})
}

// TestChallengesFailedWaitKeepsValue pins that a client that went away
// still gets its value appended and tracked, and that a failed or
// cancelled wait leaves the value for its lifetime: deleting at once would
// let a client that cancels in a loop drive unbounded provider calls.
func TestChallengesFailedWaitKeepsValue(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p := &dnstest.Provider{}
		c := newTestChallenges(p)
		c.wait = func(ctx context.Context, _, _ string) error { return ctx.Err() }

		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		require.ErrorIs(t, c.Present(ctx, testOwner, testName, "value"), context.Canceled)
		assert.Equal(t, []string{"value"}, p.Values(testName), "append must finish for a gone client")

		// A retry of the same value is not appended again.
		require.NoError(t, c.Present(context.Background(), testOwner, testName, "value"))
		assert.Len(t, p.Calls(), 1)

		time.Sleep(challengeLifetime) //nolint:forbidigo // synctest fake clock
		synctest.Wait()
		assert.Empty(t, p.Values(testName))
	})
}

// TestChallengesLimitsWaiters pins that duplicate requests for one name
// cannot pile up propagation waits.
func TestChallengesLimitsWaiters(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p := &dnstest.Provider{}
		c := newTestChallenges(p)

		release := make(chan struct{})
		c.wait = func(context.Context, string, string) error {
			<-release

			return nil
		}

		for range maxChallengesPerNode {
			go func() { _ = c.Present(context.Background(), testOwner, testName, "value") }()
		}

		synctest.Wait()
		require.ErrorIs(t, c.Present(context.Background(), testOwner, testName, "value"), ErrTooManyChallenges)

		close(release)
		synctest.Wait()

		c.wait = func(context.Context, string, string) error { return nil }
		require.NoError(t, c.Present(context.Background(), testOwner, testName, "value"))
		c.Close()
	})
}

func TestChallengesProviderError(t *testing.T) {
	p := &dnstest.Provider{}
	p.SetError(errAPIDown)
	c := newTestChallenges(p)

	err := c.Present(context.Background(), testOwner, testName, "value")
	require.ErrorIs(t, err, ErrChallengeProvider)

	p.SetError(nil)
	c.Close()
	assert.Len(t, p.Calls(), 1, "failed append must not be tracked for deletion")
}

func TestChallengesClose(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p := &dnstest.Provider{}
		p.Add(testName, operatorValue)
		c := newTestChallenges(p)
		ctx := context.Background()

		require.NoError(t, c.Present(ctx, testOwner, testName, "value-1"))
		require.NoError(t, c.Present(ctx, testOwner, testName, "value-2"))
		c.Close()

		assert.Equal(t, []string{operatorValue}, p.Values(testName))

		for _, call := range p.Calls() {
			assert.NotEmpty(t, call.Value, "a delete without value wipes the record set")
		}
	})
}

// appendGate holds AppendRecords until release is closed.
type appendGate struct {
	*dnstest.Provider

	entered, release chan struct{}
}

func (p appendGate) AppendRecords(
	ctx context.Context,
	zone string,
	recs []libdns.Record,
) ([]libdns.Record, error) {
	close(p.entered)
	<-p.release

	return p.Provider.AppendRecords(ctx, zone, recs)
}

// TestChallengesCloseRefusesNewValues pins that Close removes an append
// already under way and refuses later ones: Noise connections outlive
// the HTTP server's shutdown, so Present can still be called.
func TestChallengesCloseRefusesNewValues(t *testing.T) {
	p := appendGate{Provider: &dnstest.Provider{}, entered: make(chan struct{}), release: make(chan struct{})}
	c := NewChallenges(p, testZone, nil, 0)

	presented := make(chan error)

	go func() { presented <- c.Present(context.Background(), testOwner, testName, "in-flight") }()

	<-p.entered

	closed := make(chan struct{})

	go func() {
		c.Close()
		close(closed)
	}()

	close(p.release)
	<-closed
	require.NoError(t, <-presented)
	assert.Empty(t, p.Values(testName), "append in flight during Close must be removed")

	err := c.Present(context.Background(), testOwner+1, testName, "late")
	require.ErrorIs(t, err, ErrChallengesClosed)
	assert.Len(t, p.Calls(), 2, "only the in-flight append and its delete")
}

func TestChallengesEmptyValue(t *testing.T) {
	p := &dnstest.Provider{}
	c := newTestChallenges(p)

	require.ErrorIs(t, c.Present(context.Background(), testOwner, testName, ""), ErrEmptyChallenge)
	assert.Empty(t, p.Calls())
}

// serialProvider records whether two provider calls overlapped. Providers
// that read a record set and, one API round trip later, write back what
// they computed from it, as PowerDNS does, lose one of two overlapping
// changes to a name.
type serialProvider struct {
	*dnstest.Provider

	busy, overlapped atomic.Bool
	// entered gets a value as each call starts.
	entered chan struct{}
}

func (p *serialProvider) call() func() {
	if !p.busy.CompareAndSwap(false, true) {
		p.overlapped.Store(true)
	}

	p.entered <- struct{}{}

	time.Sleep(20 * time.Millisecond) //nolint:forbidigo // the API round trip

	return func() { p.busy.Store(false) }
}

func (p *serialProvider) AppendRecords(
	ctx context.Context,
	zone string,
	recs []libdns.Record,
) ([]libdns.Record, error) {
	defer p.call()()

	return p.Provider.AppendRecords(ctx, zone, recs)
}

func (p *serialProvider) DeleteRecords(
	ctx context.Context,
	zone string,
	recs []libdns.Record,
) ([]libdns.Record, error) {
	defer p.call()()

	return p.Provider.DeleteRecords(ctx, zone, recs)
}

// TestChallengesNameTakenOver pins that a node that took over a name
// cannot interleave its provider writes with the removal of a value the
// node that had the name left there, whichever starts first. It runs on
// the real clock: synctest cannot advance time while a goroutine waits on
// a mutex.
func TestChallengesNameTakenOver(t *testing.T) {
	p := &serialProvider{Provider: &dnstest.Provider{}, entered: make(chan struct{}, 8)}
	c := NewChallenges(p, testZone, nil, 0)
	ctx := context.Background()

	for i, name := range []string{testName, renamedName} {
		require.NoError(t, c.Present(ctx, testOwner, name, "old"))
		<-p.entered

		// testOwner renamed away, and "old" expires while the node that
		// took the name publishes there. It was shown long ago, so nothing
		// is held.
		old := challengeKey{fqdn: name, value: "old"}

		c.mu.Lock()
		c.values[old].expires = time.Time{}
		c.values[old].shownAt = time.Time{}
		c.mu.Unlock()

		first := func() { c.expire(old) }
		second := func() { assert.NoError(t, c.Present(ctx, testOwner+1, name, "new")) }

		if i == 1 {
			first, second = second, first
		}

		done := make(chan struct{})

		go func() {
			first()
			close(done)
		}()

		<-p.entered
		second()
		<-done
		<-p.entered

		assert.Equal(t, []string{"new"}, p.Values(name))
	}

	assert.False(t, p.overlapped.Load(), "provider calls overlapped")
	c.Close()
}
