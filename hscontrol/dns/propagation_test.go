package dns

import (
	"context"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	mdns "github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// acmeZone stands in for an acme-dns server's zone.
const acmeZone = "acme.example.net."

// fakeNameserver answers authoritatively for testZone and acmeZone: ns1
// and ns2 are their nameservers, TXT answers come from txt and a name in
// cname is an alias.
type fakeNameserver struct {
	mu    sync.Mutex
	txt   map[string][]string
	cname map[string]string
	// hideFor makes the first n TXT queries miss, like a nameserver that
	// has not caught up yet.
	hideFor atomic.Int32
}

func (f *fakeNameserver) set(values ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.txt[testName] = values
}

func (f *fakeNameserver) ServeDNS(w mdns.ResponseWriter, r *mdns.Msg) {
	m := new(mdns.Msg)
	m.SetReply(r)
	m.Authoritative = true

	q := r.Question[0]
	hdr := mdns.RR_Header{Name: q.Name, Class: mdns.ClassINET, Ttl: 60, Rrtype: q.Qtype}

	f.mu.Lock()
	target, alias := f.cname[q.Name]
	f.mu.Unlock()

	if alias {
		hdr.Rrtype = mdns.TypeCNAME
		m.Answer = []mdns.RR{&mdns.CNAME{Hdr: hdr, Target: target}}
		_ = w.WriteMsg(m)

		return
	}

	switch q.Qtype {
	case mdns.TypeNS:
		if q.Name != testZone && q.Name != acmeZone {
			break
		}

		m.Answer = []mdns.RR{
			&mdns.NS{Hdr: hdr, Ns: "ns1." + testZone},
			&mdns.NS{Hdr: hdr, Ns: "ns2." + testZone},
		}
	case mdns.TypeA:
		switch q.Name {
		case "ns1." + testZone:
			m.Answer = []mdns.RR{&mdns.A{Hdr: hdr, A: net.IPv4(127, 0, 0, 1)}}
		case "ns2." + testZone:
			m.Answer = []mdns.RR{&mdns.A{Hdr: hdr, A: net.IPv4(127, 0, 0, 2)}}
		}
	case mdns.TypeTXT:
		if f.hideFor.Add(-1) >= 0 {
			break
		}

		f.mu.Lock()
		for _, v := range f.txt[q.Name] {
			m.Answer = append(m.Answer, &mdns.TXT{Hdr: hdr, Txt: []string{v}})
		}
		f.mu.Unlock()
	}

	if len(m.Answer) == 0 {
		m.Ns = []mdns.RR{&mdns.SOA{
			Hdr:     mdns.RR_Header{Name: testZone, Rrtype: mdns.TypeSOA, Class: mdns.ClassINET, Ttl: 60},
			Ns:      "ns1." + testZone,
			Mbox:    "hostmaster." + testZone,
			Serial:  1,
			Refresh: 60, Retry: 60, Expire: 60, Minttl: 60,
		}}
	}

	_ = w.WriteMsg(m)
}

// startNameservers runs ns1 on 127.0.0.1 and ns2 on 127.0.0.2, both on the
// same port, and returns a checker using ns1 as its recursive resolver.
func startNameservers(t *testing.T) (txtChecker, *fakeNameserver, *fakeNameserver) {
	t.Helper()

	if runtime.GOOS != "linux" {
		t.Skip("needs 127.0.0.2, which only Linux routes by default")
	}

	ns1 := &fakeNameserver{txt: map[string][]string{}, cname: map[string]string{}}
	ns2 := &fakeNameserver{txt: map[string][]string{}, cname: map[string]string{}}

	var lc net.ListenConfig

	pc1, err := lc.ListenPacket(t.Context(), "udp", "127.0.0.1:0")
	require.NoError(t, err)

	_, port, err := net.SplitHostPort(pc1.LocalAddr().String())
	require.NoError(t, err)

	pc2, err := lc.ListenPacket(t.Context(), "udp", net.JoinHostPort("127.0.0.2", port))
	require.NoError(t, err)

	for pc, h := range map[net.PacketConn]mdns.Handler{pc1: ns1, pc2: ns2} {
		srv := &mdns.Server{PacketConn: pc, Handler: h}

		go func() { _ = srv.ActivateAndServe() }()

		t.Cleanup(func() { _ = srv.Shutdown() })
	}

	c := newTXTChecker([]string{net.JoinHostPort("127.0.0.1", port)}, 5*time.Second)
	c.interval = 10 * time.Millisecond
	c.port = port

	return c, ns1, ns2
}

func TestTXTCheckerAllNameservers(t *testing.T) {
	c, ns1, ns2 := startNameservers(t)
	ctx := context.Background()

	ns1.set("other", "value")
	ns2.set("value")
	require.NoError(t, c.wait(ctx, testName, "value"))

	// ns2 never gets the value: waiting for ns1 alone would let the CA
	// hit ns2 and fail the challenge.
	ns1.set("value-2")

	c.timeout = 200 * time.Millisecond

	err := c.wait(ctx, testName, "value-2")
	require.ErrorIs(t, err, ErrNotPropagated)
	require.ErrorContains(t, err, "ns2."+testZone)
	assert.NotContains(t, err.Error(), "ns1.")
}

func TestTXTCheckerWaitsForLaggingNameserver(t *testing.T) {
	c, ns1, ns2 := startNameservers(t)

	ns1.set("value")
	ns2.set("value")
	ns2.hideFor.Store(3)

	require.NoError(t, c.wait(context.Background(), testName, "value"))
	assert.Negative(t, ns2.hideFor.Load(), "ns2 was asked again after it missed")
}

// A challenge delegated by CNAME, as to acme-dns, is only served by the
// zone of the chain's last name; the names before it answer with a CNAME.
// The intermediate name sits in testZone, whose nameservers would answer
// without ever serving the value.
func TestTXTCheckerFollowsCNAMEChain(t *testing.T) {
	c, ns1, ns2 := startNameservers(t)

	relay := "relay." + testZone
	target := "f0e3c7." + acmeZone

	for _, ns := range []*fakeNameserver{ns1, ns2} {
		ns.mu.Lock()
		ns.cname[testName] = relay
		ns.cname[relay] = target
		ns.txt[target] = []string{"value"}
		ns.mu.Unlock()
	}

	require.NoError(t, c.wait(context.Background(), testName, "value"))

	c.timeout = 200 * time.Millisecond

	err := c.wait(context.Background(), testName, "other")
	require.ErrorIs(t, err, ErrNotPropagated)
	require.ErrorContains(t, err, target)

	// A loop fails at once instead of waiting out the timeout.
	for _, ns := range []*fakeNameserver{ns1, ns2} {
		ns.mu.Lock()
		ns.cname[relay] = testName
		ns.mu.Unlock()
	}

	err = c.wait(context.Background(), testName, "value")
	require.ErrorIs(t, err, errCNAMEChain)
}

func TestTXTCheckerErrorNamesResolvers(t *testing.T) {
	c := newTXTChecker([]string{"1.1.1.1:53", "8.8.8.8:53"}, time.Second)
	err := c.via(&net.DNSError{Err: "no such host", Name: "ts.example.com.", Server: "127.0.0.53:53"})

	assert.EqualError(t, err, "lookup ts.example.com. on 1.1.1.1:53, 8.8.8.8:53: no such host")
}
