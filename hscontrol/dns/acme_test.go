package dns

import (
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// captureResponseWriter is a minimal [dns.ResponseWriter] that records the
// message written by the handler so tests can assert on it without binding
// a real listener.
type captureResponseWriter struct {
	msg *dns.Msg
}

func (w *captureResponseWriter) LocalAddr() net.Addr         { return &net.UDPAddr{} }
func (w *captureResponseWriter) RemoteAddr() net.Addr        { return &net.UDPAddr{} }
func (w *captureResponseWriter) WriteMsg(m *dns.Msg) error   { w.msg = m; return nil }
func (w *captureResponseWriter) Write(b []byte) (int, error) { return len(b), nil }
func (w *captureResponseWriter) Close() error                { return nil }
func (w *captureResponseWriter) TsigStatus() error           { return nil }
func (w *captureResponseWriter) TsigTimersOnly(bool)         {}
func (w *captureResponseWriter) Hijack()                     {}

func query(t *testing.T, s *ACMEChallengeServer, name string, qtype uint16) *dns.Msg {
	t.Helper()

	req := new(dns.Msg)
	req.SetQuestion(dns.Fqdn(name), qtype)

	w := &captureResponseWriter{}
	s.serveDNS(w, req)

	if w.msg == nil {
		t.Fatalf("handler wrote no response for %s/%d", name, qtype)
	}

	return w.msg
}

func newTestServer() *ACMEChallengeServer {
	return NewACMEChallengeServer("tailnet.example.com", "ns1.example.com", ":0")
}

func TestACMEChallengeServerTXT(t *testing.T) {
	s := newTestServer()
	s.SetTXT("_acme-challenge.host.tailnet.example.com", "token-value")

	m := query(t, s, "_acme-challenge.host.tailnet.example.com", dns.TypeTXT)

	if m.Rcode != dns.RcodeSuccess {
		t.Fatalf("rcode = %d, want NOERROR", m.Rcode)
	}

	if !m.Authoritative {
		t.Error("response is not authoritative")
	}

	if len(m.Answer) != 1 {
		t.Fatalf("got %d answers, want 1", len(m.Answer))
	}

	txt, ok := m.Answer[0].(*dns.TXT)
	if !ok {
		t.Fatalf("answer is %T, want *dns.TXT", m.Answer[0])
	}

	if len(txt.Txt) != 1 || txt.Txt[0] != "token-value" {
		t.Errorf("txt = %v, want [token-value]", txt.Txt)
	}
}

func TestACMEChallengeServerMultipleValues(t *testing.T) {
	s := newTestServer()
	name := "_acme-challenge.host.tailnet.example.com"
	s.SetTXT(name, "value-1")
	s.SetTXT(name, "value-2")
	// Setting an existing value again must not create a duplicate RR.
	s.SetTXT(name, "value-1")

	m := query(t, s, name, dns.TypeTXT)

	if len(m.Answer) != 2 {
		t.Fatalf("got %d answers, want 2 (one RR per distinct value)", len(m.Answer))
	}

	// Each value must be its own TXT RR, not concatenated into one.
	for _, rr := range m.Answer {
		txt, ok := rr.(*dns.TXT)
		if !ok {
			t.Fatalf("answer is %T, want *dns.TXT", rr)
		}

		if len(txt.Txt) != 1 {
			t.Errorf("TXT RR has %d strings, want 1: %v", len(txt.Txt), txt.Txt)
		}
	}
}

func TestACMEChallengeServerCaseInsensitive(t *testing.T) {
	s := newTestServer()
	s.SetTXT("_acme-challenge.HOST.Tailnet.Example.com", "token")

	m := query(t, s, "_acme-challenge.host.tailnet.example.COM", dns.TypeTXT)

	if len(m.Answer) != 1 {
		t.Fatalf(
			"got %d answers, want 1 (lookup must be case-insensitive)",
			len(m.Answer),
		)
	}
}

func TestACMEChallengeServerNODATA(t *testing.T) {
	s := newTestServer()

	// In-zone name with no record of the requested type: NOERROR, no
	// answer, SOA in the authority section.
	m := query(t, s, "host.tailnet.example.com", dns.TypeTXT)

	if m.Rcode != dns.RcodeSuccess {
		t.Errorf("rcode = %d, want NOERROR (NODATA)", m.Rcode)
	}

	if len(m.Answer) != 0 {
		t.Errorf("got %d answers, want 0", len(m.Answer))
	}

	if len(m.Ns) != 1 {
		t.Fatalf("got %d authority records, want 1 SOA", len(m.Ns))
	}

	if _, ok := m.Ns[0].(*dns.SOA); !ok {
		t.Errorf("authority record is %T, want *dns.SOA", m.Ns[0])
	}
}

func TestACMEChallengeServerSOAandNS(t *testing.T) {
	s := newTestServer()

	soa := query(t, s, "tailnet.example.com", dns.TypeSOA)
	if len(soa.Answer) != 1 {
		t.Fatalf("SOA: got %d answers, want 1", len(soa.Answer))
	}

	if rr, ok := soa.Answer[0].(*dns.SOA); !ok {
		t.Errorf("SOA answer is %T, want *dns.SOA", soa.Answer[0])
	} else if rr.Ns != "ns1.example.com." {
		t.Errorf("SOA MNAME = %q, want ns1.example.com.", rr.Ns)
	}

	ns := query(t, s, "tailnet.example.com", dns.TypeNS)
	if len(ns.Answer) != 1 {
		t.Fatalf("NS: got %d answers, want 1", len(ns.Answer))
	}

	if rr, ok := ns.Answer[0].(*dns.NS); !ok {
		t.Errorf("NS answer is %T, want *dns.NS", ns.Answer[0])
	} else if rr.Ns != "ns1.example.com." {
		t.Errorf("NS target = %q, want ns1.example.com.", rr.Ns)
	}
}

func TestACMEChallengeServerOutOfZoneRefused(t *testing.T) {
	s := newTestServer()

	m := query(t, s, "_acme-challenge.host.other.example.org", dns.TypeTXT)

	if m.Rcode != dns.RcodeRefused {
		t.Errorf("rcode = %d, want REFUSED for out-of-zone query", m.Rcode)
	}

	if m.Authoritative {
		t.Error("out-of-zone response must not be authoritative")
	}
}

func TestACMEChallengeServerExpiry(t *testing.T) {
	s := newTestServer()
	name := dns.CanonicalName("_acme-challenge.host.tailnet.example.com")

	// Inject one live and one already-expired record directly.
	s.records[name] = []txtRecord{
		{value: "live", expires: time.Now().Add(time.Minute)},
		{value: "stale", expires: time.Now().Add(-time.Minute)},
	}

	got := s.txt(name)
	if len(got) != 1 || got[0] != "live" {
		t.Fatalf("txt() = %v, want [live] (expired records must be hidden)", got)
	}

	s.evictExpired()

	if recs := s.records[name]; len(recs) != 1 {
		t.Errorf("after evictExpired, %d records remain, want 1", len(recs))
	}
}
