package dns

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/rs/zerolog/log"
)

const (
	// acmeRecordTTL is how long a challenge TXT record is retained after it
	// was last published. ACME DNS-01 challenges are validated within
	// seconds to a few minutes, so a short lifetime keeps stale records
	// from lingering after a certificate has been issued.
	acmeRecordTTL = 10 * time.Minute

	// acmeAnswerTTL is the DNS TTL (seconds) advertised for challenge
	// answers. It is intentionally tiny so resolvers do not cache a
	// challenge value across certificate renewals.
	acmeAnswerTTL = 1

	// acmeZoneTTL is the DNS TTL (seconds) for the zone's SOA and NS
	// answers.
	acmeZoneTTL = 300

	// acmeCleanupInterval is how often expired records are evicted.
	acmeCleanupInterval = time.Minute
)

// ACMEChallengeServer is a minimal authoritative DNS server for the
// configured base domain. It answers the `_acme-challenge.<fqdn>` TXT
// lookups that Tailscale clients rely on to complete ACME DNS-01
// challenges (`tailscale cert` / `tailscale serve --https`).
//
// Nodes publish challenge values through the `/machine/set-dns` Noise
// endpoint; this server returns them to public resolvers (e.g. Let's
// Encrypt) until they expire. Only the zone apex SOA/NS records and the
// published challenge TXT records are served. Node A/AAAA records are
// deliberately not served here — those remain internal to the tailnet via
// MagicDNS.
//
// For this to be reachable, base_domain must be a real, publicly delegated
// zone whose NS records point at this server.
type ACMEChallengeServer struct {
	zone       string // base domain, canonical (lowercase, trailing dot)
	nameserver string // authoritative NS FQDN, canonical
	listenAddr string

	mu      sync.RWMutex
	records map[string][]txtRecord // canonical name -> live TXT values

	servers   []*dns.Server
	closeCh   chan struct{}
	closeOnce sync.Once
}

type txtRecord struct {
	value   string
	expires time.Time
}

// NewACMEChallengeServer creates a DNS server authoritative for zone (the
// configured base domain). nameserver is the FQDN reported in SOA and NS
// answers; when empty it defaults to "ns." + zone. listenAddr is the
// UDP/TCP address to listen on; when empty it defaults to ":53".
func NewACMEChallengeServer(zone, nameserver, listenAddr string) *ACMEChallengeServer {
	zone = dns.CanonicalName(zone)

	if nameserver == "" {
		nameserver = "ns." + zone
	}
	nameserver = dns.CanonicalName(nameserver)

	if listenAddr == "" {
		listenAddr = ":53"
	}

	return &ACMEChallengeServer{
		zone:       zone,
		nameserver: nameserver,
		listenAddr: listenAddr,
		records:    make(map[string][]txtRecord),
		closeCh:    make(chan struct{}),
	}
}

// SetTXT publishes value as a TXT record for name (for example
// "_acme-challenge.host.example.com"). Repeated calls append distinct
// values so concurrent challenges for the same name coexist; each value is
// retained for acmeRecordTTL after it was last set.
func (s *ACMEChallengeServer) SetTXT(name, value string) {
	name = dns.CanonicalName(name)
	expires := time.Now().Add(acmeRecordTTL)

	s.mu.Lock()
	defer s.mu.Unlock()

	recs := s.records[name]
	for i := range recs {
		if recs[i].value == value {
			recs[i].expires = expires
			return
		}
	}

	s.records[name] = append(recs, txtRecord{value: value, expires: expires})
}

// txt returns the live (non-expired) TXT values for a canonical name.
func (s *ACMEChallengeServer) txt(name string) []string {
	now := time.Now()

	s.mu.RLock()
	defer s.mu.RUnlock()

	recs := s.records[name]

	var values []string
	for _, r := range recs {
		if now.Before(r.expires) {
			values = append(values, r.value)
		}
	}

	return values
}

// Start binds the UDP and TCP listeners and launches a background goroutine
// that evicts expired records. It returns once both listeners are bound, or
// an error if either fails to bind (for example, insufficient privileges to
// bind a low port).
func (s *ACMEChallengeServer) Start() error {
	for _, network := range []string{"udp", "tcp"} {
		srv := &dns.Server{
			Addr:    s.listenAddr,
			Net:     network,
			Handler: dns.HandlerFunc(s.serveDNS),
		}

		// NotifyStartedFunc fires only after the listener is bound. If
		// binding fails, ListenAndServe returns the error before it fires,
		// so the goroutine reports that error to startErr instead.
		startErr := make(chan error, 1)
		srv.NotifyStartedFunc = func() { startErr <- nil }

		go func() {
			err := srv.ListenAndServe()
			select {
			case startErr <- err:
			default:
				if err != nil {
					log.Error().
						Caller().
						Err(err).
						Str("net", network).
						Msg("ACME challenge DNS server stopped")
				}
			}
		}()

		if err := <-startErr; err != nil {
			s.Close()
			return fmt.Errorf(
				"binding %s listener on %s: %w",
				network,
				s.listenAddr,
				err,
			)
		}

		s.servers = append(s.servers, srv)
	}

	go s.cleanupLoop()

	return nil
}

// Close shuts down the listeners and stops the cleanup goroutine. It is safe
// to call multiple times.
func (s *ACMEChallengeServer) Close() error {
	s.closeOnce.Do(func() { close(s.closeCh) })

	var errs []error
	for _, srv := range s.servers {
		if err := srv.Shutdown(); err != nil {
			errs = append(errs, err)
		}
	}

	return errors.Join(errs...)
}

func (s *ACMEChallengeServer) cleanupLoop() {
	ticker := time.NewTicker(acmeCleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-s.closeCh:
			return
		case <-ticker.C:
			s.evictExpired()
		}
	}
}

func (s *ACMEChallengeServer) evictExpired() {
	now := time.Now()

	s.mu.Lock()
	defer s.mu.Unlock()

	for name, recs := range s.records {
		kept := recs[:0]
		for _, r := range recs {
			if now.Before(r.expires) {
				kept = append(kept, r)
			}
		}

		if len(kept) == 0 {
			delete(s.records, name)
		} else {
			s.records[name] = kept
		}
	}
}

// serveDNS answers queries for the delegated zone. It is authoritative: it
// serves the apex SOA/NS and the published challenge TXT records, and
// returns NODATA for any other in-zone name. Queries outside the zone are
// refused.
func (s *ACMEChallengeServer) serveDNS(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true

	if len(r.Question) != 1 {
		m.SetRcode(r, dns.RcodeFormatError)
		s.writeMsg(w, m)

		return
	}

	q := r.Question[0]
	qname := dns.CanonicalName(q.Name)

	// Only answer for names within our delegated zone.
	if !dns.IsSubDomain(s.zone, qname) {
		m.Authoritative = false
		m.SetRcode(r, dns.RcodeRefused)
		s.writeMsg(w, m)

		return
	}

	switch {
	case q.Qtype == dns.TypeSOA && qname == s.zone:
		m.Answer = append(m.Answer, s.soa())
	case q.Qtype == dns.TypeNS && qname == s.zone:
		m.Answer = append(m.Answer, s.ns())
	case q.Qtype == dns.TypeTXT:
		// Each challenge value is returned as its own TXT RR so a resolver
		// sees independent records rather than one concatenated string.
		for _, v := range s.txt(qname) {
			m.Answer = append(m.Answer, &dns.TXT{
				Hdr: dns.RR_Header{
					Name:   qname,
					Rrtype: dns.TypeTXT,
					Class:  dns.ClassINET,
					Ttl:    acmeAnswerTTL,
				},
				Txt: []string{v},
			})
		}
	}

	// NODATA: an in-zone name with no record of the requested type. Return
	// NOERROR with the SOA in the authority section.
	if len(m.Answer) == 0 {
		m.Ns = append(m.Ns, s.soa())
	}

	s.writeMsg(w, m)
}

func (s *ACMEChallengeServer) writeMsg(w dns.ResponseWriter, m *dns.Msg) {
	if err := w.WriteMsg(m); err != nil {
		log.Debug().Caller().Err(err).Msg("writing ACME challenge DNS response")
	}
}

func (s *ACMEChallengeServer) soa() *dns.SOA {
	return &dns.SOA{
		Hdr: dns.RR_Header{
			Name:   s.zone,
			Rrtype: dns.TypeSOA,
			Class:  dns.ClassINET,
			Ttl:    acmeZoneTTL,
		},
		Ns:      s.nameserver,
		Mbox:    "hostmaster." + s.zone,
		Serial:  1,
		Refresh: 3600,
		Retry:   600,
		Expire:  86400,
		Minttl:  60,
	}
}

func (s *ACMEChallengeServer) ns() *dns.NS {
	return &dns.NS{
		Hdr: dns.RR_Header{
			Name:   s.zone,
			Rrtype: dns.TypeNS,
			Class:  dns.ClassINET,
			Ttl:    acmeZoneTTL,
		},
		Ns: s.nameserver,
	}
}
