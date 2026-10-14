package dns

import (
	"context"
	"errors"
	"fmt"
	"net"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog/log"
)

var ErrNotPropagated = errors.New("TXT record not visible on all authoritative nameservers")

const propagationInterval = 2 * time.Second

// txtChecker waits until every authoritative nameserver of a zone serves
// a TXT value. The client asks the CA to validate as soon as set-dns
// returns, so answering early fails the challenge and costs the node a
// failed authorization at the CA.
type txtChecker struct {
	resolvers []string
	timeout   time.Duration
	interval  time.Duration
	// port the authoritative nameservers are queried on.
	port string
}

func newTXTChecker(resolvers []string, timeout time.Duration) txtChecker {
	return txtChecker{
		resolvers: resolvers,
		timeout:   timeout,
		interval:  propagationInterval,
		port:      "53",
	}
}

// wait returns nil once each nameserver of the zone holding fqdn answers
// it with value.
// A timeout of zero disables the check.
func (c txtChecker) wait(ctx context.Context, fqdn, value string) error {
	if c.timeout <= 0 {
		return nil
	}

	start := time.Now()

	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	recursive := resolverAt(c.resolvers...)

	nameservers, err := nameserversOf(ctx, recursive, fqdn)
	if err != nil {
		return fmt.Errorf("looking up nameservers of %s: %w", fqdn, c.via(err))
	}

	// A nameserver counts as done when any of its addresses has the value:
	// the host may lack a route to one address family.
	pending := make(map[string][]string, len(nameservers))
	for _, ns := range nameservers {
		addrs, err := recursive.LookupHost(ctx, ns.Host)
		if err != nil {
			return fmt.Errorf("resolving nameserver %s: %w", ns.Host, c.via(err))
		}

		pending[ns.Host] = addrs
	}

	for {
		// Every address is asked at once, so a silent one delays a round by
		// at most one query.
		var (
			mu    sync.Mutex
			wg    sync.WaitGroup
			found = make(map[string]string)
		)

		for host, addrs := range pending {
			for _, addr := range addrs {
				wg.Go(func() {
					// Bound each query: the resolver's own timeout and retries
					// come from /etc/resolv.conf and make one silent address
					// cost tens of seconds.
					qctx, cancel := context.WithTimeout(ctx, c.interval)
					defer cancel()

					txts, _ := resolverAt(net.JoinHostPort(addr, c.port)).LookupTXT(qctx, fqdn)
					if slices.Contains(txts, value) {
						mu.Lock()
						found[host] = addr
						mu.Unlock()
					}
				})
			}
		}

		wg.Wait()

		for host, addr := range found {
			log.Debug().
				Str("fqdn", fqdn).
				Str("nameserver", host).
				Str("addr", addr).
				Dur("elapsed", time.Since(start)).
				Msg("ACME challenge visible on nameserver")
			delete(pending, host)
		}

		if len(pending) == 0 {
			return nil
		}

		select {
		case <-ctx.Done():
			hosts := make([]string, 0, len(pending))
			for host := range pending {
				hosts = append(hosts, host)
			}

			slices.Sort(hosts)

			return fmt.Errorf("%w: %s waiting for %s", ErrNotPropagated, fqdn, strings.Join(hosts, ", "))
		case <-time.After(c.interval):
		}
	}
}

// nameserversOf returns the nameservers of the closest enclosing name of
// name that has any, which is the zone holding it.
func nameserversOf(ctx context.Context, r *net.Resolver, name string) ([]*net.NS, error) {
	for {
		nameservers, err := r.LookupNS(ctx, name)

		_, parent, _ := strings.Cut(name, ".")
		if !isNotFound(err) || parent == "" {
			return nameservers, err
		}

		name = parent
	}
}

func isNotFound(err error) bool {
	dnsErr, ok := errors.AsType[*net.DNSError](err)

	return ok && dnsErr.IsNotFound
}

// via names the resolvers a lookup went to: Go reports the server from
// /etc/resolv.conf, which the custom dialer never contacts.
func (c txtChecker) via(err error) error {
	if dnsErr, ok := errors.AsType[*net.DNSError](err); ok {
		dnsErr.Server = strings.Join(c.resolvers, ", ")
	}

	return err
}

// resolverAt returns a resolver that sends queries to addrs instead of the
// servers in /etc/resolv.conf. Each dial takes the next address, so the
// resolver's retries move on to another server when one does not answer.
func resolverAt(addrs ...string) *net.Resolver {
	var next atomic.Uint32

	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer

			addr := addrs[int(next.Add(1)-1)%len(addrs)]

			return d.DialContext(ctx, network, addr)
		},
	}
}
