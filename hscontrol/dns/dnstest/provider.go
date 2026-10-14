// Package dnstest provides an in-memory DNS provider for tests.
package dnstest

import (
	"context"
	"slices"
	"sync"

	"github.com/libdns/libdns"
)

// Call is one provider call, one entry per record.
type Call struct {
	Method string
	Zone   string
	Name   string
	Value  string
}

// Provider keeps TXT records in memory and records every call. The zero
// value is ready to use and safe for concurrent use.
type Provider struct {
	mu      sync.Mutex
	records map[string][]string
	calls   []Call
	err     error
}

// SetError makes every following call fail with err; nil clears it.
func (p *Provider) SetError(err error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.err = err
}

// AppendRecords fails for a done context, as a provider calling an API
// would, so tests catch a caller that lets a request's end abandon a
// write.
func (p *Provider) AppendRecords(
	ctx context.Context,
	zone string,
	recs []libdns.Record,
) ([]libdns.Record, error) {
	err := ctx.Err()
	if err != nil {
		return nil, err
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	out := make([]libdns.Record, 0, len(recs))

	for _, rec := range recs {
		rr := rec.RR()
		name := libdns.AbsoluteName(rr.Name, zone)
		p.calls = append(p.calls, Call{Method: "append", Zone: zone, Name: name, Value: rr.Data})

		if p.err != nil {
			return out, p.err
		}

		if p.records == nil {
			p.records = make(map[string][]string)
		}

		p.records[name] = append(p.records[name], rr.Data)
		out = append(out, libdns.TXT{Name: rr.Name, TTL: rr.TTL, Text: rr.Data, ProviderData: name})
	}

	return out, nil
}

// DeleteRecords follows the libdns contract: an empty value deletes every
// value at the name. Tests that keep an unrelated value at the same name
// therefore catch a caller that would wipe a whole record set. Like
// AppendRecords, it fails for a done context.
func (p *Provider) DeleteRecords(
	ctx context.Context,
	zone string,
	recs []libdns.Record,
) ([]libdns.Record, error) {
	err := ctx.Err()
	if err != nil {
		return nil, err
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	var out []libdns.Record

	for _, rec := range recs {
		rr := rec.RR()
		name := libdns.AbsoluteName(rr.Name, zone)
		p.calls = append(p.calls, Call{Method: "delete", Zone: zone, Name: name, Value: rr.Data})

		if p.err != nil {
			return out, p.err
		}

		if rr.Data == "" {
			delete(p.records, name)

			out = append(out, rec)

			continue
		}

		i := slices.Index(p.records[name], rr.Data)
		if i < 0 {
			continue
		}

		p.records[name] = slices.Delete(p.records[name], i, i+1)

		out = append(out, rec)
	}

	return out, nil
}

// Add stores a value directly, as if the operator had created it.
func (p *Provider) Add(name, value string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.records == nil {
		p.records = make(map[string][]string)
	}

	p.records[name] = append(p.records[name], value)
}

// Values returns the TXT values stored at the fully qualified name.
func (p *Provider) Values(name string) []string {
	p.mu.Lock()
	defer p.mu.Unlock()

	return slices.Clone(p.records[name])
}

// Calls returns every call made so far.
func (p *Provider) Calls() []Call {
	p.mu.Lock()
	defer p.mu.Unlock()

	return slices.Clone(p.calls)
}
