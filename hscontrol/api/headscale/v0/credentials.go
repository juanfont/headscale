package apiv0

import (
	"context"
	"time"

	"github.com/danielgtaylor/huma/v2"
)

// What auth keys, API keys and OAuth clients share: how a record ends, the
// time a record is made with, the schema of a state, and who made a
// credential.

// removal is when the server removes a record revoked at revoked: the
// retention after it, or nil while the record is kept (not revoked, kept for
// ever, or kept, such as an auth key a node refers to).
func removal(revoked *time.Time, retention time.Duration, kept bool) *time.Time {
	if revoked == nil || retention <= 0 || kept {
		return nil
	}

	return new(revoked.Add(retention))
}

// micro is t as v0 writes and answers it: in UTC, to the microsecond, which
// PostgreSQL keeps, so a create answers what a get will, and a time another
// API stored answers as 002 has a time.
func micro(t time.Time) time.Time {
	return t.UTC().Truncate(time.Microsecond)
}

// stateSchema registers the enum name once and refers to it, so a client
// has one type for it, not one for each object that holds it.
func stateSchema(r huma.Registry, name, description string, values ...string) *huma.Schema {
	enum := make([]any, len(values))
	for i, v := range values {
		enum[i] = v
	}

	r.Map()[name] = &huma.Schema{Type: huma.TypeString, Enum: enum, Description: description}

	return &huma.Schema{Ref: "#/components/schemas/" + name}
}

// maker is the stored credential of the request, which a credential it makes
// holds in its write; 0 for the socket.
func maker(ctx context.Context) uint64 {
	c := callerFrom(ctx)
	if c == nil || c.credential == nil {
		return 0
	}

	return c.credential.id
}
