package apiv1

import (
	oas "github.com/juanfont/headscale/gen/api/v1"
	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// This file bridges the existing proto response builders (the Proto() methods
// on the state types) to the ogen API types. Reusing Proto() guarantees the
// new HTTP API surfaces exactly the same data the gRPC/gateway stack did
// (username fallback, masked key prefixes, online computation, the
// TaggedDevices substitution, …) without reimplementing it.
//
// Unlike grpc-gateway (which marshalled with EmitUnpopulated), these converters
// omit zero-value and absent fields — empty strings, false booleans, zero
// numbers, empty arrays, nil timestamps/objects, and the unspecified register
// method. See docs/v1-ogen/CHANGES.md. When the proto stack is removed, these
// converters are rewritten to read the state types directly.
//
// Converters are added here as each resource group is migrated.

func optString(s string) oas.OptString {
	if s == "" {
		return oas.OptString{}
	}

	return oas.NewOptString(s)
}

func optUint64(v uint64) oas.OptUint64 {
	if v == 0 {
		return oas.OptUint64{}
	}

	return oas.NewOptUint64(v)
}

func optTime(ts *timestamppb.Timestamp) oas.OptDateTime {
	if ts == nil {
		return oas.OptDateTime{}
	}

	return oas.NewOptDateTime(ts.AsTime())
}

func oasUser(u *v1.User) oas.User {
	return oas.User{
		ID:            optUint64(u.GetId()),
		Name:          optString(u.GetName()),
		CreatedAt:     optTime(u.GetCreatedAt()),
		DisplayName:   optString(u.GetDisplayName()),
		Email:         optString(u.GetEmail()),
		ProviderId:    optString(u.GetProviderId()),
		Provider:      optString(u.GetProvider()),
		ProfilePicUrl: optString(u.GetProfilePicUrl()),
	}
}
