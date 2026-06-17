package apiv1

import (
	"time"

	oas "github.com/juanfont/headscale/gen/api/v1"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"tailscale.com/types/views"
)

// This file converts the state-layer types into the ogen API types. It reads
// the copy-on-write view types (NodeView, UserView, PreAuthKeyView) directly so
// no node/user is deep-copied on the read path, and reproduces the same fields
// the previous API emitted — username fallback, masked key prefixes, online
// computation, the register-method enum.
//
// These converters omit zero-value and absent fields — empty strings, false booleans, zero
// numbers, empty arrays, nil timestamps/objects, and the unspecified register
// method. See docs/v1-ogen/CHANGES.md.

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

func optBool(b bool) oas.OptBool {
	if !b {
		return oas.OptBool{}
	}

	return oas.NewOptBool(b)
}

// optTimeVal sets a timestamp from a value; the previous proto builders always
// emitted these fields (timestamppb.New is never nil), so they are always set.
func optTimeVal(t time.Time) oas.OptDateTime {
	return oas.NewOptDateTime(t)
}

// optTimePtr sets a timestamp only when present, matching the proto builders'
// nil checks.
func optTimePtr(t *time.Time) oas.OptDateTime {
	if t == nil {
		return oas.OptDateTime{}
	}

	return oas.NewOptDateTime(*t)
}

// optTimeVP sets a timestamp from a view's optional pointer.
func optTimeVP(p views.ValuePointer[time.Time]) oas.OptDateTime {
	if !p.Valid() {
		return oas.OptDateTime{}
	}

	return oas.NewOptDateTime(p.Get())
}

// strs normalises an empty slice to nil so it is omitted from the response
// rather than emitted as an empty array.
func strs(s []string) []string {
	if len(s) == 0 {
		return nil
	}

	return s
}

func oasRegisterMethod(rm string) oas.OptRegisterMethod {
	var v oas.RegisterMethod

	switch rm {
	case "authkey":
		v = "REGISTER_METHOD_AUTH_KEY"
	case "oidc":
		v = "REGISTER_METHOD_OIDC"
	case "cli":
		v = "REGISTER_METHOD_CLI"
	default:
		return oas.OptRegisterMethod{}
	}

	return oas.NewOptRegisterMethod(v)
}

func oasUser(u types.UserView) oas.User {
	// Use Name if set, otherwise the display-friendly Username() fallback.
	name := u.Name()
	if name == "" {
		name = u.Username()
	}

	return oas.User{
		ID:            optUint64(uint64(u.Model().ID)),
		Name:          optString(name),
		CreatedAt:     optTimeVal(u.Model().CreatedAt),
		DisplayName:   optString(u.DisplayName()),
		Email:         optString(u.Email()),
		ProviderId:    optString(u.ProviderIdentifier().String),
		Provider:      optString(u.Provider()),
		ProfilePicUrl: optString(u.ProfilePicURL()),
	}
}

func optUser(u types.UserView) oas.OptUser {
	if !u.Valid() {
		return oas.OptUser{}
	}

	return oas.NewOptUser(oasUser(u))
}

func apiKeyMaskedPrefix(prefix string) string {
	if len(prefix) == types.NewAPIKeyPrefixLength {
		return "hskey-api-" + prefix + "-***"
	}

	return prefix + "***"
}

func oasAPIKey(k *types.APIKey) oas.ApiKey {
	return oas.ApiKey{
		ID:         optUint64(k.ID),
		Prefix:     optString(apiKeyMaskedPrefix(k.Prefix)),
		Expiration: optTimePtr(k.Expiration),
		CreatedAt:  optTimePtr(k.CreatedAt),
		LastSeen:   optTimePtr(k.LastSeen),
	}
}

func preAuthKeyMaskedPrefix(prefix string) string {
	if prefix != "" {
		return "hskey-auth-" + prefix + "-***"
	}

	return ""
}

func oasPreAuthKey(k types.PreAuthKeyView) oas.PreAuthKey {
	out := oas.PreAuthKey{
		User:       optUser(k.User()),
		ID:         optUint64(k.ID()),
		Reusable:   optBool(k.Reusable()),
		Ephemeral:  optBool(k.Ephemeral()),
		Used:       optBool(k.Used()),
		Expiration: optTimeVP(k.Expiration()),
		CreatedAt:  optTimeVP(k.CreatedAt()),
		AclTags:    strs(k.Tags().AsSlice()),
	}

	// New keys show the masked prefix; legacy keys (with a plaintext key) show
	// the full key for backwards compatibility.
	if masked := preAuthKeyMaskedPrefix(k.Prefix()); masked != "" {
		out.Key = optString(masked)
	} else if k.Key() != "" {
		out.Key = optString(k.Key())
	}

	return out
}

// oasPreAuthKeyNew converts a freshly created pre-auth key, which exposes the
// full secret key exactly once and has no view type.
func oasPreAuthKeyNew(k *types.PreAuthKeyNew) oas.PreAuthKey {
	out := oas.PreAuthKey{
		ID:         optUint64(k.ID),
		Key:        optString(k.Key),
		Reusable:   optBool(k.Reusable),
		Ephemeral:  optBool(k.Ephemeral),
		Expiration: optTimePtr(k.Expiration),
		CreatedAt:  optTimePtr(k.CreatedAt),
		AclTags:    strs(k.Tags),
	}

	if k.User != nil {
		out.User = oas.NewOptUser(oasUser(k.User.View()))
	}

	return out
}

// oasNode converts a node view. user is the user to present (the node's own
// user for most callers, or TaggedDevices for tagged nodes); subnetRoutes
// carries the routes actively served from the node (primary + exit), which only
// some callers populate.
func oasNode(nv types.NodeView, user types.UserView, subnetRoutes []string) oas.Node {
	out := oas.Node{
		ID:              optUint64(uint64(nv.ID())),
		MachineKey:      optString(nv.MachineKey().String()),
		NodeKey:         optString(nv.NodeKey().String()),
		DiscoKey:        optString(nv.DiscoKey().String()),
		IpAddresses:     strs(nv.IPsAsString()),
		Name:            optString(nv.Hostname()),
		User:            optUser(user),
		CreatedAt:       optTimeVal(nv.CreatedAt()),
		RegisterMethod:  oasRegisterMethod(nv.RegisterMethod()),
		GivenName:       optString(nv.GivenName()),
		Online:          optBool(nv.IsOnline().GetOr(false)),
		ApprovedRoutes:  strs(util.PrefixesToString(nv.ApprovedRoutes().AsSlice())),
		AvailableRoutes: strs(util.PrefixesToString(nv.AnnouncedRoutes())),
		SubnetRoutes:    strs(subnetRoutes),
		Tags:            strs(nv.Tags().AsSlice()),
		LastSeen:        optTimeVP(nv.LastSeen()),
		Expiry:          optTimeVP(nv.Expiry()),
	}

	if nv.AuthKey().Valid() {
		out.PreAuthKey = oas.NewOptPreAuthKey(oasPreAuthKey(nv.AuthKey()))
	}

	return out
}
