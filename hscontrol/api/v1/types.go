package apiv1

import (
	"fmt"
	"strconv"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/juanfont/headscale/hscontrol/types"
)

// The v1 contract follows protojson: 64-bit integers are JSON strings (avoiding
// precision loss above 2^53), timestamps are RFC 3339, and zero values are
// emitted. Hence response fields carry NO omitempty; request types keep
// omitempty so their fields stay optional in the spec.

// formatID renders a uint64 identifier as the contract's decimal string.
func formatID[T ~uint64 | ~uint](id T) string {
	return strconv.FormatUint(uint64(id), 10)
}

// User mirrors the v1 User message.
type User struct {
	ID            string    `format:"uint64"      json:"id"`
	Name          string    `json:"name"`
	CreatedAt     time.Time `json:"createdAt"`
	DisplayName   string    `json:"displayName"`
	Email         string    `json:"email"`
	ProviderID    string    `json:"providerId"`
	Provider      string    `json:"provider"`
	ProfilePicURL string    `json:"profilePicUrl"`
}

// userFromView converts a domain user into the v1 response shape, reading
// through the [types.UserView] accessors: Name falls back to Username()
// (email/provider/id) when the stored Name is empty, so OIDC users display
// their email.
func userFromView(u types.UserView) User {
	name := u.Name()
	if name == "" {
		name = u.Username()
	}

	return User{
		ID:            formatID(u.ID()),
		Name:          name,
		CreatedAt:     u.CreatedAt(),
		DisplayName:   u.DisplayName(),
		Email:         u.Email(),
		ProviderID:    u.ProviderIdentifier().String,
		Provider:      u.Provider(),
		ProfilePicURL: u.ProfilePicURL(),
	}
}

// refuseLeadingZero refuses a path ID with a leading zero. 0.29's gateway
// parsed path IDs with strconv.ParseUint(s, 0, 64) (runtime.Uint64), so
// /node/010 was node 8; read as decimal it would act on node 10.
func refuseLeadingZero(s, param string) error {
	if len(s) > 1 && s[0] == '0' {
		return huma.Error400BadRequest(fmt.Sprintf("type mismatch, parameter: %s, error: leading zero in %q", param, s))
	}

	return nil
}
