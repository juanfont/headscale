package apiv1

import (
	"strconv"
	"time"

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
