package types

import (
	"cmp"
	"strconv"

	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
	"github.com/juanfont/headscale/hscontrol/util"
	"google.golang.org/protobuf/types/known/timestamppb"
	"gorm.io/gorm"
	"tailscale.com/tailcfg"
)

type UserID uint64

// User is the way Headscale implements the concept of users in Tailscale
//
// At the end of the day, users in Tailscale are some kind of 'bubbles' or users
// that contain our machines.
type User struct {
	gorm.Model
	// The index `idx_name_provider_identifier` is to enforce uniqueness
	// between Name and ProviderIdentifier. This ensures that
	// you can have multiple usersnames of the same name in OIDC,
	// but not if you only run with CLI users.

	// Username for the user, is used if email is empty
	// Should not be used, please use Username().
	Name string `gorm:"index,uniqueIndex:idx_name_provider_identifier"`

	// Typically the full name of the user
	DisplayName string

	// Email of the user
	// Should not be used, please use Username().
	Email string

	// Unique identifier of the user from OIDC,
	// comes from `sub` claim in the OIDC token
	// and is used to lookup the user.
	ProviderIdentifier string `gorm:"unique,index,uniqueIndex:idx_name_provider_identifier"`

	// Provider is the origin of the user account,
	// same as RegistrationMethod, without authkey.
	Provider string

	ProfilePicURL string
}

// Username is the main way to get the username of a user,
// it will return the email if it exists, the name if it exists,
// the OIDCIdentifier if it exists, and the ID if nothing else exists.
// Email and OIDCIdentifier will be set when the user has headscale
// enabled with OIDC, which means that there is a domain involved which
// should be used throughout headscale, in information returned to the
// user and the Policy engine.
// If the username does not contain an '@' it will be added to the end.
func (u *User) Username() string {
	username := cmp.Or(u.Email, u.Name, u.ProviderIdentifier, strconv.FormatUint(uint64(u.ID), 10))
	// TODO(kradalby): Wire up all of this for the future
	// if !strings.Contains(username, "@") {
	// 	username = username + "@"
	// }

	return username
}

// DisplayNameOrUsername returns the DisplayName if it exists, otherwise
// it will return the Username.
func (u *User) DisplayNameOrUsername() string {
	return cmp.Or(u.DisplayName, u.Username())
}

// TODO(kradalby): See if we can fill in Gravatar here.
func (u *User) profilePicURL() string {
	return u.ProfilePicURL
}

func (u *User) TailscaleUser() *tailcfg.User {
	user := tailcfg.User{
		ID:            tailcfg.UserID(u.ID),
		LoginName:     u.Username(),
		DisplayName:   u.DisplayNameOrUsername(),
		ProfilePicURL: u.profilePicURL(),
		Logins:        []tailcfg.LoginID{},
		Created:       u.CreatedAt,
	}

	return &user
}

func (u *User) TailscaleLogin() *tailcfg.Login {
	login := tailcfg.Login{
		ID: tailcfg.LoginID(u.ID),
		// TODO(kradalby): this should reflect registration method.
		Provider:      u.Provider,
		LoginName:     u.Username(),
		DisplayName:   u.DisplayNameOrUsername(),
		ProfilePicURL: u.profilePicURL(),
	}

	return &login
}

func (u *User) TailscaleUserProfile() tailcfg.UserProfile {
	return tailcfg.UserProfile{
		ID:            tailcfg.UserID(u.ID),
		LoginName:     u.Username(),
		DisplayName:   u.DisplayNameOrUsername(),
		ProfilePicURL: u.profilePicURL(),
	}
}

func (u *User) Proto() *v1.User {
	return &v1.User{
		Id:            strconv.FormatUint(uint64(u.ID), util.Base10),
		Name:          u.Name,
		CreatedAt:     timestamppb.New(u.CreatedAt),
		DisplayName:   u.DisplayName,
		Email:         u.Email,
		ProviderId:    u.ProviderIdentifier,
		Provider:      u.Provider,
		ProfilePicUrl: u.ProfilePicURL,
	}
}

type OIDCClaims struct {
	// Sub is the user's unique identifier at the provider.
	Sub string `json:"sub"`
	Iss string `json:"iss"`

	// Name is the user's full name.
	Name              string   `json:"name,omitempty"`
	Groups            []string `json:"groups,omitempty"`
	Email             string   `json:"email,omitempty"`
	EmailVerified     bool     `json:"email_verified,omitempty"`
	ProfilePictureURL string   `json:"picture,omitempty"`
	Username          string   `json:"preferred_username,omitempty"`
}

func (c *OIDCClaims) Identifier() string {
	return c.Iss + "/" + c.Sub
}

// FromClaim overrides a User from OIDC claims.
// All fields will be updated, except for the ID.
func (u *User) FromClaim(claims *OIDCClaims) {
	u.ProviderIdentifier = claims.Identifier()
	u.DisplayName = claims.Name
	if claims.EmailVerified {
		u.Email = claims.Email
	}
	u.Name = claims.Username
	u.ProfilePicURL = claims.ProfilePictureURL
	u.Provider = util.RegisterMethodOIDC
}
