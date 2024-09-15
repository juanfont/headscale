package types

import (
	"strconv"

	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
	"github.com/juanfont/headscale/hscontrol/util"
	"google.golang.org/protobuf/types/known/timestamppb"
	"gorm.io/gorm"
	"tailscale.com/tailcfg"
)

// User is the way Headscale implements the concept of users in Tailscale
//
// At the end of the day, users in Tailscale are some kind of 'bubbles' or users
// that contain our machines.
type User struct {
	gorm.Model
	Name string `gorm:"unique"`
}

// TODO(kradalby): See if we can fill in Gravatar here
func (u *User) profilePicURL() string {
	return ""
}

func (u *User) TailscaleUser() *tailcfg.User {
	user := tailcfg.User{
		ID:            tailcfg.UserID(u.ID),
		LoginName:     u.Name,
		DisplayName:   u.Name,
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
		Provider:      "",
		LoginName:     u.Name,
		DisplayName:   u.Name,
		ProfilePicURL: u.profilePicURL(),
	}

	return &login
}

func (u *User) TailscaleUserProfile() tailcfg.UserProfile {
	return tailcfg.UserProfile{
		ID:            tailcfg.UserID(u.ID),
		LoginName:     u.Name,
		DisplayName:   u.Name,
		ProfilePicURL: u.profilePicURL(),
	}
}

func (n *User) Proto() *v1.User {
	return &v1.User{
		Id:        strconv.FormatUint(uint64(n.ID), util.Base10),
		Name:      n.Name,
		CreatedAt: timestamppb.New(n.CreatedAt),
	}
}
