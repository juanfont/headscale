package types

import (
	"strconv"
	"time"

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

func (n *User) TailscaleUser() *tailcfg.User {
	user := tailcfg.User{
		ID:            tailcfg.UserID(n.ID),
		LoginName:     n.Name,
		DisplayName:   n.Name,
		ProfilePicURL: "",
		Logins:        []tailcfg.LoginID{},
		Created:       time.Time{},
	}

	return &user
}

func (n *User) TailscaleLogin() *tailcfg.Login {
	login := tailcfg.Login{
		ID:            tailcfg.LoginID(n.ID),
		LoginName:     n.Name,
		DisplayName:   n.Name,
		ProfilePicURL: "",
	}

	return &login
}

func (n *User) Proto() *v1.User {
	return &v1.User{
		Id:        strconv.FormatUint(uint64(n.ID), util.Base10),
		Name:      n.Name,
		CreatedAt: timestamppb.New(n.CreatedAt),
	}
}
