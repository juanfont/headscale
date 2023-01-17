package headscale

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
	"github.com/rs/zerolog/log"
	"google.golang.org/protobuf/types/known/timestamppb"
	"gorm.io/gorm"
	"tailscale.com/tailcfg"
)

const (
	ErrUserExists        = Error("User already exists")
	ErrUserNotFound      = Error("User not found")
	ErrUserStillHasNodes = Error("User not empty: node(s) found")
	ErrInvalidUserName   = Error("Invalid user name")
)

const (
	// value related to RFC 1123 and 952.
	labelHostnameLength = 63
)

var invalidCharsInUserRegex = regexp.MustCompile("[^a-z0-9-.]+")

// User is the way Headscale implements the concept of users in Tailscale
//
// At the end of the day, users in Tailscale are some kind of 'bubbles' or users
// that contain our machines.
type User struct {
	gorm.Model
	Name string `gorm:"unique"`
}

// CreateUser creates a new User. Returns error if could not be created
// or another user already exists.
func (h *Headscale) CreateUser(name string) (*User, error) {
	err := CheckForFQDNRules(name)
	if err != nil {
		return nil, err
	}
	user := User{}
	if err := h.db.Where("name = ?", name).First(&user).Error; err == nil {
		return nil, ErrUserExists
	}
	user.Name = name
	if err := h.db.Create(&user).Error; err != nil {
		log.Error().
			Str("func", "CreateUser").
			Err(err).
			Msg("Could not create row")

		return nil, err
	}

	return &user, nil
}

// DestroyUser destroys a User. Returns error if the User does
// not exist or if there are machines associated with it.
func (h *Headscale) DestroyUser(name string) error {
	user, err := h.GetUser(name)
	if err != nil {
		return ErrUserNotFound
	}

	machines, err := h.ListMachinesByUser(name)
	if err != nil {
		return err
	}
	if len(machines) > 0 {
		return ErrUserStillHasNodes
	}

	keys, err := h.ListPreAuthKeys(name)
	if err != nil {
		return err
	}
	for _, key := range keys {
		err = h.DestroyPreAuthKey(key)
		if err != nil {
			return err
		}
	}

	if result := h.db.Unscoped().Delete(&user); result.Error != nil {
		return result.Error
	}

	return nil
}

// RenameUser renames a User. Returns error if the User does
// not exist or if another User exists with the new name.
func (h *Headscale) RenameUser(oldName, newName string) error {
	var err error
	oldUser, err := h.GetUser(oldName)
	if err != nil {
		return err
	}
	err = CheckForFQDNRules(newName)
	if err != nil {
		return err
	}
	_, err = h.GetUser(newName)
	if err == nil {
		return ErrUserExists
	}
	if !errors.Is(err, ErrUserNotFound) {
		return err
	}

	oldUser.Name = newName

	if result := h.db.Save(&oldUser); result.Error != nil {
		return result.Error
	}

	return nil
}

// GetUser fetches a user by name.
func (h *Headscale) GetUser(name string) (*User, error) {
	user := User{}
	if result := h.db.First(&user, "name = ?", name); errors.Is(
		result.Error,
		gorm.ErrRecordNotFound,
	) {
		return nil, ErrUserNotFound
	}

	return &user, nil
}

// ListUsers gets all the existing users.
func (h *Headscale) ListUsers() ([]User, error) {
	users := []User{}
	if err := h.db.Find(&users).Error; err != nil {
		return nil, err
	}

	return users, nil
}

// ListMachinesByUser gets all the nodes in a given user.
func (h *Headscale) ListMachinesByUser(name string) ([]Machine, error) {
	err := CheckForFQDNRules(name)
	if err != nil {
		return nil, err
	}
	user, err := h.GetUser(name)
	if err != nil {
		return nil, err
	}

	machines := []Machine{}
	if err := h.db.Preload("AuthKey").Preload("AuthKey.User").Preload("User").Where(&Machine{UserID: user.ID}).Find(&machines).Error; err != nil {
		return nil, err
	}

	return machines, nil
}

// SetMachineUser assigns a Machine to a user.
func (h *Headscale) SetMachineUser(machine *Machine, username string) error {
	err := CheckForFQDNRules(username)
	if err != nil {
		return err
	}
	user, err := h.GetUser(username)
	if err != nil {
		return err
	}
	machine.User = *user
	if result := h.db.Save(&machine); result.Error != nil {
		return result.Error
	}

	return nil
}

func (n *User) toTailscaleUser() *tailcfg.User {
	user := tailcfg.User{
		ID:            tailcfg.UserID(n.ID),
		LoginName:     n.Name,
		DisplayName:   n.Name,
		ProfilePicURL: "",
		Domain:        "headscale.net",
		Logins:        []tailcfg.LoginID{},
		Created:       time.Time{},
	}

	return &user
}

func (n *User) toTailscaleLogin() *tailcfg.Login {
	login := tailcfg.Login{
		ID:            tailcfg.LoginID(n.ID),
		LoginName:     n.Name,
		DisplayName:   n.Name,
		ProfilePicURL: "",
		Domain:        "headscale.net",
	}

	return &login
}

func (h *Headscale) getMapResponseUserProfiles(
	machine Machine,
	peers Machines,
) []tailcfg.UserProfile {
	userMap := make(map[string]User)
	userMap[machine.User.Name] = machine.User
	for _, peer := range peers {
		userMap[peer.User.Name] = peer.User // not worth checking if already is there
	}

	profiles := []tailcfg.UserProfile{}
	for _, user := range userMap {
		displayName := user.Name

		if h.cfg.BaseDomain != "" {
			displayName = fmt.Sprintf("%s@%s", user.Name, h.cfg.BaseDomain)
		}

		profiles = append(profiles,
			tailcfg.UserProfile{
				ID:          tailcfg.UserID(user.ID),
				LoginName:   user.Name,
				DisplayName: displayName,
			})
	}

	return profiles
}

func (n *User) toProto() *v1.User {
	return &v1.User{
		Id:        strconv.FormatUint(uint64(n.ID), Base10),
		Name:      n.Name,
		CreatedAt: timestamppb.New(n.CreatedAt),
	}
}

// NormalizeToFQDNRules will replace forbidden chars in user
// it can also return an error if the user doesn't respect RFC 952 and 1123.
func NormalizeToFQDNRules(name string, stripEmailDomain bool) (string, error) {
	name = strings.ToLower(name)
	name = strings.ReplaceAll(name, "'", "")
	atIdx := strings.Index(name, "@")
	if stripEmailDomain && atIdx > 0 {
		name = name[:atIdx]
	} else {
		name = strings.ReplaceAll(name, "@", ".")
	}
	name = invalidCharsInUserRegex.ReplaceAllString(name, "-")

	for _, elt := range strings.Split(name, ".") {
		if len(elt) > labelHostnameLength {
			return "", fmt.Errorf(
				"label %v is more than 63 chars: %w",
				elt,
				ErrInvalidUserName,
			)
		}
	}

	return name, nil
}

func CheckForFQDNRules(name string) error {
	if len(name) > labelHostnameLength {
		return fmt.Errorf(
			"DNS segment must not be over 63 chars. %v doesn't comply with this rule: %w",
			name,
			ErrInvalidUserName,
		)
	}
	if strings.ToLower(name) != name {
		return fmt.Errorf(
			"DNS segment should be lowercase. %v doesn't comply with this rule: %w",
			name,
			ErrInvalidUserName,
		)
	}
	if invalidCharsInUserRegex.MatchString(name) {
		return fmt.Errorf(
			"DNS segment should only be composed of lowercase ASCII letters numbers, hyphen and dots. %v doesn't comply with theses rules: %w",
			name,
			ErrInvalidUserName,
		)
	}

	return nil
}
