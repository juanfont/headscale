package db

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"gorm.io/gorm"
)

var (
	ErrUserExists        = errors.New("user already exists")
	ErrUserNotFound      = errors.New("user not found")
	ErrUserStillHasNodes = errors.New("user not empty: node(s) found")
	ErrUserNotUnique     = errors.New("expected exactly one user")
	ErrUserNameTaken     = errors.New("the name equals a text of another user")
	ErrUserEmailTaken    = errors.New("the email equals a text of another user")
)

// UserTakenError refuses a text of a local user that another user holds.
// It is [ErrUserNameTaken] or [ErrUserEmailTaken]; Holder is the other user.
type UserTakenError struct {
	Err    error
	Holder types.User
}

func (e *UserTakenError) Error() string { return e.Err.Error() }

func (e *UserTakenError) Unwrap() error { return e.Err }

// CheckLocalUserTexts refuses the name or the email of the local user id
// (0 for a new one) when it equals the name, the email or the provider
// identifier of another user. The policy names a user by these texts, and a
// second user with one of them either takes the rule or makes it match
// nobody. An empty text is not checked: the caller passes only what it
// changes, so old rows that clash already can still be edited and repaired.
// The name is checked first. Case is ignored, which is wider than the
// policy's exact compare: the safe side.
//
// shortcut: reads every user, as the policy manager holds them all anyway;
// move to an indexed query if a server has users in the hundreds of
// thousands.
func CheckLocalUserTexts(tx *gorm.DB, id types.UserID, name, email string) error {
	var users []types.User

	err := tx.Find(&users).Error
	if err != nil {
		return err
	}

	for _, field := range []struct {
		text string
		err  error
	}{{name, ErrUserNameTaken}, {email, ErrUserEmailTaken}} {
		if field.text == "" {
			continue
		}

		for _, u := range users {
			if types.UserID(u.ID) == id {
				continue
			}

			if strings.EqualFold(u.Name, field.text) || strings.EqualFold(u.Email, field.text) ||
				(u.ProviderIdentifier.Valid && strings.EqualFold(u.ProviderIdentifier.String, field.text)) {
				return &UserTakenError{Err: field.err, Holder: u}
			}
		}
	}

	return nil
}

func (hsdb *HSDatabase) CreateUser(user types.User) (*types.User, error) {
	return Write(hsdb.DB, func(tx *gorm.DB) (*types.User, error) {
		return CreateUser(tx, user)
	})
}

// CreateUser creates a new [types.User]. Returns error if could not be created
// or another user already exists.
func CreateUser(tx *gorm.DB, user types.User) (*types.User, error) {
	err := util.ValidateUsername(user.Name)
	if err != nil {
		return nil, err
	}

	err = tx.Create(&user).Error
	if err != nil {
		return nil, fmt.Errorf("creating user: %w", err)
	}

	return &user, nil
}

func (hsdb *HSDatabase) DestroyUser(uid types.UserID) error {
	return hsdb.Write(func(tx *gorm.DB) error {
		return DestroyUser(tx, uid)
	})
}

// DestroyUser destroys a [types.User]. Returns error if the [types.User] does
// not exist or if there are user-owned nodes associated with it.
// Tagged nodes have user_id = NULL so they do not block deletion.
func DestroyUser(tx *gorm.DB, uid types.UserID) error {
	user, err := GetUserByID(tx, uid)
	if err != nil {
		return err
	}

	nodes, err := ListNodesByUser(tx, uid)
	if err != nil {
		return err
	}

	if len(nodes) > 0 {
		blocking := make([]string, len(nodes))
		for i, node := range nodes {
			blocking[i] = fmt.Sprintf("%d (%s)", node.ID.Uint64(), node.Hostname)
		}

		return fmt.Errorf(
			"%w: %d node(s) must be deleted first: %s",
			ErrUserStillHasNodes, len(nodes), strings.Join(blocking, ", "),
		)
	}

	keys, err := ListPreAuthKeysByUser(tx, uid)
	if err != nil {
		return err
	}

	for _, key := range keys {
		// A tagged key belongs to its tags: deleting the user that made it
		// only nulls the key's user.
		if key.IsTagged() {
			continue
		}

		err = DestroyPreAuthKey(tx, key.ID)
		if err != nil {
			return err
		}
	}

	if result := tx.Unscoped().Delete(&user); result.Error != nil {
		return result.Error
	}

	return nil
}

func (hsdb *HSDatabase) RenameUser(uid types.UserID, newName string) error {
	return hsdb.Write(func(tx *gorm.DB) error {
		return RenameUser(tx, uid, newName)
	})
}

var ErrCannotChangeOIDCUser = errors.New("cannot edit OIDC user")

// RenameUser renames a [types.User]. Returns error if the [types.User] does
// not exist or if another [types.User] exists with the new name.
func RenameUser(tx *gorm.DB, uid types.UserID, newName string) error {
	oldUser, err := GetUserByID(tx, uid)
	if err != nil {
		return err
	}

	if err = util.ValidateUsername(newName); err != nil { //nolint:noinlineerr
		return err
	}

	if oldUser.Provider == util.RegisterMethodOIDC {
		return ErrCannotChangeOIDCUser
	}

	oldUser.Name = newName

	err = tx.Updates(&oldUser).Error
	if err != nil {
		return err
	}

	return nil
}

func (hsdb *HSDatabase) GetUserByID(uid types.UserID) (*types.User, error) {
	return GetUserByID(hsdb.DB, uid)
}

func GetUserByID(tx *gorm.DB, uid types.UserID) (*types.User, error) {
	return firstUser(tx, "id = ?", uid)
}

func (hsdb *HSDatabase) GetUserByOIDCIdentifier(id string) (*types.User, error) {
	return Read(hsdb.DB, func(rx *gorm.DB) (*types.User, error) {
		return GetUserByOIDCIdentifier(rx, id)
	})
}

func GetUserByOIDCIdentifier(tx *gorm.DB, id string) (*types.User, error) {
	return firstUser(tx, "provider_identifier = ?", id)
}

func (hsdb *HSDatabase) ListUsers(filter *types.User) ([]types.User, error) {
	return ListUsers(hsdb.DB, filter)
}

// ListUsers gets all the existing users, optionally filtered by a non-nil filter.
func ListUsers(tx *gorm.DB, filter *types.User) ([]types.User, error) {
	users := []types.User{}

	err := tx.Where(filter).Find(&users).Error
	if err != nil {
		return nil, err
	}

	return users, nil
}

// ListUsersPage returns at most limit users that match every non-empty field
// of filter, in ID order, from the first ID above after. A caller asks for
// one row more than it shows, to learn whether more follow.
func ListUsersPage(tx *gorm.DB, filter *types.User, after types.UserID, limit int) ([]types.User, error) {
	users := []types.User{}

	err := tx.Where(filter).Where("id > ?", uint64(after)).Order("id").Limit(limit).Find(&users).Error
	if err != nil {
		return nil, err
	}

	return users, nil
}

// GetUserByName returns a user if the provided username is
// unique, and otherwise an error.
func (hsdb *HSDatabase) GetUserByName(name string) (*types.User, error) {
	users, err := hsdb.ListUsers(&types.User{Name: name})
	if err != nil {
		return nil, err
	}

	if len(users) == 0 {
		return nil, ErrUserNotFound
	}

	if len(users) != 1 {
		return nil, fmt.Errorf("%w, found %d", ErrUserNotUnique, len(users))
	}

	return &users[0], nil
}

// ListNodesByUser gets all the nodes in a given user.
func ListNodesByUser(tx *gorm.DB, uid types.UserID) (types.Nodes, error) {
	nodes := types.Nodes{}

	uidPtr := uint(uid)

	err := preloadNode(tx).Where(&types.Node{UserID: &uidPtr}).Find(&nodes).Error
	if err != nil {
		return nil, err
	}

	return nodes, nil
}

func (hsdb *HSDatabase) CreateUserForTest(name ...string) *types.User {
	if !testing.Testing() {
		panic("CreateUserForTest can only be called during tests")
	}

	userName := firstOr("testuser", name)

	user, err := hsdb.CreateUser(types.User{Name: userName})
	if err != nil {
		panic(fmt.Sprintf("failed to create test user: %v", err))
	}

	return user
}

func (hsdb *HSDatabase) CreateUsersForTest(count int, namePrefix ...string) []*types.User {
	if !testing.Testing() {
		panic("CreateUsersForTest can only be called during tests")
	}

	prefix := firstOr("testuser", namePrefix)

	users := make([]*types.User, count)
	for i := range count {
		name := prefix + "-" + strconv.Itoa(i)
		users[i] = hsdb.CreateUserForTest(name)
	}

	return users
}

func firstUser(tx *gorm.DB, query string, arg any) (*types.User, error) {
	user := types.User{}

	err := tx.First(&user, query, arg).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrUserNotFound
		}

		return nil, err
	}

	return &user, nil
}
