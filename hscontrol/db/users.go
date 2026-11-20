package db

import (
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
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

// UserHasNodesError is [ErrUserStillHasNodes] with the nodes the user owns.
type UserHasNodesError struct {
	Nodes types.Nodes
}

func (e *UserHasNodesError) Error() string {
	blocking := make([]string, len(e.Nodes))
	for i, node := range e.Nodes {
		blocking[i] = fmt.Sprintf("%d (%s)", node.ID.Uint64(), node.Hostname)
	}

	return fmt.Sprintf("%s: %d node(s) must be deleted first: %s",
		ErrUserStillHasNodes, len(e.Nodes), strings.Join(blocking, ", "))
}

func (e *UserHasNodesError) Unwrap() error { return ErrUserStillHasNodes }

// UserContents is a user and what its delete removes with it: the nodes and
// the keys it owns. Tagged keys and nodes are owned by their tags, and the
// ones it made stay.
type UserContents struct {
	User types.User
	// Nodes, AuthKeys (the IDs of its auth keys) and APIKeys (of its API
	// keys) are in ID order, revoked and expired keys included.
	Nodes    types.Nodes
	AuthKeys []uint64
	APIKeys  []uint64
}

// LockUserContents reads the user with uid and what its delete removes,
// and holds them until tx ends. On PostgreSQL the user's row is locked for
// update, so a write that names the user, in a foreign key or through
// [holdUser], waits for tx and then finds the user gone. Its keys' rows are
// locked too, so the hourly removal of revoked credentials, which skips a
// held row, leaves them to this delete: what it reports is what it removed.
// SQLite has one writer. Nodes
// come and go only through State, which orders them against the delete
// itself.
func LockUserContents(tx *gorm.DB, uid types.UserID) (*UserContents, error) {
	return userContents(tx, uid, true)
}

// ReadUserContents reads what [LockUserContents] does, and locks nothing.
func ReadUserContents(rx *gorm.DB, uid types.UserID) (*UserContents, error) {
	return userContents(rx, uid, false)
}

// userContents reads the user and what its delete removes; with lock, the
// rows of the user and its keys are locked for update.
func userContents(tx *gorm.DB, uid types.UserID, lock bool) (*UserContents, error) {
	q := func() *gorm.DB {
		if lock {
			return tx.Clauses(clause.Locking{Strength: clause.LockingStrengthUpdate})
		}

		return tx
	}

	user, err := firstUser(q(), "id = ?", uid)
	if err != nil {
		return nil, err
	}

	nodes, err := ListNodesByUser(tx, uid)
	if err != nil {
		return nil, err
	}

	slices.SortFunc(nodes, func(a, b *types.Node) int { return cmp.Compare(a.ID, b.ID) })

	var keys []types.Credential

	err = q().Where("user_id = ? AND kind IN ?", uid, []types.CredentialKind{types.CredentialPreAuthKey, types.CredentialAPIKey}).
		Order("id").Find(&keys).Error
	if err != nil {
		return nil, fmt.Errorf("reading the keys of the user: %w", err)
	}

	c := &UserContents{User: *user, Nodes: nodes, AuthKeys: []uint64{}, APIKeys: []uint64{}}

	for _, k := range keys {
		switch {
		case k.Kind == types.CredentialAPIKey:
			c.APIKeys = append(c.APIKeys, k.ID)
		case !k.IsTagged():
			c.AuthKeys = append(c.AuthKeys, k.ID)
		}
	}

	return c, nil
}

// Token is a short token of the user and the IDs of the nodes and keys
// that go with it. A node or a key that comes or goes changes it; a rename,
// an expiry or a revoke does not, as each leaves what is removed. The
// user's creation time tells a user from a later one with its ID.
func (c *UserContents) Token() string {
	h := sha256.New()
	fmt.Fprintf(h, "%d@%d", c.User.ID, c.User.CreatedAt.UnixMicro())

	for _, n := range c.Nodes {
		fmt.Fprintf(h, "|n%d", n.ID)
	}

	for _, id := range c.AuthKeys {
		fmt.Fprintf(h, "|a%d", id)
	}

	for _, id := range c.APIKeys {
		fmt.Fprintf(h, "|k%d", id)
	}

	return hex.EncodeToString(h.Sum(nil)[:8])
}

// DestroyUserContents removes c's user, its nodes and its keys in tx, which
// must hold them ([LockUserContents]). A node that still refers to one of
// the auth keys loses the reference; the nodes and keys the user made stay
// and no longer know by whom.
func DestroyUserContents(tx *gorm.DB, c *UserContents) error {
	if len(c.Nodes) > 0 {
		ids := make([]types.NodeID, len(c.Nodes))
		for i, n := range c.Nodes {
			ids[i] = n.ID
		}

		err := tx.Unscoped().Delete(&types.Node{}, ids).Error
		if err != nil {
			return fmt.Errorf("deleting the nodes of the user: %w", err)
		}
	}

	if len(c.AuthKeys) > 0 {
		err := tx.Model(&types.Node{}).Where("auth_key_id IN ?", c.AuthKeys).Update("auth_key_id", nil).Error
		if err != nil {
			return fmt.Errorf("clearing auth_key_id on nodes: %w", err)
		}
	}

	if keys := slices.Concat(c.AuthKeys, c.APIKeys); len(keys) > 0 {
		err := tx.Unscoped().Delete(&types.Credential{}, keys).Error
		if err != nil {
			return fmt.Errorf("deleting the keys of the user: %w", err)
		}
	}

	for _, table := range []string{"nodes", "credentials"} {
		err := tx.Exec(`UPDATE `+table+` SET created_by_user_id = NULL WHERE created_by_user_id = ?`, c.User.ID).Error
		if err != nil {
			return fmt.Errorf("forgetting the user in %s.created_by_user_id: %w", table, err)
		}
	}

	return tx.Unscoped().Delete(&types.User{}, c.User.ID).Error
}

// holdUser is the user with id, its row held until tx ends: a delete of
// the user that has read what it removes ([LockUserContents]) makes tx
// wait and then find no user, and one that has not waits for tx. On
// SQLite, which has one writer, it is a plain read.
func holdUser(tx *gorm.DB, id types.UserID) (*types.User, error) {
	return firstUser(tx.Clauses(clause.Locking{Strength: "KEY SHARE"}), "id = ?", id)
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

// GetUsersByIDs reads the users with ids in one query.
func (hsdb *HSDatabase) GetUsersByIDs(ids []types.UserID) ([]types.User, error) {
	users := []types.User{}
	if len(ids) == 0 {
		return users, nil
	}

	err := hsdb.DB.Where("id IN ?", ids).Find(&users).Error
	if err != nil {
		return nil, err
	}

	return users, nil
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
