package db

import (
	"errors"
	"fmt"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"gorm.io/gorm"
)

var (
	ErrUserExists        = errors.New("user already exists")
	ErrUserNotFound      = errors.New("user not found")
	ErrUserStillHasNodes = errors.New("user not empty: node(s) found")
)

func (hsdb *HSDatabase) CreateUser(name string) (*types.User, error) {
	return Write(hsdb.DB, func(tx *gorm.DB) (*types.User, error) {
		return CreateUser(tx, name)
	})
}

// CreateUser creates a new User. Returns error if could not be created
// or another user already exists.
func CreateUser(tx *gorm.DB, name string) (*types.User, error) {
	err := util.CheckForFQDNRules(name)
	if err != nil {
		return nil, err
	}
	user := types.User{}
	if err := tx.Where("name = ?", name).First(&user).Error; err == nil {
		return nil, ErrUserExists
	}
	user.Name = name
	if err := tx.Create(&user).Error; err != nil {
		return nil, fmt.Errorf("creating user: %w", err)
	}

	return &user, nil
}

func (hsdb *HSDatabase) DestroyUser(name string) error {
	return hsdb.Write(func(tx *gorm.DB) error {
		return DestroyUser(tx, name)
	})
}

// DestroyUser destroys a User. Returns error if the User does
// not exist or if there are nodes associated with it.
func DestroyUser(tx *gorm.DB, name string) error {
	user, err := GetUser(tx, name)
	if err != nil {
		return ErrUserNotFound
	}

	nodes, err := ListNodesByUser(tx, name)
	if err != nil {
		return err
	}
	if len(nodes) > 0 {
		return ErrUserStillHasNodes
	}

	keys, err := ListPreAuthKeys(tx, name)
	if err != nil {
		return err
	}
	for _, key := range keys {
		err = DestroyPreAuthKey(tx, key)
		if err != nil {
			return err
		}
	}

	if result := tx.Unscoped().Delete(&user); result.Error != nil {
		return result.Error
	}

	return nil
}

func (hsdb *HSDatabase) RenameUser(oldName, newName string) error {
	return hsdb.Write(func(tx *gorm.DB) error {
		return RenameUser(tx, oldName, newName)
	})
}

// RenameUser renames a User. Returns error if the User does
// not exist or if another User exists with the new name.
func RenameUser(tx *gorm.DB, oldName, newName string) error {
	var err error
	oldUser, err := GetUser(tx, oldName)
	if err != nil {
		return err
	}
	err = util.CheckForFQDNRules(newName)
	if err != nil {
		return err
	}
	_, err = GetUser(tx, newName)
	if err == nil {
		return ErrUserExists
	}
	if !errors.Is(err, ErrUserNotFound) {
		return err
	}

	oldUser.Name = newName

	if result := tx.Save(&oldUser); result.Error != nil {
		return result.Error
	}

	return nil
}

func (hsdb *HSDatabase) GetUser(name string) (*types.User, error) {
	return Read(hsdb.DB, func(rx *gorm.DB) (*types.User, error) {
		return GetUser(rx, name)
	})
}

func GetUser(tx *gorm.DB, name string) (*types.User, error) {
	user := types.User{}
	if result := tx.First(&user, "name = ?", name); errors.Is(
		result.Error,
		gorm.ErrRecordNotFound,
	) {
		return nil, ErrUserNotFound
	}

	return &user, nil
}

func (hsdb *HSDatabase) ListUsers() ([]types.User, error) {
	return Read(hsdb.DB, func(rx *gorm.DB) ([]types.User, error) {
		return ListUsers(rx)
	})
}

// ListUsers gets all the existing users.
func ListUsers(tx *gorm.DB) ([]types.User, error) {
	users := []types.User{}
	if err := tx.Find(&users).Error; err != nil {
		return nil, err
	}

	return users, nil
}

// ListNodesByUser gets all the nodes in a given user.
func ListNodesByUser(tx *gorm.DB, name string) (types.Nodes, error) {
	err := util.CheckForFQDNRules(name)
	if err != nil {
		return nil, err
	}
	user, err := GetUser(tx, name)
	if err != nil {
		return nil, err
	}

	nodes := types.Nodes{}
	if err := tx.Preload("AuthKey").Preload("AuthKey.User").Preload("User").Where(&types.Node{UserID: user.ID}).Find(&nodes).Error; err != nil {
		return nil, err
	}

	return nodes, nil
}

func (hsdb *HSDatabase) AssignNodeToUser(node *types.Node, username string) error {
	return hsdb.Write(func(tx *gorm.DB) error {
		return AssignNodeToUser(tx, node, username)
	})
}

// AssignNodeToUser assigns a Node to a user.
func AssignNodeToUser(tx *gorm.DB, node *types.Node, username string) error {
	err := util.CheckForFQDNRules(username)
	if err != nil {
		return err
	}
	user, err := GetUser(tx, username)
	if err != nil {
		return err
	}
	node.User = *user
	if result := tx.Save(&node); result.Error != nil {
		return result.Error
	}

	return nil
}
