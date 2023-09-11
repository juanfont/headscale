package db

import (
	"errors"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/rs/zerolog/log"
	"gorm.io/gorm"
)

var (
	ErrUserExists        = errors.New("user already exists")
	ErrUserNotFound      = errors.New("user not found")
	ErrUserStillHasNodes = errors.New("user not empty: node(s) found")
)

// CreateUser creates a new User. Returns error if could not be created
// or another user already exists.
func (hsdb *HSDatabase) CreateUser(name string) (*types.User, error) {
	hsdb.mu.Lock()
	defer hsdb.mu.Unlock()

	err := util.CheckForFQDNRules(name)
	if err != nil {
		return nil, err
	}
	user := types.User{}
	if err := hsdb.db.Where("name = ?", name).First(&user).Error; err == nil {
		return nil, ErrUserExists
	}
	user.Name = name
	if err := hsdb.db.Create(&user).Error; err != nil {
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
func (hsdb *HSDatabase) DestroyUser(name string) error {
	hsdb.mu.Lock()
	defer hsdb.mu.Unlock()

	user, err := hsdb.getUser(name)
	if err != nil {
		return ErrUserNotFound
	}

	machines, err := hsdb.listMachinesByUser(name)
	if err != nil {
		return err
	}
	if len(machines) > 0 {
		return ErrUserStillHasNodes
	}

	keys, err := hsdb.listPreAuthKeys(name)
	if err != nil {
		return err
	}
	for _, key := range keys {
		err = hsdb.destroyPreAuthKey(key)
		if err != nil {
			return err
		}
	}

	if result := hsdb.db.Unscoped().Delete(&user); result.Error != nil {
		return result.Error
	}

	return nil
}

// RenameUser renames a User. Returns error if the User does
// not exist or if another User exists with the new name.
func (hsdb *HSDatabase) RenameUser(oldName, newName string) error {
	hsdb.mu.Lock()
	defer hsdb.mu.Unlock()

	var err error
	oldUser, err := hsdb.getUser(oldName)
	if err != nil {
		return err
	}
	err = util.CheckForFQDNRules(newName)
	if err != nil {
		return err
	}
	_, err = hsdb.getUser(newName)
	if err == nil {
		return ErrUserExists
	}
	if !errors.Is(err, ErrUserNotFound) {
		return err
	}

	oldUser.Name = newName

	if result := hsdb.db.Save(&oldUser); result.Error != nil {
		return result.Error
	}

	return nil
}

// GetUser fetches a user by name.
func (hsdb *HSDatabase) GetUser(name string) (*types.User, error) {
	hsdb.mu.RLock()
	defer hsdb.mu.RUnlock()

	return hsdb.getUser(name)
}

func (hsdb *HSDatabase) getUser(name string) (*types.User, error) {
	user := types.User{}
	if result := hsdb.db.First(&user, "name = ?", name); errors.Is(
		result.Error,
		gorm.ErrRecordNotFound,
	) {
		return nil, ErrUserNotFound
	}

	return &user, nil
}

// ListUsers gets all the existing users.
func (hsdb *HSDatabase) ListUsers() ([]types.User, error) {
	hsdb.mu.RLock()
	defer hsdb.mu.RUnlock()

	return hsdb.listUsers()
}

func (hsdb *HSDatabase) listUsers() ([]types.User, error) {
	users := []types.User{}
	if err := hsdb.db.Find(&users).Error; err != nil {
		return nil, err
	}

	return users, nil
}

// ListMachinesByUser gets all the nodes in a given user.
func (hsdb *HSDatabase) ListMachinesByUser(name string) (types.Machines, error) {
	hsdb.mu.RLock()
	defer hsdb.mu.RUnlock()

	return hsdb.listMachinesByUser(name)
}

func (hsdb *HSDatabase) listMachinesByUser(name string) (types.Machines, error) {
	err := util.CheckForFQDNRules(name)
	if err != nil {
		return nil, err
	}
	user, err := hsdb.getUser(name)
	if err != nil {
		return nil, err
	}

	machines := types.Machines{}
	if err := hsdb.db.Preload("AuthKey").Preload("AuthKey.User").Preload("User").Where(&types.Machine{UserID: user.ID}).Find(&machines).Error; err != nil {
		return nil, err
	}

	return machines, nil
}

// AssignMachineToUser assigns a Machine to a user.
func (hsdb *HSDatabase) AssignMachineToUser(machine *types.Machine, username string) error {
	hsdb.mu.Lock()
	defer hsdb.mu.Unlock()

	err := util.CheckForFQDNRules(username)
	if err != nil {
		return err
	}
	user, err := hsdb.getUser(username)
	if err != nil {
		return err
	}
	machine.User = *user
	if result := hsdb.db.Save(&machine); result.Error != nil {
		return result.Error
	}

	return nil
}
