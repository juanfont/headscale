package v2

import (
	"sync"

	"github.com/juanfont/headscale/hscontrol/types"
	"gorm.io/gorm"
)

// TestUsers provides a convenient way to manage test users across tests
type TestUsers struct {
	users map[string]*types.User
	once  sync.Once
}

var defaultTestUsers TestUsers

// GetTestUsers returns a singleton instance of TestUsers with predefined test users
func GetTestUsers() *TestUsers {
	defaultTestUsers.once.Do(func() {
		defaultTestUsers.users = map[string]*types.User{
			"testuser":   {Model: gorm.Model{ID: 1}, Name: "testuser"},
			"groupuser":  {Model: gorm.Model{ID: 2}, Name: "groupuser"},
			"groupuser1": {Model: gorm.Model{ID: 3}, Name: "groupuser1"},
			"groupuser2": {Model: gorm.Model{ID: 4}, Name: "groupuser2"},
			"notme":      {Model: gorm.Model{ID: 5}, Name: "notme"},
			"user1":      {Model: gorm.Model{ID: 6}, Name: "user1"},
			"user2":      {Model: gorm.Model{ID: 7}, Name: "user2"},
			"user3":      {Model: gorm.Model{ID: 8}, Name: "user3"},
			"otheruser":  {Model: gorm.Model{ID: 9}, Name: "otheruser", Email: "otheruser@headscale.net"},
			"mickael":    {Model: gorm.Model{ID: 10}, Name: "mickael"},
			"user100":    {Model: gorm.Model{ID: 11}, Name: "user100"},
		}
	})
	return &defaultTestUsers
}

// User returns a copy of the User with the given name
func (tu *TestUsers) User(name string) types.User {
	if user, ok := tu.users[name]; ok {
		return *user
	}
	// Return empty user if not found
	return types.User{}
}

// UserPtr returns a pointer to the User with the given name
func (tu *TestUsers) UserPtr(name string) *types.User {
	return tu.users[name]
}

// ID returns the ID for the given user name
func (tu *TestUsers) ID(name string) uint {
	if user, ok := tu.users[name]; ok {
		return user.ID
	}
	return 0
}

// IDPtr returns a pointer to the ID for the given user name
func (tu *TestUsers) IDPtr(name string) *uint {
	if user, ok := tu.users[name]; ok {
		id := user.ID
		return &id
	}
	return nil
}

// AsMap returns all users as a map
func (tu *TestUsers) AsMap() map[string]types.User {
	result := make(map[string]types.User, len(tu.users))
	for name, user := range tu.users {
		result[name] = *user
	}
	return result
}

// AsSlice returns all users as a slice
func (tu *TestUsers) AsSlice() types.Users {
	result := make(types.Users, 0, len(tu.users))
	for _, user := range tu.users {
		result = append(result, *user)
	}
	return result
}

// FilteredSlice returns a slice with only the specified user names
func (tu *TestUsers) FilteredSlice(names ...string) types.Users {
	result := make(types.Users, 0, len(names))
	for _, name := range names {
		if user, ok := tu.users[name]; ok {
			result = append(result, *user)
		}
	}
	return result
}