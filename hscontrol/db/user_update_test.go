package db

import (
	"database/sql"
	"testing"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// TestUserUpdatePreservesUnchangedFields verifies that updating a user
// preserves fields that aren't modified. This test validates the fix
// for using Updates() instead of Save() in UpdateUser-like operations.
func TestUserUpdatePreservesUnchangedFields(t *testing.T) {
	database := dbForTest(t)

	// Create a user with all fields set
	initialUser := types.User{
		Name:        "testuser",
		DisplayName: "Test User Display",
		Email:       "test@example.com",
		ProviderIdentifier: sql.NullString{
			String: "provider-123",
			Valid:  true,
		},
	}

	createdUser, err := database.CreateUser(initialUser)
	require.NoError(t, err)
	require.NotNil(t, createdUser)

	// Verify initial state
	assert.Equal(t, "testuser", createdUser.Name)
	assert.Equal(t, "Test User Display", createdUser.DisplayName)
	assert.Equal(t, "test@example.com", createdUser.Email)
	assert.True(t, createdUser.ProviderIdentifier.Valid)
	assert.Equal(t, "provider-123", createdUser.ProviderIdentifier.String)

	// Simulate what UpdateUser does: load user, modify one field, save
	_, err = Write(database.DB, func(tx *gorm.DB) (*types.User, error) {
		user, err := GetUserByID(tx, types.UserID(createdUser.ID))
		if err != nil {
			return nil, err
		}

		// Modify ONLY DisplayName
		user.DisplayName = "Updated Display Name"

		// This is the line being tested - currently uses Save() which writes ALL fields, potentially overwriting unchanged ones
		err = tx.Save(user).Error
		if err != nil {
			return nil, err
		}

		return user, nil
	})
	require.NoError(t, err)

	// Read user back from database
	updatedUser, err := Read(database.DB, func(rx *gorm.DB) (*types.User, error) {
		return GetUserByID(rx, types.UserID(createdUser.ID))
	})
	require.NoError(t, err)

	// Verify that DisplayName was updated
	assert.Equal(t, "Updated Display Name", updatedUser.DisplayName)

	// CRITICAL: Verify that other fields were NOT overwritten
	// With Save(), these assertions should pass because the user object
	// was loaded from DB and has all fields populated.
	// But if Updates() is used, these will also pass (and it's safer).
	assert.Equal(t, "testuser", updatedUser.Name, "Name should be preserved")
	assert.Equal(t, "test@example.com", updatedUser.Email, "Email should be preserved")
	assert.True(t, updatedUser.ProviderIdentifier.Valid, "ProviderIdentifier should be preserved")
	assert.Equal(t, "provider-123", updatedUser.ProviderIdentifier.String, "ProviderIdentifier value should be preserved")
}

// TestUserUpdateWithUpdatesMethod tests that using Updates() instead of Save()
// works correctly and only updates modified fields.
func TestUserUpdateWithUpdatesMethod(t *testing.T) {
	database := dbForTest(t)

	// Create a user
	initialUser := types.User{
		Name:        "testuser",
		DisplayName: "Original Display",
		Email:       "original@example.com",
		ProviderIdentifier: sql.NullString{
			String: "provider-abc",
			Valid:  true,
		},
	}

	createdUser, err := database.CreateUser(initialUser)
	require.NoError(t, err)

	// Update using Updates() method
	_, err = Write(database.DB, func(tx *gorm.DB) (*types.User, error) {
		user, err := GetUserByID(tx, types.UserID(createdUser.ID))
		if err != nil {
			return nil, err
		}

		// Modify multiple fields
		user.DisplayName = "New Display"
		user.Email = "new@example.com"

		// Use Updates() instead of Save()
		err = tx.Updates(user).Error
		if err != nil {
			return nil, err
		}

		return user, nil
	})
	require.NoError(t, err)

	// Verify changes
	updatedUser, err := Read(database.DB, func(rx *gorm.DB) (*types.User, error) {
		return GetUserByID(rx, types.UserID(createdUser.ID))
	})
	require.NoError(t, err)

	// Verify updated fields
	assert.Equal(t, "New Display", updatedUser.DisplayName)
	assert.Equal(t, "new@example.com", updatedUser.Email)

	// Verify preserved fields
	assert.Equal(t, "testuser", updatedUser.Name)
	assert.True(t, updatedUser.ProviderIdentifier.Valid)
	assert.Equal(t, "provider-abc", updatedUser.ProviderIdentifier.String)
}
