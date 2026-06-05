package db

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestGetAPIKeyByIDZeroReturnsError ensures GetAPIKeyByID(0) reports not-found
// rather than returning the lowest-ID key. GORM drops a zero-valued primary key
// from a struct condition, which would otherwise make the lookup unconditional.
func TestGetAPIKeyByIDZeroReturnsError(t *testing.T) {
	db, err := newSQLiteTestDB()
	require.NoError(t, err)

	_, key1, err := db.CreateAPIKey(nil)
	require.NoError(t, err)
	require.NotNil(t, key1)

	_, key2, err := db.CreateAPIKey(nil)
	require.NoError(t, err)
	require.NotNil(t, key2)

	key, err := db.GetAPIKeyByID(0)
	require.Error(t, err, "GetAPIKeyByID(0) should be not-found, got key=%+v", key)
	assert.Nil(t, key)
}
