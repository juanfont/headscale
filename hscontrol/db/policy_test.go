package db

import (
	"strconv"
	"testing"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSetPolicyKeepsOnlyCurrent checks repeated writes replace the stored
// policy instead of piling up rows.
func TestSetPolicyKeepsOnlyCurrent(t *testing.T) {
	db := dbForTest(t)

	for i := range 5 {
		_, err := db.SetPolicy(
			`{"hosts": {"h": "100.64.0.` + strconv.Itoa(i) + `/32"}}`,
		)
		require.NoError(t, err)
	}

	var rows int64
	require.NoError(t, db.DB.Unscoped().Model(&types.Policy{}).Count(&rows).Error)
	assert.Equal(t, int64(1), rows)

	p, err := db.GetPolicy()
	require.NoError(t, err)
	assert.JSONEq(t, `{"hosts": {"h": "100.64.0.4/32"}}`, p.Data)
}
