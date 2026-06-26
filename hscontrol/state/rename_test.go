package state

import (
	"strings"
	"testing"

	"github.com/juanfont/headscale/hscontrol/db"
	"github.com/stretchr/testify/require"
)

// TestRenameNodeRejectsNameExceedingFQDNLimit proves RenameNode rejects a name
// that is a valid DNS label but whose FQDN, under the configured base_domain,
// exceeds MaxHostnameLength. Without the FQDN-length gate such a name persists
// and then breaks map generation for the node and its peers (issue #3346):
// admin-facing writes must not be able to introduce an unmappable name.
func TestRenameNodeRejectsNameExceedingFQDNLimit(t *testing.T) {
	dbPath := t.TempDir() + "/headscale.db"
	cfg := persistTestConfig(dbPath)
	// A long base domain so a 63-char label overflows the 255-char FQDN bound.
	cfg.BaseDomain = strings.Repeat("b", 200) + ".example.com"

	database, err := db.NewHeadscaleDatabase(cfg)
	require.NoError(t, err)

	user := database.CreateUserForTest("rename-user")
	node := database.CreateRegisteredNodeForTest(user, "rename-node")
	require.NoError(t, database.Close())

	s, err := NewState(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })

	// Valid 63-char DNS label, but the resulting FQDN exceeds 255 chars.
	_, _, err = s.RenameNode(node.ID, strings.Repeat("a", 63))
	require.Error(t, err, "rename to a name whose FQDN exceeds the limit must be rejected")

	// A short, valid name is still accepted.
	_, _, err = s.RenameNode(node.ID, "short")
	require.NoError(t, err)
}
