package state

import (
	"strings"
	"testing"

	"github.com/juanfont/headscale/hscontrol/db"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

func TestNodeNameCannotShadowExtraRecord(t *testing.T) {
	cfg := persistTestConfig(t.TempDir() + "/headscale.db")
	cfg.TailcfgDNSConfig = &tailcfg.DNSConfig{ExtraRecords: []tailcfg.DNSRecord{
		{Name: "grafana." + cfg.BaseDomain, Type: "A", Value: "100.64.0.100"},
	}}
	s, err := NewState(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })

	user := s.CreateUserForTest("extra-record-user")
	pak, err := s.CreatePreAuthKey(user.TypedID(), true, false, nil, nil)
	require.NoError(t, err)

	register := func(hostname string) types.NodeView {
		t.Helper()

		node, _, err := s.HandleNodeFromPreAuthKey(tailcfg.RegisterRequest{
			Auth:     &tailcfg.RegisterResponseAuth{AuthKey: pak.Key},
			NodeKey:  key.NewNode().Public(),
			Hostinfo: &tailcfg.Hostinfo{Hostname: hostname},
		}, key.NewMachine().Public())
		require.NoError(t, err)

		return node
	}
	static := register("grafana")
	assert.Equal(t, "grafana-1", static.GivenName())

	existing := register("existing")

	cfg.SetExtraRecords([]tailcfg.DNSRecord{
		{Name: "SVC." + cfg.BaseDomain + ".", Type: "A", Value: "100.64.0.101"},
		{Name: "existing." + cfg.BaseDomain, Type: "A", Value: "100.64.0.102"},
		{Name: "child.parent." + cfg.BaseDomain, Type: "A", Value: "100.64.0.103"},
	})

	fresh, _ := s.GetNodeByID(existing.ID())
	assert.Equal(
		t,
		"existing",
		fresh.GivenName(),
		"a records reload keeps existing holders",
	)
	assert.Equal(t, []types.NodeID{existing.ID()}, s.WarnNodesHoldingExtraRecords())

	dynamic := register("svc")
	assert.Equal(t, "svc-1", dynamic.GivenName())

	_, _, err = s.RenameNode(existing.ID(), "Svc")
	require.ErrorIs(t, err, ErrNodeNameNotUnique)
	_, err = s.UpdateNodeFromMapRequest(existing.ID(), tailcfg.MapRequest{
		NodeKey: existing.NodeKey(), Hostinfo: &tailcfg.Hostinfo{Hostname: "svc"},
	})
	require.NoError(t, err)

	fresh, _ = s.GetNodeByID(existing.ID())
	assert.Equal(t, "svc-2", fresh.GivenName())

	parent := register("parent")
	assert.Equal(
		t,
		"parent",
		parent.GivenName(),
		"only exact record names are reserved",
	)
	cfg.SetExtraRecords(nil)

	renamed, _, err := s.RenameNode(existing.ID(), "Svc")
	require.NoError(t, err)
	assert.Equal(t, "svc", renamed.GivenName())
}

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
