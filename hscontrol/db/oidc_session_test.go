package db

import (
	"fmt"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/types/key"
)

func TestInvalidateOIDCSessionsForNode(t *testing.T) {
	t.Parallel()
	db := dbForTest(t)

	user, err := db.CreateUser(types.User{Name: "test-oidc-user"})
	require.NoError(t, err)

	nodeKey := key.NewNode()
	discoKey := key.NewDisco()
	machineKey := key.NewMachine()

	nodeExpiry := time.Now().Add(24 * time.Hour)
	node := &types.Node{
		MachineKey:     machineKey.Public(),
		NodeKey:        nodeKey.Public(),
		DiscoKey:       discoKey.Public(),
		Hostname:       "test-node",
		GivenName:      "test-node",
		UserID:         &user.ID,
		RegisterMethod: util.RegisterMethodOIDC,
		Expiry:         &nodeExpiry,
	}

	db.DB.Save(node)

	// Create an active OIDC session
	tokenExpiry := time.Now().Add(1 * time.Hour)
	session := &types.OIDCSession{
		NodeID:         types.NodeID(node.ID),
		SessionID:      "test-session-id-1",
		RegistrationID: types.AuthID("test-reg-id-1"),
		RefreshToken:   "test-refresh-token",
		TokenExpiry:    &tokenExpiry,
		IsActive:       true,
	}

	db.DB.Save(session)

	// Verify session is active
	var checkSession types.OIDCSession
	err = db.DB.Where("node_id = ?", node.ID).First(&checkSession).Error
	require.NoError(t, err)
	assert.True(t, checkSession.IsActive)

	// Invalidate the session
	err = db.InvalidateOIDCSessionsForNode(types.NodeID(node.ID))
	require.NoError(t, err)

	// Verify session is now inactive
	err = db.DB.Where("node_id = ?", node.ID).First(&checkSession).Error
	require.NoError(t, err)
	assert.False(t, checkSession.IsActive)
}

func TestFindAndInvalidateOIDCSessions(t *testing.T) {
	t.Parallel()
	db := dbForTest(t)

	user, err := db.CreateUser(types.User{Name: "test-oidc-expire-user"})
	require.NoError(t, err)

	// Create nodes for testing
	now := time.Now()
	nodeExpiry := now.Add(24 * time.Hour)

	node1 := &types.Node{
		MachineKey:     key.NewMachine().Public(),
		NodeKey:        key.NewNode().Public(),
		DiscoKey:       key.NewDisco().Public(),
		Hostname:       "test-node-1",
		GivenName:      "test-node-1",
		UserID:         &user.ID,
		RegisterMethod: util.RegisterMethodOIDC,
		Expiry:         &nodeExpiry,
	}
	db.DB.Save(node1)

	node2 := &types.Node{
		MachineKey:     key.NewMachine().Public(),
		NodeKey:        key.NewNode().Public(),
		DiscoKey:       key.NewDisco().Public(),
		Hostname:       "test-node-2",
		GivenName:      "test-node-2",
		UserID:         &user.ID,
		RegisterMethod: util.RegisterMethodOIDC,
		Expiry:         &nodeExpiry,
	}
	db.DB.Save(node2)

	node3 := &types.Node{
		MachineKey:     key.NewMachine().Public(),
		NodeKey:        key.NewNode().Public(),
		DiscoKey:       key.NewDisco().Public(),
		Hostname:       "test-node-3",
		GivenName:      "test-node-3",
		UserID:         &user.ID,
		RegisterMethod: util.RegisterMethodOIDC,
		Expiry:         &nodeExpiry,
	}
	db.DB.Save(node3)

	// Session 1: Expired token, last seen within grace period (5min ago)
	expiredTime1 := now.Add(-1 * time.Hour)
	lastSeen1 := now.Add(-5 * time.Minute)
	node1.LastSeen = &lastSeen1
	db.DB.Save(node1)
	session1 := &types.OIDCSession{
		NodeID:         types.NodeID(node1.ID),
		SessionID:      "expired-session-1",
		RegistrationID: types.AuthID("reg-1"),
		RefreshToken:   "refresh-1",
		TokenExpiry:    &expiredTime1,
		IsActive:       true,
	}
	db.DB.Save(session1)

	// Session 2: Expired token, last seen outside grace period (20min ago)
	expiredTime2 := now.Add(-2 * time.Hour)
	lastSeen2 := now.Add(-20 * time.Minute)
	node2.LastSeen = &lastSeen2
	db.DB.Save(node2)
	session2 := &types.OIDCSession{
		NodeID:         types.NodeID(node2.ID),
		SessionID:      "expired-session-2",
		RegistrationID: types.AuthID("reg-2"),
		RefreshToken:   "refresh-2",
		TokenExpiry:    &expiredTime2,
		IsActive:       true,
	}
	db.DB.Save(session2)

	// Session 3: Valid token (no last_seen set)
	validTime := now.Add(1 * time.Hour)
	session3 := &types.OIDCSession{
		NodeID:         types.NodeID(node3.ID),
		SessionID:      "valid-session",
		RegistrationID: types.AuthID("reg-3"),
		RefreshToken:   "refresh-3",
		TokenExpiry:    &validTime,
		IsActive:       true,
	}
	db.DB.Save(session3)

	// Find candidates with 10 minute grace period
	candidates, err := db.FindOIDCSessionCandidatesForInvalidation(10 * time.Minute)
	require.NoError(t, err)

	// Session 1 (last seen 5min ago) should NOT be a candidate (within grace period)
	// Session 2 (last seen 20min ago) should be a candidate (outside grace period)
	// Session 3 (no last_seen set) should NOT be a candidate
	require.Len(t, candidates, 1)
	assert.Equal(t, "expired-session-2", candidates[0].SessionID)

	// Invalidate the candidates
	sessionIDs := make([]string, len(candidates))
	for i, s := range candidates {
		sessionIDs[i] = s.SessionID
	}
	err = db.InvalidateOIDCSessionsByIDs(sessionIDs)
	require.NoError(t, err)

	// Check results
	var checkSession1, checkSession2, checkSession3 types.OIDCSession

	// Session 1: Should still be active (within grace period)
	err = db.DB.Where("session_id = ?", "expired-session-1").First(&checkSession1).Error
	require.NoError(t, err)
	assert.True(t, checkSession1.IsActive)

	// Session 2: Should be inactive (outside grace period)
	err = db.DB.Where("session_id = ?", "expired-session-2").First(&checkSession2).Error
	require.NoError(t, err)
	assert.False(t, checkSession2.IsActive)

	// Session 3: Should still be active (valid token)
	err = db.DB.Where("session_id = ?", "valid-session").First(&checkSession3).Error
	require.NoError(t, err)
	assert.True(t, checkSession3.IsActive)
}

func TestInvalidateOIDCSessionsWithNoSessions(t *testing.T) {
	t.Parallel()
	db := dbForTest(t)

	// Test with non-existent node ID
	err := db.InvalidateOIDCSessionsForNode(types.NodeID(99999))
	require.NoError(t, err) // Should not error even if no sessions exist
}

func TestFindOIDCSessionCandidatesWithNoneExpired(t *testing.T) {
	t.Parallel()
	db := dbForTest(t)

	user, err := db.CreateUser(types.User{Name: "test-no-expired-user"})
	require.NoError(t, err)

	nodeExpiry := time.Now().Add(24 * time.Hour)
	node := &types.Node{
		MachineKey:     key.NewMachine().Public(),
		NodeKey:        key.NewNode().Public(),
		DiscoKey:       key.NewDisco().Public(),
		Hostname:       "test-valid-node",
		GivenName:      "test-valid-node",
		UserID:         &user.ID,
		RegisterMethod: util.RegisterMethodOIDC,
		Expiry:         &nodeExpiry,
	}
	db.DB.Save(node)

	// Create only valid sessions
	validTime := time.Now().Add(24 * time.Hour)
	session := &types.OIDCSession{
		NodeID:         types.NodeID(node.ID),
		SessionID:      "valid-only-session",
		RegistrationID: types.AuthID("reg-valid"),
		RefreshToken:   "refresh-valid",
		TokenExpiry:    &validTime,
		IsActive:       true,
	}
	db.DB.Save(session)

	// Find candidates - should be empty
	candidates, err := db.FindOIDCSessionCandidatesForInvalidation(10 * time.Minute)
	require.NoError(t, err)
	assert.Empty(t, candidates)

	// Verify session is still active
	var checkSession types.OIDCSession
	err = db.DB.Where("session_id = ?", "valid-only-session").First(&checkSession).Error
	require.NoError(t, err)
	assert.True(t, checkSession.IsActive)
}

func TestInvalidateOIDCSessionsTransaction(t *testing.T) {
	t.Parallel()
	db := dbForTest(t)

	user, err := db.CreateUser(types.User{Name: "test-transaction-user"})
	require.NoError(t, err)

	nodeExpiry := time.Now().Add(24 * time.Hour)

	// Create multiple nodes and sessions (one session per node)
	var nodeIDs []types.NodeID
	for i := range 3 {
		node := &types.Node{
			MachineKey:     key.NewMachine().Public(),
			NodeKey:        key.NewNode().Public(),
			DiscoKey:       key.NewDisco().Public(),
			Hostname:       fmt.Sprintf("test-transaction-node-%d", i),
			GivenName:      fmt.Sprintf("test-transaction-node-%d", i),
			UserID:         &user.ID,
			RegisterMethod: util.RegisterMethodOIDC,
			Expiry:         &nodeExpiry,
		}
		db.DB.Save(node)
		nodeIDs = append(nodeIDs, types.NodeID(node.ID))

		tokenExpiry := time.Now().Add(1 * time.Hour)
		session := &types.OIDCSession{
			NodeID:         types.NodeID(node.ID),
			SessionID:      fmt.Sprintf("session-%d", i),
			RegistrationID: types.AuthID(fmt.Sprintf("reg-%d", i)),
			RefreshToken:   fmt.Sprintf("refresh-%d", i),
			TokenExpiry:    &tokenExpiry,
			IsActive:       true,
		}
		result := db.DB.Create(session)
		require.NoError(t, result.Error)
	}

	// Verify all sessions are active
	var count int64
	db.DB.Model(&types.OIDCSession{}).Where("is_active = ?", true).Count(&count)
	assert.Equal(t, int64(3), count)

	// Invalidate all sessions for the first node
	err = db.InvalidateOIDCSessionsForNode(nodeIDs[0])
	require.NoError(t, err)

	// Verify one session is now inactive, two still active
	db.DB.Model(&types.OIDCSession{}).Where("is_active = ?", true).Count(&count)
	assert.Equal(t, int64(2), count)

	db.DB.Model(&types.OIDCSession{}).Where("is_active = ?", false).Count(&count)
	assert.Equal(t, int64(1), count)

	// Verify the correct session was invalidated
	var inactiveSession types.OIDCSession
	err = db.DB.Where("node_id = ? AND is_active = ?", nodeIDs[0], false).First(&inactiveSession).Error
	require.NoError(t, err)
	assert.Equal(t, "session-0", inactiveSession.SessionID)
}
