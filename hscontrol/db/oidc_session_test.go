package db

import (
	"fmt"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"gopkg.in/check.v1"
	"tailscale.com/types/key"
)

func (*Suite) TestInvalidateOIDCSessionsForNode(c *check.C) {
	user, err := db.CreateUser(types.User{Name: "test-oidc-user"})
	c.Assert(err, check.IsNil)

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
		UserID:         user.ID,
		RegisterMethod: util.RegisterMethodOIDC,
		AuthKeyID:      nil, // No auth key for OIDC
		Expiry:         &nodeExpiry,
	}

	db.DB.Save(node)

	// Create an active OIDC session
	sessionID := "test-session-id-1"
	registrationID := types.RegistrationID("test-reg-id-1")
	tokenExpiry := time.Now().Add(1 * time.Hour)
	session := &types.OIDCSession{
		NodeID:         types.NodeID(node.ID),
		SessionID:      sessionID,
		RegistrationID: registrationID,
		RefreshToken:   "test-refresh-token",
		TokenExpiry:    &tokenExpiry,
		IsActive:       true,
	}

	db.DB.Save(session)

	// Verify session is active
	var checkSession types.OIDCSession
	err = db.DB.Where("node_id = ?", node.ID).First(&checkSession).Error
	c.Assert(err, check.IsNil)
	c.Assert(checkSession.IsActive, check.Equals, true)

	// Invalidate the session
	err = db.InvalidateOIDCSessionsForNode(types.NodeID(node.ID))
	c.Assert(err, check.IsNil)

	// Verify session is now inactive
	err = db.DB.Where("node_id = ?", node.ID).First(&checkSession).Error
	c.Assert(err, check.IsNil)
	c.Assert(checkSession.IsActive, check.Equals, false)
}

func (*Suite) TestInvalidateExpiredOIDCSessions(c *check.C) {
	user, err := db.CreateUser(types.User{Name: "test-oidc-expire-user"})
	c.Assert(err, check.IsNil)

	// Create nodes for testing
	nodeKey1 := key.NewNode()
	discoKey1 := key.NewDisco()
	machineKey1 := key.NewMachine()
	nodeExpiry1 := time.Now().Add(24 * time.Hour)
	node1 := &types.Node{
		MachineKey:     machineKey1.Public(),
		NodeKey:        nodeKey1.Public(),
		DiscoKey:       discoKey1.Public(),
		Hostname:       "test-node-1",
		GivenName:      "test-node-1",
		UserID:         user.ID,
		RegisterMethod: util.RegisterMethodOIDC,
		AuthKeyID:      nil, // No auth key for OIDC
		Expiry:         &nodeExpiry1,
	}
	db.DB.Save(node1)

	nodeKey2 := key.NewNode()
	discoKey2 := key.NewDisco()
	machineKey2 := key.NewMachine()
	nodeExpiry2 := time.Now().Add(24 * time.Hour)
	node2 := &types.Node{
		MachineKey:     machineKey2.Public(),
		NodeKey:        nodeKey2.Public(),
		DiscoKey:       discoKey2.Public(),
		Hostname:       "test-node-2",
		GivenName:      "test-node-2",
		UserID:         user.ID,
		RegisterMethod: util.RegisterMethodOIDC,
		AuthKeyID:      nil, // No auth key for OIDC
		Expiry:         &nodeExpiry2,
	}
	db.DB.Save(node2)

	// Create sessions with different expiry times
	now := time.Now()

	// Session 1: Expired token, last seen within grace period
	expiredTime1 := now.Add(-1 * time.Hour)
	lastSeen1 := now.Add(-5 * time.Minute)
	node1.LastSeen = &lastSeen1
	db.DB.Save(node1)
	session1 := &types.OIDCSession{
		NodeID:         types.NodeID(node1.ID),
		SessionID:      "expired-session-1",
		RegistrationID: types.RegistrationID("reg-1"),
		RefreshToken:   "refresh-1",
		TokenExpiry:    &expiredTime1,
		IsActive:       true,
	}
	db.DB.Save(session1)

	// Session 2: Expired token, last seen outside grace period
	expiredTime2 := now.Add(-2 * time.Hour)
	lastSeen2 := now.Add(-20 * time.Minute)
	node2.LastSeen = &lastSeen2
	db.DB.Save(node2)
	session2 := &types.OIDCSession{
		NodeID:         types.NodeID(node2.ID),
		SessionID:      "expired-session-2",
		RegistrationID: types.RegistrationID("reg-2"),
		RefreshToken:   "refresh-2",
		TokenExpiry:    &expiredTime2,
		IsActive:       true,
	}
	db.DB.Save(session2)

	// Create a third node for session 3
	nodeKey3 := key.NewNode()
	discoKey3 := key.NewDisco()
	machineKey3 := key.NewMachine()
	nodeExpiry3 := time.Now().Add(24 * time.Hour)
	node3 := &types.Node{
		MachineKey:     machineKey3.Public(),
		NodeKey:        nodeKey3.Public(),
		DiscoKey:       discoKey3.Public(),
		Hostname:       "test-node-3",
		GivenName:      "test-node-3",
		UserID:         user.ID,
		RegisterMethod: util.RegisterMethodOIDC,
		AuthKeyID:      nil, // No auth key for OIDC
		Expiry:         &nodeExpiry3,
	}
	db.DB.Save(node3)

	// Session 3: Valid token
	validTime := now.Add(1 * time.Hour)
	session3 := &types.OIDCSession{
		NodeID:         types.NodeID(node3.ID),
		SessionID:      "valid-session",
		RegistrationID: types.RegistrationID("reg-3"),
		RefreshToken:   "refresh-3",
		TokenExpiry:    &validTime,
		IsActive:       true,
	}
	db.DB.Save(session3)

	// Invalidate expired sessions with 10 minute grace period
	err = db.InvalidateExpiredOIDCSessions(10 * time.Minute)
	c.Assert(err, check.IsNil)

	// Check results
	var checkSession1, checkSession2, checkSession3 types.OIDCSession

	// Session 1: Should still be active (within grace period)
	err = db.DB.Where("session_id = ?", "expired-session-1").First(&checkSession1).Error
	c.Assert(err, check.IsNil)
	c.Assert(checkSession1.IsActive, check.Equals, true)

	// Session 2: Should be inactive (outside grace period)
	err = db.DB.Where("session_id = ?", "expired-session-2").First(&checkSession2).Error
	c.Assert(err, check.IsNil)
	c.Assert(checkSession2.IsActive, check.Equals, false)

	// Session 3: Should still be active (valid token)
	err = db.DB.Where("session_id = ?", "valid-session").First(&checkSession3).Error
	c.Assert(err, check.IsNil)
	c.Assert(checkSession3.IsActive, check.Equals, true)
}

func (*Suite) TestInvalidateOIDCSessionsWithNoSessions(c *check.C) {
	// Test with non-existent node ID
	err := db.InvalidateOIDCSessionsForNode(types.NodeID(99999))
	c.Assert(err, check.IsNil) // Should not error even if no sessions exist
}

func (*Suite) TestInvalidateExpiredOIDCSessionsWithNoExpired(c *check.C) {
	user, err := db.CreateUser(types.User{Name: "test-no-expired-user"})
	c.Assert(err, check.IsNil)

	// Create a node for the session
	nodeKey := key.NewNode()
	discoKey := key.NewDisco()
	machineKey := key.NewMachine()
	nodeExpiry := time.Now().Add(24 * time.Hour)
	node := &types.Node{
		MachineKey:     machineKey.Public(),
		NodeKey:        nodeKey.Public(),
		DiscoKey:       discoKey.Public(),
		Hostname:       "test-valid-node",
		GivenName:      "test-valid-node",
		UserID:         user.ID,
		RegisterMethod: util.RegisterMethodOIDC,
		AuthKeyID:      nil, // No auth key for OIDC
		Expiry:         &nodeExpiry,
	}
	db.DB.Save(node)

	// Create only valid sessions
	validTime := time.Now().Add(24 * time.Hour)
	session := &types.OIDCSession{
		NodeID:         types.NodeID(node.ID),
		SessionID:      "valid-only-session",
		RegistrationID: types.RegistrationID("reg-valid"),
		RefreshToken:   "refresh-valid",
		TokenExpiry:    &validTime,
		IsActive:       true,
	}
	db.DB.Save(session)

	// Run invalidation
	err = db.InvalidateExpiredOIDCSessions(10 * time.Minute)
	c.Assert(err, check.IsNil)

	// Verify session is still active
	var checkSession types.OIDCSession
	err = db.DB.Where("session_id = ?", "valid-only-session").First(&checkSession).Error
	c.Assert(err, check.IsNil)
	c.Assert(checkSession.IsActive, check.Equals, true)
}

func (*Suite) TestInvalidateOIDCSessionsTransaction(c *check.C) {
	user, err := db.CreateUser(types.User{Name: "test-transaction-user"})
	c.Assert(err, check.IsNil)

	// Create multiple nodes and sessions (one session per node)
	var nodeIDs []types.NodeID
	for i := 0; i < 3; i++ {
		// Create a node for each session
		nodeKey := key.NewNode()
		discoKey := key.NewDisco()
		machineKey := key.NewMachine()
		nodeExpiry := time.Now().Add(24 * time.Hour)
		node := &types.Node{
			MachineKey:     machineKey.Public(),
			NodeKey:        nodeKey.Public(),
			DiscoKey:       discoKey.Public(),
			Hostname:       fmt.Sprintf("test-transaction-node-%d", i),
			GivenName:      fmt.Sprintf("test-transaction-node-%d", i),
			UserID:         user.ID,
			RegisterMethod: util.RegisterMethodOIDC,
			AuthKeyID:      nil, // No auth key for OIDC
			Expiry:         &nodeExpiry,
		}
		db.DB.Save(node)
		nodeIDs = append(nodeIDs, types.NodeID(node.ID))

		// Create a session for this node
		tokenExpiry := time.Now().Add(1 * time.Hour)
		sessionID := fmt.Sprintf("session-%d", i)
		session := &types.OIDCSession{
			NodeID:         types.NodeID(node.ID),
			SessionID:      sessionID,
			RegistrationID: types.RegistrationID(fmt.Sprintf("reg-%d", i)),
			RefreshToken:   fmt.Sprintf("refresh-%d", i),
			TokenExpiry:    &tokenExpiry,
			IsActive:       true,
		}
		result := db.DB.Create(session)
		c.Assert(result.Error, check.IsNil)
	}

	// Verify all sessions are active
	var count int64
	db.DB.Model(&types.OIDCSession{}).Where("is_active = ?", true).Count(&count)
	c.Assert(count, check.Equals, int64(3))

	// Invalidate all sessions for the first node
	err = db.InvalidateOIDCSessionsForNode(nodeIDs[0])
	c.Assert(err, check.IsNil)

	// Verify one session is now inactive, two still active
	db.DB.Model(&types.OIDCSession{}).Where("is_active = ?", true).Count(&count)
	c.Assert(count, check.Equals, int64(2))

	db.DB.Model(&types.OIDCSession{}).Where("is_active = ?", false).Count(&count)
	c.Assert(count, check.Equals, int64(1))

	// Verify the correct session was invalidated
	var inactiveSession types.OIDCSession
	err = db.DB.Where("node_id = ? AND is_active = ?", nodeIDs[0], false).First(&inactiveSession).Error
	c.Assert(err, check.IsNil)
	c.Assert(inactiveSession.SessionID, check.Equals, "session-0")
}
