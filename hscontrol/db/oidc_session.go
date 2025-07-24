package db

import (
	"fmt"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/rs/zerolog/log"
	"gorm.io/gorm"
)

// InvalidateOIDCSessionsForNode invalidates all active OIDC sessions for a specific node
func (hsdb *HSDatabase) InvalidateOIDCSessionsForNode(nodeID types.NodeID) error {
	return hsdb.Write(func(tx *gorm.DB) error {
		return InvalidateOIDCSessionsForNode(tx, nodeID)
	})
}

// InvalidateOIDCSessionsForNode invalidates all active OIDC sessions for a specific node
func InvalidateOIDCSessionsForNode(tx *gorm.DB, nodeID types.NodeID) error {
	log.Debug().
		Uint64("node_id", uint64(nodeID)).
		Msg("OIDC: Invalidating sessions for node")

	result := tx.Model(&types.OIDCSession{}).
		Where("node_id = ? AND is_active = ?", nodeID, true).
		Updates(map[string]interface{}{
			"is_active":     false,
			"last_seen_at":  time.Now(),
			"refresh_token": nil,
		})

	if result.Error != nil {
		log.Error().Err(result.Error).
			Uint64("node_id", uint64(nodeID)).
			Msg("OIDC: Failed to invalidate sessions for node")
		return fmt.Errorf("failed to invalidate OIDC sessions for node %d: %w", nodeID, result.Error)
	}

	if result.RowsAffected > 0 {
		log.Info().
			Uint64("node_id", uint64(nodeID)).
			Int64("sessions_invalidated", result.RowsAffected).
			Msg("OIDC: Invalidated sessions for disconnected node")
	} else {
		log.Debug().
			Uint64("node_id", uint64(nodeID)).
			Msg("OIDC: No active sessions found for node")
	}

	return nil
}

// InvalidateExpiredOIDCSessions invalidates sessions for nodes that have been offline too long
func (hsdb *HSDatabase) InvalidateExpiredOIDCSessions(offlineGracePeriod time.Duration) error {
	return hsdb.Write(func(tx *gorm.DB) error {
		return InvalidateExpiredOIDCSessions(tx, offlineGracePeriod)
	})
}

// InvalidateExpiredOIDCSessions invalidates sessions for nodes that have been offline too long
func InvalidateExpiredOIDCSessions(tx *gorm.DB, offlineGracePeriod time.Duration) error {
	// Find active sessions where the node has been offline for longer than the grace period
	cutoff := time.Now().Add(-offlineGracePeriod)

	var sessions []types.OIDCSession
	err := tx.Joins("JOIN nodes ON nodes.id = oidc_sessions.node_id").
		Where("oidc_sessions.is_active = ? AND nodes.last_seen IS NOT NULL AND nodes.last_seen < ?", true, cutoff).
		Find(&sessions).Error
	if err != nil {
		return fmt.Errorf("failed to find expired OIDC sessions: %w", err)
	}

	if len(sessions) == 0 {
		return nil
	}

	// Invalidate these sessions
	sessionIDs := make([]string, len(sessions))
	for i, session := range sessions {
		sessionIDs[i] = session.SessionID
	}

	result := tx.Model(&types.OIDCSession{}).
		Where("session_id IN ?", sessionIDs).
		Updates(map[string]interface{}{
			"is_active":     false,
			"last_seen_at":  time.Now(),
			"refresh_token": nil,
		})

	if result.Error != nil {
		return fmt.Errorf("failed to invalidate expired OIDC sessions: %w", result.Error)
	}

	log.Info().
		Int("sessions_invalidated", len(sessions)).
		Dur("grace_period", offlineGracePeriod).
		Msg("OIDC: Invalidated sessions for nodes offline beyond grace period")

	return nil
}
