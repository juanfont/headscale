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
		Updates(map[string]any{
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

// FindOIDCSessionCandidatesForInvalidation finds active sessions where the node's
// database last_seen is older than the grace period. These are candidates only —
// the caller should verify the node is actually offline (e.g., via NodeStore) before
// invalidating, since last_seen in the database may be stale for online nodes.
func (hsdb *HSDatabase) FindOIDCSessionCandidatesForInvalidation(offlineGracePeriod time.Duration) ([]types.OIDCSession, error) {
	cutoff := time.Now().Add(-offlineGracePeriod)

	var sessions []types.OIDCSession
	err := hsdb.Read(func(tx *gorm.DB) error {
		return tx.Joins("JOIN nodes ON nodes.id = oidc_sessions.node_id").
			Where("oidc_sessions.is_active = ? AND nodes.last_seen IS NOT NULL AND nodes.last_seen < ?", true, cutoff).
			Find(&sessions).Error
	})
	if err != nil {
		return nil, fmt.Errorf("failed to find OIDC session candidates for invalidation: %w", err)
	}

	return sessions, nil
}

// InvalidateOIDCSessionsByIDs invalidates the specified OIDC sessions by their session IDs.
// Unlike InvalidateOIDCSessionsForNode, this preserves the refresh token so that nodes
// returning online can attempt session recovery without requiring manual re-authentication.
func (hsdb *HSDatabase) InvalidateOIDCSessionsByIDs(sessionIDs []string) error {
	if len(sessionIDs) == 0 {
		return nil
	}

	return hsdb.Write(func(tx *gorm.DB) error {
		result := tx.Model(&types.OIDCSession{}).
			Where("session_id IN ?", sessionIDs).
			Updates(map[string]any{
				"is_active":    false,
				"last_seen_at": time.Now(),
			})

		if result.Error != nil {
			return fmt.Errorf("failed to invalidate OIDC sessions: %w", result.Error)
		}

		return nil
	})
}
