package hscontrol

import (
	"context"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/rs/zerolog/log"
)

const (
	// defaultOIDCGroupRefreshInterval is how often OIDC groups are refreshed
	// from the provider for all users. Only users with a valid provider
	// identifier (OIDC-authenticated) are refreshed.
	defaultOIDCGroupRefreshInterval = 15 * time.Minute
)

// RefreshUserOIDCGroups refreshes OIDC group memberships for a single user
// by re-reading the stored claims. This is called during login when the
// fresh userinfo is available.
func (h *Headscale) RefreshUserOIDCGroups(userID types.UserID, groups []string) {
	if err := h.state.SetUserOIDCGroups(userID, groups); err != nil {
		log.Error().Err(err).Uint("user_id", uint(userID)).Msg("failed to refresh OIDC groups for user")
	}
}

// RefreshAllOIDCGroups iterates over all OIDC-authenticated users and
// clears their group memberships. On the next login, fresh groups will be
// fetched from the provider. This is a best-effort periodic cleanup:
// users whose groups have changed will pick up the new groups at next
// login. For immediate refresh, call [RefreshUserOIDCGroups] during login.
func (h *Headscale) RefreshAllOIDCGroups() {
	users, err := h.state.ListAllUsers()
	if err != nil {
		log.Error().Err(err).Msg("failed to list users for OIDC group refresh")
		return
	}

	refreshed := 0
	for _, user := range users {
		// Only refresh OIDC-authenticated users (those with a provider identifier).
		if !user.ProviderIdentifier.Valid || user.ProviderIdentifier.String == "" {
			continue
		}

		// Clear stale groups. Fresh groups will be populated on next login.
		if err := h.state.SetUserOIDCGroups(types.UserID(user.ID), nil); err != nil {
			log.Error().Err(err).Uint("user_id", user.ID).Str("user", user.Username()).Msg("failed to clear OIDC groups")
			continue
		}

		refreshed++
	}

	if refreshed > 0 {
		log.Info().Int("count", refreshed).Msg("cleared OIDC groups for OIDC-authenticated users")
	}
}

// StartOIDCGroupRefresh starts a background goroutine that periodically
// clears stale OIDC group memberships. Fresh groups are populated on
// the user's next login.
func (h *Headscale) StartOIDCGroupRefresh(ctx context.Context) {
	if h.cfg.OIDC.Issuer == "" {
		return // OIDC not configured, nothing to refresh
	}

	ticker := time.NewTicker(defaultOIDCGroupRefreshInterval)
	defer ticker.Stop()

	log.Info().Dur("interval", defaultOIDCGroupRefreshInterval).Msg("OIDC group refresh started")

	for {
		select {
		case <-ctx.Done():
			log.Info().Msg("OIDC group refresh stopped")
			return
		case <-ticker.C:
			h.RefreshAllOIDCGroups()
		}
	}
}
