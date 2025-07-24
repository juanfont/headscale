package types

import (
	"time"

	"gorm.io/gorm"
)

// OIDCSession represents an OIDC authentication session linked to a specific node
type OIDCSession struct {
	gorm.Model

	// Core relationships
	NodeID NodeID `gorm:"not null;uniqueIndex"`
	Node   Node   `gorm:"constraint:OnDelete:CASCADE;"`

	// Session identification
	SessionID      string         `gorm:"uniqueIndex;not null"`
	RegistrationID RegistrationID `gorm:"not null"` // For reusing HandleNodeFromAuthPath

	// Token data
	RefreshToken string `gorm:"type:text"` //TODO: Encrypt?

	// Token lifecycle
	TokenExpiry     *time.Time `gorm:"index"`
	LastRefreshedAt *time.Time
	RefreshCount    int `gorm:"default:0"`

	// Session state
	IsActive   bool `gorm:"default:true;index"`
	LastSeenAt *time.Time
}

func (s *OIDCSession) TableName() string {
	return "oidc_sessions"
}

// IsExpired checks if the session's token has expired
func (s *OIDCSession) IsExpired() bool {
	return s.TokenExpiry != nil && s.TokenExpiry.Before(time.Now())
}

// IsExpiringSoon checks if the session's token will expire within the given duration
func (s *OIDCSession) IsExpiringSoon(duration time.Duration) bool {
	return s.TokenExpiry != nil && s.TokenExpiry.Before(time.Now().Add(duration))
}

// Deactivate marks the session as inactive
func (s *OIDCSession) Deactivate() {
	s.IsActive = false
}

// UpdateLastSeen updates the last seen timestamp
func (s *OIDCSession) UpdateLastSeen() {
	now := time.Now()
	s.LastSeenAt = &now
}
