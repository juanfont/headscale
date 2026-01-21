package db

import (
	"errors"
	"os"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// SetPolicy sets the policy in the database.
func (hsdb *HSDatabase) SetPolicy(policy string) (*types.Policy, error) {
	// Create a new policy.
	p := types.Policy{
		Data: policy,
	}

	if err := hsdb.DB.Clauses(clause.Returning{}).Create(&p).Error; err != nil {
		return nil, err
	}

	return &p, nil
}

// GetPolicy returns the latest policy in the database.
func (hsdb *HSDatabase) GetPolicy() (*types.Policy, error) {
	return GetPolicy(hsdb.DB)
}

// GetPolicy returns the latest policy from the database.
// This standalone function can be used in contexts where HSDatabase is not available,
// such as during migrations.
func GetPolicy(tx *gorm.DB) (*types.Policy, error) {
	var p types.Policy

	// Query:
	// SELECT * FROM policies ORDER BY id DESC LIMIT 1;
	err := tx.
		Order("id DESC").
		Limit(1).
		First(&p).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, types.ErrPolicyNotFound
		}

		return nil, err
	}

	return &p, nil
}

// PolicyBytes loads policy configuration from file or database based on the configured mode.
// Returns nil if no policy is configured, which is valid.
// This standalone function can be used in contexts where HSDatabase is not available,
// such as during migrations.
func PolicyBytes(tx *gorm.DB, cfg *types.Config) ([]byte, error) {
	switch cfg.Policy.Mode {
	case types.PolicyModeFile:
		path := cfg.Policy.Path

		// It is fine to start headscale without a policy file.
		if len(path) == 0 {
			return nil, nil
		}

		absPath := util.AbsolutePathFromConfigPath(path)

		return os.ReadFile(absPath)

	case types.PolicyModeDB:
		p, err := GetPolicy(tx)
		if err != nil {
			if errors.Is(err, types.ErrPolicyNotFound) {
				return nil, nil
			}

			return nil, err
		}

		if p.Data == "" {
			return nil, nil
		}

		return []byte(p.Data), nil
	}

	return nil, nil
}
