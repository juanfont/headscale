package state

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/rs/zerolog/log"
)

var (
	// ErrNodeMarkedTaggedButHasNoTags is returned when a node is marked as tagged but has no tags.
	ErrNodeMarkedTaggedButHasNoTags = errors.New("node marked as tagged but has no tags")

	// ErrNodeHasNeitherUserNorTags is returned when a node has neither a user nor tags.
	ErrNodeHasNeitherUserNorTags = errors.New("node has neither user nor tags - must be owned by user or tagged")

	// ErrInvalidOrUnauthorizedTags is returned when tags are invalid or unauthorized.
	ErrInvalidOrUnauthorizedTags = errors.New("invalid or unauthorized tags")
)

// validateNodeOwnership ensures proper node ownership model.
// A node must be EITHER user-owned OR tagged (mutually exclusive by behavior).
// Tagged nodes CAN have a UserID for "created by" tracking, but the tag is the owner.
func validateNodeOwnership(node *types.Node) error {
	isTagged := node.IsTagged()

	// Tagged nodes: Must have tags, UserID is optional (just "created by")
	if isTagged {
		if len(node.Tags) == 0 {
			return fmt.Errorf("%w: %q", ErrNodeMarkedTaggedButHasNoTags, node.Hostname)
		}
		// UserID can be set (created by) or nil (orphaned), both valid for tagged nodes
		return nil
	}

	// User-owned nodes: Must have UserID, must NOT have tags
	if node.UserID == nil {
		return fmt.Errorf("%w: %q", ErrNodeHasNeitherUserNorTags, node.Hostname)
	}

	return nil
}

// validateAndNormalizeTags validates tags against policy and normalizes them.
// Returns validated and normalized tags, or an error if validation fails.
func (s *State) validateAndNormalizeTags(node *types.Node, requestedTags []string) ([]string, error) {
	if len(requestedTags) == 0 {
		return nil, nil
	}

	var (
		validTags   []string
		invalidTags []string
	)

	for _, tag := range requestedTags {
		// Validate format
		if !strings.HasPrefix(tag, "tag:") {
			invalidTags = append(invalidTags, tag)
			continue
		}

		// Validate against policy
		nodeView := node.View()
		if s.polMan.NodeCanHaveTag(nodeView, tag) {
			validTags = append(validTags, tag)
		} else {
			invalidTags = append(invalidTags, tag)
		}
	}

	if len(invalidTags) > 0 {
		return nil, fmt.Errorf("%w: %v", ErrInvalidOrUnauthorizedTags, invalidTags)
	}

	// Normalize: sort and deduplicate
	slices.Sort(validTags)

	return slices.Compact(validTags), nil
}

// logTagOperation logs tag assignment operations for audit purposes.
func logTagOperation(existingNode types.NodeView, newTags []string) {
	if existingNode.IsTagged() {
		log.Info().
			Uint64("node.id", existingNode.ID().Uint64()).
			Str("node.name", existingNode.Hostname()).
			Strs("old.tags", existingNode.Tags().AsSlice()).
			Strs("new.tags", newTags).
			Msg("Updating tags on already-tagged node")
	} else {
		var userID uint
		if existingNode.UserID().Valid() {
			userID = existingNode.UserID().Get()
		}

		log.Info().
			Uint64("node.id", existingNode.ID().Uint64()).
			Str("node.name", existingNode.Hostname()).
			Uint("created.by.user", userID).
			Strs("new.tags", newTags).
			Msg("Converting user-owned node to tagged node (irreversible)")
	}
}
