package state

import (
	"errors"
	"fmt"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/rs/zerolog/log"
)

var (
	// ErrNodeMarkedTaggedButHasNoTags is returned when a node is marked as tagged but has no tags.
	ErrNodeMarkedTaggedButHasNoTags = errors.New("node marked as tagged but has no tags")

	// ErrNodeHasNeitherUserNorTags is returned when a node has neither a user nor tags.
	ErrNodeHasNeitherUserNorTags = errors.New("node has neither user nor tags - must be owned by user or tagged")

	// ErrRequestedTagsInvalidOrNotPermitted is returned when requested tags are invalid or not permitted.
	// This message format matches Tailscale SaaS: "requested tags [tag:xxx] are invalid or not permitted".
	ErrRequestedTagsInvalidOrNotPermitted = errors.New("requested tags")
)

// ErrTaggedNodeHasUser is returned when a tagged node has a UserID set.
var ErrTaggedNodeHasUser = errors.New("tagged node must not have user_id set")

// validateNodeOwnership ensures proper node ownership model.
// A node must be either user-owned or tagged, and these are mutually exclusive:
// tagged nodes must not have a UserID, and user-owned nodes must not have tags.
func validateNodeOwnership(node *types.Node) error {
	if node.IsTagged() {
		if len(node.Tags) == 0 {
			return fmt.Errorf("%w: %q", ErrNodeMarkedTaggedButHasNoTags, node.Hostname)
		}

		if node.UserID != nil {
			return fmt.Errorf("%w: %q", ErrTaggedNodeHasUser, node.Hostname)
		}

		return nil
	}

	// User-owned nodes must have a UserID.
	if node.UserID == nil {
		return fmt.Errorf("%w: %q", ErrNodeHasNeitherUserNorTags, node.Hostname)
	}

	return nil
}

// logTagOperation logs tag assignment operations for audit purposes.
func logTagOperation(existingNode types.NodeView, newTags []string) {
	if existingNode.IsTagged() {
		log.Info().
			EmbedObject(existingNode).
			Strs("old.tags", existingNode.Tags().AsSlice()).
			Strs("new.tags", newTags).
			Msg("Updating tags on already-tagged node")
	} else {
		var userID uint
		if existingNode.UserID().Valid() {
			userID = existingNode.UserID().Get()
		}

		log.Info().
			EmbedObject(existingNode).
			Uint("previous.user", userID).
			Strs("new.tags", newTags).
			Msg("Converting user-owned node to tagged node")
	}
}
