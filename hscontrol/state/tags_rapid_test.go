package state

import (
	"errors"
	"testing"

	"github.com/juanfont/headscale/hscontrol/types"
	"pgregory.net/rapid"
)

// ============================================================================
// Generators
// ============================================================================

// genNonEmptyTags generates a slice of 1..maxLen unique "tag:name" tags.
func genNonEmptyTags(maxLen int) *rapid.Generator[[]string] {
	return rapid.Custom[[]string](func(t *rapid.T) []string {
		n := rapid.IntRange(1, maxLen).Draw(t, "numTags")
		seen := make(map[string]bool, n)

		result := make([]string, 0, n)
		for len(result) < n {
			tag := genTag().Draw(t, "tag")
			if !seen[tag] {
				seen[tag] = true
				result = append(result, tag)
			}
		}

		return result
	})
}

// ============================================================================
// validateNodeOwnership: 4-quadrant property tests
// ============================================================================

// Quadrant 1: tagged node + no UserID -> ok.
func TestRapid_ValidateNodeOwnership_TaggedNoUser_OK(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		tags := genNonEmptyTags(5).Draw(t, "tags")
		hostname := rapid.StringMatching(`[a-z][a-z0-9]{2,10}`).Draw(t, "hostname")

		node := &types.Node{
			Hostname: hostname,
			Tags:     tags,
			UserID:   nil,
		}

		err := validateNodeOwnership(node)
		if err != nil {
			t.Fatalf("tagged node without UserID should be valid, got: %v", err)
		}
	})
}

// Quadrant 2: tagged node + UserID set -> error (ErrTaggedNodeHasUser).
func TestRapid_ValidateNodeOwnership_TaggedWithUser_Error(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		tags := genNonEmptyTags(5).Draw(t, "tags")
		uid := genUserID().Draw(t, "uid")
		hostname := rapid.StringMatching(`[a-z][a-z0-9]{2,10}`).Draw(t, "hostname")

		node := &types.Node{
			Hostname: hostname,
			Tags:     tags,
			UserID:   &uid,
		}

		err := validateNodeOwnership(node)
		if err == nil {
			t.Fatalf("tagged node with UserID should fail, but got nil")
		}

		if !errors.Is(err, ErrTaggedNodeHasUser) {
			t.Fatalf("expected ErrTaggedNodeHasUser, got: %v", err)
		}
	})
}

// Quadrant 3: not tagged + no UserID -> error (ErrNodeHasNeitherUserNorTags).
func TestRapid_ValidateNodeOwnership_UntaggedNoUser_Error(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		hostname := rapid.StringMatching(`[a-z][a-z0-9]{2,10}`).Draw(t, "hostname")

		node := &types.Node{
			Hostname: hostname,
			Tags:     nil,
			UserID:   nil,
		}

		err := validateNodeOwnership(node)
		if err == nil {
			t.Fatal("untagged node without UserID should fail, but got nil")
		}

		if !errors.Is(err, ErrNodeHasNeitherUserNorTags) {
			t.Fatalf("expected ErrNodeHasNeitherUserNorTags, got: %v", err)
		}
	})
}

// Quadrant 4: not tagged + UserID set -> ok.
func TestRapid_ValidateNodeOwnership_UntaggedWithUser_OK(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		uid := genUserID().Draw(t, "uid")
		hostname := rapid.StringMatching(`[a-z][a-z0-9]{2,10}`).Draw(t, "hostname")

		node := &types.Node{
			Hostname: hostname,
			Tags:     nil,
			UserID:   &uid,
		}

		err := validateNodeOwnership(node)
		if err != nil {
			t.Fatalf("untagged node with UserID should be valid, got: %v", err)
		}
	})
}

// Property: validateNodeOwnership always returns nil xor an error for any
// combination of tags and userID. This tests that all 4 quadrants are covered
// exhaustively and there are no panics.
func TestRapid_ValidateNodeOwnership_NoPanic(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		tags := genTags(5).Draw(t, "tags")
		hasUser := rapid.Bool().Draw(t, "hasUser")
		hostname := rapid.StringMatching(`[a-z][a-z0-9]{2,10}`).Draw(t, "hostname")

		var userID *uint

		if hasUser {
			uid := genUserID().Draw(t, "uid")
			userID = &uid
		}

		node := &types.Node{
			Hostname: hostname,
			Tags:     tags,
			UserID:   userID,
		}

		// Should not panic
		err := validateNodeOwnership(node)

		isTagged := len(tags) > 0
		hasUID := userID != nil

		switch {
		case isTagged && !hasUID:
			if err != nil {
				t.Fatalf("tagged+noUser should be ok, got: %v", err)
			}
		case isTagged && hasUID:
			if !errors.Is(err, ErrTaggedNodeHasUser) {
				t.Fatalf("tagged+user should be ErrTaggedNodeHasUser, got: %v", err)
			}
		case !isTagged && !hasUID:
			if !errors.Is(err, ErrNodeHasNeitherUserNorTags) {
				t.Fatalf("untagged+noUser should be ErrNodeHasNeitherUserNorTags, got: %v", err)
			}
		case !isTagged && hasUID:
			if err != nil {
				t.Fatalf("untagged+user should be ok, got: %v", err)
			}
		}
	})
}

// Property: tagged nodes with empty Tags slice (but IsTagged checks len > 0)
// are actually not tagged, so they fall into the "untagged" path.
func TestRapid_ValidateNodeOwnership_EmptyTagsEqualsUntagged(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		uid := genUserID().Draw(t, "uid")
		hostname := rapid.StringMatching(`[a-z][a-z0-9]{2,10}`).Draw(t, "hostname")

		node := &types.Node{
			Hostname: hostname,
			Tags:     []string{},
			UserID:   &uid,
		}

		// Empty tags = not tagged, so user-owned node with UserID should be valid.
		err := validateNodeOwnership(node)
		if err != nil {
			t.Fatalf("empty tags + UserID should be valid (user-owned), got: %v", err)
		}

		// Empty tags + no UserID should fail.
		nodeNoUser := &types.Node{
			Hostname: hostname,
			Tags:     []string{},
			UserID:   nil,
		}

		err = validateNodeOwnership(nodeNoUser)
		if !errors.Is(err, ErrNodeHasNeitherUserNorTags) {
			t.Fatalf("empty tags + no UserID should be ErrNodeHasNeitherUserNorTags, got: %v", err)
		}
	})
}
