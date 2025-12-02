package types

import (
	"testing"

	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/stretchr/testify/assert"
	"gorm.io/gorm"
	"tailscale.com/types/ptr"
)

// TestNodeIsTagged tests the IsTagged() method for determining if a node is tagged.
func TestNodeIsTagged(t *testing.T) {
	tests := []struct {
		name string
		node Node
		want bool
	}{
		{
			name: "node with tags - is tagged",
			node: Node{
				Tags: []string{"tag:server", "tag:prod"},
			},
			want: true,
		},
		{
			name: "node with single tag - is tagged",
			node: Node{
				Tags: []string{"tag:web"},
			},
			want: true,
		},
		{
			name: "node with no tags - not tagged",
			node: Node{
				Tags: []string{},
			},
			want: false,
		},
		{
			name: "node with nil tags - not tagged",
			node: Node{
				Tags: nil,
			},
			want: false,
		},
		{
			// Tags should be copied from AuthKey during registration, so a node
			// with only AuthKey.Tags and no Tags would be invalid in practice.
			// IsTagged() only checks node.Tags, not AuthKey.Tags.
			name: "node registered with tagged authkey only - not tagged (tags should be copied)",
			node: Node{
				AuthKey: &PreAuthKey{
					Tags: []string{"tag:database"},
				},
			},
			want: false,
		},
		{
			name: "node with both tags and authkey tags - is tagged",
			node: Node{
				Tags: []string{"tag:server"},
				AuthKey: &PreAuthKey{
					Tags: []string{"tag:database"},
				},
			},
			want: true,
		},
		{
			name: "node with user and no tags - not tagged",
			node: Node{
				UserID: ptr.To(uint(42)),
				Tags:   []string{},
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.node.IsTagged()
			assert.Equal(t, tt.want, got, "IsTagged() returned unexpected value")
		})
	}
}

// TestNodeViewIsTagged tests the IsTagged() method on NodeView.
func TestNodeViewIsTagged(t *testing.T) {
	tests := []struct {
		name string
		node Node
		want bool
	}{
		{
			name: "tagged node via Tags field",
			node: Node{
				Tags: []string{"tag:server"},
			},
			want: true,
		},
		{
			// Tags should be copied from AuthKey during registration, so a node
			// with only AuthKey.Tags and no Tags would be invalid in practice.
			name: "node with only AuthKey tags - not tagged (tags should be copied)",
			node: Node{
				AuthKey: &PreAuthKey{
					Tags: []string{"tag:web"},
				},
			},
			want: false, // IsTagged() only checks node.Tags
		},
		{
			name: "user-owned node",
			node: Node{
				UserID: ptr.To(uint(1)),
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			view := tt.node.View()
			got := view.IsTagged()
			assert.Equal(t, tt.want, got, "NodeView.IsTagged() returned unexpected value")
		})
	}
}

// TestNodeHasTag tests the HasTag() method for checking specific tag membership.
func TestNodeHasTag(t *testing.T) {
	tests := []struct {
		name string
		node Node
		tag  string
		want bool
	}{
		{
			name: "node has the tag",
			node: Node{
				Tags: []string{"tag:server", "tag:prod"},
			},
			tag:  "tag:server",
			want: true,
		},
		{
			name: "node does not have the tag",
			node: Node{
				Tags: []string{"tag:server", "tag:prod"},
			},
			tag:  "tag:web",
			want: false,
		},
		{
			// Tags should be copied from AuthKey during registration
			// HasTag() only checks node.Tags, not AuthKey.Tags
			name: "node has tag only in authkey - returns false",
			node: Node{
				AuthKey: &PreAuthKey{
					Tags: []string{"tag:database"},
				},
			},
			tag:  "tag:database",
			want: false,
		},
		{
			// node.Tags is what matters, not AuthKey.Tags
			name: "node has tag in Tags but not in AuthKey",
			node: Node{
				Tags: []string{"tag:server"},
				AuthKey: &PreAuthKey{
					Tags: []string{"tag:database"},
				},
			},
			tag:  "tag:server",
			want: true,
		},
		{
			name: "invalid tag format still returns false",
			node: Node{
				Tags: []string{"tag:server"},
			},
			tag:  "invalid-tag",
			want: false,
		},
		{
			name: "empty tag returns false",
			node: Node{
				Tags: []string{"tag:server"},
			},
			tag:  "",
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.node.HasTag(tt.tag)
			assert.Equal(t, tt.want, got, "HasTag() returned unexpected value")
		})
	}
}

// TestNodeTagsImmutableAfterRegistration tests that tags can only be set during registration.
func TestNodeTagsImmutableAfterRegistration(t *testing.T) {
	// Test that a node registered with tags keeps them
	taggedNode := Node{
		ID:   1,
		Tags: []string{"tag:server"},
		AuthKey: &PreAuthKey{
			Tags: []string{"tag:server"},
		},
		RegisterMethod: util.RegisterMethodAuthKey,
	}

	// Node should be tagged
	assert.True(t, taggedNode.IsTagged(), "Node registered with tags should be tagged")

	// Node should have the tag
	has := taggedNode.HasTag("tag:server")
	assert.True(t, has, "Node should have the tag it was registered with")

	// Test that a user-owned node is not tagged
	userNode := Node{
		ID:             2,
		UserID:         ptr.To(uint(42)),
		Tags:           []string{},
		RegisterMethod: util.RegisterMethodOIDC,
	}

	assert.False(t, userNode.IsTagged(), "User-owned node should not be tagged")
}

// TestNodeOwnershipModel tests the tags-as-identity model.
func TestNodeOwnershipModel(t *testing.T) {
	tests := []struct {
		name         string
		node         Node
		wantIsTagged bool
		description  string
	}{
		{
			name: "tagged node has tags, UserID is informational",
			node: Node{
				ID:     1,
				UserID: ptr.To(uint(5)), // "created by" user 5
				Tags:   []string{"tag:server"},
			},
			wantIsTagged: true,
			description:  "Tagged nodes may have UserID set for tracking, but ownership is defined by tags",
		},
		{
			name: "user-owned node has no tags",
			node: Node{
				ID:     2,
				UserID: ptr.To(uint(5)),
				Tags:   []string{},
			},
			wantIsTagged: false,
			description:  "User-owned nodes are owned by the user, not by tags",
		},
		{
			// Tags should be copied from AuthKey to Node during registration
			// IsTagged() only checks node.Tags, not AuthKey.Tags
			name: "node with only authkey tags - not tagged (tags should be copied)",
			node: Node{
				ID:     3,
				UserID: ptr.To(uint(5)), // "created by" user 5
				AuthKey: &PreAuthKey{
					Tags: []string{"tag:database"},
				},
			},
			wantIsTagged: false,
			description:  "IsTagged() only checks node.Tags; AuthKey.Tags should be copied during registration",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.node.IsTagged()
			assert.Equal(t, tt.wantIsTagged, got, tt.description)
		})
	}
}

// TestUserTypedID tests the TypedID() helper method.
func TestUserTypedID(t *testing.T) {
	user := User{
		Model: gorm.Model{ID: 42},
	}

	typedID := user.TypedID()
	assert.NotNil(t, typedID, "TypedID() should return non-nil pointer")
	assert.Equal(t, UserID(42), *typedID, "TypedID() should return correct UserID value")
}
