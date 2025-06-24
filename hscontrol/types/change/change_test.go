package change

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test node constructor functions
func TestNodeConstructors(t *testing.T) {
	nodeID := NodeID(123)
	
	tests := []struct {
		name     string
		fn       func(NodeID) Change
		expected func(Change) bool
	}{
		{"NodeOnline", NodeOnline, func(c Change) bool { return c.Node.Online && c.Node.ID == nodeID }},
		{"NodeOffline", NodeOffline, func(c Change) bool { return c.Node.Offline && c.Node.ID == nodeID }},
		{"NodeAdded", NodeAdded, func(c Change) bool { return c.Node.NewNode && c.Node.ID == nodeID }},
		{"NodeRemoved", NodeRemoved, func(c Change) bool { return c.Node.RemovedNode && c.Node.ID == nodeID }},
		{"NodeKeyChanged", NodeKeyChanged, func(c Change) bool { return c.Node.KeyChanged && c.Node.ID == nodeID }},
		{"NodeTagsChanged", NodeTagsChanged, func(c Change) bool { return c.Node.TagsChanged && c.Node.ID == nodeID }},
		{"NodeRoutesChanged", NodeRoutesChanged, func(c Change) bool { return c.Node.RoutesChanged && c.Node.ID == nodeID }},
		{"NodeExpiryChanged", NodeExpiryChanged, func(c Change) bool { return c.Node.ExpiryChanged && c.Node.ID == nodeID }},
		{"NodeHostinfoChanged", NodeHostinfoChanged, func(c Change) bool { return c.Node.HostinfoChanged && c.Node.ID == nodeID }},
		{"NodeFullUpdate", NodeFullUpdate, func(c Change) bool { return c.Node.FullChange && c.Node.ID == nodeID }},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := tt.fn(nodeID)
			if !tt.expected(c) {
				t.Errorf("%s failed to set expected fields", tt.name)
			}
			if !c.HasChange() {
				t.Errorf("%s should indicate a change occurred", tt.name)
			}
		})
	}
}

// Test user constructor functions
func TestUserConstructors(t *testing.T) {
	userID := UserID(456)
	
	tests := []struct {
		name     string
		fn       func(UserID) Change
		expected func(Change) bool
	}{
		{"UserAdded", UserAdded, func(c Change) bool { return c.User.NewUser && c.User.ID == userID }},
		{"UserRemoved", UserRemoved, func(c Change) bool { return c.User.RemovedUser && c.User.ID == userID }},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := tt.fn(userID)
			if !tt.expected(c) {
				t.Errorf("%s failed to set expected fields", tt.name)
			}
			if !c.HasChange() {
				t.Errorf("%s should indicate a change occurred", tt.name)
			}
		})
	}
}

// Test system constructor functions
func TestSystemConstructors(t *testing.T) {
	tests := []struct {
		name     string
		fn       func() Change
		expected func(Change) bool
	}{
		{"FullUpdate", FullUpdate, func(c Change) bool { return c.Full }},
		{"DERPUpdate", DERPUpdate, func(c Change) bool { return c.DERPChanged }},
		{"PolicyUpdate", PolicyUpdate, func(c Change) bool { return c.PolicyChanged }},
		{"ExtraRecordsUpdate", ExtraRecordsUpdate, func(c Change) bool { return c.ExtraRecordsChanged }},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := tt.fn()
			if !tt.expected(c) {
				t.Errorf("%s failed to set expected fields", tt.name)
			}
			if !c.HasChange() {
				t.Errorf("%s should indicate a change occurred", tt.name)
			}
		})
	}
}

// Test merge functionality
func TestMerge(t *testing.T) {
	nodeID1 := NodeID(123)
	nodeID2 := NodeID(456)
	userID1 := UserID(789)
	
	// Test merging same node changes
	c1 := NodeOnline(nodeID1)
	c2 := NodeRoutesChanged(nodeID1)
	merged := c1.Merge(c2)
	
	if !merged.Node.Online || !merged.Node.RoutesChanged {
		t.Error("Merge should combine node changes for same ID")
	}
	if merged.Node.ID != nodeID1 {
		t.Error("Merge should preserve node ID")
	}
	
	// Test merging different node changes (should keep first ID)
	c3 := NodeOnline(nodeID1)
	c4 := NodeOffline(nodeID2)
	merged2 := c3.Merge(c4)
	
	if merged2.Node.ID != nodeID1 {
		t.Error("Merge should keep first non-zero node ID")
	}
	
	// Test merging system changes
	c5 := DERPUpdate()
	c6 := PolicyUpdate()
	merged3 := c5.Merge(c6)
	
	if !merged3.DERPChanged || !merged3.PolicyChanged {
		t.Error("Merge should combine system changes")
	}
	
	// Test merging node and user changes
	c7 := NodeOnline(nodeID1)
	c8 := UserAdded(userID1)
	merged4 := c7.Merge(c8)
	
	if !merged4.Node.Online || !merged4.User.NewUser {
		t.Error("Merge should combine node and user changes")
	}
}

// Test builder pattern (Set methods)
func TestSetMethods(t *testing.T) {
	nodeID := NodeID(123)
	userID := UserID(456)
	
	// Test chaining node set methods
	c := Change{}.
		SetOnline(nodeID).
		SetRoutesChanged(nodeID)
	
	if !c.Node.Online || !c.Node.RoutesChanged {
		t.Error("Set methods should chain and set multiple fields")
	}
	if c.Node.ID != nodeID {
		t.Error("Set methods should set node ID")
	}
	
	// Test system set methods
	c2 := Change{}.
		SetDERPChanged().
		SetPolicyChanged()
	
	if !c2.DERPChanged || !c2.PolicyChanged {
		t.Error("System set methods should chain and set multiple fields")
	}
	
	// Test mixing set methods
	c3 := Change{}.
		SetOnline(nodeID).
		SetNewUser(userID).
		SetFull()
	
	if !c3.Node.Online || !c3.User.NewUser || !c3.Full {
		t.Error("Mixed set methods should work together")
	}
}

// Test HasChange function with table-driven tests
func TestHasChange(t *testing.T) {
	nodeID := NodeID(123)
	userID := UserID(456)

	tests := []struct {
		name     string
		change   Change
		expected bool
	}{
		{
			name:     "Zero value should have no change",
			change:   Change{},
			expected: false,
		},
		{
			name:     "None should have no change",
			change:   None,
			expected: false,
		},
		{
			name:     "Full change should be detected",
			change:   Change{Full: true},
			expected: true,
		},
		{
			name:     "DERP change should be detected",
			change:   Change{DERPChanged: true},
			expected: true,
		},
		{
			name:     "Policy change should be detected",
			change:   Change{PolicyChanged: true},
			expected: true,
		},
		{
			name:     "ExtraRecords change should be detected",
			change:   Change{ExtraRecordsChanged: true},
			expected: true,
		},
		{
			name:     "Node change with ID only should be detected",
			change:   Change{Node: NodeChange{ID: nodeID}},
			expected: true,
		},
		{
			name:     "Node change with boolean field should be detected",
			change:   Change{Node: NodeChange{Online: true}},
			expected: true,
		},
		{
			name:     "User change with ID only should be detected",
			change:   Change{User: UserChange{ID: userID}},
			expected: true,
		},
		{
			name:     "User change with boolean field should be detected",
			change:   Change{User: UserChange{NewUser: true}},
			expected: true,
		},
		{
			name: "Multiple changes should be detected",
			change: Change{
				Full:                true,
				DERPChanged:         true,
				Node:                NodeChange{ID: nodeID, Online: true},
				User:                UserChange{ID: userID, NewUser: true},
				PolicyChanged:       true,
				ExtraRecordsChanged: true,
			},
			expected: true,
		},
		{
			name: "Empty nested structs should have no change",
			change: Change{
				Node: NodeChange{},
				User: UserChange{},
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.change.HasChange()
			assert.Equal(t, tt.expected, result, "HasChange() result mismatch")
			
			if diff := cmp.Diff(tt.expected, result); diff != "" {
				t.Errorf("HasChange() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// Test NeedsFullUpdate logic
func TestNeedsFullUpdate(t *testing.T) {
	nodeID := NodeID(123)
	userID := UserID(456)
	
	// Full flag should trigger full update
	c := FullUpdate()
	if !c.NeedsFullUpdate() {
		t.Error("FullUpdate should need full update")
	}
	
	// Important node changes should trigger full update
	importantChanges := []func(NodeID) Change{
		NodeAdded,
		NodeKeyChanged,
		NodeTagsChanged,
	}
	
	for _, fn := range importantChanges {
		c := fn(nodeID)
		if !c.NeedsFullUpdate() {
			t.Errorf("Important node change should need full update")
		}
	}
	
	// User changes should trigger full update
	userChanges := []func(UserID) Change{
		UserAdded,
		UserRemoved,
	}
	
	for _, fn := range userChanges {
		c := fn(userID)
		if !c.NeedsFullUpdate() {
			t.Errorf("User change should need full update")
		}
	}
	
	// Non-important node changes should not trigger full update
	c = NodeOnline(nodeID)
	if c.NeedsFullUpdate() {
		t.Error("NodeOnline alone should not need full update")
	}
}

// Test OnlyKeyChange logic
func TestOnlyKeyChange(t *testing.T) {
	nodeID := NodeID(123)
	
	// Only key change should return true
	c := NodeKeyChanged(nodeID)
	if !c.Node.OnlyKeyChange() {
		t.Error("Only key change should return true for OnlyKeyChange")
	}
	
	// Key change with other changes should return false
	c = NodeKeyChanged(nodeID).Merge(NodeTagsChanged(nodeID))
	if c.Node.OnlyKeyChange() {
		t.Error("Key change with other changes should not return true for OnlyKeyChange")
	}
	
	// No key change should return false
	c = NodeOnline(nodeID)
	if c.Node.OnlyKeyChange() {
		t.Error("Non-key change should not return true for OnlyKeyChange")
	}
}

// Test ImportantChange logic
func TestImportantChange(t *testing.T) {
	nodeID := NodeID(123)
	
	importantChanges := []func(NodeID) Change{
		NodeAdded,
		NodeKeyChanged,
		NodeTagsChanged,
	}
	
	for _, fn := range importantChanges {
		c := fn(nodeID)
		if !c.Node.ImportantChange() {
			t.Error("Important change should return true for ImportantChange")
		}
	}
	
	// Non-important changes
	c := NodeOnline(nodeID)
	if c.Node.ImportantChange() {
		t.Error("NodeOnline should not be important change")
	}
}

// Test edge cases
func TestEdgeCases(t *testing.T) {
	// Merging with None should preserve the change
	c1 := NodeOnline(NodeID(123))
	merged := c1.Merge(None)
	if !merged.Node.Online {
		t.Error("Merging with None should preserve original change")
	}
	
	// Merging None with change should preserve the change
	merged2 := None.Merge(c1)
	if !merged2.Node.Online {
		t.Error("Merging None with change should preserve the change")
	}
	
	// Multiple merges should accumulate
	c2 := NodeOffline(NodeID(123))
	c3 := NodeRoutesChanged(NodeID(123))
	final := c1.Merge(c2).Merge(c3)
	
	if !final.Node.Online || !final.Node.Offline || !final.Node.RoutesChanged {
		t.Error("Multiple merges should accumulate all changes")
	}
}

// Test NodeChange hasChange method
func TestNodeChangeHasChange(t *testing.T) {
	nodeID := NodeID(123)

	tests := []struct {
		name     string
		change   NodeChange
		expected bool
	}{
		{
			name:     "Empty NodeChange should have no change",
			change:   NodeChange{},
			expected: false,
		},
		{
			name:     "NodeChange with ID only should have change",
			change:   NodeChange{ID: nodeID},
			expected: true,
		},
		{
			name:     "NodeChange with FullChange should have change",
			change:   NodeChange{FullChange: true},
			expected: true,
		},
		{
			name:     "NodeChange with ExpiryChanged should have change",
			change:   NodeChange{ExpiryChanged: true},
			expected: true,
		},
		{
			name:     "NodeChange with RoutesChanged should have change",
			change:   NodeChange{RoutesChanged: true},
			expected: true,
		},
		{
			name:     "NodeChange with Online should have change",
			change:   NodeChange{Online: true},
			expected: true,
		},
		{
			name:     "NodeChange with Offline should have change",
			change:   NodeChange{Offline: true},
			expected: true,
		},
		{
			name:     "NodeChange with HostinfoChanged should have change",
			change:   NodeChange{HostinfoChanged: true},
			expected: true,
		},
		{
			name:     "NodeChange with NewNode should have change",
			change:   NodeChange{NewNode: true},
			expected: true,
		},
		{
			name:     "NodeChange with RemovedNode should have change",
			change:   NodeChange{RemovedNode: true},
			expected: true,
		},
		{
			name:     "NodeChange with KeyChanged should have change",
			change:   NodeChange{KeyChanged: true},
			expected: true,
		},
		{
			name:     "NodeChange with TagsChanged should have change",
			change:   NodeChange{TagsChanged: true},
			expected: true,
		},
		{
			name: "NodeChange with multiple fields should have change",
			change: NodeChange{
				ID:              nodeID,
				FullChange:      true,
				ExpiryChanged:   true,
				RoutesChanged:   true,
				Online:          true,
				Offline:         true,
				HostinfoChanged: true,
				NewNode:         true,
				RemovedNode:     true,
				KeyChanged:      true,
				TagsChanged:     true,
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.change.hasChange()
			require.Equal(t, tt.expected, result, "hasChange() result mismatch")
			
			if diff := cmp.Diff(tt.expected, result); diff != "" {
				t.Errorf("hasChange() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// Test UserChange hasChange method
func TestUserChangeHasChange(t *testing.T) {
	userID := UserID(456)

	tests := []struct {
		name     string
		change   UserChange
		expected bool
	}{
		{
			name:     "Empty UserChange should have no change",
			change:   UserChange{},
			expected: false,
		},
		{
			name:     "UserChange with ID only should have change",
			change:   UserChange{ID: userID},
			expected: true,
		},
		{
			name:     "UserChange with NewUser should have change",
			change:   UserChange{NewUser: true},
			expected: true,
		},
		{
			name:     "UserChange with RemovedUser should have change",
			change:   UserChange{RemovedUser: true},
			expected: true,
		},
		{
			name: "UserChange with multiple fields should have change",
			change: UserChange{
				ID:          userID,
				NewUser:     true,
				RemovedUser: true,
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.change.hasChange()
			require.Equal(t, tt.expected, result, "hasChange() result mismatch")
			
			if diff := cmp.Diff(tt.expected, result); diff != "" {
				t.Errorf("hasChange() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}