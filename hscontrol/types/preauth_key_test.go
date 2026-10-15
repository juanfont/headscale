package types

import (
	"errors"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"
)

func TestCanUsePreAuthKey(t *testing.T) {
	now := time.Now()
	past := now.Add(-time.Hour)
	future := now.Add(time.Hour)

	tests := []struct {
		name string
		pak  *PreAuthKey
		// at, when set, checks ValidAt(at) instead of Validate.
		at      time.Time
		wantErr bool
		err     PAKError
	}{
		{
			name: "valid at the instant of expiration",
			pak: &PreAuthKey{
				Reusable:   true,
				Expiration: &now,
			},
			at:      now,
			wantErr: false,
		},
		{
			name: "expired one nanosecond after expiration",
			pak: &PreAuthKey{
				Reusable:   true,
				Expiration: &now,
			},
			at:      now.Add(time.Nanosecond),
			wantErr: true,
			err:     PAKError("authkey expired"),
		},
		{
			name: "valid reusable key",
			pak: &PreAuthKey{
				Reusable:   true,
				Used:       false,
				Expiration: &future,
			},
			wantErr: false,
		},
		{
			name: "valid non-reusable key",
			pak: &PreAuthKey{
				Reusable:   false,
				Used:       false,
				Expiration: &future,
			},
			wantErr: false,
		},
		{
			name: "expired key",
			pak: &PreAuthKey{
				Reusable:   false,
				Used:       false,
				Expiration: &past,
			},
			wantErr: true,
			err:     PAKError("authkey expired"),
		},
		{
			name: "used non-reusable key",
			pak: &PreAuthKey{
				Reusable:   false,
				Used:       true,
				Expiration: &future,
			},
			wantErr: true,
			err:     PAKError("authkey already used"),
		},
		{
			name: "used reusable key",
			pak: &PreAuthKey{
				Reusable:   true,
				Used:       true,
				Expiration: &future,
			},
			wantErr: false,
		},
		{
			name: "no expiration date",
			pak: &PreAuthKey{
				Reusable:   false,
				Used:       false,
				Expiration: nil,
			},
			wantErr: false,
		},
		{
			name:    "nil preauth key",
			pak:     nil,
			wantErr: true,
			err:     PAKError("invalid authkey"),
		},
		{
			name: "expired and used key",
			pak: &PreAuthKey{
				Reusable:   false,
				Used:       true,
				Expiration: &past,
			},
			wantErr: true,
			err:     PAKError("authkey expired"),
		},
		{
			name: "no expiration and used key",
			pak: &PreAuthKey{
				Reusable:   false,
				Used:       true,
				Expiration: nil,
			},
			wantErr: true,
			err:     PAKError("authkey already used"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var err error
			if tt.at.IsZero() {
				err = tt.pak.Validate()
				if diff := cmp.Diff(err, tt.pak.ValidAt(time.Now())); diff != "" {
					t.Errorf("Validate and ValidAt(now) disagree (-Validate +ValidAt):\n%s", diff)
				}
			} else {
				err = tt.pak.ValidAt(tt.at)
			}

			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error but got none")
				} else {
					httpErr, ok := errors.AsType[PAKError](err)
					if !ok {
						t.Errorf("expected HTTPError but got %T", err)
					} else {
						if diff := cmp.Diff(tt.err, httpErr); diff != "" {
							t.Errorf("unexpected error (-want +got):\n%s", diff)
						}
					}
				}
			} else {
				if err != nil {
					t.Errorf("expected no error but got %v", err)
				}
			}
		})
	}
}

func TestPreAuthKeyUsername(t *testing.T) {
	user := &User{Name: "creator", Email: "creator@example.com"}
	for _, pak := range []*PreAuthKey{
		{User: user},
		{User: user, Tags: []string{"tag:server"}},
	} {
		require.Equal(t, user.Username(), pak.Username())
	}

	require.Equal(t, TaggedDevices.Name, (&PreAuthKey{Tags: []string{"tag:server"}}).Username())
}

func TestPreAuthKeyTagChanges(t *testing.T) {
	keyID := uint64(1)
	userID := uint(1)
	pak := &PreAuthKey{ID: keyID, Tags: []string{"tag:original"}, User: &User{ID: userID}}

	userNode := (&Node{ID: 1, UserID: &userID}).View()
	require.True(t, pak.ConvertsNodeToTagged(userNode))
	require.False(t, pak.RetagsNode(userNode))

	// An admin changed the tags, but the key identity is unchanged. The
	// creator's UserID does not make this tagged node user-owned.
	taggedNode := (&Node{
		ID: 1, Tags: []string{"tag:admin"}, AuthKeyID: &keyID, UserID: &userID,
	}).View()
	require.False(t, pak.ConvertsNodeToTagged(taggedNode))
	require.False(t, pak.RetagsNode(taggedNode))

	otherKey := &PreAuthKey{ID: 2, Tags: []string{"tag:replacement"}}
	require.True(t, otherKey.RetagsNode(taggedNode))
	require.False(t, otherKey.ConvertsNodeToTagged(taggedNode))
	require.True(t, pak.RetagsNode((&Node{ID: 1, Tags: []string{"tag:admin"}}).View()))

	userKey := &PreAuthKey{User: &User{ID: userID}}
	require.False(t, userKey.ConvertsNodeToTagged(userNode))
	require.False(t, userKey.RetagsNode(taggedNode))
	require.False(t, pak.ConvertsNodeToTagged(NodeView{}))
	require.False(t, pak.RetagsNode(NodeView{}))
}
