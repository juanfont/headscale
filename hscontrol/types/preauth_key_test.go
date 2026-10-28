package types

import (
	"errors"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/stretchr/testify/require"
)

func TestCanUsePreAuthKey(t *testing.T) {
	now := time.Now()
	past := now.Add(-time.Hour)
	future := now.Add(time.Hour)

	tests := []struct {
		name    string
		pak     *PreAuthKey
		wantErr bool
		err     PAKError
	}{
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
			err := tt.pak.Validate()
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

func TestPreAuthKeyCanReauthenticate(t *testing.T) {
	owner, other := uint(1), uint(2)
	userNode := (&Node{ID: 1, UserID: &owner}).View()

	// An admin tagged a node its user joined with a user key.
	taggedByUserKey := (&Node{
		ID: 1, Tags: []string{"tag:prod"}, RegisterMethod: util.RegisterMethodAuthKey,
		AuthKey: &PreAuthKey{ID: 10, UserID: &owner},
	}).View()
	// A user made the tagged key the node joined with.
	taggedByTaggedKey := (&Node{
		ID: 1, Tags: []string{"tag:prod"}, RegisterMethod: util.RegisterMethodAuthKey,
		AuthKey: &PreAuthKey{ID: 10, UserID: &owner, Tags: []string{"tag:prod"}},
	}).View()
	// A node registered by login records no user.
	taggedByLogin := (&Node{
		ID: 1, Tags: []string{"tag:prod"}, RegisterMethod: util.RegisterMethodOIDC,
	}).View()

	userKey := func(id uint) *PreAuthKey { return &PreAuthKey{ID: 11, User: &User{ID: id}} }
	taggedKey := &PreAuthKey{Tags: []string{"tag:ci"}}

	for _, tt := range []struct {
		name string
		pak  *PreAuthKey
		node NodeView
		want bool
	}{
		{"tagged key converts", taggedKey, userNode, true},
		{"tagged key retags", taggedKey, taggedByTaggedKey, true},
		{"same user", userKey(owner), userNode, true},
		{"other user", userKey(other), userNode, false},
		{"former owner after admin tagging", userKey(owner), taggedByUserKey, true},
		{"other user on admin-tagged node", userKey(other), taggedByUserKey, false},
		{"tagged key creator", userKey(owner), taggedByTaggedKey, true},
		{"other user on tagged key node", userKey(other), taggedByTaggedKey, false},
		{"node registered by login", userKey(owner), taggedByLogin, false},
		{"no owner", &PreAuthKey{ID: 11}, userNode, false},
		{"invalid node", taggedKey, NodeView{}, false},
		{"nil key", nil, userNode, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, tt.pak.CanReauthenticate(tt.node))
		})
	}
}
