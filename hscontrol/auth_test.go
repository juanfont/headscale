package hscontrol

import (
	"net/http"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/juanfont/headscale/hscontrol/types"
)

func TestCanUsePreAuthKey(t *testing.T) {
	now := time.Now()
	past := now.Add(-time.Hour)
	future := now.Add(time.Hour)

	tests := []struct {
		name    string
		pak     *types.PreAuthKey
		wantErr bool
		err     HTTPError
	}{
		{
			name: "valid reusable key",
			pak: &types.PreAuthKey{
				Reusable:   true,
				Used:       false,
				Expiration: &future,
			},
			wantErr: false,
		},
		{
			name: "valid non-reusable key",
			pak: &types.PreAuthKey{
				Reusable:   false,
				Used:       false,
				Expiration: &future,
			},
			wantErr: false,
		},
		{
			name: "expired key",
			pak: &types.PreAuthKey{
				Reusable:   false,
				Used:       false,
				Expiration: &past,
			},
			wantErr: true,
			err:     NewHTTPError(http.StatusUnauthorized, "authkey expired", nil),
		},
		{
			name: "used non-reusable key",
			pak: &types.PreAuthKey{
				Reusable:   false,
				Used:       true,
				Expiration: &future,
			},
			wantErr: true,
			err:     NewHTTPError(http.StatusUnauthorized, "authkey already used", nil),
		},
		{
			name: "used reusable key",
			pak: &types.PreAuthKey{
				Reusable:   true,
				Used:       true,
				Expiration: &future,
			},
			wantErr: false,
		},
		{
			name: "no expiration date",
			pak: &types.PreAuthKey{
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
			err:     NewHTTPError(http.StatusUnauthorized, "invalid authkey", nil),
		},
		{
			name: "expired and used key",
			pak: &types.PreAuthKey{
				Reusable:   false,
				Used:       true,
				Expiration: &past,
			},
			wantErr: true,
			err:     NewHTTPError(http.StatusUnauthorized, "authkey expired", nil),
		},
		{
			name: "no expiration and used key",
			pak: &types.PreAuthKey{
				Reusable:   false,
				Used:       true,
				Expiration: nil,
			},
			wantErr: true,
			err:     NewHTTPError(http.StatusUnauthorized, "authkey already used", nil),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := canUsePreAuthKey(tt.pak)
			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error but got none")
				} else {
					httpErr, ok := err.(HTTPError)
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
