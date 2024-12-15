package types

import (
	"encoding/json"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestUnmarshallOIDCClaims(t *testing.T) {
	tests := []struct {
		name    string
		jsonstr string
		want    OIDCClaims
	}{
		{
			name: "normal-bool",
			jsonstr: `
{
  "sub": "test",
  "email": "test@test.no",
  "email_verified": true
}
			`,
			want: OIDCClaims{
				Sub:           "test",
				Email:         "test@test.no",
				EmailVerified: true,
			},
		},
		{
			name: "string-bool-true",
			jsonstr: `
{
  "sub": "test2",
  "email": "test2@test.no",
  "email_verified": "true"
}
			`,
			want: OIDCClaims{
				Sub:           "test2",
				Email:         "test2@test.no",
				EmailVerified: true,
			},
		},
		{
			name: "string-bool-false",
			jsonstr: `
{
  "sub": "test3",
  "email": "test3@test.no",
  "email_verified": "false"
}
			`,
			want: OIDCClaims{
				Sub:           "test3",
				Email:         "test3@test.no",
				EmailVerified: false,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got OIDCClaims
			if err := json.Unmarshal([]byte(tt.jsonstr), &got); err != nil {
				t.Errorf("UnmarshallOIDCClaims() error = %v", err)
				return
			}
			if diff := cmp.Diff(got, tt.want); diff != "" {
				t.Errorf("UnmarshallOIDCClaims() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
