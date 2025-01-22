package types

import (
	"database/sql"
	"encoding/json"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/juanfont/headscale/hscontrol/util"
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

func TestOIDCClaimsJSONToUser(t *testing.T) {
	tests := []struct {
		name    string
		jsonstr string
		want    User
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
			want: User{
				Provider: util.RegisterMethodOIDC,
				Email:    "test@test.no",
				ProviderIdentifier: sql.NullString{
					String: "/test",
					Valid:  true,
				},
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
			want: User{
				Provider: util.RegisterMethodOIDC,
				Email:    "test2@test.no",
				ProviderIdentifier: sql.NullString{
					String: "/test2",
					Valid:  true,
				},
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
			want: User{
				Provider: util.RegisterMethodOIDC,
				ProviderIdentifier: sql.NullString{
					String: "/test3",
					Valid:  true,
				},
			},
		},
		{
			// From https://github.com/juanfont/headscale/issues/2333
			name: "okta-oidc-claim-20250121",
			jsonstr: `
{
  "sub": "00u7dr4qp7XXXXXXXXXX",
  "name": "Tim Horton",
  "email": "tim.horton@company.com",
  "ver": 1,
  "iss": "https://sso.company.com/oauth2/default",
  "aud": "0oa8neto4tXXXXXXXXXX",
  "iat": 1737455152,
  "exp": 1737458752,
  "jti": "ID.zzJz93koTunMKv5Bq-XXXXXXXXXXXXXXXXXXXXXXXXX",
  "amr": [
    "pwd"
  ],
  "idp": "00o42r3s2cXXXXXXXX",
  "nonce": "nonce",
  "preferred_username": "tim.horton@company.com",
  "auth_time": 1000,
  "at_hash": "preview_at_hash"
}
			`,
			want: User{
				Provider:    util.RegisterMethodOIDC,
				DisplayName: "Tim Horton",
				Name:        "tim.horton@company.com",
				ProviderIdentifier: sql.NullString{
					String: "https://sso.company.com/oauth2/default/00u7dr4qp7XXXXXXXXXX",
					Valid:  true,
				},
			},
		},
		{
			// From https://github.com/juanfont/headscale/issues/2333
			name: "okta-oidc-claim-20250121",
			jsonstr: `
{
  "aud": "79xxxxxx-xxxx-xxxx-xxxx-892146xxxxxx",
  "iss": "https://login.microsoftonline.com//v2.0",
  "iat": 1737346441,
  "nbf": 1737346441,
  "exp": 1737350341,
  "aio": "AWQAm/8ZAAAABKne9EWr6ygVO2DbcRmoPIpRM819qqlP/mmK41AAWv/C2tVkld4+znbG8DaXFdLQa9jRUzokvsT7rt9nAT6Fg7QC+/ecDWsF5U+QX11f9Ox7ZkK4UAIWFcIXpuZZvRS7",
  "email": "user@domain.com",
  "name": "XXXXXX XXXX",
  "oid": "54c2323d-5052-4130-9588-ad751909003f",
  "preferred_username": "user@domain.com",
  "rh": "1.AXUAXdg0Rfc11UifLDJv67ChfSluoXmD9z1EmK-JIUYuSK9cAQl1AA.",
  "sid": "5250a0a2-0b4e-4e68-8652-b4e97866411d",
  "sub": "I-70OQnj3TogrNSfkZQqB3f7dGwyBWSm1dolHNKrMzQ",
  "tid": "<redacted>",
  "uti": "zAuXeEtMM0GwcTAcOsBZAA",
  "ver": "2.0"
}
			`,
			want: User{
				Provider:    util.RegisterMethodOIDC,
				DisplayName: "XXXXXX XXXX",
				Name:        "user@domain.com",
				ProviderIdentifier: sql.NullString{
					String: "https://login.microsoftonline.com//v2.0/I-70OQnj3TogrNSfkZQqB3f7dGwyBWSm1dolHNKrMzQ",
					Valid:  true,
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got OIDCClaims
			if err := json.Unmarshal([]byte(tt.jsonstr), &got); err != nil {
				t.Errorf("TestOIDCClaimsJSONToUser() error = %v", err)
				return
			}

			var user User

			user.FromClaim(&got)
			if diff := cmp.Diff(user, tt.want); diff != "" {
				t.Errorf("TestOIDCClaimsJSONToUser() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
