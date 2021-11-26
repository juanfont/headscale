package headscale

import (
	"sync"
	"testing"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/patrickmn/go-cache"
	"golang.org/x/oauth2"
	"gorm.io/gorm"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

func TestHeadscale_getNamespaceFromEmail(t *testing.T) {
	type fields struct {
		cfg             Config
		db              *gorm.DB
		dbString        string
		dbType          string
		dbDebug         bool
		publicKey       *key.MachinePublic
		privateKey      *key.MachinePrivate
		aclPolicy       *ACLPolicy
		aclRules        []tailcfg.FilterRule
		lastStateChange sync.Map
		oidcProvider    *oidc.Provider
		oauth2Config    *oauth2.Config
		oidcStateCache  *cache.Cache
	}
	type args struct {
		email string
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   string
		want1  bool
	}{
		{
			name: "match all",
			fields: fields{
				cfg: Config{
					OIDC: OIDCConfig{
						MatchMap: map[string]string{
							".*": "space",
						},
					},
				},
			},
			args: args{
				email: "test@example.no",
			},
			want:  "space",
			want1: true,
		},
		{
			name: "match user",
			fields: fields{
				cfg: Config{
					OIDC: OIDCConfig{
						MatchMap: map[string]string{
							"specific@user\\.no": "user-namespace",
						},
					},
				},
			},
			args: args{
				email: "specific@user.no",
			},
			want:  "user-namespace",
			want1: true,
		},
		{
			name: "match domain",
			fields: fields{
				cfg: Config{
					OIDC: OIDCConfig{
						MatchMap: map[string]string{
							".*@example\\.no": "example",
						},
					},
				},
			},
			args: args{
				email: "test@example.no",
			},
			want:  "example",
			want1: true,
		},
		{
			name: "multi match domain",
			fields: fields{
				cfg: Config{
					OIDC: OIDCConfig{
						MatchMap: map[string]string{
							".*@example\\.no": "exammple",
							".*@gmail\\.com":  "gmail",
						},
					},
				},
			},
			args: args{
				email: "someuser@gmail.com",
			},
			want:  "gmail",
			want1: true,
		},
		{
			name: "no match domain",
			fields: fields{
				cfg: Config{
					OIDC: OIDCConfig{
						MatchMap: map[string]string{
							".*@dontknow.no": "never",
						},
					},
				},
			},
			args: args{
				email: "test@wedontknow.no",
			},
			want:  "",
			want1: false,
		},
		{
			name: "multi no match domain",
			fields: fields{
				cfg: Config{
					OIDC: OIDCConfig{
						MatchMap: map[string]string{
							".*@dontknow.no":   "never",
							".*@wedontknow.no": "other",
							".*\\.no":          "stuffy",
						},
					},
				},
			},
			args: args{
				email: "tasy@nonofthem.com",
			},
			want:  "",
			want1: false,
		},
	}
	//nolint
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			app := &Headscale{
				cfg:             test.fields.cfg,
				db:              test.fields.db,
				dbString:        test.fields.dbString,
				dbType:          test.fields.dbType,
				dbDebug:         test.fields.dbDebug,
				publicKey:       test.fields.publicKey,
				privateKey:      test.fields.privateKey,
				aclPolicy:       test.fields.aclPolicy,
				aclRules:        test.fields.aclRules,
				lastStateChange: test.fields.lastStateChange,
				oidcProvider:    test.fields.oidcProvider,
				oauth2Config:    test.fields.oauth2Config,
				oidcStateCache:  test.fields.oidcStateCache,
			}
			got, got1 := app.getNamespaceFromEmail(test.args.email)
			if got != test.want {
				t.Errorf(
					"Headscale.getNamespaceFromEmail() got = %v, want %v",
					got,
					test.want,
				)
			}
			if got1 != test.want1 {
				t.Errorf(
					"Headscale.getNamespaceFromEmail() got1 = %v, want %v",
					got1,
					test.want1,
				)
			}
		})
	}
}
