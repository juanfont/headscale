package hscontrol

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-jose/go-jose/v3"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"net/http/httptest"
	"reflect"
	"testing"
)

func Test_extractIDTokenClaims(t *testing.T) {
	tests := []verificationTest{
		{
			name:    "default claim names",
			idToken: `{"iss":"https://foo", "email": "foo@bar.baz", "groups": ["group1", "group2"]}`,
			cfg: types.OIDCConfig{
				EmailClaim:  "email",
				GroupsClaim: "groups",
			},
			want: &IDTokenClaims{
				Groups: []string{"group1", "group2"},
				Email:  "foo@bar.baz",
			},
			wantErr: false,
		},
		{
			name:    "custom claim names",
			idToken: `{"iss":"https://foo", "my_custom_claim": "foo@bar.baz", "https://foo.baz/groups": ["group3", "group4"]}`,
			cfg: types.OIDCConfig{
				EmailClaim:  "my_custom_claim",
				GroupsClaim: "https://foo.baz/groups",
			},
			want: &IDTokenClaims{
				Groups: []string{"group3", "group4"},
				Email:  "foo@bar.baz",
			},
			wantErr: false,
		},
		{
			name:    "group claim not present",
			idToken: `{"iss":"https://foo", "my_custom_claim": "foo@bar.baz"}`,
			cfg: types.OIDCConfig{
				EmailClaim:  "my_custom_claim",
				GroupsClaim: "https://foo.baz/groups",
			},
			want: &IDTokenClaims{
				Email: "foo@bar.baz",
			},
			wantErr: false,
		},
		{
			name:    "email claim not present",
			idToken: `{"iss":"https://foo", "groups": ["group1", "group2"]}`,
			cfg: types.OIDCConfig{
				EmailClaim:  "email",
				GroupsClaim: "groups",
			},
			want:    nil,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			token, err := tt.getToken(t)
			if err != nil {
				t.Errorf("could not parse the token: %v", err)

				return
			}

			if !tt.wantErr {
				assert.Equal(t, 200, recorder.Result().StatusCode)
				assert.Empty(t, recorder.Result().Header)
			}

			got, err := extractIDTokenClaims(recorder, tt.cfg, token)
			if (err != nil) != tt.wantErr {
				t.Errorf("extractIDTokenClaims() error = %v, wantErr %v", err, tt.wantErr)

				return
			}

			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("extractIDTokenClaims() got = %v, want %v", got, tt.want)

				return
			}
		})
	}
}

type signingKey struct {
	keyID string
	key   interface{}
	pub   interface{}
	alg   jose.SignatureAlgorithm
}

// sign creates a JWS using the private key from the provided payload.
func (s *signingKey) sign(t testing.TB, payload []byte) string {
	privKey := &jose.JSONWebKey{Key: s.key, Algorithm: string(s.alg), KeyID: s.keyID}

	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: s.alg, Key: privKey}, nil)
	if err != nil {
		t.Fatal(err)
	}
	jws, err := signer.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}

	data, err := jws.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}

	return data
}

type verificationTest struct {
	name    string
	idToken string
	cfg     types.OIDCConfig
	want    *IDTokenClaims
	wantErr bool
}

func newRSAKey(t testing.TB) *signingKey {
	priv, err := rsa.GenerateKey(rand.Reader, 1028)
	if err != nil {
		t.Fatal(err)
	}

	return &signingKey{"", priv, priv.Public(), jose.RS256}
}

func (v verificationTest) getToken(t *testing.T) (*oidc.IDToken, error) {
	key := newRSAKey(t)
	token := key.sign(t, []byte(v.idToken))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	verifier := oidc.NewVerifier(
		"https://foo",
		&oidc.StaticKeySet{PublicKeys: []crypto.PublicKey{key.pub}},
		&oidc.Config{
			SkipClientIDCheck:          true,
			SkipExpiryCheck:            true,
			SkipIssuerCheck:            true,
			InsecureSkipSignatureCheck: true,
		},
	)

	return verifier.Verify(ctx, token)
}
