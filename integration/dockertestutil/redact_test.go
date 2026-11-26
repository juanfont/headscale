package dockertestutil

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestRedact: the secret part of every form of credential the suite meets
// is hidden; what names the credential stays.
func TestRedact(t *testing.T) {
	for in, want := range map[string]string{ //nolint:gosec // sentinels, not credentials
		"hskey-api-0123456789ab-sentinel1":             "hskey-api-0123456789ab-***",
		"--authkey=hskey-auth-ba9876543210-sentinel2":  "--authkey=hskey-auth-ba9876543210-***",
		"hskey-client-c9f2a1-sentinel3":                "hskey-client-***",
		"Bearer hskey-oauthtok-ab12cd34ef56-sentinel4": "Bearer hskey-oauthtok-ab12cd34ef56-***",
		"tskey-client-c9f2a1-sentinel5":                "tskey-client-***",
		"tskey-auth-kAbc123-sentinel6":                 "tskey-auth-***",
		"hskey-auth-a-_b-c_d-e_f-sentinel-_7":          "hskey-auth-a-_b-c_d-e_f-***",
		"hskey-api-x_y-sentinel_8-":                    "hskey-api-***",
		"hskey-authreq-0123456789abcdef01234567":       "hskey-authreq-0123456789abcdef01234567",
		"hskey-auth-ba9876543210-***":                  "hskey-auth-ba9876543210-***",
	} {
		assert.Equal(t, want, Redact(in))
	}

	err := Redactf(ErrDockertestCommandFailed, "failed: %s", "hskey-api-0123456789ab-sentinel1")
	assert.Equal(t, "failed: hskey-api-0123456789ab-***", err.Error())
	assert.ErrorIs(t, err, ErrDockertestCommandFailed)
}
