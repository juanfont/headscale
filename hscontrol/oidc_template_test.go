package hscontrol

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/juanfont/headscale/hscontrol/templates"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOIDCCallbackTemplate(t *testing.T) {
	tests := []struct {
		name     string
		userName string
		verb     string
	}{
		{
			name:     "logged_in_user",
			userName: "test@example.com",
			verb:     "Logged in",
		},
		{
			name:     "registered_user",
			userName: "newuser@example.com",
			verb:     "Registered",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Render using the elem-go template
			html := templates.OIDCCallback(tt.userName, tt.verb).Render()

			// Verify the HTML contains expected elements
			assert.Contains(t, html, "<!DOCTYPE html>")
			assert.Contains(t, html, "<title>Headscale Authentication Succeeded</title>")
			assert.Contains(t, html, tt.verb)
			assert.Contains(t, html, tt.userName)
			assert.Contains(t, html, "Signed in via your OIDC provider")
			assert.Contains(t, html, "you can now close this window")
			assert.Contains(t, html, "View the headscale documentation")
			assert.Contains(t, html, "View the tailscale documentation")

			// Verify CSS styles are present
			assert.Contains(t, html, "font-family:")
			assert.Contains(t, html, "system-ui")
			assert.Contains(t, html, ".container")
			assert.Contains(t, html, ".message")

			// Verify SVG elements are present
			assert.Contains(t, html, "<svg")
			assert.Contains(t, html, "id=\"logo\"")
			assert.Contains(t, html, "id=\"checkbox\"")

			// Save the output for manual inspection
			testDataDir := filepath.Join("testdata", "oidc_templates")
			err := os.MkdirAll(testDataDir, 0o755)
			require.NoError(t, err)

			outputFile := filepath.Join(testDataDir, tt.name+".html")
			err = os.WriteFile(outputFile, []byte(html), 0o644)
			require.NoError(t, err)
		})
	}
}
