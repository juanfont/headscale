package hscontrol

import (
	"testing"

	"github.com/juanfont/headscale/hscontrol/templates"
	"github.com/stretchr/testify/assert"
)

func TestAuthSuccessTemplate(t *testing.T) {
	tests := []struct {
		name   string
		result templates.AuthSuccessResult
	}{
		{
			name: "node_registered",
			result: templates.AuthSuccessResult{
				Title:   "Headscale - Node Registered",
				Heading: "Node registered",
				Verb:    "Registered",
				User:    "newuser@example.com",
				Message: "You can now close this window.",
			},
		},
		{
			name: "node_reauthenticated",
			result: templates.AuthSuccessResult{
				Title:   "Headscale - Node Reauthenticated",
				Heading: "Node reauthenticated",
				Verb:    "Reauthenticated",
				User:    "test@example.com",
				Message: "You can now close this window.",
			},
		},
		{
			name: "ssh_session_authorized",
			result: templates.AuthSuccessResult{
				Title:   "Headscale - SSH Session Authorized",
				Heading: "SSH session authorized",
				Verb:    "Authorized",
				User:    "test@example.com",
				Message: "You may return to your terminal.",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			html := templates.AuthSuccess(tt.result).Render()

			// Verify the HTML contains expected structural elements
			assert.Contains(t, html, "<!DOCTYPE html>")
			assert.Contains(t, html, "<title>"+tt.result.Title+"</title>")
			assert.Contains(t, html, tt.result.Heading)
			assert.Contains(t, html, tt.result.Verb+" as ")
			assert.Contains(t, html, tt.result.User)
			assert.Contains(t, html, tt.result.Message)

			// Verify Material for MkDocs design system CSS is present
			assert.Contains(t, html, "Material for MkDocs")
			assert.Contains(t, html, "Roboto")
			assert.Contains(t, html, ".md-typeset")

			// Verify SVG elements are present
			assert.Contains(t, html, "<svg")
			assert.Contains(t, html, "class=\"headscale-logo\"")
			assert.Contains(t, html, "id=\"checkbox\"")
		})
	}
}
