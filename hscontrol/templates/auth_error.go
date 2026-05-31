package templates

import (
	"github.com/chasefleming/elem-go"
)

// AuthErrorResult contains the text content for an error page shown
// to users in their browser when a browser-facing operation fails
// (OIDC callback, SSH check, registration confirmation, etc.).
type AuthErrorResult struct {
	// Title is the browser tab / page title,
	// e.g. "Headscale - Error".
	Title string

	// Heading is the bold red text inside the error box,
	// e.g. "Forbidden".
	Heading string

	// Message is the actionable user-facing message shown below
	// the heading, e.g. "You are not authorized. Please contact
	// your administrator."
	Message string
}

// AuthError renders a styled error page for browser-facing failures.
// The caller controls every user-visible string via [AuthErrorResult].
func AuthError(result AuthErrorResult) *elem.Element {
	box := errorBox(
		result.Heading,
		elem.Text(result.Message),
	)

	return HtmlStructure(
		elem.Title(nil, elem.Text(result.Title)),
		mdTypesetBody(
			headscaleLogo(),
			box,
			pageFooter(),
		),
	)
}
