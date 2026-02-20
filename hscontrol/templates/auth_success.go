package templates

import (
	"github.com/chasefleming/elem-go"
)

// AuthSuccessResult contains the text content for an authentication success page.
// Each field controls a distinct piece of user-facing text so that every auth
// flow (node registration, reauthentication, SSH check, …) can clearly
// communicate what just happened.
type AuthSuccessResult struct {
	// Title is the browser tab / page title,
	// e.g. "Headscale - Node Registered".
	Title string

	// Heading is the bold green text inside the success box,
	// e.g. "Node registered".
	Heading string

	// Verb is the action prefix in the body text before "as <user>",
	// e.g. "Registered", "Reauthenticated", "Authorized".
	Verb string

	// User is the display name shown in bold in the body text,
	// e.g. "user@example.com".
	User string

	// Message is the follow-up instruction shown after the user name,
	// e.g. "You can now close this window."
	Message string
}

// AuthSuccess renders an authentication / authorisation success page.
// The caller controls every user-visible string via [AuthSuccessResult] so the
// page clearly describes what succeeded (registration, reauth, SSH check, …).
func AuthSuccess(result AuthSuccessResult) *elem.Element {
	box := successBox(
		result.Heading,
		elem.Text(result.Verb+" as "),
		elem.Strong(nil, elem.Text(result.User)),
		elem.Text(". "+result.Message),
	)

	return HtmlStructure(
		elem.Title(nil, elem.Text(result.Title)),
		mdTypesetBody(
			headscaleLogo(),
			box,
			H2(elem.Text("Getting started")),
			P(elem.Text("Check out the documentation to learn more about headscale and Tailscale:")),
			Ul(
				elem.Li(nil,
					externalLink("https://headscale.net/stable/", "Headscale documentation"),
				),
				elem.Li(nil,
					externalLink("https://tailscale.com/kb/", "Tailscale knowledge base"),
				),
			),
			pageFooter(),
		),
	)
}
