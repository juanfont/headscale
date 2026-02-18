package templates

import (
	"github.com/chasefleming/elem-go"
)

// AuthWeb renders a page that instructs an administrator to run a CLI command
// to complete an authentication or registration flow.
// It is used by both the registration and auth-approve web handlers.
func AuthWeb(title, description, command string) *elem.Element {
	return HtmlStructure(
		elem.Title(nil, elem.Text(title+" - Headscale")),
		mdTypesetBody(
			headscaleLogo(),
			H1(elem.Text(title)),
			P(elem.Text(description)),
			Pre(PreCode(command)),
			pageFooter(),
		),
	)
}
