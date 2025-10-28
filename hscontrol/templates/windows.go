package templates

import (
	"github.com/chasefleming/elem-go"
)

func Windows(url string) *elem.Element {
	return HtmlStructure(
		elem.Title(nil,
			elem.Text("headscale - Windows"),
		),
		mdTypesetBody(
			headscaleLogo(),
			H1(elem.Text("Windows configuration")),
			P(
				elem.Text("Download "),
				externalLink("https://tailscale.com/download/windows", "Tailscale for Windows"),
				elem.Text(" and install it."),
			),
			P(
				elem.Text("Open a Command Prompt or PowerShell and use Tailscale's login command to connect with headscale:"),
			),
			Pre(PreCode("tailscale login --login-server "+url)),
			pageFooter(),
		),
	)
}
