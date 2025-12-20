package templates

import (
	"github.com/chasefleming/elem-go"
	"github.com/chasefleming/elem-go/attrs"
	"github.com/chasefleming/elem-go/styles"
)

// checkboxIcon returns the success checkbox SVG icon as raw HTML.
func checkboxIcon() elem.Node {
	return elem.Raw(`<svg id="checkbox" aria-hidden="true" xmlns="http://www.w3.org/2000/svg" width="48" height="48" viewBox="0 0 512 512">
  <path d="M256 32C132.3 32 32 132.3 32 256s100.3 224 224 224 224-100.3 224-224S379.7 32 256 32zm114.9 149.1L231.8 359.6c-1.1 1.1-2.9 3.5-5.1 3.5-2.3 0-3.8-1.6-5.1-2.9-1.3-1.3-78.9-75.9-78.9-75.9l-1.5-1.5c-.6-.9-1.1-2-1.1-3.2 0-1.2.5-2.3 1.1-3.2.4-.4.7-.7 1.1-1.2 7.7-8.1 23.3-24.5 24.3-25.5 1.3-1.3 2.4-3 4.8-3 2.5 0 4.1 2.1 5.3 3.3 1.2 1.2 45 43.3 45 43.3l111.3-143c1-.8 2.2-1.4 3.5-1.4 1.3 0 2.5.5 3.5 1.3l30.6 24.1c.8 1 1.3 2.2 1.3 3.5.1 1.3-.4 2.4-1 3.3z"></path>
</svg>`)
}

// OIDCCallback renders the OIDC authentication success callback page.
func OIDCCallback(user, verb string) *elem.Element {
	// Success message box
	successBox := elem.Div(attrs.Props{
		attrs.Style: styles.Props{
			styles.Display:         "flex",
			styles.AlignItems:      "center",
			styles.Gap:             spaceM,
			styles.Padding:         spaceL,
			styles.BackgroundColor: colorSuccessLight,
			styles.Border:          "1px solid " + colorSuccess,
			styles.BorderRadius:    "0.5rem",
			styles.MarginBottom:    spaceXL,
		}.ToInline(),
	},
		checkboxIcon(),
		elem.Div(nil,
			elem.Strong(attrs.Props{
				attrs.Style: styles.Props{
					styles.Display:      "block",
					styles.Color:        colorSuccess,
					styles.FontSize:     fontSizeH3,
					styles.MarginBottom: spaceXS,
				}.ToInline(),
			}, elem.Text("Signed in successfully")),
			elem.P(attrs.Props{
				attrs.Style: styles.Props{
					styles.Margin:   "0",
					styles.Color:    colorTextPrimary,
					styles.FontSize: fontSizeBase,
				}.ToInline(),
			}, elem.Text(verb), elem.Text(" as "), elem.Strong(nil, elem.Text(user)), elem.Text(". You can now close this window.")),
		),
	)

	return HtmlStructure(
		elem.Title(nil, elem.Text("Headscale Authentication Succeeded")),
		mdTypesetBody(
			headscaleLogo(),
			successBox,
			H2(elem.Text("Getting started")),
			P(elem.Text("Check out the documentation to learn more about headscale and Tailscale:")),
			Ul(
				elem.Li(nil,
					externalLink("https://github.com/juanfont/headscale/tree/main/docs", "Headscale documentation"),
				),
				elem.Li(nil,
					externalLink("https://tailscale.com/kb/", "Tailscale knowledge base"),
				),
			),
			pageFooter(),
		),
	)
}
