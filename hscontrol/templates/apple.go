package templates

import (
	"fmt"

	"github.com/chasefleming/elem-go"
	"github.com/chasefleming/elem-go/attrs"
	"github.com/chasefleming/elem-go/styles"
)

func Apple(url string) *elem.Element {
	return HtmlStructure(
		elem.Title(nil,
			elem.Text("headscale - Apple")),
		mdTypesetBody(
			headscaleLogo(),
			H1(elem.Text("iOS configuration")),
			H2(elem.Text("GUI")),
			Ol(
				elem.Li(
					nil,
					elem.Text("Install the official Tailscale iOS client from the "),
					externalLink("https://apps.apple.com/app/tailscale/id1470499037", "App Store"),
				),
				elem.Li(
					nil,
					elem.Text("Open the "),
					elem.Strong(nil, elem.Text("Tailscale")),
					elem.Text(" app"),
				),
				elem.Li(
					nil,
					elem.Text("Click the account icon in the top-right corner and select "),
					elem.Strong(nil, elem.Text("Log in…")),
				),
				elem.Li(
					nil,
					elem.Text("Tap the top-right options menu button and select "),
					elem.Strong(nil, elem.Text("Use custom coordination server")),
				),
				elem.Li(
					nil,
					elem.Text("Enter your instance URL: "),
					Code(elem.Text(url)),
				),
				elem.Li(
					nil,
					elem.Text(
						"Enter your credentials and log in. Headscale should now be working on your iOS device",
					),
				),
			),
			H1(elem.Text("macOS configuration")),
			H2(elem.Text("Command line")),
			P(
				elem.Text("Use Tailscale's login command to add your profile:"),
			),
			Pre(PreCode("tailscale login --login-server "+url)),
			H2(elem.Text("GUI")),
			Ol(
				elem.Li(
					nil,
					elem.Text("Option + Click the "),
					elem.Strong(nil, elem.Text("Tailscale")),
					elem.Text(" icon in the menu and hover over the "),
					elem.Strong(nil, elem.Text("Debug")),
					elem.Text(" menu"),
				),
				elem.Li(nil,
					elem.Text("Under "),
					elem.Strong(nil, elem.Text("Custom Login Server")),
					elem.Text(", select "),
					elem.Strong(nil, elem.Text("Add Account...")),
				),
				elem.Li(
					nil,
					elem.Text("Enter "),
					Code(elem.Text(url)),
					elem.Text(" of the headscale instance and press "),
					elem.Strong(nil, elem.Text("Add Account")),
				),
				elem.Li(nil,
					elem.Text("Follow the login procedure in the browser"),
				),
			),
			H2(elem.Text("Profiles")),
			P(
				elem.Text(
					"Headscale can be set to the default server by installing a Headscale configuration profile:",
				),
			),
			elem.Div(attrs.Props{attrs.Style: styles.Props{styles.MarginTop: spaceL, styles.MarginBottom: spaceL}.ToInline()},
				downloadButton("/apple/macos-app-store", "macOS AppStore profile"),
				downloadButton("/apple/macos-standalone", "macOS Standalone profile"),
			),
			Ol(
				elem.Li(
					nil,
					elem.Text(
						"Download the profile, then open it. When it has been opened, there should be a notification that a profile can be installed",
					),
				),
				elem.Li(nil,
					elem.Text("Open "),
					elem.Strong(nil, elem.Text("System Preferences")),
					elem.Text(" and go to "),
					elem.Strong(nil, elem.Text("Profiles")),
				),
				elem.Li(nil,
					elem.Text("Find and install the "),
					elem.Strong(nil, elem.Text("Headscale")),
					elem.Text(" profile"),
				),
				elem.Li(nil,
					elem.Text("Restart "),
					elem.Strong(nil, elem.Text("Tailscale.app")),
					elem.Text(" and log in"),
				),
			),
			orDivider(),
			P(
				elem.Text(
					"Use your terminal to configure the default setting for Tailscale by issuing one of the following commands:",
				),
			),
			P(elem.Text("For app store client:")),
			Pre(PreCode("defaults write io.tailscale.ipn.macos ControlURL "+url)),
			P(elem.Text("For standalone client:")),
			Pre(PreCode("defaults write io.tailscale.ipn.macsys ControlURL "+url)),
			P(
				elem.Text("Restart "),
				elem.Strong(nil, elem.Text("Tailscale.app")),
				elem.Text(" and log in."),
			),
			warningBox("Caution", "You should always download and inspect the profile before installing it."),
			P(elem.Text("For app store client:")),
			Pre(PreCode(fmt.Sprintf(`curl %s/apple/macos-app-store`, url))),
			P(elem.Text("For standalone client:")),
			Pre(PreCode(fmt.Sprintf(`curl %s/apple/macos-standalone`, url))),
			H1(elem.Text("tvOS configuration")),
			H2(elem.Text("GUI")),
			Ol(
				elem.Li(
					nil,
					elem.Text("Install the official Tailscale tvOS client from the "),
					externalLink("https://apps.apple.com/app/tailscale/id1470499037", "App Store"),
				),
				elem.Li(
					nil,
					elem.Text("Open "),
					elem.Strong(nil, elem.Text("Settings")),
					elem.Text(" (the Apple tvOS settings) > "),
					elem.Strong(nil, elem.Text("Apps")),
					elem.Text(" > "),
					elem.Strong(nil, elem.Text("Tailscale")),
				),
				elem.Li(
					nil,
					elem.Text("Enter "),
					Code(elem.Text(url)),
					elem.Text(" under "),
					elem.Strong(nil, elem.Text("ALTERNATE COORDINATION SERVER URL")),
				),
				elem.Li(nil,
					elem.Text("Return to the tvOS "),
					elem.Strong(nil, elem.Text("Home")),
					elem.Text(" screen"),
				),
				elem.Li(nil,
					elem.Text("Open "),
					elem.Strong(nil, elem.Text("Tailscale")),
				),
				elem.Li(nil,
					elem.Text("Select "),
					elem.Strong(nil, elem.Text("Install VPN configuration")),
				),
				elem.Li(nil,
					elem.Text("Select "),
					elem.Strong(nil, elem.Text("Allow")),
				),
				elem.Li(nil,
					elem.Text("Scan the QR code and follow the login procedure"),
				),
				elem.Li(nil,
					elem.Text("Headscale should now be working on your tvOS device"),
				),
			),
			pageFooter(),
		),
	)
}
