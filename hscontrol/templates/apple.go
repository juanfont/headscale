package templates

import (
	"fmt"

	"github.com/chasefleming/elem-go"
	"github.com/chasefleming/elem-go/attrs"
)

func Apple(url string) *elem.Element {
	return HtmlStructure(
		elem.Title(nil,
			elem.Text("headscale - Apple")),
		elem.Body(attrs.Props{
			attrs.Style: bodyStyle.ToInline(),
		},
			headerOne("headscale: iOS configuration"),
			headerTwo("GUI"),
			elem.Ol(nil,
				elem.Li(
					nil,
					elem.Text("Install the official Tailscale iOS client from the "),
					elem.A(
						attrs.Props{
							attrs.Href: "https://apps.apple.com/app/tailscale/id1470499037",
						},
						elem.Text("App store"),
					),
				),
				elem.Li(nil,
					elem.Text("Open Tailscale and make sure you are "),
					elem.I(nil, elem.Text("not ")),
					elem.Text("logged in to any account"),
				),
				elem.Li(nil,
					elem.Text("Open Settings on the iOS device"),
				),
				elem.Li(
					nil,
					elem.Text(
						`Scroll down to the "third party apps" section, under "Game Center" or "TV Provider"`,
					),
				),
				elem.Li(nil,
					elem.Text("Find Tailscale and select it"),
					elem.Ul(nil,
						elem.Li(
							nil,
							elem.Text(
								`If the iOS device was previously logged into Tailscale, switch the "Reset Keychain" toggle to "on"`,
							),
						),
					),
				),
				elem.Li(
					nil,
					elem.Text(
						fmt.Sprintf(
							`Enter "%s" under "Alternate Coordination Server URL"`,
							url,
						),
					),
				),
				elem.Li(
					nil,
					elem.Text(
						"Restart the app by closing it from the iOS app switcher, open the app and select the regular sign in option ",
					),
					elem.I(nil, elem.Text("(non-SSO)")),
					elem.Text(
						". It should open up to the headscale authentication page.",
					),
				),
				elem.Li(
					nil,
					elem.Text(
						"Enter your credentials and log in. Headscale should now be working on your iOS device",
					),
				),
			),
			headerOne("headscale: macOS configuration"),
			headerTwo("Command line"),
			elem.P(nil,
				elem.Text("Use Tailscale's login command to add your profile:"),
			),
			elem.Pre(nil,
				elem.Code(nil,
					elem.Text(fmt.Sprintf("tailscale login --login-server %s", url)),
				),
			),
			headerTwo("GUI"),
			elem.Ol(nil,
				elem.Li(
					nil,
					elem.Text(
						"ALT + Click the Tailscale icon in the menu and hover over the Debug menu",
					),
				),
				elem.Li(nil,
					elem.Text(`Under "Custom Login Server", select "Add Account..."`),
				),
				elem.Li(
					nil,
					elem.Text(
						fmt.Sprintf(
							`Enter "%s" of the headscale instance and press "Add Account"`,
							url,
						),
					),
				),
				elem.Li(nil,
					elem.Text(`Follow the login procedure in the browser`),
				),
			),
			headerTwo("Profiles"),
			elem.P(
				nil,
				elem.Text(
					"Headscale can be set to the default server by installing a Headscale configuration profile:",
				),
			),
			elem.P(
				nil,
				elem.A(
					attrs.Props{
						attrs.Href:     "/apple/macos-app-store",
						attrs.Download: "headscale_macos.mobileconfig",
					},
					elem.Text("macOS AppStore profile "),
				),
				elem.A(
					attrs.Props{
						attrs.Href:     "/apple/macos-standalone",
						attrs.Download: "headscale_macos.mobileconfig",
					},
					elem.Text("macOS Standalone profile"),
				),
			),
			elem.Ol(nil,
				elem.Li(
					nil,
					elem.Text(
						"Download the profile, then open it. When it has been opened, there should be a notification that a profile can be installed",
					),
				),
				elem.Li(nil,
					elem.Text(`Open System Preferences and go to "Profiles"`),
				),
				elem.Li(nil,
					elem.Text(`Find and install the Headscale profile`),
				),
				elem.Li(nil,
					elem.Text(`Restart Tailscale.app and log in`),
				),
			),
			elem.P(nil, elem.Text("Or")),
			elem.P(
				nil,
				elem.Text(
					"Use your terminal to configure the default setting for Tailscale by issuing:",
				),
			),
			elem.Ul(nil,
				elem.Li(nil,
					elem.Text(`for app store client:`),
					elem.Code(
						nil,
						elem.Text(
							fmt.Sprintf(
								`defaults write io.tailscale.ipn.macos ControlURL %s`,
								url,
							),
						),
					),
				),
				elem.Li(nil,
					elem.Text(`for standalone client:`),
					elem.Code(
						nil,
						elem.Text(
							fmt.Sprintf(
								`defaults write io.tailscale.ipn.macsys ControlURL %s`,
								url,
							),
						),
					),
				),
			),
			elem.P(nil,
				elem.Text("Restart Tailscale.app and log in."),
			),
			headerThree("Caution"),
			elem.P(
				nil,
				elem.Text(
					"You should always download and inspect the profile before installing it:",
				),
			),
			elem.Ul(nil,
				elem.Li(nil,
					elem.Text(`for app store client: `),
					elem.Code(nil,
						elem.Text(fmt.Sprintf(`curl %s/apple/macos-app-store`, url)),
					),
				),
				elem.Li(nil,
					elem.Text(`for standalone client: `),
					elem.Code(nil,
						elem.Text(fmt.Sprintf(`curl %s/apple/macos-standalone`, url)),
					),
				),
			),
			headerOne("headscale: tvOS configuration"),
			headerTwo("GUI"),
			elem.Ol(nil,
				elem.Li(
					nil,
					elem.Text("Install the official Tailscale tvOS client from the "),
					elem.A(
						attrs.Props{
							attrs.Href: "https://apps.apple.com/app/tailscale/id1470499037",
						},
						elem.Text("App store"),
					),
				),
				elem.Li(
					nil,
					elem.Text(
						"Go Settings (the apple tvOS settings) > Apps > Tailscale",
					),
				),
				elem.Li(
					nil,
					elem.Text(
						fmt.Sprintf(
							`Enter "%s" under "ALTERNATE COORDINATION SERVER URL"`,
							url,
						),
					),
				),
				elem.Li(nil,
					elem.Text("Return to the tvOS Home screen"),
				),
				elem.Li(nil,
					elem.Text("Open Tailscale"),
				),
				elem.Li(nil,
					elem.Text("Select \"Install VPN configuration\""),
				),
				elem.Li(nil,
					elem.Text("Select \"Allow\""),
				),
				elem.Li(nil,
					elem.Text("Scan the QR code and follow the login procedure"),
				),
				elem.Li(nil,
					elem.Text("Headscale should now be working on your tvOS device"),
				),
			),
		),
	)
}
