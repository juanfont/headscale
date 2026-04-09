package templates

import (
	"github.com/chasefleming/elem-go"
	"github.com/chasefleming/elem-go/attrs"
)

// RegisterConfirmInfo carries the human-readable information shown on
// the registration confirmation interstitial that an OIDC-authenticated
// user must explicitly accept before a pending node is registered to
// their identity. The fields here intentionally include enough device
// detail (hostname, OS, machine-key fingerprint) for the user to
// recognise whether the device they are about to claim is in fact
// theirs.
type RegisterConfirmInfo struct {
	// FormAction is the absolute or relative URL the confirm form
	// POSTs to. Typically /register/confirm/{auth_id}.
	FormAction string

	// CSRFTokenName is the name of the hidden form field carrying the
	// CSRF token. The corresponding cookie shares this name.
	CSRFTokenName string

	// CSRFToken is the per-session token that must match the value of
	// the cookie set by the OIDC callback before the POST is honoured.
	CSRFToken string

	// User is the OIDC-authenticated identity the device will be
	// registered to if the user confirms.
	User string

	// Hostname is the hostname the registering tailscaled instance
	// reported in its RegisterRequest.
	Hostname string

	// OS is the operating system the registering tailscaled reported.
	// May be the empty string when the client did not send Hostinfo.
	OS string

	// MachineKey is the short fingerprint of the registering machine
	// key. The full key is intentionally not shown.
	MachineKey string
}

// RegisterConfirm renders an interstitial page that asks the
// OIDC-authenticated user to explicitly confirm that they want to
// register the named device under their account. Without this
// confirmation step a single GET to /register/{auth_id} could
// silently complete a phishing-style registration when the victim's
// IdP allows silent SSO.
func RegisterConfirm(info RegisterConfirmInfo) *elem.Element {
	deviceList := elem.Ul(nil,
		elem.Li(nil, elem.Strong(nil, elem.Text("Hostname: ")), elem.Text(info.Hostname)),
		elem.Li(nil, elem.Strong(nil, elem.Text("OS: ")), elem.Text(displayOrUnknown(info.OS))),
		elem.Li(nil, elem.Strong(nil, elem.Text("Machine key: ")), Code(elem.Text(info.MachineKey))),
		elem.Li(nil, elem.Strong(nil, elem.Text("Will be registered to: ")), elem.Text(info.User)),
	)

	form := elem.Form(
		attrs.Props{
			attrs.Method: "POST",
			attrs.Action: info.FormAction,
		},
		elem.Input(attrs.Props{
			attrs.Type:  "hidden",
			attrs.Name:  info.CSRFTokenName,
			attrs.Value: info.CSRFToken,
		}),
		elem.Button(
			attrs.Props{attrs.Type: "submit"},
			elem.Text("Confirm registration"),
		),
	)

	return HtmlStructure(
		elem.Title(nil, elem.Text("Headscale - Confirm node registration")),
		mdTypesetBody(
			headscaleLogo(),
			H2(elem.Text("Confirm node registration")),
			P(elem.Text(
				"A device is asking to be added to your tailnet. "+
					"Please review the details below and confirm that this device is yours.",
			)),
			deviceList,
			form,
			P(elem.Text(
				"If you do not recognise this device, close this window. "+
					"The registration request will expire automatically.",
			)),
			pageFooter(),
		),
	)
}

func displayOrUnknown(s string) string {
	if s == "" {
		return "(unknown)"
	}

	return s
}
