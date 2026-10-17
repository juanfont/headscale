package templates

import (
	"cmp"
	"strings"

	"github.com/chasefleming/elem-go"
	"github.com/chasefleming/elem-go/attrs"
	"github.com/chasefleming/elem-go/styles"
)

// RegisterConfirmInfo carries the human-readable information shown on
// the registration confirmation interstitial that an OIDC-authenticated
// user must explicitly accept before a pending node is registered to
// their identity. The fields here intentionally include enough device
// detail (hostname, OS, machine-key fingerprint) for the user to
// recognise whether the device they are about to claim is in fact
// theirs.
// The form and user fields are also used for SSH check confirmations.
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

	// User is the OIDC-authenticated identity approving the request.
	User string

	// Hostname is the hostname the registering tailscaled instance
	// reported in its [tailcfg.RegisterRequest].
	Hostname string

	// OS is the operating system the registering tailscaled reported.
	// May be the empty string when the client did not send [tailcfg.Hostinfo].
	OS string

	// MachineKey is the short fingerprint of the registering machine
	// key. The full key is intentionally not shown.
	MachineKey string

	// ExistingNode is the stored node name, empty for a new device.
	ExistingNode string

	// Tags are the ownership tags requested by the registering client.
	Tags []string
}

// RegisterConfirm renders an interstitial page that asks the
// OIDC-authenticated user to explicitly confirm that they want to
// register the named device under their account. Without this
// confirmation step a single GET to /register/{auth_id} could
// silently complete a phishing-style registration when the victim's
// IdP allows silent SSO.
func RegisterConfirm(info RegisterConfirmInfo) *elem.Element {
	rows := []deviceRow{
		{"Hostname", elem.Text(info.Hostname)},
		{"OS", elem.Text(cmp.Or(info.OS, "(unknown)"))},
		{"Machine key", Code(elem.Text(info.MachineKey))},
		{"Existing node", elem.Text(cmp.Or(info.ExistingNode, "None, this is a new device"))},
	}
	if len(info.Tags) > 0 {
		rows = append(rows,
			deviceRow{"Registered to", elem.Text(strings.Join(info.Tags, ", "))},
			deviceRow{"Approved by", elem.Text(info.User)},
		)
	} else {
		rows = append(rows, deviceRow{"Registered to", elem.Text(info.User)})
	}

	deviceList := deviceTable(rows)

	return page(
		"Headscale - Confirm node registration",
		H2(elem.Text("Confirm node registration")),
		P(elem.Text(
			"A device is asking to be added to your tailnet. "+
				"Please review the details below and confirm that this device is yours.",
		)),
		deviceList,
		confirmForm(info, "Confirm registration"),
		P(elem.Text(
			"If you do not recognise this device, close this window. "+
				"The registration request will expire automatically.",
		)),
	)
}

// SSHCheckConfirm asks the owner to approve the source and destination node pair.
func SSHCheckConfirm(
	info RegisterConfirmInfo,
	source, destination string,
) *elem.Element {
	return page(
		"Headscale - Confirm SSH session",
		H2(elem.Text("Confirm SSH session")),
		P(elem.Text(
			"An SSH session is waiting for your approval. "+
				"Review the source and destination nodes before continuing.",
		)),
		deviceTable([]deviceRow{
			{"From", elem.Text(source)},
			{"To", elem.Text(destination)},
			{"Approved by", elem.Text(info.User)},
		}),
		P(elem.Text(
			"Approval also allows new SSH sessions between these two nodes "+
				"without asking again until the check period ends.",
		)),
		confirmForm(info, "Approve SSH session"),
		P(elem.Text(
			"If you do not recognise this request, close this window. "+
				"The request will expire automatically.",
		)),
	)
}

func confirmForm(info RegisterConfirmInfo, buttonText string) *elem.Element {
	return elem.Form(
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
			elem.Text(buttonText),
		),
	)
}

type deviceRow struct {
	label string
	value elem.Node
}

func deviceTable(rows []deviceRow) *elem.Element {
	tableRows := make([]elem.Node, 0, len(rows))
	for _, row := range rows {
		tableRows = append(tableRows, elem.Tr(
			nil,
			elem.Td(attrs.Props{
				attrs.Style: styles.Props{
					styles.Padding:      "0.5rem 1rem 0.5rem 0",
					styles.FontWeight:   "600",
					styles.WhiteSpace:   "nowrap",
					styles.Color:        "var(--md-default-fg-color--light)",
					styles.BorderBottom: cssBorderHS,
				}.ToInline(),
			}, elem.Text(row.label)),
			elem.Td(attrs.Props{
				attrs.Style: styles.Props{
					styles.Padding:      "0.5rem 0",
					styles.BorderBottom: cssBorderHS,
				}.ToInline(),
			}, row.value),
		))
	}

	return elem.Table(attrs.Props{
		attrs.Style: styles.Props{
			styles.Width:          "100%",
			styles.BorderCollapse: "collapse",
			styles.MarginTop:      "1em",
			styles.MarginBottom:   "1.5em",
		}.ToInline(),
	}, tableRows...)
}
