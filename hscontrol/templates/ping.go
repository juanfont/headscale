package templates

import (
	"fmt"
	"strings"
	"time"

	elem "github.com/chasefleming/elem-go"
	"github.com/chasefleming/elem-go/attrs"
	"github.com/chasefleming/elem-go/styles"
	"github.com/juanfont/headscale/hscontrol/types"
)

// PingResult contains the outcome of a ping request.
type PingResult struct {
	// Status is "ok", "timeout", or "error".
	Status string

	// Latency is the round-trip time (only meaningful when Status is "ok").
	Latency time.Duration

	// NodeID is the ID of the pinged node.
	NodeID types.NodeID

	// Message is a human-readable description of the result.
	Message string
}

// ConnectedNode is a node currently connected to the batcher,
// displayed as a quick-ping link on the debug ping page.
type ConnectedNode struct {
	ID       types.NodeID
	Hostname string
	IPs      []string
}

// PingPage renders the /debug/ping page with a form, optional result,
// and a list of connected nodes as quick-ping links.
func PingPage(query string, result *PingResult, nodes []ConnectedNode) *elem.Element {
	children := []elem.Node{
		headscaleLogo(),
		H1(elem.Text("Ping Node")),
		P(elem.Text("Check if a connected node responds to a PingRequest.")),
		pingForm(query),
	}

	if result != nil {
		children = append(children, pingResult(result))
	}

	if len(nodes) > 0 {
		children = append(children, connectedNodeList(nodes))
	}

	children = append(children, pageFooter())

	return HtmlStructure(
		elem.Title(nil, elem.Text("Ping Node - Headscale")),
		mdTypesetBody(children...),
	)
}

func pingForm(query string) *elem.Element {
	inputStyle := styles.Props{
		styles.Padding:      spaceS,
		styles.Border:       "1px solid " + colorBorderMedium,
		styles.BorderRadius: "0.25rem",
		styles.FontSize:     fontSizeBase,
		styles.FontFamily:   fontFamilySystem,
		styles.Width:        "280px",
	}

	buttonStyle := styles.Props{
		styles.Padding:         spaceS + " " + spaceM,
		styles.BackgroundColor: colorPrimaryAccent,
		styles.Color:           "#ffffff",
		styles.Border:          "none",
		styles.BorderRadius:    "0.25rem",
		styles.FontSize:        fontSizeBase,
		styles.FontFamily:      fontFamilySystem,
		"cursor":               "pointer",
	}

	return elem.Form(attrs.Props{
		attrs.Method: "POST",
		attrs.Action: "/debug/ping",
		attrs.Style: styles.Props{
			styles.Display:    "flex",
			styles.Gap:        spaceS,
			styles.AlignItems: "center",
			styles.MarginTop:  spaceM,
		}.ToInline(),
	},
		elem.Input(attrs.Props{
			attrs.Type:        "text",
			attrs.Name:        "node",
			attrs.Value:       query,
			attrs.Placeholder: "Node ID, IP, or hostname",
			attrs.Autofocus:   "true",
			attrs.Style:       inputStyle.ToInline(),
		}),
		elem.Button(attrs.Props{
			attrs.Type:  "submit",
			attrs.Style: buttonStyle.ToInline(),
		}, elem.Text("Ping")),
	)
}

func connectedNodeList(nodes []ConnectedNode) *elem.Element {
	items := make([]elem.Node, 0, len(nodes))

	for _, n := range nodes {
		label := fmt.Sprintf("%s (ID: %d, %s)", n.Hostname, n.ID, strings.Join(n.IPs, ", "))
		href := fmt.Sprintf("/debug/ping?node=%d", n.ID)

		items = append(items, elem.Li(nil,
			elem.A(attrs.Props{
				attrs.Href: href,
				attrs.Style: styles.Props{
					styles.Color: colorPrimaryAccent,
				}.ToInline(),
			}, elem.Text(label)),
		))
	}

	return elem.Div(attrs.Props{
		attrs.Style: styles.Props{
			styles.MarginTop: spaceL,
		}.ToInline(),
	},
		H2(elem.Text("Connected Nodes")),
		elem.Ul(nil, items...),
	)
}

func pingResult(result *PingResult) *elem.Element {
	switch result.Status {
	case "ok":
		return successBox(
			"Pong",
			elem.Text(fmt.Sprintf("Node %d responded in %s",
				result.NodeID, result.Latency.Round(time.Millisecond))),
		)
	case "timeout":
		return warningBox(
			"Timeout",
			fmt.Sprintf("Node %d did not respond. %s", result.NodeID, result.Message),
		)
	default:
		return warningBox("Error", result.Message)
	}
}
