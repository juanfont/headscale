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
		pingExplanation(),
		pingForm(query),
	}

	if result != nil {
		children = append(children, pingResultSection(result))
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

func pingExplanation() *elem.Element {
	return detailsBox("How does this work?",
		Ol(
			elem.Li(nil, elem.Text(
				"The server sends a PingRequest to the target node via its MapResponse stream.",
			)),
			elem.Li(nil, elem.Text(
				"The node's Tailscale client receives the request and responds back to the server.",
			)),
			elem.Li(nil, elem.Text(
				"The server measures the round-trip latency from send to callback.",
			)),
			elem.Li(nil, elem.Text(
				"If no response arrives within 30 seconds, the ping times out.",
			)),
		),
		P(elem.Raw(
			"This tests the <strong>full control plane path</strong>"+
				" — map stream delivery, client processing, and network"+
				" connectivity back to the server."+
				" It does not test ICMP or WireGuard tunnel connectivity.",
		)),
	)
}

func pingForm(query string) *elem.Element {
	return elem.Form(attrs.Props{
		attrs.Method: "POST",
		attrs.Action: "/debug/ping",
		attrs.Style: styles.Props{
			styles.Display:    "flex",
			styles.Gap:        spaceS,
			styles.AlignItems: "center",
			styles.FlexWrap:   "wrap",
			styles.MarginTop:  spaceM,
		}.ToInline(),
	},
		elem.Input(attrs.Props{
			attrs.Type:        "text",
			attrs.Name:        "node",
			attrs.Value:       query,
			attrs.Placeholder: "Node ID, IP, or hostname",
			attrs.Autofocus:   "true",
			attrs.Style: styles.Props{
				styles.Padding:      "0.75rem " + spaceM,
				styles.Border:       "1px solid var(--hs-border)",
				styles.BorderRadius: "0.375rem",
				styles.Width:        "280px",
				styles.MaxWidth:     "100%",
				styles.Background:   "var(--hs-bg)",
				styles.Color:        "var(--md-default-fg-color)",
			}.ToInline(),
		}),
		elem.Button(attrs.Props{
			attrs.Type: "submit",
		}, elem.Text("Ping")),
	)
}

func connectedNodeList(nodes []ConnectedNode) *elem.Element {
	items := make([]elem.Node, 0, len(nodes))

	for _, n := range nodes {
		label := fmt.Sprintf("%s (ID: %d, %s)", n.Hostname, n.ID, strings.Join(n.IPs, ", "))
		href := fmt.Sprintf("/debug/ping?node=%d", n.ID)

		items = append(items, elem.Li(nil, A(href, elem.Text(label))))
	}

	return elem.Div(attrs.Props{
		attrs.Style: styles.Props{
			styles.MarginTop: space2XL,
		}.ToInline(),
	},
		H2(elem.Text("Connected Nodes")),
		Ul(items...),
	)
}

func pingResultSection(result *PingResult) *elem.Element {
	return elem.Div(attrs.Props{
		attrs.Style: styles.Props{
			styles.MarginTop: spaceXL,
		}.ToInline(),
	}, pingResultBox(result))
}

func pingResultBox(result *PingResult) *elem.Element {
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
