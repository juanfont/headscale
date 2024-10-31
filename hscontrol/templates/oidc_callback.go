package templates

import (
	"fmt"

	"github.com/chasefleming/elem-go"
	"github.com/chasefleming/elem-go/attrs"
	"github.com/chasefleming/elem-go/styles"
	"github.com/juanfont/headscale/hscontrol/types"
)

func OidcCallback(node *types.Node, user *types.User, verb string) string {
	styleMgr := styles.NewStyleManager()
	styleBody := styleMgr.AddStyle(styles.Props{
		styles.FontSize:   styles.Pixels(14), //nolint
		styles.FontFamily: "system-ui, -apple-system, BlinkMacSystemFont, \"Segoe UI\", \"Roboto\", \"Oxygen\", \"Ubuntu\", \"Cantarell\", \"Fira Sans\", \"Droid Sans\", \"Helvetica Neue\", sans-serif",
	})
	styleHr := styleMgr.AddStyle(styles.Props{
		styles.BorderColor: "#fdfdfe",
		styles.Margin:      "24px 0",
	})
	classContainer := styleMgr.AddStyle(styles.Props{
		styles.Display:        "flex",
		styles.JustifyContent: "center",
		styles.AlignItems:     "center",
		styles.Height:         styles.ViewportHeight(70), //nolint
	})
	classLogo := styleMgr.AddStyle(styles.Props{
		styles.Display:      "block",
		styles.MarginLeft:   styles.Pixels(-20), //nolint
		styles.MarginBottom: styles.Pixels(16),  //nolint
	})

	colorMessageSuccess := styles.Props{
		styles.Background: "#fafdfa",
		styles.Border:     "1px solid #c6e9c9",
	}
	colorMessageWarning := styles.Props{
		styles.Background: "#fff9f2",
		styles.Border:     "1px solid #f7d7b0",
	}
	styleMessage := styles.Props{
		styles.Display:      "flex",
		styles.MinWidth:     styles.ViewportWidth(40), //nolint
		styles.MarginBottom: styles.Pixels(12),        //nolint
		styles.Padding:      "12px 16px 16px 12px",
		styles.Position:     "relative",
		styles.BorderRadius: styles.Pixels(2),  //nolint
		styles.FontSize:     styles.Pixels(14), //nolint
	}

	var classMessage string
	if node.Approved {
		classMessage = styleMgr.AddStyle(styles.Merge(styleMessage, colorMessageSuccess))
	} else {
		classMessage = styleMgr.AddStyle(styles.Merge(styleMessage, colorMessageWarning))
	}

	classMessageContent := styleMgr.AddStyle(styles.Props{
		styles.MarginLeft: styles.Pixels(4), //nolint
	})
	classIconSuccess := styleMgr.AddStyle(styles.Props{
		"fill": "#2eb039",
	})

	colorMessageTitleSuccess := styles.Props{
		styles.Color: "#1e7125",
	}
	colorMessageTitleWarning := styles.Props{
		styles.Color: "#d58525",
	}
	styleMessageTitle := styles.Props{
		styles.FontSize:   styles.Pixels(16),  //nolint
		styles.FontWeight: styles.Int(700),    //nolint
		styles.LineHeight: styles.Float(1.25), //nolint
	}

	var classMessageTitle string
	if node.Approved {
		classMessageTitle = styleMgr.AddStyle(styles.Merge(styleMessageTitle, colorMessageTitleSuccess))
	} else {
		classMessageTitle = styleMgr.AddStyle(styles.Merge(styleMessageTitle, colorMessageTitleWarning))
	}

	colorMessageBodySuccess := styles.Props{
		styles.Color: "#17421b",
	}
	colorMessageBodyWarning := styles.Props{
		styles.Color: "#824c0b",
	}
	styleMessageBody := styles.Props{
		styles.FontSize:  styles.Pixels(12), //nolint
		styles.Margin:    styles.Int(0),     //nolint
		styles.Padding:   styles.Int(0),     //nolint
		styles.Border:    styles.Int(0),     //nolint
		styles.MarginTop: styles.Pixels(4),  //nolint
	}

	var classMessageBody string
	if node.Approved {
		classMessageBody = styleMgr.AddStyle(styles.Merge(styleMessageBody, colorMessageBodySuccess))
	} else {
		classMessageBody = styleMgr.AddStyle(styles.Merge(styleMessageBody, colorMessageBodyWarning))
	}

	styleA := styleMgr.AddCompositeStyle(styles.CompositeStyle{
		Default: styles.Props{
			styles.Display:        "block",
			styles.Margin:         "8px 0",
			styles.Color:          "#1563ff",
			styles.TextDecoration: "none",
			styles.FontWeight:     styles.Int(600), //nolint
		},
		PseudoClasses: map[string]styles.Props{
			styles.PseudoHover: {styles.Color: "black"},
		},
	})
	classIcon := styleMgr.AddStyle(styles.Props{
		styles.AlignItems:     "center",
		styles.Display:        "inline-flex",
		styles.JustifyContent: "center",
		styles.Width:          styles.Pixels(21), //nolint
		styles.Height:         styles.Pixels(21), //nolint
		styles.VerticalAlign:  "middle",
	})
	styleH1 := styleMgr.AddStyle(styles.Props{
		styles.FontSize:     "17.5px",
		styles.FontWeight:   styles.Pixels(700), //nolint
		styles.MarginBottom: styles.Pixels(0),   //nolint
	})
	styleH1P := styleMgr.AddStyle(styles.Props{
		styles.Margin: "8px 0 16px 0",
	})

	var messageText string
	var icon *elem.Element

	if node.Approved {
		messageText = fmt.Sprintf(
			"%s as %s, you can now close this window.",
			verb,
			user.DisplayNameOrUsername(),
		)
		icon = iconSuccess(classIconSuccess)
	} else {
		messageText = fmt.Sprintf(
			"%s as %s, but not connected!",
			verb,
			user.DisplayNameOrUsername(),
		)
		icon = iconWarning()
	}

	description := &elem.Element{
		Tag: "span",
	}

	if !node.Approved {
		description = elem.Div(
			nil,
			elem.P(
				attrs.Props{
					attrs.Class: classMessageBody,
					attrs.Style: styles.Props{
						styles.MarginTop: "1rem",
					}.ToInline(),
				},
				elem.Text("However, it can't connect until approved by the administrator a network."),
			),
			elem.P(
				attrs.Props{
					attrs.Class: classMessageBody,
				},
				elem.Text("Once approved, your node will connect automatically."),
			),
		)
	}

	return HtmlStructure(
		elem.Title(
			nil,
			elem.Text("headscale - Authentication Succeeded"),
		),
		elem.Body(
			attrs.Props{
				attrs.DataAttr("translate"): "no",
				attrs.Class:                 styleBody,
			},
			elem.Div(
				attrs.Props{
					attrs.Class: classContainer,
				},
				elem.Div(
					nil,
					logo(classLogo),
					elem.Div(
						attrs.Props{
							attrs.Class: classMessage,
						},
						icon,
						elem.Div(
							attrs.Props{
								attrs.Class: classMessageContent,
							},
							elem.Div(
								attrs.Props{
									attrs.Class: classMessageTitle,
								},
								elem.Text("Signed in via your OIDC provider"),
							),
							elem.P(
								attrs.Props{
									attrs.Class: classMessageBody,
								},
								elem.Text(messageText),
							),
							description,
						),
					),
					elem.Hr(
						attrs.Props{
							attrs.Class: styleHr,
						},
					),
					elem.H1(
						attrs.Props{
							attrs.Class: styleH1,
						},
						elem.Text("Not sure how to get started?"),
					),
					elem.P(
						attrs.Props{
							attrs.Class: styleH1P,
						},
						elem.Text(" Check out beginner and advanced guides on, or read more in the documentation."),
					),
					elem.A(
						attrs.Props{
							attrs.Href:   "https://github.com/juanfont/headscale/tree/main/docs",
							attrs.Rel:    "noreferrer noopener",
							attrs.Target: "_blank",
							attrs.Class:  styleA,
						},
						elem.Span(
							attrs.Props{
								attrs.Class: classIcon,
							},
							iconExternalLink(),
						),
						elem.Text("View the headscale documentation"),
					),
					elem.A(
						attrs.Props{
							attrs.Href:   "https://tailscale.com/kb/",
							attrs.Rel:    "noreferrer noopener",
							attrs.Target: "_blank",
							attrs.Class:  styleA,
						},
						elem.Span(
							attrs.Props{
								attrs.Class: classIcon,
							},
							iconExternalLink(),
						),
						elem.Text("View the tailscale documentation"),
					),
				),
			),
		),
	).RenderWithOptions(elem.RenderOptions{
		StyleManager: styleMgr,
	})
}
