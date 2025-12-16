package templates

import (
	"github.com/chasefleming/elem-go"
	"github.com/chasefleming/elem-go/attrs"
	"github.com/chasefleming/elem-go/styles"
	"github.com/juanfont/headscale/hscontrol/assets"
)

var bodyStyle = styles.Props{
	styles.Margin:     "40px auto",
	styles.MaxWidth:   "800px",
	styles.LineHeight: "1.5",
	styles.FontSize:   "16px",
	styles.Color:      "#444",
	styles.Padding:    "0 10px",
	styles.FontFamily: "Sans-serif",
}

var headerStyle = styles.Props{
	styles.LineHeight: "1.2",
}

func headerOne(text string) *elem.Element {
	return elem.H1(attrs.Props{attrs.Style: headerStyle.ToInline()}, elem.Text(text))
}

func headerTwo(text string) *elem.Element {
	return elem.H2(attrs.Props{attrs.Style: headerStyle.ToInline()}, elem.Text(text))
}

func headerThree(text string) *elem.Element {
	return elem.H3(attrs.Props{attrs.Style: headerStyle.ToInline()}, elem.Text(text))
}

func HtmlStructure(head, body *elem.Element) *elem.Element {
	return elem.Html(nil,
		elem.Head(
			attrs.Props{
				attrs.Lang: "en",
			},
			elem.Meta(attrs.Props{
				attrs.Charset: "UTF-8",
			}),
			elem.Meta(attrs.Props{
				attrs.HTTPequiv: "X-UA-Compatible",
				attrs.Content:   "IE=edge",
			}),
			elem.Meta(attrs.Props{
				attrs.Name:    "viewport",
				attrs.Content: "width=device-width, initial-scale=1.0",
			}),
			elem.Style(nil, elem.Text(assets.CSS)),
			head,
		),
		body,
	)
}

// mdTypesetBody creates a body element with md-typeset styling for Material for MkDocs design.
func mdTypesetBody(children ...elem.Node) *elem.Element {
	return elem.Body(attrs.Props{
		attrs.Class: "md-typeset",
		attrs.Style: baseTypesetStyles().ToInline(),
	}, children...)
}

// headscaleLogo returns the headscale logo SVG as a raw HTML element.
func headscaleLogo() elem.Node {
	return elem.Raw(assets.SVG)
}

// H2 creates an H2 heading with Material for MkDocs styling.
func H2(children ...elem.Node) *elem.Element {
	return elem.H2(attrs.Props{
		attrs.Style: h2Styles().ToInline(),
	}, children...)
}

// P creates a paragraph with Material for MkDocs styling.
func P(children ...elem.Node) *elem.Element {
	return elem.P(attrs.Props{
		attrs.Style: paragraphStyles().ToInline(),
	}, children...)
}

// Ul creates an unordered list with Material for MkDocs styling.
func Ul(children ...elem.Node) *elem.Element {
	return elem.Ul(attrs.Props{
		attrs.Style: unorderedListStyles().ToInline(),
	}, children...)
}

// pageFooter creates a simple footer with copyright information.
func pageFooter() *elem.Element {
	return elem.Div(attrs.Props{
		attrs.Style: styles.Props{
			styles.MarginTop:    space2XL,
			styles.PaddingTop:   spaceM,
			styles.BorderTop:    "1px solid " + colorBorderLight,
			styles.Color:        colorTextSecondary,
			styles.FontSize:     fontSizeSmall,
			styles.TextAlign:    "center",
		}.ToInline(),
	},
		elem.P(attrs.Props{
			attrs.Style: styles.Props{
				styles.Margin: "0",
			}.ToInline(),
		}, elem.Text("Powered by "), externalLink("https://github.com/juanfont/headscale", "Headscale")),
	)
}
