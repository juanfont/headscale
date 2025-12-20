package templates

import (
	"github.com/chasefleming/elem-go"
	"github.com/chasefleming/elem-go/attrs"
	"github.com/chasefleming/elem-go/styles"
	"github.com/juanfont/headscale/hscontrol/assets"
)

// mdTypesetBody creates a body element with md-typeset styling
// that matches the official Headscale documentation design.
// Uses CSS classes with styles defined in assets.CSS.
func mdTypesetBody(children ...elem.Node) *elem.Element {
	return elem.Body(attrs.Props{
		attrs.Style: styles.Props{
			styles.MinHeight:       "100vh",
			styles.Display:         "flex",
			styles.FlexDirection:   "column",
			styles.AlignItems:      "center",
			styles.BackgroundColor: "#ffffff",
			styles.Padding:         "3rem 1.5rem",
		}.ToInline(),
		"translate": "no",
	},
		elem.Div(attrs.Props{
			attrs.Class: "md-typeset",
			attrs.Style: styles.Props{
				styles.MaxWidth: "min(800px, 90vw)",
				styles.Width:    "100%",
			}.ToInline(),
		}, children...),
	)
}

// Styled Element Wrappers
// These functions wrap elem-go elements using CSS classes.
// Styling is handled by the CSS in assets.CSS.

// H1 creates a H1 element styled by .md-typeset h1
func H1(children ...elem.Node) *elem.Element {
	return elem.H1(nil, children...)
}

// H2 creates a H2 element styled by .md-typeset h2
func H2(children ...elem.Node) *elem.Element {
	return elem.H2(nil, children...)
}

// H3 creates a H3 element styled by .md-typeset h3
func H3(children ...elem.Node) *elem.Element {
	return elem.H3(nil, children...)
}

// P creates a paragraph element styled by .md-typeset p
func P(children ...elem.Node) *elem.Element {
	return elem.P(nil, children...)
}

// Ol creates an ordered list element styled by .md-typeset ol
func Ol(children ...elem.Node) *elem.Element {
	return elem.Ol(nil, children...)
}

// Ul creates an unordered list element styled by .md-typeset ul
func Ul(children ...elem.Node) *elem.Element {
	return elem.Ul(nil, children...)
}

// A creates a link element styled by .md-typeset a
func A(href string, children ...elem.Node) *elem.Element {
	return elem.A(attrs.Props{attrs.Href: href}, children...)
}

// Code creates an inline code element styled by .md-typeset code
func Code(children ...elem.Node) *elem.Element {
	return elem.Code(nil, children...)
}

// Pre creates a preformatted text block styled by .md-typeset pre
func Pre(children ...elem.Node) *elem.Element {
	return elem.Pre(nil, children...)
}

// PreCode creates a code block inside Pre styled by .md-typeset pre > code
func PreCode(code string) *elem.Element {
	return elem.Code(nil, elem.Text(code))
}

// Deprecated: use H1, H2, H3 instead
func headerOne(text string) *elem.Element {
	return H1(elem.Text(text))
}

// Deprecated: use H1, H2, H3 instead
func headerTwo(text string) *elem.Element {
	return H2(elem.Text(text))
}

// Deprecated: use H1, H2, H3 instead
func headerThree(text string) *elem.Element {
	return H3(elem.Text(text))
}

// contentContainer wraps page content with proper width.
// Content inside is left-aligned by default.
func contentContainer(children ...elem.Node) *elem.Element {
	containerStyle := styles.Props{
		styles.MaxWidth:      "720px",
		styles.Width:         "100%",
		styles.Display:       "flex",
		styles.FlexDirection: "column",
		styles.AlignItems:    "flex-start", // Left-align all children
	}

	return elem.Div(attrs.Props{attrs.Style: containerStyle.ToInline()}, children...)
}

// headscaleLogo returns the Headscale SVG logo for consistent branding across all pages.
// The logo is styled by the .headscale-logo CSS class.
func headscaleLogo() elem.Node {
	// Return the embedded SVG as-is
	return elem.Raw(assets.SVG)
}

// pageFooter creates a consistent footer for all pages.
func pageFooter() *elem.Element {
	footerStyle := styles.Props{
		styles.MarginTop:  space3XL,
		styles.TextAlign:  "center",
		styles.FontSize:   fontSizeSmall,
		styles.Color:      colorTextSecondary,
		styles.LineHeight: lineHeightBase,
	}

	linkStyle := styles.Props{
		styles.Color:          colorTextSecondary,
		styles.TextDecoration: "underline",
	}

	return elem.Div(attrs.Props{attrs.Style: footerStyle.ToInline()},
		elem.Text("Powered by "),
		elem.A(attrs.Props{
			attrs.Href:   "https://github.com/juanfont/headscale",
			attrs.Rel:    "noreferrer noopener",
			attrs.Target: "_blank",
			attrs.Style:  linkStyle.ToInline(),
		}, elem.Text("Headscale")),
	)
}

// listStyle provides consistent styling for ordered and unordered lists
// EXTRACTED FROM: .md-typeset ol, .md-typeset ul CSS rules
var listStyle = styles.Props{
	styles.LineHeight:   lineHeightBase,               // 1.6 - From .md-typeset
	styles.MarginTop:    "1em",                        // From CSS: margin-top: 1em
	styles.MarginBottom: "1em",                        // From CSS: margin-bottom: 1em
	styles.PaddingLeft:  "clamp(1.5rem, 5vw, 2.5rem)", // Responsive indentation
}

// HtmlStructure creates a complete HTML document structure with proper meta tags
// and semantic HTML5 structure. The head and body elements are passed as parameters
// to allow for customization of each page.
// Styling is provided via a CSS stylesheet (Material for MkDocs design system) with
// minimal inline styles for layout and positioning.
func HtmlStructure(head, body *elem.Element) *elem.Element {
	return elem.Html(attrs.Props{attrs.Lang: "en"},
		elem.Head(nil,
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
			elem.Link(attrs.Props{
				attrs.Rel:  "icon",
				attrs.Href: "/favicon.ico",
			}),
			// Google Fonts for Roboto and Roboto Mono
			elem.Link(attrs.Props{
				attrs.Rel:     "preconnect",
				attrs.Href:    "https://fonts.gstatic.com",
				"crossorigin": "",
			}),
			elem.Link(attrs.Props{
				attrs.Rel:  "stylesheet",
				attrs.Href: "https://fonts.googleapis.com/css2?family=Roboto:wght@300;400;500;700&family=Roboto+Mono:wght@400;700&display=swap",
			}),
			// Material for MkDocs CSS styles
			elem.Style(attrs.Props{attrs.Type: "text/css"}, elem.Raw(assets.CSS)),
			head,
		),
		body,
	)
}

// BlankPage creates a minimal blank HTML page with favicon.
// Used for endpoints that need to return a valid HTML page with no content.
func BlankPage() *elem.Element {
	return elem.Html(attrs.Props{attrs.Lang: "en"},
		elem.Head(nil,
			elem.Meta(attrs.Props{
				attrs.Charset: "UTF-8",
			}),
			elem.Link(attrs.Props{
				attrs.Rel:  "icon",
				attrs.Href: "/favicon.ico",
			}),
		),
		elem.Body(nil),
	)
}
