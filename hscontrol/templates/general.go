package templates

import (
	"github.com/chasefleming/elem-go"
	"github.com/chasefleming/elem-go/attrs"
	"github.com/chasefleming/elem-go/styles"
)

// bodyStyle provides consistent body styling across all templates with
// a centered, readable layout and appropriate spacing.
var bodyStyle = styles.Props{
	styles.Margin:     "40px auto",
	styles.MaxWidth:   "800px",
	styles.LineHeight: "1.5",
	styles.FontSize:   "16px",
	styles.Color:      "#444",
	styles.Padding:    "0 10px",
	styles.FontFamily: "sans-serif",
}

// headerStyle provides consistent header styling with improved line height
var headerStyle = styles.Props{
	styles.LineHeight: "1.2",
}

// headerOne creates a level 1 heading with consistent styling
func headerOne(text string) *elem.Element {
	return elem.H1(attrs.Props{attrs.Style: headerStyle.ToInline()}, elem.Text(text))
}

// headerTwo creates a level 2 heading with consistent styling
func headerTwo(text string) *elem.Element {
	return elem.H2(attrs.Props{attrs.Style: headerStyle.ToInline()}, elem.Text(text))
}

// headerThree creates a level 3 heading with consistent styling
func headerThree(text string) *elem.Element {
	return elem.H3(attrs.Props{attrs.Style: headerStyle.ToInline()}, elem.Text(text))
}

// HtmlStructure creates a complete HTML document structure with proper meta tags
// and semantic HTML5 structure. The head and body elements are passed as parameters
// to allow for customization of each page.
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
				attrs.Rel: "icon",
				attrs.Href: "/favicon.ico",
			}),
			head,
		),
		body,
	)
}
