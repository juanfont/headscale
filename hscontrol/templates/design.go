package templates

import (
	elem "github.com/chasefleming/elem-go"
	"github.com/chasefleming/elem-go/attrs"
	"github.com/chasefleming/elem-go/styles"
)

// Design System Constants
// These constants define the visual language for all Headscale HTML templates.
// They ensure consistency across all pages and make it easy to maintain and update the design.

// Spacing System
// Based on 4px/8px base unit for consistent rhythm.
// Uses rem units for scalability with user font size preferences.
const (
	spaceXS  = "0.25rem" //nolint:unused // 4px - Tight spacing
	spaceS   = "0.5rem"  //nolint:unused // 8px - Small spacing
	spaceM   = "1rem"    //nolint:unused // 16px - Medium spacing (base)
	spaceL   = "1.5rem"  //nolint:unused // 24px - Large spacing
	spaceXL  = "2rem"    //nolint:unused // 32px - Extra large spacing
	space2XL = "3rem"    //nolint:unused // 48px - 2x extra large spacing
	space3XL = "4rem"    //nolint:unused // 64px - 3x extra large spacing
)

// Shared CSS value constants used across templates.
const (
	cssBorderHS = "1px solid var(--hs-border)" //nolint:unused // Shared HS border
	cssCenter   = "center"                     //nolint:unused // Center alignment
)

// Typography System
// EXTRACTED FROM: https://headscale.net/stable/assets/stylesheets/main.342714a4.min.css
// Material for MkDocs typography - exact values from .md-typeset CSS.
const (
	// Font sizes - from .md-typeset CSS rules.
	fontSizeBase  = "0.8rem" //nolint:unused // 12.8px - Base text (.md-typeset)
	fontSizeH3    = "1.25em" //nolint:unused // 1.25x base - Subsection headings
	fontSizeSmall = "0.8em"  //nolint:unused // 0.8x base - Small text

	// Line heights - from .md-typeset CSS rules.
	lineHeightBase = "1.6" //nolint:unused // Body text (.md-typeset)
)

// orDivider creates a visual "or" divider between sections.
// Styled with lines on either side for better visual separation.
//
//nolint:unused // Used in apple.go template.
func orDivider() *elem.Element {
	lineStyle := styles.Props{
		styles.Flex:            "1",
		styles.Height:          "1px",
		styles.BackgroundColor: "var(--hs-border)",
	}.ToInline()

	return elem.Div(
		attrs.Props{
			attrs.Style: styles.Props{
				styles.Display:      "flex",
				styles.AlignItems:   cssCenter,
				styles.Gap:          spaceM,
				styles.MarginTop:    space2XL,
				styles.MarginBottom: space2XL,
				styles.Width:        "100%",
			}.ToInline(),
		},
		elem.Div(attrs.Props{attrs.Style: lineStyle}),
		elem.Strong(attrs.Props{
			attrs.Style: styles.Props{
				styles.Color:      "var(--md-default-fg-color--light)",
				styles.FontSize:   fontSizeBase,
				styles.FontWeight: "500",
				"text-transform":  "uppercase",
				"letter-spacing":  "0.05em",
			}.ToInline(),
		}, elem.Text("or")),
		elem.Div(attrs.Props{attrs.Style: lineStyle}),
	)
}

// feedbackBox creates a coloured feedback box with an icon and a bold heading.
// colorVar provides both the border and heading colour, bgVar the background;
// role and ariaLive set the accessibility attributes. Children render below the
// heading.
//
//nolint:unused // Wrapped by successBox and errorBox.
func feedbackBox(
	icon elem.Node,
	colorVar, bgVar, role, ariaLive, heading string,
	children ...elem.Node,
) *elem.Element {
	return elem.Div(
		attrs.Props{
			attrs.Style: styles.Props{
				styles.Display:         "flex",
				styles.AlignItems:      cssCenter,
				styles.Gap:             spaceM,
				styles.Padding:         spaceL,
				styles.BackgroundColor: bgVar,
				styles.Border:          "1px solid " + colorVar,
				styles.BorderRadius:    spaceS,
				styles.MarginBottom:    spaceXL,
			}.ToInline(),
			attrs.Role:  role,
			"aria-live": ariaLive,
		},
		icon,
		elem.Div(
			nil,
			append([]elem.Node{
				elem.Strong(attrs.Props{
					attrs.Style: styles.Props{
						styles.Display:      "block",
						styles.Color:        colorVar,
						styles.FontSize:     fontSizeH3,
						styles.FontWeight:   "700",
						styles.MarginBottom: spaceXS,
					}.ToInline(),
				}, elem.Text(heading)),
			}, children...)...,
		),
	)
}

// successBox creates a green success feedback box with a checkmark icon.
// The heading is displayed as bold green text, and children are rendered below it.
// Pairs with warningBox for consistent feedback styling.
//
//nolint:unused // Used in auth_success.go template.
func successBox(heading string, children ...elem.Node) *elem.Element {
	return feedbackBox(
		checkboxIcon(),
		"var(--hs-success)", "var(--hs-success-bg)", "status", "polite",
		heading, children...,
	)
}

// checkboxIcon returns the success checkbox SVG icon as raw HTML.
func checkboxIcon() elem.Node {
	return elem.Raw(`<svg id="checkbox" aria-hidden="true" xmlns="http://www.w3.org/2000/svg" width="48" height="48" viewBox="0 0 512 512" style="flex-shrink:0">
  <path fill="currentColor" d="M256 32C132.3 32 32 132.3 32 256s100.3 224 224 224 224-100.3 224-224S379.7 32 256 32zm114.9 149.1L231.8 359.6c-1.1 1.1-2.9 3.5-5.1 3.5-2.3 0-3.8-1.6-5.1-2.9-1.3-1.3-78.9-75.9-78.9-75.9l-1.5-1.5c-.6-.9-1.1-2-1.1-3.2 0-1.2.5-2.3 1.1-3.2.4-.4.7-.7 1.1-1.2 7.7-8.1 23.3-24.5 24.3-25.5 1.3-1.3 2.4-3 4.8-3 2.5 0 4.1 2.1 5.3 3.3 1.2 1.2 45 43.3 45 43.3l111.3-143c1-.8 2.2-1.4 3.5-1.4 1.3 0 2.5.5 3.5 1.3l30.6 24.1c.8 1 1.3 2.2 1.3 3.5.1 1.3-.4 2.4-1 3.3z"></path>
</svg>`)
}

// errorBox creates a red error feedback box with an X-circle icon.
// The heading is displayed as bold red text, and children are rendered below it.
// Pairs with successBox for consistent feedback styling.
//
//nolint:unused // Used in auth_error.go template.
func errorBox(heading string, children ...elem.Node) *elem.Element {
	return feedbackBox(
		errorIcon(),
		"var(--hs-error)", "var(--hs-error-bg)", "alert", "assertive",
		heading, children...,
	)
}

// errorIcon returns the error X-circle SVG icon as raw HTML.
func errorIcon() elem.Node {
	return elem.Raw(`<svg id="error-icon" aria-hidden="true" xmlns="http://www.w3.org/2000/svg" width="48" height="48" viewBox="0 0 24 24" style="flex-shrink:0">
  <circle cx="12" cy="12" r="10" fill="currentColor"/>
  <path d="M15 9l-6 6M9 9l6 6" stroke="var(--hs-error-bg, #fee2e2)" stroke-width="2" stroke-linecap="round"/>
</svg>`)
}

// warningBox creates a warning message box with icon and content.
//
//nolint:unused // Used in apple.go template.
func warningBox(title, message string) *elem.Element {
	return elem.Div(
		attrs.Props{
			attrs.Style: styles.Props{
				styles.Display:         "flex",
				styles.AlignItems:      "flex-start",
				styles.Gap:             spaceM,
				styles.Padding:         spaceL,
				styles.BackgroundColor: "var(--hs-warning-bg)",
				styles.Border:          "1px solid var(--hs-warning-border)",
				styles.BorderRadius:    spaceS,
				styles.MarginTop:       spaceL,
				styles.MarginBottom:    spaceL,
			}.ToInline(),
			attrs.Role: "note",
		},
		elem.Raw(`<svg aria-hidden="true" xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="var(--hs-warning-border)" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="flex-shrink: 0; margin-top: 2px;"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg>`),
		elem.Div(
			nil,
			elem.Strong(attrs.Props{
				attrs.Style: styles.Props{
					styles.Display:      "block",
					styles.Color:        "var(--hs-warning-text)",
					styles.FontSize:     fontSizeH3,
					styles.MarginBottom: spaceXS,
				}.ToInline(),
			}, elem.Text(title)),
			elem.Div(nil, elem.Text(message)),
		),
	)
}

// downloadButton creates a nice button-style link for downloads.
//
//nolint:unused // Used in apple.go template.
func downloadButton(href, text string) *elem.Element {
	return elem.A(attrs.Props{
		attrs.Href:     href,
		attrs.Download: "headscale_macos.mobileconfig",
		attrs.Style: styles.Props{
			styles.Display:         "inline-flex",
			styles.AlignItems:      cssCenter,
			styles.Padding:         "0.75rem 1.5rem",
			styles.BackgroundColor: "var(--md-primary-fg-color)",
			styles.Color:           "#ffffff",
			styles.TextDecoration:  "none",
			styles.BorderRadius:    "0.375rem",
			styles.FontWeight:      "500",
			styles.Transition:      "background-color 150ms ease-out",
			styles.MarginRight:     spaceM,
			styles.MarginBottom:    spaceM,
			"min-height":           "44px",
		}.ToInline(),
	}, elem.Text(text))
}

// External Link Component
// Creates a link with proper security attributes for external URLs.
// Automatically adds rel="noreferrer noopener" and target="_blank".
//
//nolint:unused // Used in apple.go, oidc_callback.go templates.
func externalLink(href, text string) *elem.Element {
	return elem.A(attrs.Props{
		attrs.Href:   href,
		attrs.Rel:    "noreferrer noopener",
		attrs.Target: "_blank",
	}, elem.Text(text))
}

// detailsBox creates a collapsible <details>/<summary> section.
// Styled to match the card/box component family (border, radius, CSS variables).
// Collapsed by default; the user clicks the summary to expand.
//
//nolint:unused // Used in ping.go template.
func detailsBox(summary string, children ...elem.Node) *elem.Element {
	return elem.Details(
		attrs.Props{
			attrs.Style: styles.Props{
				styles.Background:   "var(--hs-bg)",
				styles.Border:       cssBorderHS,
				styles.BorderRadius: spaceS,
				styles.Padding:      spaceS + " " + spaceM,
				styles.MarginTop:    spaceL,
				styles.MarginBottom: spaceL,
			}.ToInline(),
		},
		elem.Summary(attrs.Props{
			attrs.Style: styles.Props{
				"cursor":          "pointer",
				styles.FontWeight: "500",
				styles.Color:      "var(--md-default-fg-color--light)",
				styles.Padding:    spaceS + " 0",
			}.ToInline(),
		}, elem.Text(summary)),
		elem.Div(attrs.Props{
			attrs.Style: styles.Props{
				styles.PaddingTop: spaceS,
				styles.Color:      "var(--md-default-fg-color)",
			}.ToInline(),
		}, children...),
	)
}
