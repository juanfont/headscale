package templates

import (
	elem "github.com/chasefleming/elem-go"
	"github.com/chasefleming/elem-go/attrs"
	"github.com/chasefleming/elem-go/styles"
)

// Design System Constants
// These constants define the visual language for all Headscale HTML templates.
// They ensure consistency across all pages and make it easy to maintain and update the design.

// Color System
// EXTRACTED FROM: https://headscale.net/stable/assets/stylesheets/main.342714a4.min.css
// Material for MkDocs design system - exact values from official docs.
const (
	// Text colors - from --md-default-fg-color CSS variables.
	colorTextPrimary   = "#000000de" //nolint:unused // rgba(0,0,0,0.87) - Body text
	colorTextSecondary = "#0000008a" //nolint:unused // rgba(0,0,0,0.54) - Headings (--md-default-fg-color--light)
	colorTextTertiary  = "#00000052" //nolint:unused // rgba(0,0,0,0.32) - Lighter text
	colorTextLightest  = "#00000012" //nolint:unused // rgba(0,0,0,0.07) - Lightest text

	// Code colors - from --md-code-* CSS variables.
	colorCodeFg = "#36464e" //nolint:unused // Code text color (--md-code-fg-color)
	colorCodeBg = "#f5f5f5" //nolint:unused // Code background (--md-code-bg-color)

	// Border colors.
	colorBorderLight  = "#e5e7eb" //nolint:unused // Light borders
	colorBorderMedium = "#d1d5db" //nolint:unused // Medium borders

	// Background colors.
	colorBackgroundPage = "#ffffff" //nolint:unused // Page background
	colorBackgroundCard = "#ffffff" //nolint:unused // Card/content background

	// Accent colors - from --md-primary/accent-fg-color.
	colorPrimaryAccent = "#4051b5" //nolint:unused // Primary accent (links)
	colorAccent        = "#526cfe" //nolint:unused // Secondary accent

	// Success colors.
	colorSuccess      = "#059669" //nolint:unused // Success states
	colorSuccessLight = "#d1fae5" //nolint:unused // Success backgrounds
)

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

// Typography System
// EXTRACTED FROM: https://headscale.net/stable/assets/stylesheets/main.342714a4.min.css
// Material for MkDocs typography - exact values from .md-typeset CSS.
const (
	// Font families - from CSS custom properties.
	fontFamilySystem = `"Roboto", -apple-system, BlinkMacSystemFont, "Segoe UI", "Helvetica Neue", Arial, sans-serif` //nolint:unused
	fontFamilyCode   = `"Roboto Mono", "SF Mono", Monaco, "Cascadia Code", Consolas, "Courier New", monospace`        //nolint:unused

	// Font sizes - from .md-typeset CSS rules.
	fontSizeBase  = "0.8rem"   //nolint:unused // 12.8px - Base text (.md-typeset)
	fontSizeH1    = "2em"      //nolint:unused // 2x base - Main headings
	fontSizeH2    = "1.5625em" //nolint:unused // 1.5625x base - Section headings
	fontSizeH3    = "1.25em"   //nolint:unused // 1.25x base - Subsection headings
	fontSizeSmall = "0.8em"    //nolint:unused // 0.8x base - Small text
	fontSizeCode  = "0.85em"   //nolint:unused // 0.85x base - Inline code

	// Line heights - from .md-typeset CSS rules.
	lineHeightBase = "1.6" //nolint:unused // Body text (.md-typeset)
	lineHeightH1   = "1.3" //nolint:unused // H1 headings
	lineHeightH2   = "1.4" //nolint:unused // H2 headings
	lineHeightH3   = "1.5" //nolint:unused // H3 headings
	lineHeightCode = "1.4" //nolint:unused // Code blocks (pre)
)

// Responsive Container Component
// Creates a centered container with responsive padding and max-width.
// Mobile-first approach: starts at 100% width with padding, constrains on larger screens.
//
//nolint:unused // Reserved for future use in Phase 4.
func responsiveContainer(children ...elem.Node) *elem.Element {
	return elem.Div(attrs.Props{
		attrs.Style: styles.Props{
			styles.Width:    "100%",
			styles.MaxWidth: "min(800px, 90vw)",         // Responsive: 90% of viewport or 800px max
			styles.Margin:   "0 auto",                   // Center horizontally
			styles.Padding:  "clamp(1rem, 5vw, 2.5rem)", // Fluid padding: 16px to 40px
		}.ToInline(),
	}, children...)
}

// Card Component
// Reusable card for grouping related content with visual separation.
// Parameters:
//   - title: Optional title for the card (empty string for no title)
//   - children: Content elements to display in the card
//
//nolint:unused // Reserved for future use in Phase 4.
func card(title string, children ...elem.Node) *elem.Element {
	cardContent := children
	if title != "" {
		// Prepend title as H3 if provided
		cardContent = append([]elem.Node{
			elem.H3(attrs.Props{
				attrs.Style: styles.Props{
					styles.MarginTop:    "0",
					styles.MarginBottom: spaceM,
					styles.FontSize:     fontSizeH3,
					styles.LineHeight:   lineHeightH3, // 1.5 - H3 line height
					styles.Color:        colorTextSecondary,
				}.ToInline(),
			}, elem.Text(title)),
		}, children...)
	}

	return elem.Div(attrs.Props{
		attrs.Style: styles.Props{
			styles.Background:   colorBackgroundCard,
			styles.Border:       "1px solid " + colorBorderLight,
			styles.BorderRadius: "0.5rem",                   // 8px rounded corners
			styles.Padding:      "clamp(1rem, 3vw, 1.5rem)", // Responsive padding
			styles.MarginBottom: spaceL,
			styles.BoxShadow:    "0 1px 3px rgba(0,0,0,0.1)", // Subtle shadow
		}.ToInline(),
	}, cardContent...)
}

// Code Block Component
// EXTRACTED FROM: .md-typeset pre CSS rules
// Exact styling from Material for MkDocs documentation.
//
//nolint:unused // Used across apple.go, windows.go, register_web.go templates.
func codeBlock(code string) *elem.Element {
	return elem.Pre(attrs.Props{
		attrs.Style: styles.Props{
			styles.Display:         "block",
			styles.Padding:         "0.77em 1.18em", // From .md-typeset pre
			styles.Border:          "none",          // No border in original
			styles.BorderRadius:    "0.1rem",        // From .md-typeset code
			styles.BackgroundColor: colorCodeBg,     // #f5f5f5
			styles.FontFamily:      fontFamilyCode,  // Roboto Mono
			styles.FontSize:        fontSizeCode,    // 0.85em
			styles.LineHeight:      lineHeightCode,  // 1.4
			styles.OverflowX:       "auto",          // Horizontal scroll
			"overflow-wrap":        "break-word",    // Word wrapping
			"word-wrap":            "break-word",    // Legacy support
			styles.WhiteSpace:      "pre-wrap",      // Preserve whitespace
			styles.MarginTop:       spaceM,          // 1em
			styles.MarginBottom:    spaceM,          // 1em
			styles.Color:           colorCodeFg,     // #36464e
			styles.BoxShadow:       "none",          // No shadow in original
		}.ToInline(),
	},
		elem.Code(nil, elem.Text(code)),
	)
}

// Base Typeset Styles
// Returns inline styles for the main content container that matches .md-typeset.
// EXTRACTED FROM: .md-typeset CSS rule from Material for MkDocs.
//
//nolint:unused // Used in general.go for mdTypesetBody.
func baseTypesetStyles() styles.Props {
	return styles.Props{
		styles.FontSize:   fontSizeBase,   // 0.8rem
		styles.LineHeight: lineHeightBase, // 1.6
		styles.Color:      colorTextPrimary,
		styles.FontFamily: fontFamilySystem,
		"overflow-wrap":   "break-word",
		styles.TextAlign:  "left",
	}
}

// H1 Styles
// Returns inline styles for H1 headings that match .md-typeset h1.
// EXTRACTED FROM: .md-typeset h1 CSS rule from Material for MkDocs.
//
//nolint:unused // Used across templates for main headings.
func h1Styles() styles.Props {
	return styles.Props{
		styles.Color:      colorTextSecondary, // rgba(0, 0, 0, 0.54)
		styles.FontSize:   fontSizeH1,         // 2em
		styles.LineHeight: lineHeightH1,       // 1.3
		styles.Margin:     "0 0 1.25em",
		styles.FontWeight: "300",
		"letter-spacing":  "-0.01em",
		styles.FontFamily: fontFamilySystem, // Roboto
		"overflow-wrap":   "break-word",
	}
}

// H2 Styles
// Returns inline styles for H2 headings that match .md-typeset h2.
// EXTRACTED FROM: .md-typeset h2 CSS rule from Material for MkDocs.
//
//nolint:unused // Used across templates for section headings.
func h2Styles() styles.Props {
	return styles.Props{
		styles.FontSize:   fontSizeH2,   // 1.5625em
		styles.LineHeight: lineHeightH2, // 1.4
		styles.Margin:     "1.6em 0 0.64em",
		styles.FontWeight: "300",
		"letter-spacing":  "-0.01em",
		styles.Color:      colorTextSecondary, // rgba(0, 0, 0, 0.54)
		styles.FontFamily: fontFamilySystem,   // Roboto
		"overflow-wrap":   "break-word",
	}
}

// H3 Styles
// Returns inline styles for H3 headings that match .md-typeset h3.
// EXTRACTED FROM: .md-typeset h3 CSS rule from Material for MkDocs.
//
//nolint:unused // Used across templates for subsection headings.
func h3Styles() styles.Props {
	return styles.Props{
		styles.FontSize:   fontSizeH3,   // 1.25em
		styles.LineHeight: lineHeightH3, // 1.5
		styles.Margin:     "1.6em 0 0.8em",
		styles.FontWeight: "400",
		"letter-spacing":  "-0.01em",
		styles.Color:      colorTextSecondary, // rgba(0, 0, 0, 0.54)
		styles.FontFamily: fontFamilySystem,   // Roboto
		"overflow-wrap":   "break-word",
	}
}

// Paragraph Styles
// Returns inline styles for paragraphs that match .md-typeset p.
// EXTRACTED FROM: .md-typeset p CSS rule from Material for MkDocs.
//
//nolint:unused // Used for consistent paragraph spacing.
func paragraphStyles() styles.Props {
	return styles.Props{
		styles.Margin:     "1em 0",
		styles.FontFamily: fontFamilySystem, // Roboto
		styles.FontSize:   fontSizeBase,     // 0.8rem - inherited from .md-typeset
		styles.LineHeight: lineHeightBase,   // 1.6 - inherited from .md-typeset
		styles.Color:      colorTextPrimary, // rgba(0, 0, 0, 0.87)
		"overflow-wrap":   "break-word",
	}
}

// Ordered List Styles
// Returns inline styles for ordered lists that match .md-typeset ol.
// EXTRACTED FROM: .md-typeset ol CSS rule from Material for MkDocs.
//
//nolint:unused // Used for numbered instruction lists.
func orderedListStyles() styles.Props {
	return styles.Props{
		styles.MarginBottom: "1em",
		styles.MarginTop:    "1em",
		styles.PaddingLeft:  "2em",
		styles.FontFamily:   fontFamilySystem, // Roboto - inherited from .md-typeset
		styles.FontSize:     fontSizeBase,     // 0.8rem - inherited from .md-typeset
		styles.LineHeight:   lineHeightBase,   // 1.6 - inherited from .md-typeset
		styles.Color:        colorTextPrimary, // rgba(0, 0, 0, 0.87) - inherited from .md-typeset
		"overflow-wrap":     "break-word",
	}
}

// Unordered List Styles
// Returns inline styles for unordered lists that match .md-typeset ul.
// EXTRACTED FROM: .md-typeset ul CSS rule from Material for MkDocs.
//
//nolint:unused // Used for bullet point lists.
func unorderedListStyles() styles.Props {
	return styles.Props{
		styles.MarginBottom: "1em",
		styles.MarginTop:    "1em",
		styles.PaddingLeft:  "2em",
		styles.FontFamily:   fontFamilySystem, // Roboto - inherited from .md-typeset
		styles.FontSize:     fontSizeBase,     // 0.8rem - inherited from .md-typeset
		styles.LineHeight:   lineHeightBase,   // 1.6 - inherited from .md-typeset
		styles.Color:        colorTextPrimary, // rgba(0, 0, 0, 0.87) - inherited from .md-typeset
		"overflow-wrap":     "break-word",
	}
}

// Link Styles
// Returns inline styles for links that match .md-typeset a.
// EXTRACTED FROM: .md-typeset a CSS rule from Material for MkDocs.
// Note: Hover states cannot be implemented with inline styles.
//
//nolint:unused // Used for text links.
func linkStyles() styles.Props {
	return styles.Props{
		styles.Color:          colorPrimaryAccent, // #4051b5 - var(--md-primary-fg-color)
		styles.TextDecoration: "none",
		"word-break":          "break-word",
		styles.FontFamily:     fontFamilySystem, // Roboto - inherited from .md-typeset
	}
}

// Inline Code Styles (updated)
// Returns inline styles for inline code that matches .md-typeset code.
// EXTRACTED FROM: .md-typeset code CSS rule from Material for MkDocs.
//
//nolint:unused // Used for inline code snippets.
func inlineCodeStyles() styles.Props {
	return styles.Props{
		styles.BackgroundColor: colorCodeBg, // #f5f5f5
		styles.Color:           colorCodeFg, // #36464e
		styles.BorderRadius:    "0.1rem",
		styles.FontSize:        fontSizeCode,   // 0.85em
		styles.FontFamily:      fontFamilyCode, // Roboto Mono
		styles.Padding:         "0 0.2941176471em",
		"word-break":           "break-word",
	}
}

// Inline Code Component
// For inline code snippets within text.
//
//nolint:unused // Reserved for future inline code usage.
func inlineCode(code string) *elem.Element {
	return elem.Code(attrs.Props{
		attrs.Style: inlineCodeStyles().ToInline(),
	}, elem.Text(code))
}

// orDivider creates a visual "or" divider between sections.
// Styled with lines on either side for better visual separation.
//
//nolint:unused // Used in apple.go template.
func orDivider() *elem.Element {
	return elem.Div(attrs.Props{
		attrs.Style: styles.Props{
			styles.Display:      "flex",
			styles.AlignItems:   "center",
			styles.Gap:          spaceM,
			styles.MarginTop:    space2XL,
			styles.MarginBottom: space2XL,
			styles.Width:        "100%",
		}.ToInline(),
	},
		elem.Div(attrs.Props{
			attrs.Style: styles.Props{
				styles.Flex:            "1",
				styles.Height:          "1px",
				styles.BackgroundColor: colorBorderLight,
			}.ToInline(),
		}),
		elem.Strong(attrs.Props{
			attrs.Style: styles.Props{
				styles.Color:      colorTextSecondary,
				styles.FontSize:   fontSizeBase,
				styles.FontWeight: "500",
				"text-transform":  "uppercase",
				"letter-spacing":  "0.05em",
			}.ToInline(),
		}, elem.Text("or")),
		elem.Div(attrs.Props{
			attrs.Style: styles.Props{
				styles.Flex:            "1",
				styles.Height:          "1px",
				styles.BackgroundColor: colorBorderLight,
			}.ToInline(),
		}),
	)
}

// warningBox creates a warning message box with icon and content.
//
//nolint:unused // Used in apple.go template.
func warningBox(title, message string) *elem.Element {
	return elem.Div(attrs.Props{
		attrs.Style: styles.Props{
			styles.Display:         "flex",
			styles.AlignItems:      "flex-start",
			styles.Gap:             spaceM,
			styles.Padding:         spaceL,
			styles.BackgroundColor: "#fef3c7",           // yellow-100
			styles.Border:          "1px solid #f59e0b", // yellow-500
			styles.BorderRadius:    "0.5rem",
			styles.MarginTop:       spaceL,
			styles.MarginBottom:    spaceL,
		}.ToInline(),
	},
		elem.Raw(`<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#f59e0b" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="flex-shrink: 0; margin-top: 2px;"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg>`),
		elem.Div(nil,
			elem.Strong(attrs.Props{
				attrs.Style: styles.Props{
					styles.Display:      "block",
					styles.Color:        "#92400e", // yellow-800
					styles.FontSize:     fontSizeH3,
					styles.MarginBottom: spaceXS,
				}.ToInline(),
			}, elem.Text(title)),
			elem.Div(attrs.Props{
				attrs.Style: styles.Props{
					styles.Color:    colorTextPrimary,
					styles.FontSize: fontSizeBase,
				}.ToInline(),
			}, elem.Text(message)),
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
			styles.Display:         "inline-block",
			styles.Padding:         "0.75rem 1.5rem",
			styles.BackgroundColor: "#3b82f6", // blue-500
			styles.Color:           "#ffffff",
			styles.TextDecoration:  "none",
			styles.BorderRadius:    "0.5rem",
			styles.FontWeight:      "500",
			styles.Transition:      "background-color 0.2s",
			styles.MarginRight:     spaceM,
			styles.MarginBottom:    spaceM,
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
		attrs.Style: styles.Props{
			styles.Color:          colorPrimaryAccent, // #4051b5 - base link color
			styles.TextDecoration: "none",
		}.ToInline(),
	}, elem.Text(text))
}

// Instruction Step Component
// For numbered instruction lists with consistent formatting.
//
//nolint:unused // Reserved for future use in Phase 4.
func instructionStep(_ int, text string) *elem.Element {
	return elem.Li(attrs.Props{
		attrs.Style: styles.Props{
			styles.MarginBottom: spaceS,
			styles.LineHeight:   lineHeightBase,
		}.ToInline(),
	}, elem.Text(text))
}

// Status Message Component
// For displaying success/error/info messages with appropriate styling.
//
//nolint:unused // Reserved for future use in Phase 4.
func statusMessage(message string, isSuccess bool) *elem.Element {
	bgColor := colorSuccessLight
	textColor := colorSuccess

	if !isSuccess {
		bgColor = "#fee2e2"   // red-100
		textColor = "#dc2626" // red-600
	}

	return elem.Div(attrs.Props{
		attrs.Style: styles.Props{
			styles.Padding:         spaceM,
			styles.BackgroundColor: bgColor,
			styles.Color:           textColor,
			styles.BorderRadius:    "0.5rem",
			styles.Border:          "1px solid " + textColor,
			styles.MarginBottom:    spaceL,
			styles.FontSize:        fontSizeBase,
			styles.LineHeight:      lineHeightBase,
		}.ToInline(),
	}, elem.Text(message))
}
