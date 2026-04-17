package templates

import (
	"strings"
	"testing"
)

// TestPingPageEscapesQuery asserts hostile query values cannot break out of
// the input's value attribute. elem-go does not escape attribute values, so
// the template must escape before rendering.
func TestPingPageEscapesQuery(t *testing.T) {
	payloads := []string{
		`" autofocus onfocus=alert(1) x="`,
		`"><script>alert(1)</script>`,
		`<img src=x onerror=alert(1)>`,
	}

	for _, p := range payloads {
		t.Run(p, func(t *testing.T) {
			out := PingPage(p, nil, nil).Render()
			if strings.Contains(out, p) {
				t.Fatalf("unescaped payload rendered verbatim: %q", p)
			}
		})
	}
}
