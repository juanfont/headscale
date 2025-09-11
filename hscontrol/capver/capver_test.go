package capver

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestTailscaleLatestMajorMinor(t *testing.T) {
	for _, test := range tailscaleLatestMajorMinorTests {
		t.Run("", func(t *testing.T) {
			output := TailscaleLatestMajorMinor(test.n, test.stripV)
			if diff := cmp.Diff(output, test.expected); diff != "" {
				t.Errorf("TailscaleLatestMajorMinor(%d, %v) mismatch (-want +got):\n%s", test.n, test.stripV, diff)
			}
		})
	}
}

func TestCapVerMinimumTailscaleVersion(t *testing.T) {
	for _, test := range capVerMinimumTailscaleVersionTests {
		t.Run("", func(t *testing.T) {
			output := TailscaleVersion(test.input)
			if output != test.expected {
				t.Errorf("CapVerFromTailscaleVersion(%d) = %s; want %s", test.input, output, test.expected)
			}
		})
	}
}
