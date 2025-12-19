package capver

// Generated DO NOT EDIT

import "tailscale.com/tailcfg"

var tailscaleLatestMajorMinorTests = []struct {
	n        int
	stripV   bool
	expected []string
}{
	{3, false, []string{"v1.88", "v1.90", "v1.92"}},
	{2, true, []string{"1.90", "1.92"}},
	{9, true, []string{
		"1.76",
		"1.78",
		"1.80",
		"1.82",
		"1.84",
		"1.86",
		"1.88",
		"1.90",
		"1.92",
	}},
	{0, false, nil},
}

var capVerMinimumTailscaleVersionTests = []struct {
	input    tailcfg.CapabilityVersion
	expected string
}{
	{106, "v1.74.1"},
	{109, "v1.78.0"},
	{113, "v1.80.0"},
	{115, "v1.82.0"},
	{116, "v1.84.0"},
	{9001, ""}, // Test case for a version higher than any in the map
	{60, ""},   // Test case for a version lower than any in the map
}
