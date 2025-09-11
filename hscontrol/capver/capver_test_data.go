package capver

// Generated DO NOT EDIT

import "tailscale.com/tailcfg"

var tailscaleLatestMajorMinorTests = []struct {
	n        int
	stripV   bool
	expected []string
}{
	{3, false, []string{"v1.82", "v1.84", "v1.86"}},
	{2, true, []string{"1.84", "1.86"}},
	{10, true, []string{
		"1.68",
		"1.70",
		"1.72",
		"1.74",
		"1.76",
		"1.78",
		"1.80",
		"1.82",
		"1.84",
		"1.86",
	}},
	{0, false, nil},
}

var capVerMinimumTailscaleVersionTests = []struct {
	input    tailcfg.CapabilityVersion
	expected string
}{
	{97, "v1.68.0"},
	{90, "v1.64.2"},
	{95, "v1.66.0"},
	{102, "v1.70.0"},
	{104, "v1.72.0"},
	{9001, ""}, // Test case for a version higher than any in the map
	{60, ""},   // Test case for a version lower than any in the map
}
