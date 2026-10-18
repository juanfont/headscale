package capver

// Generated DO NOT EDIT

import "tailscale.com/tailcfg"

var tailscaleLatestMajorMinorTests = []struct {
	n        int
	stripV   bool
	expected []string
}{
	{3, false, []string{"v1.98", "v1.102", "v1.104"}},
	{2, true, []string{"1.102", "1.104"}},
	{10, true, []string{
		"1.84",
		"1.86",
		"1.88",
		"1.90",
		"1.92",
		"1.94",
		"1.96",
		"1.98",
		"1.102",
		"1.104",
	}},
	{0, false, nil},
}

var capVerMinimumTailscaleVersionTests = []struct {
	input    tailcfg.CapabilityVersion
	expected string
}{
	{116, "v1.84"},
	{32, "v1.24"},
	{41, "v1.30"},
	{46, "v1.32"},
	{51, "v1.34"},
	{9001, ""}, // Test case for a version higher than any in the map
	{60, ""},   // Test case for a version lower than any in the map
}
