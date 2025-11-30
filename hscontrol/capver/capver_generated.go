package capver

// Generated DO NOT EDIT

import "tailscale.com/tailcfg"

var tailscaleToCapVer = map[string]tailcfg.CapabilityVersion{
	"v1.70.0": 102,
	"v1.72.0": 104,
	"v1.72.1": 104,
	"v1.74.0": 106,
	"v1.74.1": 106,
	"v1.76.0": 106,
	"v1.76.1": 106,
	"v1.76.6": 106,
	"v1.78.0": 109,
	"v1.78.1": 109,
	"v1.80.0": 113,
	"v1.80.1": 113,
	"v1.80.2": 113,
	"v1.80.3": 113,
	"v1.82.0": 115,
	"v1.82.5": 115,
	"v1.84.0": 116,
	"v1.84.1": 116,
	"v1.84.2": 116,
	"v1.86.0": 122,
	"v1.86.2": 123,
	"v1.88.1": 125,
	"v1.88.3": 125,
	"v1.90.1": 130,
	"v1.90.2": 130,
	"v1.90.3": 130,
	"v1.90.4": 130,
	"v1.90.6": 130,
	"v1.90.8": 130,
	"v1.90.9": 130,
}

var capVerToTailscaleVer = map[tailcfg.CapabilityVersion]string{
	102: "v1.70.0",
	104: "v1.72.0",
	106: "v1.74.0",
	109: "v1.78.0",
	113: "v1.80.0",
	115: "v1.82.0",
	116: "v1.84.0",
	122: "v1.86.0",
	123: "v1.86.2",
	125: "v1.88.1",
	130: "v1.90.1",
}

// SupportedMajorMinorVersions is the number of major.minor Tailscale versions supported.
const SupportedMajorMinorVersions = 9

// MinSupportedCapabilityVersion represents the minimum capability version
// supported by this Headscale instance (latest 10 minor versions)
const MinSupportedCapabilityVersion tailcfg.CapabilityVersion = 106
