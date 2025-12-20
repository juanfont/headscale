package capver

// Generated DO NOT EDIT

import "tailscale.com/tailcfg"

var tailscaleToCapVer = map[string]tailcfg.CapabilityVersion{
	"v1.24": 32,
	"v1.26": 32,
	"v1.28": 32,
	"v1.30": 41,
	"v1.32": 46,
	"v1.34": 51,
	"v1.36": 56,
	"v1.38": 58,
	"v1.40": 61,
	"v1.42": 62,
	"v1.44": 63,
	"v1.46": 65,
	"v1.48": 68,
	"v1.50": 74,
	"v1.52": 79,
	"v1.54": 79,
	"v1.56": 82,
	"v1.58": 85,
	"v1.60": 87,
	"v1.62": 88,
	"v1.64": 90,
	"v1.66": 95,
	"v1.68": 97,
	"v1.70": 102,
	"v1.72": 104,
	"v1.74": 106,
	"v1.76": 106,
	"v1.78": 109,
	"v1.80": 113,
	"v1.82": 115,
	"v1.84": 116,
	"v1.86": 123,
	"v1.88": 125,
	"v1.90": 130,
	"v1.92": 131,
}

var capVerToTailscaleVer = map[tailcfg.CapabilityVersion]string{
	32:  "v1.24",
	41:  "v1.30",
	46:  "v1.32",
	51:  "v1.34",
	56:  "v1.36",
	58:  "v1.38",
	61:  "v1.40",
	62:  "v1.42",
	63:  "v1.44",
	65:  "v1.46",
	68:  "v1.48",
	74:  "v1.50",
	79:  "v1.52",
	82:  "v1.56",
	85:  "v1.58",
	87:  "v1.60",
	88:  "v1.62",
	90:  "v1.64",
	95:  "v1.66",
	97:  "v1.68",
	102: "v1.70",
	104: "v1.72",
	106: "v1.74",
	109: "v1.78",
	113: "v1.80",
	115: "v1.82",
	116: "v1.84",
	123: "v1.86",
	125: "v1.88",
	130: "v1.90",
	131: "v1.92",
}

// SupportedMajorMinorVersions is the number of major.minor Tailscale versions supported.
const SupportedMajorMinorVersions = 10

// MinSupportedCapabilityVersion represents the minimum capability version
// supported by this Headscale instance (latest 10 minor versions)
const MinSupportedCapabilityVersion tailcfg.CapabilityVersion = 106
