package cli

import (
	"testing"
)

func TestFilterPreReleasesIfStable(t *testing.T) {
	tests := []struct {
		name           string
		currentVersion string
		tag            string
		expectedFilter bool
		description    string
	}{
		{
			name:           "stable version filters alpha tag",
			currentVersion: "0.23.0",
			tag:            "v0.24.0-alpha.1",
			expectedFilter: true,
			description:    "When on stable release, alpha tags should be filtered",
		},
		{
			name:           "stable version filters beta tag",
			currentVersion: "0.23.0",
			tag:            "v0.24.0-beta.2",
			expectedFilter: true,
			description:    "When on stable release, beta tags should be filtered",
		},
		{
			name:           "stable version filters rc tag",
			currentVersion: "0.23.0",
			tag:            "v0.24.0-rc.1",
			expectedFilter: true,
			description:    "When on stable release, rc tags should be filtered",
		},
		{
			name:           "stable version allows stable tag",
			currentVersion: "0.23.0",
			tag:            "v0.24.0",
			expectedFilter: false,
			description:    "When on stable release, stable tags should not be filtered",
		},
		{
			name:           "alpha version allows alpha tag",
			currentVersion: "0.23.0-alpha.1",
			tag:            "v0.24.0-alpha.2",
			expectedFilter: false,
			description:    "When on alpha release, alpha tags should not be filtered",
		},
		{
			name:           "alpha version allows beta tag",
			currentVersion: "0.23.0-alpha.1",
			tag:            "v0.24.0-beta.1",
			expectedFilter: false,
			description:    "When on alpha release, beta tags should not be filtered",
		},
		{
			name:           "alpha version allows rc tag",
			currentVersion: "0.23.0-alpha.1",
			tag:            "v0.24.0-rc.1",
			expectedFilter: false,
			description:    "When on alpha release, rc tags should not be filtered",
		},
		{
			name:           "alpha version allows stable tag",
			currentVersion: "0.23.0-alpha.1",
			tag:            "v0.24.0",
			expectedFilter: false,
			description:    "When on alpha release, stable tags should not be filtered",
		},
		{
			name:           "beta version allows alpha tag",
			currentVersion: "0.23.0-beta.1",
			tag:            "v0.24.0-alpha.1",
			expectedFilter: false,
			description:    "When on beta release, alpha tags should not be filtered",
		},
		{
			name:           "beta version allows beta tag",
			currentVersion: "0.23.0-beta.2",
			tag:            "v0.24.0-beta.3",
			expectedFilter: false,
			description:    "When on beta release, beta tags should not be filtered",
		},
		{
			name:           "beta version allows rc tag",
			currentVersion: "0.23.0-beta.1",
			tag:            "v0.24.0-rc.1",
			expectedFilter: false,
			description:    "When on beta release, rc tags should not be filtered",
		},
		{
			name:           "beta version allows stable tag",
			currentVersion: "0.23.0-beta.1",
			tag:            "v0.24.0",
			expectedFilter: false,
			description:    "When on beta release, stable tags should not be filtered",
		},
		{
			name:           "rc version allows alpha tag",
			currentVersion: "0.23.0-rc.1",
			tag:            "v0.24.0-alpha.1",
			expectedFilter: false,
			description:    "When on rc release, alpha tags should not be filtered",
		},
		{
			name:           "rc version allows beta tag",
			currentVersion: "0.23.0-rc.1",
			tag:            "v0.24.0-beta.1",
			expectedFilter: false,
			description:    "When on rc release, beta tags should not be filtered",
		},
		{
			name:           "rc version allows rc tag",
			currentVersion: "0.23.0-rc.2",
			tag:            "v0.24.0-rc.3",
			expectedFilter: false,
			description:    "When on rc release, rc tags should not be filtered",
		},
		{
			name:           "rc version allows stable tag",
			currentVersion: "0.23.0-rc.1",
			tag:            "v0.24.0",
			expectedFilter: false,
			description:    "When on rc release, stable tags should not be filtered",
		},
		{
			name:           "stable version with patch filters alpha",
			currentVersion: "0.23.1",
			tag:            "v0.24.0-alpha.1",
			expectedFilter: true,
			description:    "Stable version with patch number should filter alpha tags",
		},
		{
			name:           "stable version with patch allows stable",
			currentVersion: "0.23.1",
			tag:            "v0.24.0",
			expectedFilter: false,
			description:    "Stable version with patch number should allow stable tags",
		},
		{
			name:           "tag with alpha substring in version number",
			currentVersion: "0.23.0",
			tag:            "v1.0.0-alpha.1",
			expectedFilter: true,
			description:    "Tags with alpha in version string should be filtered on stable",
		},
		{
			name:           "tag with beta substring in version number",
			currentVersion: "0.23.0",
			tag:            "v1.0.0-beta.1",
			expectedFilter: true,
			description:    "Tags with beta in version string should be filtered on stable",
		},
		{
			name:           "tag with rc substring in version number",
			currentVersion: "0.23.0",
			tag:            "v1.0.0-rc.1",
			expectedFilter: true,
			description:    "Tags with rc in version string should be filtered on stable",
		},
		{
			name:           "empty tag on stable version",
			currentVersion: "0.23.0",
			tag:            "",
			expectedFilter: false,
			description:    "Empty tags should not be filtered",
		},
		{
			name:           "dev version allows all tags",
			currentVersion: "0.23.0-dev",
			tag:            "v0.24.0-alpha.1",
			expectedFilter: false,
			description:    "Dev versions should not filter any tags (pre-release allows all)",
		},
		{
			name:           "stable version filters dev tag",
			currentVersion: "0.23.0",
			tag:            "v0.24.0-dev",
			expectedFilter: true,
			description:    "When on stable release, dev tags should be filtered",
		},
		{
			name:           "dev version allows dev tag",
			currentVersion: "0.23.0-dev",
			tag:            "v0.24.0-dev.1",
			expectedFilter: false,
			description:    "When on dev release, dev tags should not be filtered",
		},
		{
			name:           "dev version allows stable tag",
			currentVersion: "0.23.0-dev",
			tag:            "v0.24.0",
			expectedFilter: false,
			description:    "When on dev release, stable tags should not be filtered",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := filterPreReleasesIfStable(func() string { return tt.currentVersion })(tt.tag)
			if result != tt.expectedFilter {
				t.Errorf("%s: got %v, want %v\nDescription: %s\nCurrent version: %s, Tag: %s",
					tt.name,
					result,
					tt.expectedFilter,
					tt.description,
					tt.currentVersion,
					tt.tag,
				)
			}
		})
	}
}

func TestIsPreReleaseVersion(t *testing.T) {
	tests := []struct {
		name        string
		version     string
		expected    bool
		description string
	}{
		{
			name:        "stable version",
			version:     "0.23.0",
			expected:    false,
			description: "Stable version should not be pre-release",
		},
		{
			name:        "alpha version",
			version:     "0.23.0-alpha.1",
			expected:    true,
			description: "Alpha version should be pre-release",
		},
		{
			name:        "beta version",
			version:     "0.23.0-beta.1",
			expected:    true,
			description: "Beta version should be pre-release",
		},
		{
			name:        "rc version",
			version:     "0.23.0-rc.1",
			expected:    true,
			description: "RC version should be pre-release",
		},
		{
			name:        "version with alpha substring",
			version:     "0.23.0-alphabetical",
			expected:    true,
			description: "Version containing 'alpha' should be pre-release",
		},
		{
			name:        "version with beta substring",
			version:     "0.23.0-betamax",
			expected:    true,
			description: "Version containing 'beta' should be pre-release",
		},
		{
			name:        "dev version",
			version:     "0.23.0-dev",
			expected:    true,
			description: "Dev version should be pre-release",
		},
		{
			name:        "empty version",
			version:     "",
			expected:    false,
			description: "Empty version should not be pre-release",
		},
		{
			name:        "version with patch number",
			version:     "0.23.1",
			expected:    false,
			description: "Stable version with patch should not be pre-release",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isPreReleaseVersion(tt.version)
			if result != tt.expected {
				t.Errorf("%s: got %v, want %v\nDescription: %s\nVersion: %s",
					tt.name,
					result,
					tt.expected,
					tt.description,
					tt.version,
				)
			}
		})
	}
}
