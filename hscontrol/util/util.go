package util

import (
	"errors"
	"fmt"
	"net/url"
	"strings"

	"tailscale.com/util/cmpver"
)

func TailscaleVersionNewerOrEqual(minimum, toCheck string) bool {
	if cmpver.Compare(minimum, toCheck) <= 0 ||
		toCheck == "unstable" ||
		toCheck == "head" {
		return true
	}

	return false
}

// ParseLoginURLFromCLILogin parses the output of the tailscale up command to extract the login URL.
// It returns an error if not exactly one URL is found.
func ParseLoginURLFromCLILogin(output string) (*url.URL, error) {
	lines := strings.Split(output, "\n")
	var urlStr string

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "http://") || strings.HasPrefix(line, "https://") {
			if urlStr != "" {
				return nil, fmt.Errorf("multiple URLs found: %s and %s", urlStr, line)
			}
			urlStr = line
		}
	}

	if urlStr == "" {
		return nil, errors.New("no URL found")
	}

	loginURL, err := url.Parse(urlStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse URL: %w", err)
	}

	return loginURL, nil
}
