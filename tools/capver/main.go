package main

//go:generate go run main.go

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"go/format"
	"io"
	"log"
	"net/http"
	"os"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"

	xmaps "golang.org/x/exp/maps"
	"tailscale.com/tailcfg"
)

const (
	ghcrTokenURL                = "https://ghcr.io/token?service=ghcr.io&scope=repository:tailscale/tailscale:pull" //nolint:gosec
	ghcrTagsURL                 = "https://ghcr.io/v2/tailscale/tailscale/tags/list?n=10000"
	rawFileURL                  = "https://github.com/tailscale/tailscale/raw/refs/tags/%s/tailcfg/tailcfg.go"
	outputFile                  = "../../hscontrol/capver/capver_generated.go"
	testFile                    = "../../hscontrol/capver/capver_test_data.go"
	fallbackCapVer              = 90
	maxTestCases                = 4
	supportedMajorMinorVersions = 10
	filePermissions             = 0o600
	semverMatchGroups           = 4
	latest3Count                = 3
	latest2Count                = 2
)

var errUnexpectedStatusCode = errors.New("unexpected status code")

// GHCRTokenResponse represents the response from GHCR token endpoint.
type GHCRTokenResponse struct {
	Token string `json:"token"`
}

// GHCRTagsResponse represents the response from GHCR tags list endpoint.
type GHCRTagsResponse struct {
	Name string   `json:"name"`
	Tags []string `json:"tags"`
}

// getGHCRToken fetches an anonymous token from GHCR for accessing public container images.
func getGHCRToken(ctx context.Context) (string, error) {
	client := &http.Client{}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ghcrTokenURL, nil)
	if err != nil {
		return "", fmt.Errorf("error creating token request: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("error fetching GHCR token: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("%w: %d", errUnexpectedStatusCode, resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("error reading token response: %w", err)
	}

	var tokenResp GHCRTokenResponse

	err = json.Unmarshal(body, &tokenResp)
	if err != nil {
		return "", fmt.Errorf("error parsing token response: %w", err)
	}

	return tokenResp.Token, nil
}

// getGHCRTags fetches all available tags from GHCR for tailscale/tailscale.
func getGHCRTags(ctx context.Context) ([]string, error) {
	token, err := getGHCRToken(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get GHCR token: %w", err)
	}

	client := &http.Client{}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ghcrTagsURL, nil)
	if err != nil {
		return nil, fmt.Errorf("error creating tags request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error fetching tags: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: %d", errUnexpectedStatusCode, resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading tags response: %w", err)
	}

	var tagsResp GHCRTagsResponse

	err = json.Unmarshal(body, &tagsResp)
	if err != nil {
		return nil, fmt.Errorf("error parsing tags response: %w", err)
	}

	return tagsResp.Tags, nil
}

// semverRegex matches semantic version tags like v1.90.0 or v1.90.1.
var semverRegex = regexp.MustCompile(`^v(\d+)\.(\d+)\.(\d+)$`)

// parseSemver extracts major, minor, patch from a semver tag.
// Returns -1 for all values if not a valid semver.
func parseSemver(tag string) (int, int, int) {
	matches := semverRegex.FindStringSubmatch(tag)
	if len(matches) != semverMatchGroups {
		return -1, -1, -1
	}

	major, _ := strconv.Atoi(matches[1])
	minor, _ := strconv.Atoi(matches[2])
	patch, _ := strconv.Atoi(matches[3])

	return major, minor, patch
}

// getMinorVersionsFromTags processes container tags and returns a map of minor versions
// to the first available patch version for each minor.
// For example: {"v1.90": "v1.90.0", "v1.92": "v1.92.0"}.
func getMinorVersionsFromTags(tags []string) map[string]string {
	// Map minor version (e.g., "v1.90") to lowest patch version available
	minorToLowestPatch := make(map[string]struct {
		patch   int
		fullVer string
	})

	for _, tag := range tags {
		major, minor, patch := parseSemver(tag)
		if major < 0 {
			continue // Not a semver tag
		}

		minorKey := fmt.Sprintf("v%d.%d", major, minor)

		existing, exists := minorToLowestPatch[minorKey]
		if !exists || patch < existing.patch {
			minorToLowestPatch[minorKey] = struct {
				patch   int
				fullVer string
			}{
				patch:   patch,
				fullVer: tag,
			}
		}
	}

	// Convert to simple map
	result := make(map[string]string)
	for minorVer, info := range minorToLowestPatch {
		result[minorVer] = info.fullVer
	}

	return result
}

// getCapabilityVersions fetches container tags from GHCR, identifies minor versions,
// and fetches the capability version for each from the Tailscale source.
func getCapabilityVersions(ctx context.Context) (map[string]tailcfg.CapabilityVersion, error) {
	// Fetch container tags from GHCR
	tags, err := getGHCRTags(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get container tags: %w", err)
	}

	log.Printf("Found %d container tags", len(tags))

	// Get minor versions with their representative patch versions
	minorVersions := getMinorVersionsFromTags(tags)
	log.Printf("Found %d minor versions", len(minorVersions))

	// Regular expression to find the CurrentCapabilityVersion line
	re := regexp.MustCompile(`const CurrentCapabilityVersion CapabilityVersion = (\d+)`)

	versions := make(map[string]tailcfg.CapabilityVersion)
	client := &http.Client{}

	for minorVer, patchVer := range minorVersions {
		// Fetch the raw Go file for the patch version
		rawURL := fmt.Sprintf(rawFileURL, patchVer)

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil) //nolint:gosec
		if err != nil {
			log.Printf("Warning: failed to create request for %s: %v", patchVer, err)
			continue
		}

		resp, err := client.Do(req)
		if err != nil {
			log.Printf("Warning: failed to fetch %s: %v", patchVer, err)
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			log.Printf("Warning: got status %d for %s", resp.StatusCode, patchVer)
			continue
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			log.Printf("Warning: failed to read response for %s: %v", patchVer, err)
			continue
		}

		// Find the CurrentCapabilityVersion
		matches := re.FindStringSubmatch(string(body))
		if len(matches) > 1 {
			capabilityVersionStr := matches[1]
			capabilityVersion, _ := strconv.Atoi(capabilityVersionStr)
			versions[minorVer] = tailcfg.CapabilityVersion(capabilityVersion)
			log.Printf("  %s (from %s): capVer %d", minorVer, patchVer, capabilityVersion)
		}
	}

	return versions, nil
}

func calculateMinSupportedCapabilityVersion(versions map[string]tailcfg.CapabilityVersion) tailcfg.CapabilityVersion {
	// Since we now store minor versions directly, just sort and take the oldest of the latest N
	minorVersions := xmaps.Keys(versions)
	sort.Strings(minorVersions)

	supportedCount := min(len(minorVersions), supportedMajorMinorVersions)

	if supportedCount == 0 {
		return fallbackCapVer
	}

	// The minimum supported version is the oldest of the latest 10
	oldestSupportedMinor := minorVersions[len(minorVersions)-supportedCount]

	return versions[oldestSupportedMinor]
}

func writeCapabilityVersionsToFile(versions map[string]tailcfg.CapabilityVersion, minSupportedCapVer tailcfg.CapabilityVersion) error {
	// Generate the Go code as a string
	var content strings.Builder
	content.WriteString("package capver\n\n")
	content.WriteString("// Generated DO NOT EDIT\n\n")
	content.WriteString(`import "tailscale.com/tailcfg"`)
	content.WriteString("\n\n")
	content.WriteString("var tailscaleToCapVer = map[string]tailcfg.CapabilityVersion{\n")

	sortedVersions := xmaps.Keys(versions)
	sort.Strings(sortedVersions)

	for _, version := range sortedVersions {
		fmt.Fprintf(&content, "\t\"%s\": %d,\n", version, versions[version])
	}

	content.WriteString("}\n")

	content.WriteString("\n\n")
	content.WriteString("var capVerToTailscaleVer = map[tailcfg.CapabilityVersion]string{\n")

	capVarToTailscaleVer := make(map[tailcfg.CapabilityVersion]string)

	for _, v := range sortedVersions {
		capabilityVersion := versions[v]

		// If it is already set, skip and continue,
		// we only want the first tailscale version per
		// capability version.
		if _, ok := capVarToTailscaleVer[capabilityVersion]; ok {
			continue
		}

		capVarToTailscaleVer[capabilityVersion] = v
	}

	capsSorted := xmaps.Keys(capVarToTailscaleVer)
	slices.Sort(capsSorted)

	for _, capVer := range capsSorted {
		fmt.Fprintf(&content, "\t%d:\t\t\"%s\",\n", capVer, capVarToTailscaleVer[capVer])
	}

	content.WriteString("}\n\n")

	// Add the SupportedMajorMinorVersions constant
	content.WriteString("// SupportedMajorMinorVersions is the number of major.minor Tailscale versions supported.\n")
	fmt.Fprintf(&content, "const SupportedMajorMinorVersions = %d\n\n", supportedMajorMinorVersions)

	// Add the MinSupportedCapabilityVersion constant
	content.WriteString("// MinSupportedCapabilityVersion represents the minimum capability version\n")
	content.WriteString("// supported by this Headscale instance (latest 10 minor versions)\n")
	fmt.Fprintf(&content, "const MinSupportedCapabilityVersion tailcfg.CapabilityVersion = %d\n", minSupportedCapVer)

	// Format the generated code
	formatted, err := format.Source([]byte(content.String()))
	if err != nil {
		return fmt.Errorf("error formatting Go code: %w", err)
	}

	// Write to file
	err = os.WriteFile(outputFile, formatted, filePermissions)
	if err != nil {
		return fmt.Errorf("error writing file: %w", err)
	}

	return nil
}

func writeTestDataFile(versions map[string]tailcfg.CapabilityVersion, minSupportedCapVer tailcfg.CapabilityVersion) error {
	// Sort minor versions
	minorVersions := xmaps.Keys(versions)
	sort.Strings(minorVersions)

	// Take latest N
	supportedCount := min(len(minorVersions), supportedMajorMinorVersions)

	latest10 := minorVersions[len(minorVersions)-supportedCount:]
	latest3 := minorVersions[len(minorVersions)-min(latest3Count, len(minorVersions)):]
	latest2 := minorVersions[len(minorVersions)-min(latest2Count, len(minorVersions)):]

	// Generate test data file content
	var content strings.Builder
	content.WriteString("package capver\n\n")
	content.WriteString("// Generated DO NOT EDIT\n\n")
	content.WriteString("import \"tailscale.com/tailcfg\"\n\n")

	// Generate complete test struct for TailscaleLatestMajorMinor
	content.WriteString("var tailscaleLatestMajorMinorTests = []struct {\n")
	content.WriteString("\tn        int\n")
	content.WriteString("\tstripV   bool\n")
	content.WriteString("\texpected []string\n")
	content.WriteString("}{\n")

	// Latest 3 with v prefix
	content.WriteString("\t{3, false, []string{")

	for i, version := range latest3 {
		content.WriteString(fmt.Sprintf("\"%s\"", version))

		if i < len(latest3)-1 {
			content.WriteString(", ")
		}
	}

	content.WriteString("}},\n")

	// Latest 2 without v prefix
	content.WriteString("\t{2, true, []string{")

	for i, version := range latest2 {
		// Strip v prefix for this test case
		verNoV := strings.TrimPrefix(version, "v")
		content.WriteString(fmt.Sprintf("\"%s\"", verNoV))

		if i < len(latest2)-1 {
			content.WriteString(", ")
		}
	}

	content.WriteString("}},\n")

	// Latest N without v prefix (all supported)
	content.WriteString(fmt.Sprintf("\t{%d, true, []string{\n", supportedMajorMinorVersions))

	for _, version := range latest10 {
		verNoV := strings.TrimPrefix(version, "v")
		content.WriteString(fmt.Sprintf("\t\t\"%s\",\n", verNoV))
	}

	content.WriteString("\t}},\n")

	// Empty case
	content.WriteString("\t{0, false, nil},\n")
	content.WriteString("}\n\n")

	// Build capVerToTailscaleVer for test data
	capVerToTailscaleVer := make(map[tailcfg.CapabilityVersion]string)
	sortedVersions := xmaps.Keys(versions)
	sort.Strings(sortedVersions)

	for _, v := range sortedVersions {
		capabilityVersion := versions[v]
		if _, ok := capVerToTailscaleVer[capabilityVersion]; !ok {
			capVerToTailscaleVer[capabilityVersion] = v
		}
	}

	// Generate complete test struct for CapVerMinimumTailscaleVersion
	content.WriteString("var capVerMinimumTailscaleVersionTests = []struct {\n")
	content.WriteString("\tinput    tailcfg.CapabilityVersion\n")
	content.WriteString("\texpected string\n")
	content.WriteString("}{\n")

	// Add minimum supported version
	minVersionString := capVerToTailscaleVer[minSupportedCapVer]
	content.WriteString(fmt.Sprintf("\t{%d, \"%s\"},\n", minSupportedCapVer, minVersionString))

	// Add a few more test cases
	capsSorted := xmaps.Keys(capVerToTailscaleVer)
	slices.Sort(capsSorted)

	testCount := 0
	for _, capVer := range capsSorted {
		if testCount >= maxTestCases {
			break
		}

		if capVer != minSupportedCapVer { // Don't duplicate the min version test
			version := capVerToTailscaleVer[capVer]
			content.WriteString(fmt.Sprintf("\t{%d, \"%s\"},\n", capVer, version))

			testCount++
		}
	}

	// Edge cases
	content.WriteString("\t{9001, \"\"}, // Test case for a version higher than any in the map\n")
	content.WriteString("\t{60, \"\"},   // Test case for a version lower than any in the map\n")
	content.WriteString("}\n")

	// Format the generated code
	formatted, err := format.Source([]byte(content.String()))
	if err != nil {
		return fmt.Errorf("error formatting test data Go code: %w", err)
	}

	// Write to file
	err = os.WriteFile(testFile, formatted, filePermissions)
	if err != nil {
		return fmt.Errorf("error writing test data file: %w", err)
	}

	return nil
}

func main() {
	ctx := context.Background()

	versions, err := getCapabilityVersions(ctx)
	if err != nil {
		log.Println("Error:", err)
		return
	}

	// Calculate the minimum supported capability version
	minSupportedCapVer := calculateMinSupportedCapabilityVersion(versions)

	err = writeCapabilityVersionsToFile(versions, minSupportedCapVer)
	if err != nil {
		log.Println("Error writing to file:", err)
		return
	}

	err = writeTestDataFile(versions, minSupportedCapVer)
	if err != nil {
		log.Println("Error writing test data file:", err)
		return
	}

	log.Println("Capability versions written to", outputFile)
}
