package main

//go:generate go run main.go

import (
	"encoding/json"
	"fmt"
	"go/format"
	"io"
	"log"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"

	xmaps "golang.org/x/exp/maps"
	"tailscale.com/tailcfg"
)

const (
	releasesURL     = "https://api.github.com/repos/tailscale/tailscale/releases"
	rawFileURL      = "https://github.com/tailscale/tailscale/raw/refs/tags/%s/tailcfg/tailcfg.go"
	outputFile      = "../../hscontrol/capver/capver_generated.go"
	testFile        = "../../hscontrol/capver/capver_test_data.go"
	minVersionParts = 2
	fallbackCapVer  = 90
	maxTestCases    = 4
	// TODO(https://github.com/tailscale/tailscale/issues/12849): Restore to 10 when v1.92 is released.
	supportedMajorMinorVersions = 9
	filePermissions             = 0o600
)

type Release struct {
	Name string `json:"name"`
}

func getCapabilityVersions() (map[string]tailcfg.CapabilityVersion, error) {
	// Fetch the releases
	resp, err := http.Get(releasesURL)
	if err != nil {
		return nil, fmt.Errorf("error fetching releases: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading response body: %w", err)
	}

	var releases []Release

	err = json.Unmarshal(body, &releases)
	if err != nil {
		return nil, fmt.Errorf("error unmarshalling JSON: %w", err)
	}

	// Regular expression to find the CurrentCapabilityVersion line
	re := regexp.MustCompile(`const CurrentCapabilityVersion CapabilityVersion = (\d+)`)

	versions := make(map[string]tailcfg.CapabilityVersion)

	for _, release := range releases {
		version := strings.TrimSpace(release.Name)
		if !strings.HasPrefix(version, "v") {
			version = "v" + version
		}

		// Fetch the raw Go file
		rawURL := fmt.Sprintf(rawFileURL, version)

		resp, err := http.Get(rawURL)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			continue
		}

		// Find the CurrentCapabilityVersion
		matches := re.FindStringSubmatch(string(body))
		if len(matches) > 1 {
			capabilityVersionStr := matches[1]
			capabilityVersion, _ := strconv.Atoi(capabilityVersionStr)
			versions[version] = tailcfg.CapabilityVersion(capabilityVersion)
		}
	}

	return versions, nil
}

func calculateMinSupportedCapabilityVersion(versions map[string]tailcfg.CapabilityVersion) tailcfg.CapabilityVersion {
	// Get unique major.minor versions
	majorMinorToCapVer := make(map[string]tailcfg.CapabilityVersion)

	for version, capVer := range versions {
		// Remove 'v' prefix and split by '.'
		cleanVersion := strings.TrimPrefix(version, "v")

		parts := strings.Split(cleanVersion, ".")
		if len(parts) >= minVersionParts {
			majorMinor := parts[0] + "." + parts[1]
			// Keep the earliest (lowest) capver for each major.minor
			if existing, exists := majorMinorToCapVer[majorMinor]; !exists || capVer < existing {
				majorMinorToCapVer[majorMinor] = capVer
			}
		}
	}

	// Sort major.minor versions
	majorMinors := xmaps.Keys(majorMinorToCapVer)
	sort.Strings(majorMinors)

	// Take the latest 10 versions
	supportedCount := supportedMajorMinorVersions
	if len(majorMinors) < supportedCount {
		supportedCount = len(majorMinors)
	}

	if supportedCount == 0 {
		return fallbackCapVer
	}

	// The minimum supported version is the oldest of the latest 10
	oldestSupportedMajorMinor := majorMinors[len(majorMinors)-supportedCount]

	return majorMinorToCapVer[oldestSupportedMajorMinor]
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
		// we only want the first tailscale vsion per
		// capability vsion.
		if _, ok := capVarToTailscaleVer[capabilityVersion]; ok {
			continue
		}

		capVarToTailscaleVer[capabilityVersion] = v
	}

	capsSorted := xmaps.Keys(capVarToTailscaleVer)
	sort.Slice(capsSorted, func(i, j int) bool {
		return capsSorted[i] < capsSorted[j]
	})

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
	// Get unique major.minor versions for test generation
	majorMinorToCapVer := make(map[string]tailcfg.CapabilityVersion)

	for version, capVer := range versions {
		cleanVersion := strings.TrimPrefix(version, "v")

		parts := strings.Split(cleanVersion, ".")
		if len(parts) >= minVersionParts {
			majorMinor := parts[0] + "." + parts[1]
			if existing, exists := majorMinorToCapVer[majorMinor]; !exists || capVer < existing {
				majorMinorToCapVer[majorMinor] = capVer
			}
		}
	}

	// Sort major.minor versions
	majorMinors := xmaps.Keys(majorMinorToCapVer)
	sort.Strings(majorMinors)

	// Take latest 10
	supportedCount := supportedMajorMinorVersions
	if len(majorMinors) < supportedCount {
		supportedCount = len(majorMinors)
	}

	latest10 := majorMinors[len(majorMinors)-supportedCount:]
	latest3 := majorMinors[len(majorMinors)-3:]
	latest2 := majorMinors[len(majorMinors)-2:]

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
		content.WriteString(fmt.Sprintf("\"v%s\"", version))

		if i < len(latest3)-1 {
			content.WriteString(", ")
		}
	}

	content.WriteString("}},\n")

	// Latest 2 without v prefix
	content.WriteString("\t{2, true, []string{")

	for i, version := range latest2 {
		content.WriteString(fmt.Sprintf("\"%s\"", version))

		if i < len(latest2)-1 {
			content.WriteString(", ")
		}
	}

	content.WriteString("}},\n")

	// Latest N without v prefix (all supported)
	content.WriteString(fmt.Sprintf("\t{%d, true, []string{\n", supportedMajorMinorVersions))

	for _, version := range latest10 {
		content.WriteString(fmt.Sprintf("\t\t\"%s\",\n", version))
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
	sort.Slice(capsSorted, func(i, j int) bool {
		return capsSorted[i] < capsSorted[j]
	})

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
	versions, err := getCapabilityVersions()
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
