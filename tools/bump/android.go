package main

import (
	"context"
	"encoding/xml"
	"fmt"
	"net/http"
	"regexp"

	"golang.org/x/mod/semver"
)

const (
	// androidRepoURL is the index sdkmanager itself reads.
	androidRepoURL    = "https://dl.google.com/android/repository/repository2-3.xml"
	androidArchiveURL = "https://dl.google.com/android/repository/"
	androidStable     = "channel-0"
	androidDockerfile = "Dockerfile.android-integration"
)

var (
	cmdlineToolsRef = regexp.MustCompile(`(?m)^(ARG ANDROID_CMDLINE_TOOLS_VERSION=)(\d+)$`)
	buildToolsRef   = regexp.MustCompile(`(?m)^(ARG ANDROID_BUILD_TOOLS=)(\S+)$`)

	cmdlineToolsArchive = regexp.MustCompile(`^commandlinetools-linux-(\d+)_latest\.zip$`)
	stableBuildTools    = regexp.MustCompile(`^build-tools;(\d+\.\d+\.\d+)$`)
)

type androidRepo struct {
	Packages []struct {
		Path    string `xml:"path,attr"`
		Channel struct {
			Ref string `xml:"ref,attr"`
		} `xml:"channelRef"`
		Archives []struct {
			URL    string `xml:"complete>url"`
			HostOS string `xml:"host-os"`
		} `xml:"archives>archive"`
	} `xml:"remotePackage"`
}

// androidSDK is what the stable channel of the SDK index currently offers.
type androidSDK struct {
	// CmdlineTools is the build number in the Linux command-line tools
	// archive name, which is how the Dockerfile downloads them.
	CmdlineTools string
	BuildTools   string
	// Listed holds every stable build-tools release in the index.
	Listed map[string]bool
}

func parseAndroidRepo(body []byte) (androidSDK, error) {
	var repo androidRepo

	err := xml.Unmarshal(body, &repo)
	if err != nil {
		return androidSDK{}, fmt.Errorf("decoding Android SDK index: %w", err)
	}

	sdk := androidSDK{Listed: map[string]bool{}}

	for _, p := range repo.Packages {
		if p.Channel.Ref != androidStable {
			continue
		}

		if p.Path == "cmdline-tools;latest" {
			for _, a := range p.Archives {
				m := cmdlineToolsArchive.FindStringSubmatch(a.URL)
				if a.HostOS == "linux" && m != nil {
					sdk.CmdlineTools = m[1]
				}
			}
		}

		// Release candidates share the stable channel; only X.Y.Z is a release.
		m := stableBuildTools.FindStringSubmatch(p.Path)
		if m == nil {
			continue
		}

		sdk.Listed[m[1]] = true

		if sdk.BuildTools == "" || semver.Compare("v"+m[1], "v"+sdk.BuildTools) > 0 {
			sdk.BuildTools = m[1]
		}
	}

	if sdk.CmdlineTools == "" || sdk.BuildTools == "" {
		return androidSDK{}, fmt.Errorf("%w: Android SDK index lacks stable cmdline-tools or build-tools", errNoMatchingTag)
	}

	return sdk, nil
}

func latestAndroidSDK(ctx context.Context) (androidSDK, error) {
	body, err := fetch(ctx, androidRepoURL)
	if err != nil {
		return androidSDK{}, err
	}

	return parseAndroidRepo(body)
}

// archivePublished asks Google's download server for the archive the
// Dockerfile would fetch, so a bump cannot point at a missing file.
func archivePublished(ctx context.Context, name string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, androidArchiveURL+name, nil)
	if err != nil {
		return fmt.Errorf("building request for %s: %w", name, err)
	}

	client := &http.Client{Timeout: proxyTimeout}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("HEAD %s: %w", name, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%w: %s (%s)", errTagMissing, name, resp.Status)
	}

	return nil
}

// androidBumps are the Android SDK pins of the emulator image. They reuse the
// image machinery: a value captured in a file, resolved and verified. The API
// level is not among them; it is the Android release under test, picked on
// purpose.
func androidBumps() []imageBump {
	return []imageBump{
		{
			Name:   "cmdline-tools",
			Prefix: androidDockerfile,
			Files:  []string{androidDockerfile},
			Ref:    cmdlineToolsRef,
			Resolve: func(ctx context.Context, _ string) (string, error) {
				sdk, err := latestAndroidSDK(ctx)

				return sdk.CmdlineTools, err
			},
			Verify: func(ctx context.Context, want string) error {
				return archivePublished(ctx, "commandlinetools-linux-"+want+"_latest.zip")
			},
		},
		{
			Name:   "build-tools",
			Prefix: androidDockerfile,
			Files:  []string{androidDockerfile},
			Ref:    buildToolsRef,
			Resolve: func(ctx context.Context, _ string) (string, error) {
				sdk, err := latestAndroidSDK(ctx)

				return sdk.BuildTools, err
			},
			// sdkmanager installs build tools by name from the same index,
			// so being listed there is being published.
			Verify: func(ctx context.Context, want string) error {
				sdk, err := latestAndroidSDK(ctx)
				if err != nil {
					return err
				}

				if !sdk.Listed[want] {
					return fmt.Errorf("%w: build-tools %s", errTagMissing, want)
				}

				return nil
			},
		},
	}
}

func androidAreas() []area {
	defs := androidBumps()
	areas := make([]area, 0, len(defs))

	for _, def := range defs {
		areas = append(areas, area{
			Name:    "android:" + def.Name,
			Apply:   applyImage(def),
			Gate:    gateImage(def),
			Message: func(c change) string { return def.Prefix + ": bump " + c.Summary },
		})
	}

	return areas
}
