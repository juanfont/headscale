package main

import (
	"regexp"
	"testing"
)

func TestImageRefPatterns(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    string
		bumped  string
	}{
		{
			name:    "alpine",
			content: "FROM alpine:3.23\nRUN true\n",
			want:    "3.23",
			bumped:  "FROM alpine:3.24\nRUN true\n",
		},
		{
			name:    "debian slim",
			content: "FROM debian:trixie-slim\n",
			want:    "trixie-slim",
			bumped:  "FROM debian:3.24\n",
		},
		{
			name:    "node alpine",
			content: "FROM node:24-alpine\n",
			want:    "24-alpine",
			bumped:  "FROM node:3.24\n",
		},
		{
			// The Rust tag folds the version and the Debian codename together,
			// so it has to be captured and replaced as one value.
			name:    "rust on debian",
			content: "FROM rust:1.95-trixie AS builder\n",
			want:    "1.95-trixie",
			bumped:  "FROM rust:3.24 AS builder\n",
		},
	}

	refs := map[string]*regexp.Regexp{
		"alpine":         alpineRef,
		"debian slim":    debianRef,
		"node alpine":    nodeRef,
		"rust on debian": rustRef,
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			re := refs[test.name]

			m := re.FindStringSubmatch(test.content)
			if m == nil {
				t.Fatalf("pattern did not match %q", test.content)
			}

			if m[2] != test.want {
				t.Errorf("captured %q, want %q", m[2], test.want)
			}

			if got := re.ReplaceAllString(test.content, "${1}3.24"); got != test.bumped {
				t.Errorf("rewrite = %q, want %q", got, test.bumped)
			}
		})
	}
}

// The Rust builder and the runtime stage live in the same file; matching the
// wrong one would rewrite a Debian tag with a Rust version.
func TestImageRefsDoNotCrossMatch(t *testing.T) {
	const tailscaleRS = "FROM rust:1.95-trixie AS builder\nRUN true\nFROM debian:trixie-slim\n"

	if got := rustRef.FindStringSubmatch(tailscaleRS)[2]; got != "1.95-trixie" {
		t.Errorf("rustRef captured %q", got)
	}

	if got := debianRef.FindStringSubmatch(tailscaleRS)[2]; got != "trixie-slim" {
		t.Errorf("debianRef captured %q", got)
	}
}

func TestDistrolessRef(t *testing.T) {
	const goreleaser = "    base_image: gcr.io/distroless/base-debian13\n" +
		"    base_image: gcr.io/distroless/base-debian13:debug\n"

	got := distrolessRef.ReplaceAllString(goreleaser, "${1}14")

	want := "    base_image: gcr.io/distroless/base-debian14\n" +
		"    base_image: gcr.io/distroless/base-debian14:debug\n"
	if got != want {
		t.Errorf("rewrite =\n%q\nwant\n%q", got, want)
	}
}

func TestIsEvenMajor(t *testing.T) {
	tests := []struct {
		in   string
		want bool
	}{
		{in: "24", want: true},
		{in: "26", want: true},
		{in: "25"},
		{in: "lts"},
	}

	for _, test := range tests {
		t.Run(test.in, func(t *testing.T) {
			if got := isEvenMajor(test.in); got != test.want {
				t.Errorf("isEvenMajor(%q) = %v, want %v", test.in, got, test.want)
			}
		})
	}
}

func TestTemurinRef(t *testing.T) {
	const dockerfile = "FROM --platform=linux/amd64 eclipse-temurin:21-jdk-noble\nRUN true\n"

	m := temurinRef.FindStringSubmatch(dockerfile)
	if m == nil || m[2] != "21-jdk-noble" {
		t.Fatalf("temurinRef captured %v", m)
	}

	want := "FROM --platform=linux/amd64 eclipse-temurin:25-jdk-noble\nRUN true\n"
	if got := temurinRef.ReplaceAllString(dockerfile, "${1}25-jdk-noble"); got != want {
		t.Errorf("rewrite = %q, want %q", got, want)
	}
}

func TestIsJavaLTS(t *testing.T) {
	for in, want := range map[string]bool{"17": true, "21": true, "25": true, "29": true, "11": false, "22": false, "26": false, "x": false} {
		if got := isJavaLTS(in); got != want {
			t.Errorf("isJavaLTS(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestAndroidRefs(t *testing.T) {
	const dockerfile = "ARG ANDROID_API=33\nARG ANDROID_CMDLINE_TOOLS_VERSION=9477386\nARG ANDROID_BUILD_TOOLS=34.0.0\n"

	if got := cmdlineToolsRef.FindStringSubmatch(dockerfile)[2]; got != "9477386" {
		t.Errorf("cmdlineToolsRef captured %q", got)
	}

	if got := buildToolsRef.FindStringSubmatch(dockerfile)[2]; got != "34.0.0" {
		t.Errorf("buildToolsRef captured %q", got)
	}
}

// A trimmed copy of the index sdkmanager reads: a newer cmdline-tools on a
// preview channel and build-tools release candidates must not win.
const androidIndex = `<?xml version="1.0"?>
<sdk:sdk-repository xmlns:sdk="http://schemas.android.com/sdk/android/repo/repository2/03">
  <channel id="channel-0">stable</channel>
  <channel id="channel-2">dev</channel>
  <remotePackage path="build-tools;37.0.0-rc2"><channelRef ref="channel-0"/></remotePackage>
  <remotePackage path="build-tools;36.1.0"><channelRef ref="channel-0"/></remotePackage>
  <remotePackage path="build-tools;36.0.0"><channelRef ref="channel-0"/></remotePackage>
  <remotePackage path="cmdline-tools;99.0-alpha01"><channelRef ref="channel-2"/>
    <archives><archive><complete><url>commandlinetools-linux-99_latest.zip</url></complete><host-os>linux</host-os></archive></archives>
  </remotePackage>
  <remotePackage path="cmdline-tools;latest"><channelRef ref="channel-0"/>
    <archives>
      <archive><complete><url>commandlinetools-mac_arm64-16111833_latest.zip</url></complete><host-os>macosx</host-os></archive>
      <archive><complete><url>commandlinetools-linux-16111833_latest.zip</url></complete><host-os>linux</host-os></archive>
    </archives>
  </remotePackage>
</sdk:sdk-repository>`

func TestParseAndroidRepo(t *testing.T) {
	sdk, err := parseAndroidRepo([]byte(androidIndex))
	if err != nil {
		t.Fatal(err)
	}

	if sdk.CmdlineTools != "16111833" {
		t.Errorf("CmdlineTools = %q, want 16111833", sdk.CmdlineTools)
	}

	if sdk.BuildTools != "36.1.0" {
		t.Errorf("BuildTools = %q, want 36.1.0", sdk.BuildTools)
	}

	if !sdk.Listed["36.0.0"] || sdk.Listed["37.0.0-rc2"] {
		t.Errorf("Listed = %v", sdk.Listed)
	}
}
