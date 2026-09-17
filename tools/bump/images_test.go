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
