package main

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestGolangTagRewrite(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    string
		found   bool
		bumped  string
	}{
		{
			name:    "alpine builder",
			content: "FROM golang:1.27.1-alpine AS build-env\n",
			want:    "1.27.1",
			found:   true,
			bumped:  "FROM golang:1.28.0-alpine AS build-env\n",
		},
		{
			name:    "registry qualified trixie builder",
			content: "FROM docker.io/golang:1.27.0-trixie AS builder\n",
			want:    "1.27.0",
			found:   true,
			bumped:  "FROM docker.io/golang:1.28.0-trixie AS builder\n",
		},
		{
			name:    "no suffix",
			content: "FROM golang:1.27.0\n",
			want:    "1.27.0",
			found:   true,
			bumped:  "FROM golang:1.28.0\n",
		},
		{
			// A floating tag has no version to rewrite, so the pattern must
			// leave it alone rather than mangle it.
			content: "FROM golang:alpine\n",
			name:    "floating tag",
			found:   false,
			bumped:  "FROM golang:alpine\n",
		},
		{
			name:    "unrelated base image",
			content: "FROM alpine:3.23\n",
			found:   false,
			bumped:  "FROM alpine:3.23\n",
		},
		{
			// Only the builder stage carries a golang reference; the runtime
			// stage must survive untouched.
			name:    "multi stage",
			content: "FROM golang:1.27.1-alpine AS build-env\nRUN true\nFROM alpine:3.23\n",
			want:    "1.27.1",
			found:   true,
			bumped:  "FROM golang:1.28.0-alpine AS build-env\nRUN true\nFROM alpine:3.23\n",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, ok := currentGolangTag(test.content)
			if ok != test.found {
				t.Fatalf("currentGolangTag found = %v, want %v", ok, test.found)
			}

			if got != test.want {
				t.Errorf("currentGolangTag = %q, want %q", got, test.want)
			}

			if bumped := setGolangTag(test.content, "1.28.0"); bumped != test.bumped {
				t.Errorf("setGolangTag =\n%q\nwant\n%q", bumped, test.bumped)
			}
		})
	}
}

func TestGoDirective(t *testing.T) {
	tests := []struct {
		name    string
		goMod   string
		want    string
		wantErr bool
	}{
		{
			name:  "plain",
			goMod: "module example.com/x\n\ngo 1.27.1\n\nrequire (\n)\n",
			want:  "1.27.1",
		},
		{
			// "gopkg.in/..." lines start with "go" too; only the directive counts.
			name:  "require line starting with go",
			goMod: "module x\n\ngo 1.27.0\n\nrequire gopkg.in/yaml.v3 v3.0.1\n",
			want:  "1.27.0",
		},
		{
			name:    "missing",
			goMod:   "module example.com/x\n",
			wantErr: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := goDirective(test.goMod)
			if (err != nil) != test.wantErr {
				t.Fatalf("goDirective error = %v, wantErr %v", err, test.wantErr)
			}

			if got != test.want {
				t.Errorf("goDirective = %q, want %q", got, test.want)
			}
		})
	}
}

func TestHigher(t *testing.T) {
	tests := []struct{ a, b, want string }{
		{"1.27.0", "1.27.1", "1.27.1"},
		{"1.27.1", "1.27.0", "1.27.1"},
		{"1.27.0", "1.27.0", "1.27.0"},
		{"1.28.0", "1.9.0", "1.28.0"},
	}

	for _, test := range tests {
		t.Run(test.a+"/"+test.b, func(t *testing.T) {
			if got := higher(test.a, test.b); got != test.want {
				t.Errorf("higher(%q, %q) = %q, want %q", test.a, test.b, got, test.want)
			}
		})
	}
}

func TestLockDiff(t *testing.T) {
	node := func(rev string) lockNode {
		var n lockNode

		n.Locked.Rev = rev

		return n
	}

	before := flakeLock{Nodes: map[string]lockNode{
		"nixpkgs":      node("aaaaaaaaaaaaaaaa"),
		"flake-utils":  node("bbbbbbbbbbbbbbbb"),
		"flake-checks": node("cccccccccccccccc"),
	}}
	after := flakeLock{Nodes: map[string]lockNode{
		"nixpkgs":      node("dddddddddddddddd"),
		"flake-utils":  node("bbbbbbbbbbbbbbbb"),
		"flake-checks": node("eeeeeeeeeeeeeeee"),
	}}

	detail, names := lockDiff(before, after)

	if diff := cmp.Diff([]string{"flake-checks", "nixpkgs"}, names); diff != "" {
		t.Errorf("names mismatch (-want +got):\n%s", diff)
	}

	want := []string{"flake-checks ccccccc -> eeeeeee", "nixpkgs aaaaaaa -> ddddddd"}
	if diff := cmp.Diff(want, detail); diff != "" {
		t.Errorf("detail mismatch (-want +got):\n%s", diff)
	}
}

func TestGolangTagSuffix(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    string
	}{
		{name: "alpine", content: "FROM golang:1.27.1-alpine AS build-env\n", want: "-alpine"},
		{name: "trixie", content: "FROM docker.io/golang:1.27.0-trixie AS builder\n", want: "-trixie"},
		{name: "none", content: "FROM golang:1.27.0\n"},
		{name: "no golang image", content: "FROM alpine:3.23\n"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := golangTagSuffix(test.content); got != test.want {
				t.Errorf("golangTagSuffix = %q, want %q", got, test.want)
			}
		})
	}
}
