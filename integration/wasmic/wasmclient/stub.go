//go:build !js

// This package only does something when built for GOOS=js (see main.go). The
// stub exists so `go build ./...` and `go vet ./...` on the host don't fail with
// "build constraints exclude all Go files" for this directory.
package main

func main() {}
