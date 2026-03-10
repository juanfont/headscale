package v2

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// TestMain ensures the working directory is set to the package source directory
// so that relative testdata/ paths resolve correctly when the test binary is
// executed from an arbitrary location (e.g., via "go tool stress").
func TestMain(m *testing.M) {
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		panic("could not determine test source directory")
	}

	err := os.Chdir(filepath.Dir(filename))
	if err != nil {
		panic("could not chdir to test source directory: " + err.Error())
	}

	os.Exit(m.Run())
}
