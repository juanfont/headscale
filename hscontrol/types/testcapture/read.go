package testcapture

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/tailscale/hujson"
)

// ErrUnsupportedSchemaVersion is returned by Read when a capture
// advertises a SchemaVersion newer than the current binary supports.
var ErrUnsupportedSchemaVersion = errors.New("testcapture: unsupported schema version")

// Read parses a HuJSON capture file from disk into a Capture.
//
// Comments and trailing commas in the file are stripped before
// unmarshaling. Files advertising a SchemaVersion newer than the
// current binary's are rejected with ErrUnsupportedSchemaVersion;
// SchemaVersion == 0 (pre-versioning) is accepted for backwards compat.
// The returned Capture's CapturedAt is the value recorded in the file
// (not "now").
func Read(path string) (*Capture, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("testcapture: read %s: %w", path, err)
	}

	var c Capture

	err = unmarshalHuJSON(data, &c)
	if err != nil {
		return nil, fmt.Errorf("testcapture: %s: %w", path, err)
	}

	if c.SchemaVersion > SchemaVersion {
		return nil, fmt.Errorf("%w: %s has version %d, binary supports %d",
			ErrUnsupportedSchemaVersion, path, c.SchemaVersion, SchemaVersion)
	}

	return &c, nil
}

// unmarshalHuJSON parses HuJSON bytes (JSON with comments / trailing
// commas) into v. Comments are stripped via hujson.Standardize before
// json.Unmarshal is called.
func unmarshalHuJSON(data []byte, v any) error {
	ast, err := hujson.Parse(data)
	if err != nil {
		return fmt.Errorf("hujson parse: %w", err)
	}

	ast.Standardize()

	err = json.Unmarshal(ast.Pack(), v)
	if err != nil {
		return fmt.Errorf("json unmarshal: %w", err)
	}

	return nil
}
