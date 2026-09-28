package testcapture

import (
	"errors"
	"fmt"

	"github.com/juanfont/headscale/hscontrol/util"
)

// ErrUnsupportedSchemaVersion is returned by [Read] when a capture
// advertises a [Capture.SchemaVersion] newer than the current binary supports.
var ErrUnsupportedSchemaVersion = errors.New("testcapture: unsupported schema version")

// Read parses a HuJSON capture file from disk into a [Capture].
//
// Comments and trailing commas in the file are stripped before
// unmarshaling. Files advertising a [Capture.SchemaVersion] newer than the
// current binary's are rejected with [ErrUnsupportedSchemaVersion];
// [Capture.SchemaVersion] == 0 (pre-versioning) is accepted for backwards compat.
// The returned [Capture]'s [Capture.CapturedAt] is the value recorded in the file
// (not "now").
func Read(path string) (*Capture, error) {
	c, err := util.ReadFileByExt[Capture](path)
	if err != nil {
		return nil, fmt.Errorf("testcapture: %w", err)
	}

	if c.SchemaVersion > SchemaVersion {
		return nil, fmt.Errorf("%w: %s has version %d, binary supports %d",
			ErrUnsupportedSchemaVersion, path, c.SchemaVersion, SchemaVersion)
	}

	return &c, nil
}
