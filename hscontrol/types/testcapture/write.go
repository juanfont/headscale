package testcapture

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/tailscale/hujson"
)

// ErrNilCapture is returned by Write when called with a nil Capture.
var ErrNilCapture = errors.New("testcapture: nil capture")

// Write serializes c as a HuJSON file with a comment header.
//
// The comment header is built by CommentHeader from c's TestID,
// Description, and Captures. If the file's parent directory does
// not exist, Write returns the error from os.WriteFile (it does
// not create the directory itself; callers should MkdirAll first).
func Write(path string, c *Capture) error {
	if c == nil {
		return fmt.Errorf("testcapture: Write %s: %w", path, ErrNilCapture)
	}

	header := CommentHeader(c)

	body, err := marshalHuJSON(c)
	if err != nil {
		return fmt.Errorf("testcapture: marshal %s: %w", path, err)
	}

	data := prependCommentHeader(body, header)

	err = os.WriteFile(path, data, 0o600)
	if err != nil {
		return fmt.Errorf("testcapture: write %s: %w", path, err)
	}

	return nil
}

// marshalHuJSON serializes v as HuJSON-formatted bytes. It is
// standard JSON encoding followed by hujson.Format which produces
// consistent indentation/whitespace.
func marshalHuJSON(v any) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("json marshal: %w", err)
	}

	formatted, err := hujson.Format(raw)
	if err != nil {
		return nil, fmt.Errorf("hujson format: %w", err)
	}

	return formatted, nil
}

// prependCommentHeader emits header as // comment lines at the top of
// body. Empty lines in header become "//" alone (no trailing space).
// The returned bytes always end with a single trailing newline.
func prependCommentHeader(body []byte, header string) []byte {
	if header == "" {
		if len(body) == 0 || body[len(body)-1] != '\n' {
			body = append(body, '\n')
		}

		return body
	}

	var buf strings.Builder

	for line := range strings.SplitSeq(header, "\n") {
		if line == "" {
			buf.WriteString("//\n")
			continue
		}

		buf.WriteString("// ")
		buf.WriteString(line)
		buf.WriteByte('\n')
	}

	buf.Write(body)

	if !strings.HasSuffix(buf.String(), "\n") {
		buf.WriteByte('\n')
	}

	return []byte(buf.String())
}
