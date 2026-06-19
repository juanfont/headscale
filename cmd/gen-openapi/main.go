// Command gen-openapi emits the Headscale v1 OpenAPI document from the
// authoritative Huma definitions in hscontrol/api/v1. The server also serves the
// spec live at /openapi.yaml; this tool emits it on demand, and with -downgrade
// the 3.0.3 form used to generate the client. The output is not committed.
//
// Usage:
//
//	go run ./cmd/gen-openapi              # write the 3.1 spec to openapi/v1/headscale.yaml
//	go run ./cmd/gen-openapi -downgrade <path>  # write the 3.0.3 downgrade (for client gen)
package main

import (
	"log"
	"os"
	"path/filepath"

	apiv1 "github.com/juanfont/headscale/hscontrol/api/v1"
)

// outPath is relative to the repository root.
const outPath = "openapi/v1/headscale.yaml"

func main() {
	if len(os.Args) == 3 && os.Args[1] == "-downgrade" {
		writeSpec(os.Args[2], apiv1.Spec30)

		return
	}

	writeSpec(outPath, apiv1.Spec)
}

func writeSpec(path string, gen func() ([]byte, error)) {
	spec, err := gen()
	if err != nil {
		log.Fatalf("generating OpenAPI spec: %v", err)
	}

	err = os.MkdirAll(filepath.Dir(path), 0o755)
	if err != nil {
		log.Fatalf("creating output directory: %v", err)
	}

	err = os.WriteFile(path, spec, 0o600)
	if err != nil {
		log.Fatalf("writing %s: %v", path, err)
	}

	log.Printf("wrote %s", path)
}
