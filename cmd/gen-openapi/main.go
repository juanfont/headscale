// Command gen-openapi emits a Headscale OpenAPI document from the authoritative
// Huma definitions in hscontrol/api/v1, hscontrol/api/v2 and
// hscontrol/api/headscale/v0. The server also serves each spec live; this tool
// emits them on demand, and with -downgrade the 3.0.3 form used to generate the
// typed v1 and v2 clients. Only the v0 document is committed: a test fails
// when it is stale, and the docs site serves it.
//
// Usage:
//
//	go run ./cmd/gen-openapi                       # write the v1 3.1 spec to its default path
//	go run ./cmd/gen-openapi -api v2               # write the v2 3.1 spec to its default path
//	go run ./cmd/gen-openapi -downgrade <path>     # write the v1 3.0.3 downgrade (for client gen)
//	go run ./cmd/gen-openapi -api v2 -downgrade <path>  # the v2 3.0.3 downgrade
//	go run ./cmd/gen-openapi -api headscale/v0     # write the committed v0 3.1 spec
package main

import (
	"flag"
	"log"
	"os"
	"path/filepath"

	apiv1 "github.com/juanfont/headscale/hscontrol/api/v1"
	apiv0 "github.com/juanfont/headscale/hscontrol/api/headscale/v0"
	apiv2 "github.com/juanfont/headscale/hscontrol/api/v2"
)

// spec bundles a version's full (3.1) and downgraded (3.0.3) generators with the
// committed output path. outPath is relative to the repository root.
type spec struct {
	full    func() ([]byte, error)
	down    func() ([]byte, error)
	outPath string
}

// specs maps the -api value to its generators.
var specs = map[string]spec{
	"v1": {apiv1.Spec, apiv1.Spec30, "openapi/v1/headscale.yaml"},
	"v2": {apiv2.Spec, apiv2.Spec30, "openapi/v2/headscale.yaml"},
	// v0 is generated from the 3.1 document, which is in the tree.
	"headscale/v0": {apiv0.Spec, nil, "docs/ref/api/headscale-v0.yaml"},
}

func main() {
	api := flag.String("api", "v1", "which API spec to emit: v1, v2 or headscale/v0")
	downgrade := flag.String("downgrade", "", "write the OpenAPI 3.0.3 downgrade to this path instead of the committed 3.1 spec")
	flag.Parse()

	s, ok := specs[*api]
	if !ok {
		log.Fatalf("unknown -api %q (want v1, v2 or headscale/v0)", *api)
	}

	if *downgrade != "" {
		if s.down == nil {
			log.Fatalf("-api %s has no 3.0.3 downgrade", *api)
		}

		writeSpec(*downgrade, s.down)

		return
	}

	writeSpec(s.outPath, s.full)

	// The page of problem codes goes with the document: the type of every
	// problem leads to it.
	if *api == "headscale/v0" {
		writeSpec("docs/ref/api/problems.md", func() ([]byte, error) { return apiv0.ProblemsPage(), nil })
	}
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
