// Command gen-openapi emits a Headscale OpenAPI 3.1 document from the
// authoritative Huma definitions in hscontrol/api/v1, hscontrol/api/v2 and
// hscontrol/api/headscale/v0, and with -client the document `make client`
// generates that API's typed client from. The server also serves each
// document live. Only the v0 document is committed: the docs site publishes
// it, and a test fails when it is stale.
//
// Usage:
//
//	go run ./cmd/gen-openapi                          # write the v1 document to its path
//	go run ./cmd/gen-openapi -api v2                  # write the v2 document to its path
//	go run ./cmd/gen-openapi -api headscale/v0        # write the committed v0 document
//	go run ./cmd/gen-openapi -api v2 -client <path>   # the input of the v2 client
package main

import (
	"flag"
	"log"
	"os"
	"path/filepath"

	apiv0 "github.com/juanfont/headscale/hscontrol/api/headscale/v0"
	apiv1 "github.com/juanfont/headscale/hscontrol/api/v1"
	apiv2 "github.com/juanfont/headscale/hscontrol/api/v2"
)

// spec is one API: the document it serves, the document its client is
// generated from, and where the first is written, relative to the
// repository root.
type spec struct {
	full    func() ([]byte, error)
	client  func() ([]byte, error)
	outPath string
}

// specs is every API, each generated the same way: oapi-codegen reads its
// 3.1 document with cmd/gen-openapi/<api>-client.yaml. The client of v2
// alone reads a document of its own, because v2's request bodies spell out
// additionalProperties: true (see [apiv2.ClientSpec]).
var specs = map[string]spec{
	"v1":           {apiv1.Spec, apiv1.Spec, "openapi/v1/headscale.yaml"},
	"v2":           {apiv2.Spec, apiv2.ClientSpec, "openapi/v2/headscale.yaml"},
	"headscale/v0": {apiv0.Spec, apiv0.Spec, "docs/ref/api/headscale-v0.yaml"},
}

func main() {
	api := flag.String("api", "v1", "which API spec to emit: v1, v2 or headscale/v0")
	client := flag.String("client", "", "write the document the API's client is generated from to this path instead")
	flag.Parse()

	s, ok := specs[*api]
	if !ok {
		log.Fatalf("unknown -api %q (want v1, v2 or headscale/v0)", *api)
	}

	if *client != "" {
		writeSpec(*client, s.client)

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
