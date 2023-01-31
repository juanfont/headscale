package main

//go:generate go run ./main.go

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
	"text/template"
)

var (
	jobFileNameTemplate = `test-integration-v2-%s.yaml`
	jobTemplate         = template.Must(
		template.New("jobTemplate").
			Parse(`# DO NOT EDIT, generated with cmd/gh-action-integration-generator/main.go
# To regenerate, run "go generate" in cmd/gh-action-integration-generator/

name: Integration Test v2 - {{.Name}}

on: [pull_request]

concurrency:
  group: {{ "${{ github.workflow }}-$${{ github.head_ref || github.run_id }}" }}
  cancel-in-progress: true

jobs:
  test:
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v3
        with:
          fetch-depth: 2

      - name: Get changed files
        id: changed-files
        uses: tj-actions/changed-files@v34
        with:
          files: |
            *.nix
            go.*
            **/*.go
            integration_test/
            config-example.yaml

      - uses: cachix/install-nix-action@v18
        if: {{ "${{ env.ACT }}" }} || steps.changed-files.outputs.any_changed == 'true'

      - name: Run general integration tests
        if: steps.changed-files.outputs.any_changed == 'true'
        run: |
            nix develop --command -- docker run \
              --tty --rm \
              --volume ~/.cache/hs-integration-go:/go \
              --name headscale-test-suite \
              --volume $PWD:$PWD -w $PWD/integration \
              --volume /var/run/docker.sock:/var/run/docker.sock \
              --volume $PWD/control_logs:/tmp/control \
              golang:1 \
                go test ./... \
                  -tags ts2019 \
                  -failfast \
                  -timeout 120m \
                  -parallel 1 \
                  -run "^{{.Name}}$"

      - uses: actions/upload-artifact@v3
        if: always() && steps.changed-files.outputs.any_changed == 'true'
        with:
          name: logs
          path: "control_logs/*.log"
`),
	)
)

const workflowFilePerm = 0o600

func findTests() []string {
	rgBin, err := exec.LookPath("rg")
	if err != nil {
		log.Fatalf("failed to find rg (ripgrep) binary")
	}

	args := []string{
		"--regexp", "func (Test.+)\\(.*",
		"../../integration/",
		"--replace", "$1",
		"--sort", "path",
		"--no-line-number",
		"--no-filename",
		"--no-heading",
	}

	log.Printf("executing: %s %s", rgBin, strings.Join(args, " "))

	ripgrep := exec.Command(
		rgBin,
		args...,
	)

	result, err := ripgrep.CombinedOutput()
	if err != nil {
		log.Printf("out: %s", result)
		log.Fatalf("failed to run ripgrep: %s", err)
	}

	tests := strings.Split(string(result), "\n")
	tests = tests[:len(tests)-1]

	return tests
}

func main() {
	type testConfig struct {
		Name string
	}

	tests := findTests()

	for _, test := range tests {
		log.Printf("generating workflow for %s", test)

		var content bytes.Buffer

		if err := jobTemplate.Execute(&content, testConfig{
			Name: test,
		}); err != nil {
			log.Fatalf("failed to render template: %s", err)
		}

		path := "../../.github/workflows/" + fmt.Sprintf(jobFileNameTemplate, test)

		err := os.WriteFile(path, content.Bytes(), workflowFilePerm)
		if err != nil {
			log.Fatalf("failed to write github job: %s", err)
		}
	}
}
