package main

//go:generate go run ./main.go

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"text/template"
)

var (
	jobFileNameTemplate = `test-integration-v2-%s.yaml`
	jobTemplate         = template.Must(template.New("jobTemplate").Parse(`
# DO NOT EDIT, generated with cmd/gh-action-integration-generator/main.go
# To regenerate, run "go generate" in cmd/gh-action-integration-generator/

name: Integration Test v2 - {{.Name}}

on: [pull_request]

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

      - uses: cachix/install-nix-action@v16
        if: steps.changed-files.outputs.any_changed == 'true'

      - name: Run general integration tests
        if: steps.changed-files.outputs.any_changed == 'true'
        run: |
            nix develop --command -- docker run \
              --tty --rm \
              --volume ~/.cache/hs-integration-go:/go \
              --name headscale-test-suite \
              --volume $PWD:$PWD -w $PWD/integration \
              --volume /var/run/docker.sock:/var/run/docker.sock \
              golang:1 \
                go test ./... \
                  -tags ts2019 \
                  -failfast \
                  -timeout 120m \
                  -parallel 1 \
                  -run "^{{.Name}}$"
`))
)

const workflowFilePerm = 0o600

func main() {
	type testConfig struct {
		Name string
	}

	// TODO(kradalby): automatic fetch tests at runtime
	tests := []string{
		"TestAuthKeyLogoutAndRelogin",
		"TestAuthWebFlowAuthenticationPingAll",
		"TestAuthWebFlowLogoutAndRelogin",
		"TestCreateTailscale",
		"TestEnablingRoutes",
		"TestHeadscale",
		"TestUserCommand",
		"TestOIDCAuthenticationPingAll",
		"TestOIDCExpireNodes",
		"TestPingAllByHostname",
		"TestPingAllByIP",
		"TestPreAuthKeyCommand",
		"TestPreAuthKeyCommandReusableEphemeral",
		"TestPreAuthKeyCommandWithoutExpiry",
		"TestResolveMagicDNS",
		"TestSSHIsBlockedInACL",
		"TestSSHMultipleUsersAllToAll",
		"TestSSHNoSSHConfigured",
		"TestSSHOneUserAllToAll",
		"TestSSUserOnlyIsolation",
		"TestTaildrop",
		"TestTailscaleNodesJoiningHeadcale",
	}

	for _, test := range tests {
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
