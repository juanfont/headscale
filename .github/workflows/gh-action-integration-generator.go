package main

//go:generate go run ./gh-action-integration-generator.go

import (
	"bytes"
	"fmt"
	"log"
	"os/exec"
	"strings"
)

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

	cmd := exec.Command(rgBin, args...)
	var out bytes.Buffer
	cmd.Stdout = &out
	err = cmd.Run()
	if err != nil {
		log.Fatalf("failed to run command: %s", err)
	}

	tests := strings.Split(strings.TrimSpace(out.String()), "\n")
	return tests
}

func updateYAML(tests []string, testPath string) {
	testsForYq := fmt.Sprintf("[%s]", strings.Join(tests, ", "))

	yqCommand := fmt.Sprintf(
		"yq eval '.jobs.integration-test.strategy.matrix.test = %s' %s -i",
		testsForYq,
		testPath,
	)
	cmd := exec.Command("bash", "-c", yqCommand)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		log.Printf("stdout: %s", stdout.String())
		log.Printf("stderr: %s", stderr.String())
		log.Fatalf("failed to run yq command: %s", err)
	}

	fmt.Printf("YAML file (%s) updated successfully\n", testPath)
}

func main() {
	tests := findTests()

	quotedTests := make([]string, len(tests))
	for i, test := range tests {
		quotedTests[i] = fmt.Sprintf("\"%s\"", test)
	}

	updateYAML(quotedTests, "./test-integration.yaml")
	updateYAML(quotedTests, "./test-integration-policyv2.yaml")
}
