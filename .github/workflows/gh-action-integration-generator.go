package main

//go:generate go run ./gh-action-integration-generator.go

import (
	"bytes"
	"fmt"
	"log"
	"os/exec"
	"strings"
)

// testsToSplit defines tests that should be split into multiple CI jobs.
// Key is the test function name, value is a list of subtest prefixes.
// Each prefix becomes a separate CI job as "TestName/prefix".
//
// Example: TestAutoApproveMultiNetwork has subtests like:
//   - TestAutoApproveMultiNetwork/authkey-tag-advertiseduringup-false-pol-database
//   - TestAutoApproveMultiNetwork/webauth-user-advertiseduringup-true-pol-file
//
// Splitting by approver type (tag, user, group) creates 6 CI jobs with 4 tests each:
//   - TestAutoApproveMultiNetwork/authkey-tag.* (4 tests)
//   - TestAutoApproveMultiNetwork/authkey-user.* (4 tests)
//   - TestAutoApproveMultiNetwork/authkey-group.* (4 tests)
//   - TestAutoApproveMultiNetwork/webauth-tag.* (4 tests)
//   - TestAutoApproveMultiNetwork/webauth-user.* (4 tests)
//   - TestAutoApproveMultiNetwork/webauth-group.* (4 tests)
//
// This reduces load per CI job (4 tests instead of 12) to avoid infrastructure
// flakiness when running many sequential Docker-based integration tests.
var testsToSplit = map[string][]string{
	"TestAutoApproveMultiNetwork": {
		"authkey-tag",
		"authkey-user",
		"authkey-group",
		"webauth-tag",
		"webauth-user",
		"webauth-group",
	},
}

// expandTests takes a list of test names and expands any that need splitting
// into multiple subtest patterns.
func expandTests(tests []string) []string {
	var expanded []string
	for _, test := range tests {
		if prefixes, ok := testsToSplit[test]; ok {
			// This test should be split into multiple jobs.
			// We append ".*" to each prefix because the CI runner wraps patterns
			// with ^...$ anchors. Without ".*", a pattern like "authkey$" wouldn't
			// match "authkey-tag-advertiseduringup-false-pol-database".
			for _, prefix := range prefixes {
				expanded = append(expanded, fmt.Sprintf("%s/%s.*", test, prefix))
			}
		} else {
			expanded = append(expanded, test)
		}
	}
	return expanded
}

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

func updateYAML(tests []string, jobName string, testPath string) {
	testsForYq := fmt.Sprintf("[%s]", strings.Join(tests, ", "))

	yqCommand := fmt.Sprintf(
		"yq eval '.jobs.%s.strategy.matrix.test = %s' %s -i",
		jobName,
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

	fmt.Printf("YAML file (%s) job %s updated successfully\n", testPath, jobName)
}

func main() {
	tests := findTests()

	// Expand tests that should be split into multiple jobs
	expandedTests := expandTests(tests)

	quotedTests := make([]string, len(expandedTests))
	for i, test := range expandedTests {
		quotedTests[i] = fmt.Sprintf("\"%s\"", test)
	}

	// Define selected tests for PostgreSQL
	postgresTestNames := []string{
		"TestACLAllowUserDst",
		"TestPingAllByIP",
		"TestEphemeral2006DeletedTooQuickly",
		"TestPingAllByIPManyUpDown",
		"TestSubnetRouterMultiNetwork",
	}

	quotedPostgresTests := make([]string, len(postgresTestNames))
	for i, test := range postgresTestNames {
		quotedPostgresTests[i] = fmt.Sprintf("\"%s\"", test)
	}

	// Update both SQLite and PostgreSQL job matrices
	updateYAML(quotedTests, "sqlite", "./test-integration.yaml")
	updateYAML(quotedPostgresTests, "postgres", "./test-integration.yaml")
}
