# Integration testing

Headscale relies on integration testing to ensure we remain compatible with Tailscale.

This is typically performed by starting a Headscale server and running a test "scenario"
with an array of Tailscale clients and versions.

Headscale's test framework and the current set of scenarios are defined in this directory.

Tests are located in files ending with `_test.go` and the framework are located in the rest.

## Running integration tests on GitHub Actions

Each test currently runs as a separate workflows in GitHub actions, to add new test, add
the new test to the list in `../cmd/gh-action-integration-generator/main.go` and run
`go generate` inside `../cmd/gh-action-integration-generator/` and commit the result.
