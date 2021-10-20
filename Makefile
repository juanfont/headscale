# Calculate version
version = $(shell ./scripts/version-at-commit.sh)

build:
	go build -ldflags "-s -w -X github.com/juanfont/headscale/cmd/headscale/cli.Version=$(version)" cmd/headscale/headscale.go

dev: lint test build

test:
	@go test -coverprofile=coverage.out ./...

test_integration:
	go test -tags integration -timeout 30m ./...

coverprofile_func:
	go tool cover -func=coverage.out

coverprofile_html:
	go tool cover -html=coverage.out

lint:
	golangci-lint run --timeout 10m

compress: build
	upx --brute headscale

