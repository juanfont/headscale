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
	golint
	golangci-lint run --timeout 5m

compress: build
	upx --brute headscale

generate:
	rm -rf gen
	buf generate proto

install-protobuf-plugins:
	go install \
		github.com/grpc-ecosystem/grpc-gateway/v2/protoc-gen-grpc-gateway \
		github.com/grpc-ecosystem/grpc-gateway/v2/protoc-gen-openapiv2 \
		google.golang.org/protobuf/cmd/protoc-gen-go \
		google.golang.org/grpc/cmd/protoc-gen-go-grpc
