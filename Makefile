# Calculate version
version = $(shell ./scripts/version-at-commit.sh)

rwildcard=$(foreach d,$(wildcard $1*),$(call rwildcard,$d/,$2) $(filter $(subst *,%,$2),$d))

# GO_SOURCES = $(wildcard *.go)
# PROTO_SOURCES = $(wildcard **/*.proto)
GO_SOURCES = $(call rwildcard,,*.go)
PROTO_SOURCES = $(call rwildcard,,*.proto)


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
	golangci-lint run --fix --timeout 10m

fmt:
	prettier --write '**/**.{ts,js,md,yaml,yml,sass,css,scss,html}'
	golines --max-len=88 --base-formatter=gofumpt -w $(GO_SOURCES)
	clang-format -style="{BasedOnStyle: Google, IndentWidth: 4, AlignConsecutiveDeclarations: true, AlignConsecutiveAssignments: true, ColumnLimit: 0}" -i $(PROTO_SOURCES)

proto-lint:
	cd proto/ && buf lint

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
