# Calculate version
version ?= $(shell git describe --always --tags --dirty)

rwildcard=$(foreach d,$(wildcard $1*),$(call rwildcard,$d/,$2) $(filter $(subst *,%,$2),$d))

# Determine if OS supports pie
GOOS ?= $(shell uname | tr '[:upper:]' '[:lower:]')
ifeq ($(filter $(GOOS), openbsd netbsd soloaris plan9), )
	pieflags = -buildmode=pie
else
endif

# GO_SOURCES = $(wildcard *.go)
# PROTO_SOURCES = $(wildcard **/*.proto)
GO_SOURCES = $(call rwildcard,,*.go)
PROTO_SOURCES = $(call rwildcard,,*.proto)


build:
	GOOS=$(GOOS) CGO_ENABLED=0 go build -trimpath $(pieflags) -mod=readonly -ldflags "-s -w -X github.com/juanfont/headscale/cmd/headscale/cli.Version=$(version)" cmd/headscale/headscale.go

dev: lint test build

test:
	@go test -coverprofile=coverage.out ./...

test_integration: test_integration_cli test_integration_derp test_integration_general

test_integration_cli:
	go test -failfast -tags integration_cli,integration -timeout 30m -count=1 ./...

test_integration_derp:
	go test -failfast -tags integration_derp,integration -timeout 30m -count=1 ./...

test_integration_general:
	go test -failfast -tags integration_general,integration -timeout 30m -count=1 ./...

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
	cd proto/ && go run github.com/bufbuild/buf/cmd/buf lint

compress: build
	upx --brute headscale

generate:
	rm -rf gen
	go run github.com/bufbuild/buf/cmd/buf generate proto

install-protobuf-plugins:
	go install \
		github.com/grpc-ecosystem/grpc-gateway/v2/protoc-gen-grpc-gateway \
		github.com/grpc-ecosystem/grpc-gateway/v2/protoc-gen-openapiv2 \
		google.golang.org/protobuf/cmd/protoc-gen-go \
		google.golang.org/grpc/cmd/protoc-gen-go-grpc
