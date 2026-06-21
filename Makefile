# Headscale Makefile
# Modern Makefile following best practices

# Version calculation
VERSION ?= $(shell git describe --always --tags --dirty)

# Build configuration
GOOS ?= $(shell uname | tr '[:upper:]' '[:lower:]')
ifeq ($(filter $(GOOS), openbsd netbsd solaris plan9), )
	PIE_FLAGS = -buildmode=pie
endif

# Tool availability check with nix warning
define check_tool
	@command -v $(1) >/dev/null 2>&1 || { \
		echo "Warning: $(1) not found. Run 'nix develop' to ensure all dependencies are available."; \
		exit 1; \
	}
endef

# Source file collections using shell find for better performance
GO_SOURCES := $(shell find . -name '*.go' -not -path './gen/*' -not -path './vendor/*')
PRETTIER_SOURCES := $(shell find . \( -name '*.md' -o -name '*.yaml' -o -name '*.yml' -o -name '*.ts' -o -name '*.js' -o -name '*.html' -o -name '*.css' -o -name '*.scss' -o -name '*.sass' \) -not -path './gen/*' -not -path './vendor/*' -not -path './node_modules/*')

# Default target
.PHONY: all
all: lint test build

# Dependency checking
.PHONY: check-deps
check-deps:
	$(call check_tool,go)
	$(call check_tool,golangci-lint)
	$(call check_tool,gofumpt)
	$(call check_tool,mdformat)
	$(call check_tool,prettier)

# Build targets
.PHONY: build
build: check-deps $(GO_SOURCES) go.mod go.sum
	@echo "Building headscale..."
	go build $(PIE_FLAGS) -ldflags "-X main.version=$(VERSION)" -o headscale ./cmd/headscale

# Test targets
.PHONY: test
test: check-deps $(GO_SOURCES) go.mod go.sum
	@echo "Running Go tests..."
	go test -race ./...


# Formatting targets
.PHONY: fmt
fmt: fmt-go fmt-mdformat fmt-prettier

.PHONY: fmt-go
fmt-go: check-deps $(GO_SOURCES)
	@echo "Formatting Go code..."
	gofumpt -l -w .
	golangci-lint run --fix

.PHONY: fmt-mdformat
fmt-mdformat: check-deps
	@echo "Formatting documentation..."
	mdformat docs/

.PHONY: fmt-prettier
fmt-prettier: check-deps $(PRETTIER_SOURCES)
	@echo "Formatting markup and config files..."
	prettier --write '**/*.{ts,js,md,yaml,yml,sass,css,scss,html}'

# Linting targets
.PHONY: lint
lint: lint-go

.PHONY: lint-go
lint-go: check-deps $(GO_SOURCES) go.mod go.sum
	@echo "Linting Go code..."
	golangci-lint run --timeout 10m

# Code generation
.PHONY: generate
generate: check-deps
	@echo "Generating code..."
	go generate ./...
	$(MAKE) client

# Emit the OpenAPI spec on demand. The server serves it live at /openapi.yaml;
# this is for external consumers or inspection and is not committed.
.PHONY: openapi
openapi:
	@echo "Emitting OpenAPI spec from code..."
	go run ./cmd/gen-openapi

# Generate the strongly-typed Go HTTP clients (v1 and v2). The served specs are
# OpenAPI 3.1, but oapi-codegen v2 does not yet read 3.1, so each client is
# generated from a transient 3.0.3 downgrade of its document. Pinned so the
# committed clients are reproducible.
.PHONY: client
client:
	@echo "Generating API clients..."
	@tmp=$$(mktemp -t headscale-openapi-3.0.XXXXXX.yaml); \
	go run ./cmd/gen-openapi -downgrade "$$tmp" && \
	go run github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@v2.7.1 \
		-generate types,client -package clientv1 -o gen/client/v1/client.gen.go "$$tmp" && \
	go run ./cmd/gen-openapi -api v2 -downgrade "$$tmp" && \
	go run github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@v2.7.1 \
		-generate types,client -package clientv2 -o gen/client/v2/client.gen.go "$$tmp"; \
	status=$$?; rm -f "$$tmp"; exit $$status

# Clean targets
.PHONY: clean
clean:
	rm -rf headscale gen/client

# Development workflow
.PHONY: dev
dev: fmt lint test build

# Start a local headscale dev server (use mts to add nodes)
.PHONY: dev-server
dev-server:
	go run ./cmd/dev

# Help target
.PHONY: help
help:
	@echo "Headscale Development Makefile"
	@echo ""
	@echo "Main targets:"
	@echo "  all          - Run lint, test, and build (default)"
	@echo "  build        - Build headscale binary"
	@echo "  test         - Run Go tests"
	@echo "  fmt          - Format all code (Go, docs, markup)"
	@echo "  lint         - Lint all code (Go)"
	@echo "  generate     - Generate code (go generate + client)"
	@echo "  dev          - Full development workflow (fmt + lint + test + build)"
	@echo "  clean        - Clean build artifacts"
	@echo ""
	@echo "Specific targets:"
	@echo "  fmt-go       - Format Go code only"
	@echo "  fmt-mdformat - Format documentation only"
	@echo "  fmt-prettier - Format markup and config files only"
	@echo "  lint-go      - Lint Go code only"
	@echo ""
	@echo "Dependencies:"
	@echo "  check-deps   - Verify required tools are available"
	@echo ""
	@echo "Note: If not running in a nix shell, ensure dependencies are available:"
	@echo "  nix develop"
