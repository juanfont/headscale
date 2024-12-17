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
	nix build

dev: lint test build

test:
	gotestsum -- -short -race -coverprofile=coverage.out ./...

test_integration:
	docker run \
		-t --rm \
		-v ~/.cache/hs-integration-go:/go \
		--name headscale-test-suite \
		-v $$PWD:$$PWD -w $$PWD/integration \
		-v /var/run/docker.sock:/var/run/docker.sock \
		-v $$PWD/control_logs:/tmp/control \
		golang:1 \
		go run gotest.tools/gotestsum@latest -- -race -failfast ./... -timeout 120m -parallel 8

lint:
	golangci-lint run --fix --timeout 10m

fmt: fmt-go fmt-prettier fmt-proto

fmt-prettier:
	prettier --write '**/**.{ts,js,md,yaml,yml,sass,css,scss,html}'
	prettier --write --print-width 80 --prose-wrap always CHANGELOG.md

fmt-go:
	# TODO(kradalby): Reeval if we want to use 88 in the future.
	# golines --max-len=88 --base-formatter=gofumpt -w $(GO_SOURCES)
	gofumpt -l -w .
	golangci-lint run --fix

fmt-proto:
	clang-format -i $(PROTO_SOURCES)

proto-lint:
	cd proto/ && go run github.com/bufbuild/buf/cmd/buf lint

compress: build
	upx --brute headscale

generate:
	rm -rf gen
	buf generate proto
