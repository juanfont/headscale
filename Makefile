# Calculate version
version ?= $(shell git describe --always --tags --dirty)

rwildcard=$(foreach d,$(wildcard $1*),$(call rwildcard,$d/,$2) $(filter $(subst *,%,$2),$d))

# Determine if OS supports pie
GOOS ?= $(shell uname | tr '[:upper:]' '[:lower:]')
ifeq ($(filter $(GOOS), openbsd netbsd soloaris plan9), )
	pieflags = -buildmode=pie
else
endif

TAGS = -tags ts2019

# GO_SOURCES = $(wildcard *.go)
# PROTO_SOURCES = $(wildcard **/*.proto)
GO_SOURCES = $(call rwildcard,,*.go)
PROTO_SOURCES = $(call rwildcard,,*.proto)


build:
	nix build --extra-experimental-features nix-command --extra-experimental-features flakes

dev: lint test build

test:
	gotestsum -- $(TAGS) -short -coverprofile=coverage.out ./...

test_integration:
	docker run \
		-t --rm \
		-v ~/.cache/hs-integration-go:/go \
		--name headscale-test-suite \
		-v $$PWD:$$PWD -w $$PWD/integration \
		-v /var/run/docker.sock:/var/run/docker.sock \
		golang:1 \
		go run gotest.tools/gotestsum@latest -- $(TAGS) -failfast ./... -timeout 120m -parallel 8

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
	buf generate proto
