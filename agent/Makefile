BINARY     := openidx-agent
MODULE     := github.com/openidx/openidx/agent
CMD_PKG    := ./cmd/openidx-agent

# Version injection – override on CI with:
#   make build VERSION=$(git describe --tags --always --dirty)
VERSION    ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT     ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "none")
BUILD_TIME ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

LD_PKG     := main
LDFLAGS    := -s -w \
	-X '$(LD_PKG).Version=$(VERSION)' \
	-X '$(LD_PKG).Commit=$(COMMIT)' \
	-X '$(LD_PKG).BuildTime=$(BUILD_TIME)'

OUT_DIR    := dist

.PHONY: build test clean build-all

## build: compile the agent for the current platform
build:
	go build -ldflags "$(LDFLAGS)" -o $(BINARY) $(CMD_PKG)

## test: run all unit tests
test:
	go test -v -race ./...

## clean: remove build artifacts
clean:
	rm -f $(BINARY)
	rm -rf $(OUT_DIR)

## build-all: cross-compile for all supported platforms
build-all: clean
	@mkdir -p $(OUT_DIR)

	GOOS=linux   GOARCH=amd64  go build -ldflags "$(LDFLAGS)" -o $(OUT_DIR)/$(BINARY)-linux-amd64   $(CMD_PKG)
	GOOS=linux   GOARCH=arm64  go build -ldflags "$(LDFLAGS)" -o $(OUT_DIR)/$(BINARY)-linux-arm64   $(CMD_PKG)
	GOOS=darwin  GOARCH=amd64  go build -ldflags "$(LDFLAGS)" -o $(OUT_DIR)/$(BINARY)-darwin-amd64  $(CMD_PKG)
	GOOS=darwin  GOARCH=arm64  go build -ldflags "$(LDFLAGS)" -o $(OUT_DIR)/$(BINARY)-darwin-arm64  $(CMD_PKG)
	GOOS=windows GOARCH=amd64  go build -ldflags "$(LDFLAGS)" -o $(OUT_DIR)/$(BINARY)-windows-amd64.exe $(CMD_PKG)

	@echo "Build artifacts in $(OUT_DIR)/:"
	@ls -lh $(OUT_DIR)/

## help: print this help
help:
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/^## //'
