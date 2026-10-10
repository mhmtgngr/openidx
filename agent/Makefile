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

.PHONY: build test clean build-all build-screenshare package-linux

## build: compile the agent for the current platform
build:
	go build -ldflags "$(LDFLAGS)" -o $(BINARY) $(CMD_PKG)

## build-screenshare: compile WITH real screen capture + VP8 (remote support).
## Requires CGO + libvpx (Linux: apt install libvpx-dev libx11-dev;
## Windows CI: the toolchain ships libvpx). The default build uses a no-op
## capture stub so it cross-compiles as pure Go.
build-screenshare:
	CGO_ENABLED=1 go build -tags screenshare -ldflags "$(LDFLAGS)" -o $(BINARY) $(CMD_PKG)

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

## package-linux: build .deb and .rpm for linux amd64+arm64 (requires nfpm)
## See https://nfpm.goreleaser.com. macOS .pkg and Windows .msi are built in CI
## on their native runners (pkgbuild / WiX); see packaging/DEEPLINK.md.
##
## ZITI_TUNNEL_DIR, when set, names a directory holding verified OpenZiti
## tunneler binaries ziti-edge-tunnel-linux-amd64 and -arm64 (the workflow's
## "Fetch the OpenZiti tunneler" step); the packages then carry the tunneler and
## openidx-tunnel.service (packaging/nfpm-tunnel.contents.yaml). It is outside
## dist/ because build-all starts by deleting dist/. Unset = no tunneler, as
## before. See docs/AGENT-TUNNEL.md.
ZITI_TUNNEL_DIR ?=

package-linux: build-all
	@command -v nfpm >/dev/null || { echo "nfpm not installed: https://nfpm.goreleaser.com"; exit 1; }
	@mkdir -p $(OUT_DIR)/pkg
	@set -e; nfpmcfg=packaging/nfpm.yaml; \
	if [ -n "$(ZITI_TUNNEL_DIR)" ]; then \
		nfpmcfg=$(OUT_DIR)/nfpm-tunnel.yaml; \
		cat packaging/nfpm.yaml packaging/nfpm-tunnel.contents.yaml > $$nfpmcfg; \
		echo "bundling the OpenZiti tunneler from $(ZITI_TUNNEL_DIR)"; \
	fi; \
	for arch in amd64 arm64; do \
		cp $(OUT_DIR)/$(BINARY)-linux-$$arch $(OUT_DIR)/$(BINARY)-linux ; \
		if [ -n "$(ZITI_TUNNEL_DIR)" ]; then \
			install -m 0755 "$(ZITI_TUNNEL_DIR)/ziti-edge-tunnel-linux-$$arch" $(OUT_DIR)/ziti-edge-tunnel-linux ; \
		fi; \
		for pkg in deb rpm; do \
			VERSION=$(VERSION) ARCH=$$arch nfpm pkg -f $$nfpmcfg -p $$pkg -t $(OUT_DIR)/pkg/ ; \
		done ; \
	done; rm -f $(OUT_DIR)/$(BINARY)-linux $(OUT_DIR)/ziti-edge-tunnel-linux $(OUT_DIR)/nfpm-tunnel.yaml
	@ls -lh $(OUT_DIR)/pkg/

## help: print this help
help:
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/^## //'
