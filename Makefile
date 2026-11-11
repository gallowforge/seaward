# make            the binary in bin/
# make test       Go tests with the race detector, then the page's
# make lab        the engine against the real kernel: every scenario, each in a private network namespace
# make demo       the demo page in pages/, with the engine compiled to WebAssembly
# make pages      the same, plus the picture for its link card: what goes live
# make release    static binaries for Linux and macOS in dist/
# make shots      the README's pictures: real terminal sessions and the running demo, staged as glass
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X github.com/gallowforge/seaward/internal/snapshot.Version=$(VERSION:v%=%)
TARGETS := linux/amd64 linux/arm64 darwin/arm64 darwin/amd64
export CGO_ENABLED = 0

.PHONY: all build test lab demo pages release shots

all: build

build:
	go build -trimpath -ldflags '$(LDFLAGS)' -o bin/seaward ./cmd/seaward

test:
	go vet ./...
	CGO_ENABLED=1 go test -race ./...    # the race detector needs cgo; builds stay static
	cd web && npm run typecheck && npm test

# Builds real rulesets in throwaway network namespaces, sends real packets through them and
# compares what the kernel did with what the engine says. Nothing outside the namespaces is touched.
lab:
	go test -tags kernel ./internal/lab/ -run Kernel -count=1 -v

# The page with the engine compiled for the browser. wasm_exec.js is Go's loader and has to come
# from the Go that built the engine. `demo` is the page without its link card's picture, which is
# one of the README's pictures and is itself taken from the running demo.
demo:
	cd web && npm ci --no-audit --no-fund && npm run build
	GOOS=js GOARCH=wasm go build -trimpath -ldflags '$(LDFLAGS)' -o pages/seaward.wasm ./cmd/seaward-wasm
	cp "$$(go env GOROOT)/lib/wasm/wasm_exec.js" pages/wasm_exec.js

pages: demo
	cp docs/readme/social.png pages/social.png

release:
	mkdir -p dist
	set -e; for t in $(TARGETS); do \
		GOOS=$${t%/*} GOARCH=$${t#*/} go build -trimpath -ldflags '$(LDFLAGS)' -o dist/seaward-$${t%/*}-$${t#*/} ./cmd/seaward; \
	done
	cd dist && sha256sum seaward-* > SHA256SUMS

shots: build demo
	cd docs/readme/src && npm ci --no-audit --no-fund && ./build.sh ../../../bin/seaward ../../../pages
