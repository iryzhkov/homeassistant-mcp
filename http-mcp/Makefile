SHELL := /bin/sh
export HOME := $(CURDIR)/.cache/ha-impl/home
export TMPDIR := $(CURDIR)/.cache/ha-impl/tmp
export HUYANG_FRICTION := 0
export GOTOOLCHAIN := local

.PHONY: prepare check test build
prepare:
	test "$$HOME" = "$(CURDIR)/.cache/ha-impl/home"
	test "$$TMPDIR" = "$(CURDIR)/.cache/ha-impl/tmp"
	mkdir -p "$$HOME" "$$TMPDIR"

test: prepare
	go test -mod=readonly -race -count=1 -timeout=90s ./...

build: prepare
	mkdir -p bin
	CGO_ENABLED=0 go build -mod=readonly -trimpath -o bin/ha-mcp ./cmd/ha-mcp

check: test build
	test -z "$$(gofmt -l cmd internal)"
	go vet -mod=readonly ./...
