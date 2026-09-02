# aivault — single static binary (SPEC 1, 9)

BINARY := aivault
GO     ?= go

.PHONY: build test vet fmt staticcheck govulncheck

build:
	$(GO) build -trimpath -ldflags "-s -w" -o $(BINARY) ./cmd/aivault

test:
	$(GO) test ./...

vet:
	$(GO) vet ./...

fmt:
	$(GO) fmt ./...

# Dependency hygiene per SPEC 8.9.
staticcheck:
	staticcheck ./...

govulncheck:
	$(GO) run golang.org/x/vuln/cmd/govulncheck@latest ./...