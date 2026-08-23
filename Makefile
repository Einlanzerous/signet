BINARY  := signet
MODULE  := github.com/Einlanzerous/signet
# `sed 's/^v//'` is not cosmetic (SGNT-38). `git describe` returns the tag as
# written — `v1.9.0` — and that is what /healthz would then report, while the
# estate-wide form is bare semver. Switchyard compares versions with strict
# equality, so the form has to be identical everywhere it is produced.
VERSION ?= $(shell (git describe --tags --always --dirty 2>/dev/null || echo dev) | sed 's/^v//')
COMMIT  ?= $(shell git rev-parse HEAD 2>/dev/null)

.PHONY: build test fmt vet clean

build:
	CGO_ENABLED=0 go build -trimpath \
		-ldflags "-s -w -X $(MODULE)/internal/version.Version=$(VERSION) -X $(MODULE)/internal/version.Commit=$(COMMIT)" \
		-o $(BINARY) ./cmd/signet

test:
	go test ./...

fmt:
	gofmt -l -w .

vet:
	go vet ./...

clean:
	rm -f $(BINARY)
