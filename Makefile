BINARY  := signet
MODULE  := github.com/Einlanzerous/signet
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

.PHONY: build test fmt vet clean

build:
	CGO_ENABLED=0 go build -trimpath \
		-ldflags "-s -w -X $(MODULE)/internal/version.Version=$(VERSION)" \
		-o $(BINARY) ./cmd/signet

test:
	go test ./...

fmt:
	gofmt -l -w .

vet:
	go vet ./...

clean:
	rm -f $(BINARY)
