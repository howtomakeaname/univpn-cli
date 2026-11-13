export GOPATH := $(CURDIR)/.cache/gopath
export GOCACHE := $(CURDIR)/.cache/gobuild

.PHONY: build test check
build:
	CGO_ENABLED=0 go build -trimpath -o bin/uvpn ./cmd/uvpn
test:
	go test -race ./...
check:
	go vet ./...
