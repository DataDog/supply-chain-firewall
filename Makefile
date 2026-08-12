BINARY := bin/scfw

.PHONY: all build clean golangci-lint lint test test-build test-cli test-ddapi test-ecosystem test-npm test-pip test-pm test-poetry

all: build

build:
	go build -o $(BINARY) ./scfw

clean:
	rm -f $(BINARY)

golangci-lint:
	golangci-lint run --tests=false

lint:
	test -z "$$(gofmt -l .)"
	go vet ./...

test: test-build test-cli test-ddapi test-ecosystem test-npm test-pip test-pm test-poetry

test-build:
	go test -count=2 ./scfw/internal/build

test-cli:
	go test -count=2 ./scfw/internal/cli/...

test-ddapi:
	go test -count=2 ./scfw/internal/ddapi/...

test-ecosystem:
	go test -count=2 ./scfw/internal/ecosystem/...

test-npm:
	go test -count=2 ./scfw/internal/pm/npm/...

test-pip:
	go test -count=2 ./scfw/internal/pm/pip/...

test-pm:
	go test -count=2 ./scfw/internal/pm

test-poetry:
	go test ./scfw/internal/pm/poetry/...
