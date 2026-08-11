BINARY := scfw

.PHONY: all build clean golangci-lint lint test test-build test-cli test-ddapi test-ecosystem test-npm test-pip test-pm test-poetry

all: build

build:
	go build -o $(BINARY) .

clean:
	rm -f $(BINARY)

golangci-lint:
	golangci-lint run --tests=false

lint:
	test -z "$$(gofmt -l .)"
	go vet ./...

test: test-build test-cli test-ddapi test-ecosystem test-npm test-pip test-pm test-poetry

test-build:
	go test -count=2 ./internal/build

test-cli:
	go test -count=2 ./internal/cli/...

test-ddapi:
	go test -count=2 ./internal/ddapi/...

test-ecosystem:
	go test -count=2 ./internal/ecosystem/...

test-npm:
	go test -count=2 ./internal/pm/npm/...

test-pip:
	go test -count=2 ./internal/pm/pip/...

test-pm:
	go test -count=2 ./internal/pm

test-poetry:
	go test ./internal/pm/poetry/...
