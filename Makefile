BINARY := bin/scfw

.PHONY: all build clean golangci-lint lint test

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

test:
	go test -count=2 ./scfw/...
