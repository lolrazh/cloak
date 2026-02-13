BINARY := cloak
MODULE := github.com/lolrazh/cloak
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS := -ldflags "-X $(MODULE)/cmd.Version=$(VERSION)"

.PHONY: build test clean run build-all

build:
	go build $(LDFLAGS) -o $(BINARY) .

test:
	go test ./... -v

clean:
	rm -f $(BINARY) $(BINARY)-*

run: build
	./$(BINARY)

build-all: build-linux build-darwin

build-linux:
	GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o $(BINARY)-linux-amd64 .
	GOOS=linux GOARCH=arm64 go build $(LDFLAGS) -o $(BINARY)-linux-arm64 .

build-darwin:
	GOOS=darwin GOARCH=arm64 go build $(LDFLAGS) -o $(BINARY)-darwin-arm64 .
	GOOS=darwin GOARCH=amd64 go build $(LDFLAGS) -o $(BINARY)-darwin-amd64 .
