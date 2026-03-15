VERSION := 0.1.0
LDFLAGS := -ldflags "-X main.version=$(VERSION)"

.PHONY: build test release clean

build:
	go build $(LDFLAGS) -o bin/primust-hook ./cmd/primust-hook

test:
	go test ./...

release:
	GOOS=darwin GOARCH=arm64 go build $(LDFLAGS) -o bin/primust-hook-darwin-arm64 ./cmd/primust-hook
	GOOS=darwin GOARCH=amd64 go build $(LDFLAGS) -o bin/primust-hook-darwin-amd64 ./cmd/primust-hook
	GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o bin/primust-hook-linux-amd64 ./cmd/primust-hook
	GOOS=linux GOARCH=arm64 go build $(LDFLAGS) -o bin/primust-hook-linux-arm64 ./cmd/primust-hook

clean:
	rm -rf bin/
