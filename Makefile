.PHONY: all build dev clean test lint fmt

BINARY=fang

all: build

build:
	wails build

dev:
	wails dev

clean:
	rm -f $(BINARY)
	rm -rf build/
	rm -rf ~/.fang/reports/*

test:
	go test ./...

lint:
	go vet ./...

fmt:
	go fmt ./...
