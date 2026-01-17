
DAY=2
PROBLEM=2

SHELL:=/bin/bash
BINARY_NAME=aocd$(DAY)p$(PROBLEM)
EBPF_NAME=aocd$(DAY)p$(PROBLEM)

.PHONY: build run clean tidy generate example input

tidy:
	go mod tidy

generate:
	go generate

build: tidy generate
	CGO_ENABLED=0 go build -o bin/$(BINARY_NAME)

run: build
	sudo ./bin/$(BINARY_NAME)

clean:
	rm -rf bin/
	rm -f *_*.o
	rm -f *_*.go
	go clean

example:
	sudo uv run --project feed/ feed/feed.py < example.txt

input:
	sudo uv run --project feed/ feed/feed.py < input.txt
