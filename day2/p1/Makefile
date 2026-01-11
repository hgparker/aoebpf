
DAY=2
PROBLEM=1

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
	while IFS= read -r line; do \
		echo "$$line"; \
	done < example.txt

input:
	while IFS= read -r line; do \
		echo "$$line"; \
	done < input.txt
