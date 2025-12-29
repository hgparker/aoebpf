
SHELL:=/bin/bash
BINARY_NAME=aocd1p2
EBPF_NAME=aocd1p2

.PHONY: build run clean tidy generate example input

tidy:
	go mod tidy

generate:
	go generate

build: tidy generate
	go build -o bin/$(BINARY_NAME)

run: build
	sudo ./bin/$(BINARY_NAME)

clean:
	rm -rf bin/
	rm -f $(EBPF_NAME)_*
	go clean

example:
	while IFS= read -r line; do \
		echo "$$line"; \
	done < example.txt

input:
	while IFS= read -r line; do \
		echo "$$line"; \
	done < input.txt
