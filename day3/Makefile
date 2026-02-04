DAY := 3
SHELL := /bin/bash
BINARY_NAME := aocd$(DAY)
EBPF_NAME := aocd$(DAY)
PROBLEM ?= p1

.PHONY: build run clean tidy generate example input

ifeq ($(PROBLEM),p1)
SEQUENCE_LEN := 2
else
SEQUENCE_LEN := 12
endif

tidy:
	go mod tidy

generate:
	SEQUENCE_LEN=$(SEQUENCE_LEN) go generate

clean:
	rm -rf bin/
	rm -f *_*.o
	rm -f *_*.go
	go clean

vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

build: tidy generate
	CGO_ENABLED=0 go build -o bin/$(BINARY_NAME)

run: build
	sudo ./bin/$(BINARY_NAME)

example:
	while IFS= read -r line; do \
		echo "$$line" | nc localhost -N 9999; \
	done < example.txt

input:
	while IFS= read -r line; do \
		echo "$$line" | nc localhost -N 9999; \
	done < input.txt
