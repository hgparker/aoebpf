DAY=3

SHELL:/bin/bash
BINARY_NAME=aocd$(DAY)
EBPF_NAME=aocd$(DAY)

.PHONY build run clean tidy generate example input

PROBLEM ?= p1

tidy:
	go mod tidy

generate:
	ifeq ($(PROBLEM),p1)
		SEQUENCE_LEN=2 go generate
	else
		SEQUENCE_LEN=12 go generate
	endif

clean:
		rm -rf bin/
		rm -f *_*.o
		rm -f *_*.go
		go clean
