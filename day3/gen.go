package main

//go:generate go tool bpf2go -tags linux -cflags "-DSEQUENCE_LEN=$SEQUENCE_LEN" aocd3 aocd3.c
