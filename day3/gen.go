package main

//go:generate sh -c "echo Compiling with Sequence Len: $SEQUENCE_LEN"
//go:generate sh -c "go tool bpf2go -tags linux -cflags \"-DSEQUENCE_LEN=$SEQUENCE_LEN\" aocd3 aocd3.c"
