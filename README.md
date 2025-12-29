### Advent of Code in eBPF

To gain experience in eBPF, I decided to try to code up AoC 2025 in eBPF.

There is no way I will complete the entire project. The problems are a terrible fit for eBPF in general. So far, I have only done the first day's problem. It's possible I'll attempt the first three days.

For the helper programs running in userspace, I've used Golang so far (along with the essential tool `bpf2go`). Re: attaching the eBPF programs, I've used a uprobe on echo_builtin in the bash binary. Thus, when `echo abc` is passed to the command-line, the eBPF program will run on entry.

Here's how to run one of the programs: 
```
make run
...
[in a different terminal]
make example or make input
```

This starts the Golang helper program, which loads and attaches the eBPF, then polls an eBPF map to get any answers. `make example` or `make input` just calls echo a bunch of times on the problem input.
