### Advent of Code in eBPF

To gain experience in eBPF, I decided to try to code up [AoC 2025](https://adventofcode.com/) in eBPF.

As I have already done these problems in Python, the focus will be on replicating the algorithms I happened to use given the constraints of eBPF. I would also like to explore the variety of hook points available and gain some eBPF and Linux kernel intuition.

There is likely no way I will complete the entire project. The problems are not a great fit for eBPF in general.
First goal is to do the first three days.

For helper programs running in userspace, I've been using Golang, specifically the [ebpf-go library](https://github.com/cilium/ebpf). The super useful thing this library does is, given eBPF maps and functions defined in C, generating  ways to refer to these structures and functions in Golang.

#### Structure of Repo

`<day>/{p1|p2}/`

The main files worth inspecting in each directory will be `aocdXp{1|2}.c` and `main.go`. The first is the actual eBPF program, and the second is the Golang helper, responsible for loading and attaching the eBPF program as well as populating/polling eBPF maps.

I adhere to the following conventions: `make run` starts the eBPF program, `make example` submits the example input, and `make input` submits the test input. You'll need to run the latter two make commands in a different terminal than the first. 

#### Day1

For Day1, I decided to keep thing simple. For hook point, I used a uprobe on `echo_builtin` in the bash binary. Thus, when `echo abc` is submitted to bash, the eBPF program is first run on the to-be-echoed input before echo itself does anything with it. To submit the input, we just echo each line. The helper polls a map to get the answer.

Various learnings and thoughts:
*  `nm -D <binary>` is a good way to learn about uprobe hook points
*  Having to work around the fact that you can't do modulo operations with signed integers is annoying
*  Having to 'parse' anything in eBPF C is annoying. It's definitely a good idea to have the helper take care of this.
* You have to make a lot of explicit, almost paranoid checks to satisfy the verifier.
* Interestingly, while many mistakes involving concurrency are possible, nothing will stop you from making these mistakes. From the verifier's perspective, it doesn't care about your business logic, just that you don't crash the kernel.

