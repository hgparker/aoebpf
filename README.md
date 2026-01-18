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

For Day1, I decided to keep thing simple. For hook point, I used a uprobe on `echo_builtin` in the bash binary. Thus, when `echo abc` is submitted to bash, the eBPF program is first run on the to-be-echoed input before echo itself does anything with it. To submit the input, we just echo each line. The helper polls a map to get the answer. We don't need to worry about concurrency in updating our map because the input is strictly serialized and blocks until echoed.

Various learnings and thoughts:
*  `nm -D <binary>` is a good way to learn about uprobe hook points
*  Having to work around the fact that you can't do modulo operations with signed integers is annoying
*  Having to 'parse' anything in eBPF C is annoying. It's definitely a good idea to have the helper take care of this.
* You have to make a lot of explicit, almost paranoid checks to satisfy the verifier.
* Interestingly, while many mistakes involving concurrency are possible, nothing will stop you from making these mistakes. From the verifier's perspective, it doesn't care about your business logic, just that you don't crash the kernel.

#### Day2

Decided to do some eBPF in the Linux network stack. Specifically, we attach our program to the egress traffic control (tc) hook point. Originally, my plan was that the "input" would be wholly contained in the sequence number of fake outgoing TCP packets. Here I encountered a problem -- I didn't check the inputs beforehand, and it turns out some of them don't fit in an unsigned 32 bit integer, but that's what the kernel (and presumably the TCP protocol itself) use to represent the sequence number. To adjust, I split the input up and encoded it in two ways: for each input, (a) input % 2^32 becomes the destination IP address, and (b) input // 2^32 becomes the sequence number. The eBPF program puts these two 32 bit integers together to make a 64 bit integer. Re: concurrency, we use a per-cpu map to record our results -- thus, we don't have to worry about concurrency problems, though it is necessary for the helper program to accumulate results from all maps. In order to not mess up normal outgoing packets, I insisted all the input packets go to port 9999. To generate the stream of fake packets, I used the scapy library in Python. 

Various learnings and thoughts:

* eBPF programs remind me of those old TV shows where you have one frantic minute to grab whatever you want from a store for free. Unlimited power, but you have to keep things simple: get in, do your thing, get out.
* I didn't realize how much big endian stuff was still around. A lot of it, apparently, at least as far as networking goes. There are macros to do all the conversions for you.
* It's a funny flow in eBPF-land where, after you cast a pointer to a struct pointer, you're not allowed to access anything in that struct until you've actually proved to the verifier's satisfaction that the entire struct doesn't exceed the allotted memory.
* Looping up to a variable limit is something the verifier hates -- it doesn't care or respect semantic assumptions we might make like an integer will only have so many digits in base10 and that therefore we can loop up to this. I found I was better off using an arbitrary, low-ish constraint for my loops while including the real condition as an early exit in an if clause.
