module aoebpf2

go 1.25.5

tool github.com/cilium/ebpf/cmd/bpf2go

require (
	github.com/cilium/ebpf v0.20.0
	github.com/vishvananda/netlink v1.3.1
	golang.org/x/sys v0.40.0
)

require github.com/vishvananda/netns v0.0.5 // indirect
