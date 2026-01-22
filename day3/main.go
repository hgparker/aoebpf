package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

func main() {
	// Load ebpf program
	var objs aocd3Objects
	if err := loadAocd3Objects(&objs, nil); err != nil {
		log.Fatal("Error loading eBPF:", err)
	}
	defer objs.Close()
	log.Println("Successfully loaded eBPF program")

	// Initialize map with empty values
	var workspace aocd3Workspace
	sequenceLen := len(workspace.InputWorkspaces[0].BestSuffix)
	log.Printf("Value we have for SequenceLen is %d\n", sequenceLen)
	workspace.FirstWorkableInput = 0
	workspace.FirstNonworkableInput = 0
	var countIndex uint32 = 0
	if err := objs.Workspace.Update(&countIndex, workspace, ebpf.UpdateAny); err != nil {
		log.Fatalf("failed to initialize ebpf map: %v", err)
	}

	// Attach ebpf program
	tp, err := link.Tracepoint("syscalls", "sys_enter_epoll_wait", objs.EpollWork, nil)
	if err != nil {
		log.Fatal("Error attaching eBPF:", err)
	}
	defer tp.Close()

	// Wait around
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)
	<-stopper
}
