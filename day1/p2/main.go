package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

func main() {
	// Load ebpf program
	var objs aocd1p2Objects
	if err := loadAocd1p2Objects(&objs, nil); err != nil {
		log.Fatal("Loading eBPF objects:", err)
	}
	defer objs.Close()
	fmt.Println("Successfully loaded eBPF program")

	// Attach ebpf program
	ex, err := link.OpenExecutable("/bin/bash")
	if err != nil {
		log.Fatal("Opening executable: ", err)
	}
	up, err := ex.Uprobe("echo_builtin", objs.TraceEchoEntry, nil)
	if err != nil {
		log.Fatal("Attaching uprobe: ", err)
	}
	defer up.Close()
	fmt.Println("Successfully attached uprobe")

	// Initialize map
	var currIndex uint32 = 0
	var initialCurr int32 = 50
	var ansIndex uint32 = 1
	var initialAns int32 = 0

	if err := objs.State.Update(&currIndex, &initialCurr, ebpf.UpdateAny); err != nil {
		log.Fatalf("failed to update map: %v", err)
	}

	if err := objs.State.Update(&ansIndex, &initialAns, ebpf.UpdateAny); err != nil {
		log.Fatalf("failed to update map: %v", err)
	}

	// Set up channels
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	ticker:= time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	// Poll eBPF Map
	for {
		select {
		case<-ticker.C:
			var curr int32
			var ans int32
			objs.State.Lookup(&currIndex, &curr)
			objs.State.Lookup(&ansIndex, &ans)
			fmt.Printf("curr: %d, (running) ans: %d\n", curr, ans)
			// We assume all the input happens at once, so that if anything has changed, exit
			if curr != initialCurr || ans != 0 {
				return
			}
		case<-stopper:
			fmt.Println("Shutting down")
			return
		}
	}
}
