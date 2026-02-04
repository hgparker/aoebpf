package main

import (
	"bufio"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

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

	// Determine sequence len variable
	var sampleInputWorkspace aocd3InputWorkspace
	sequenceLen := len(sampleInputWorkspace.BestSuffix) - 1
	log.Printf("Value we have for SequenceLen is %d\n", sequenceLen)

	// Initialize necessary variables
	objs.FirstWorkableInputIndex.Set(0)   // Safe b/c ebpf isn't running yet
	objs.FirstUnworkableInputIndex.Set(0) // Only set from userspace

	// Attach ebpf program
	tp, err := link.Tracepoint("syscalls", "sys_enter_epoll_wait", objs.EpollWork, nil)
	if err != nil {
		log.Fatal("Error attaching eBPF:", err)
	}
	defer tp.Close()

	// Set up input handler to pass inputs to the map
	inputChan := make(chan string, 1000)
	go func() {
		for input := range inputChan {
			log.Printf("Input handler received input: %s", input)
			var currFirstUnworkableInputIndex uint32
			objs.FirstUnworkableInputIndex.Get(&currFirstUnworkableInputIndex)
			newInputWorkSpace := aocd3InputWorkspace{
				Locked:   0,
				InputLen: uint32(len(input)),
				NextK:    int32(len(input)) - 1,
			}
			for i := 0; i < len(input) && i < len(newInputWorkSpace.Input); i++ {
				newInputWorkSpace.Input[i] = uint32(input[i] - '0')
			}
			for i := 1; i < sequenceLen+1; i++ {
				newInputWorkSpace.BestSuffix[i] = -1
			}
			objs.InputWorkspaces.Update(&currFirstUnworkableInputIndex, &newInputWorkSpace, ebpf.UpdateAny) // Safe because hitherto unworkable
			objs.FirstUnworkableInputIndex.Set(currFirstUnworkableInputIndex + 1)                           // Safe b/c only set from userspace
		}
	}()

	// Set up server to receive input and pass to channel
	listener, err := net.Listen("tcp", ":9999")
	if err != nil {
		log.Fatalf("Error binding to port 9999: %v", err)
	}
	go func() {
		log.Println("Server live, listening on :9999")
		for {
			conn, err := listener.Accept()
			if err != nil {
				log.Println("Listener closed or error occurred")
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				scanner := bufio.NewScanner(conn)
				for scanner.Scan() {
					input := scanner.Text()
					log.Printf("Server received input: %s", input)
					inputChan <- input
				}
			}(conn)
		}
	}()

	// Prepare for graceful exit
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	// Poll to see if can print answer
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-stopper:
			listener.Close()
			return
		case <-ticker.C:
			sum := 0
			var currFirstUnworkableIndex uint32
			objs.FirstUnworkableInputIndex.Get(&currFirstUnworkableIndex)
			for i := uint32(0); i < currFirstUnworkableIndex; i += 1 {
				var inputWorkspace aocd3InputWorkspace
				objs.InputWorkspaces.Lookup(&i, &inputWorkspace)
				if inputWorkspace.NextK == -1 {
					sum += int(inputWorkspace.BestSuffix[sequenceLen])
				}
			}
			log.Printf("Current ans = %d", sum)
		}
	}
}
