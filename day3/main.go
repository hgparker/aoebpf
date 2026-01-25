package main

import (
	"bufio"
	"log"
	"net"
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

	// Determine sequence len variable
	var sampleInputWorkspace aocd3InputWorkspace
	sequenceLen := len(sampleInputWorkspace.BestSuffix) - 1
	log.Printf("Value we have for SequenceLen is %d\n", sequenceLen)

	// Initialize Workstate map
	var initialWorkState aocd3WorkState
	initialWorkState.FirstUnworkedInput = 0
	initialWorkState.WorkableInputBoundary = 0
	var workStateIndex uint32 = 0
	if err := objs.WorkState.Update(&workStateIndex, &initialWorkState, ebpf.UpdateAny); err != nil {
		log.Fatalf("Failed to initialize WorkState: %v", err)
	}

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
			// get boundary
			// prepare inputWorkspace
			// write inputWorkspace
			// adjust boundary
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
	<-stopper
	listener.Close()
}
