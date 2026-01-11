package main

import (
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func main() {
	// Load ebpf program
	var objs aocd2p1Objects
	if err := loadAocd2p1Objects(&objs, nil); err != nil {
		log.Fatal("Loading eBPF objects:", err)
	}
	defer objs.Close()
	log.Println("Successfully loaded eBPF program")

	// Attach ebpf program
	devID, err := net.InterfaceByName("wlp4s0")
	if err != nil {
		log.Fatal("Could not find interface by name", err)
	}
	link, err := netlink.LinkByIndex(devID.Index)
	if err != nil {
		log.Fatal("Could not find interface", err)
	}
	attrs := netlink.QdiscAttrs{
		LinkIndex: link.Attrs().Index,
		Handle:    netlink.MakeHandle(0xffff, 0),
		Parent:    netlink.HANDLE_CLSACT,
	}
	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: attrs,
		QdiscType:  "clsact",
	}
	if err := netlink.QdiscReplace(qdisc); err != nil {
		log.Fatal("could not add/replace qdisc", err)
	}
	defer netlink.QdiscDel(qdisc)
	filter := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: link.Attrs().Index,
			Parent:    netlink.HANDLE_MIN_EGRESS,
			Priority:  1,
			Protocol:  unix.ETH_P_ALL,
		},
		Fd:           objs.HandleEgress.FD(),
		Name:         "aocd2p1",
		DirectAction: true,
	}
	if err := netlink.FilterReplace(filter); err != nil {
		log.Fatal("failed to add/replace filter", err)
	}
	defer netlink.FilterDel(filter)
	log.Println("Successfully attached eBPF program")

	// Initialize map
	numCPU, err := ebpf.PossibleCPU()
	if err != nil {
		log.Fatalf("failed to get cpu count: %v", err)
	}
	var countIndex uint32 = 0
	var initialCount uint32 = 0
	countValues := make([]uint32, numCPU)
	for i := range countValues {
		countValues[i] = initialCount
	}
	if err := objs.State.Update(&countIndex, countValues, ebpf.UpdateAny); err != nil {
		log.Fatalf("failed to initialize ebpf map: %v", err)
	}

	// Catch SIGTERM so that we can hit our defers, poll map otherwise
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)

	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-sig:
			log.Println("Exiting")
			return
		case <-ticker.C:
			currResults := make([]uint32, numCPU)
			if err := objs.State.Lookup(&countIndex, &currResults); err != nil {
				log.Fatalf("could not perform lookup on map: %v", err)
			}
			var totalCount uint32 = 0
			for _, result := range currResults {
				totalCount += result
			}
			log.Printf("Total count so far: %d", totalCount)
		}
	}
}
