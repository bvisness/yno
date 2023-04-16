package main

import (
	"fmt"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func main() {
	handle, err := pcap.OpenLive("any", 1600, true, pcap.BlockForever)
	if err != nil {
		panic(err)
	}

	err = handle.SetBPFFilter("tcp and not tcp port 22")
	if err != nil {
		panic(err)
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			tcp, _ := tcpLayer.(*layers.TCP)
			if strings.Contains(string(tcp.Payload), "HTTP") {
				fmt.Printf("From src port %d to dst port %d\n", tcp.SrcPort, tcp.DstPort)
				fmt.Println(string(tcp.Payload))
			}
		}
	}
}
