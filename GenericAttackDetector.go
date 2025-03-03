package main

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"net"
	"time"
	"strings"
)

const DOS_THRESHOLD = 100 // Threshold for DoS (100 packets in 5 seconds)
const TIMEOUT = 60        // Monitor for 60 seconds

// Struct to track packet counts for each IP address
type packetCountEntry struct {
	ip        string
	count     int
	lastTime  time.Time
}

// Global slice to store packet count information
var packetCounts []packetCountEntry

// Find or add an entry for the source IP address
func findOrAddIP(ip string) *packetCountEntry {
	for i := range packetCounts {
		if packetCounts[i].ip == ip {
			return &packetCounts[i]
		}
	}

	// Add a new entry if not found
	packetCounts = append(packetCounts, packetCountEntry{
		ip:       ip,
		count:    0,
		lastTime: time.Now(),
	})
	return &packetCounts[len(packetCounts)-1]
}

// Function to detect DDoS/DoS attacks
func detectDdosOrDos(ipAddress string) {
	for i := range packetCounts {
		entry := &packetCounts[i]
		if entry.ip == ipAddress {
			if entry.count > DOS_THRESHOLD {
				fmt.Printf("Potential DoS/DDoS Attack detected! IP %s sent %d packets in the last 5 seconds.\n", ipAddress, entry.count)
				entry.count = 0 // Reset packet count after detection
			} else {
				fmt.Printf("IP %s sent %d packets, within normal threshold.\n", ipAddress, entry.count)
			}
			return
		}
	}
	fmt.Printf("No packets received from %s yet.\n", ipAddress)
}

// Packet processing callback function
func packetCallback(packet gopacket.Packet, ipAddress string) {
	// Check if the packet has an IP layer
	ipLayer := packet.Layer(gopacket.LayerTypeIPv4)
	if ipLayer == nil {
		return
	}

	// Extract the source and destination IP addresses
	ip, _ := ipLayer.(*gopacket.layers.IPv4)
	srcIP := ip.SrcIP.String()
	dstIP := ip.DstIP.String()

	// Find or create an entry for the source IP address
	srcEntry := findOrAddIP(srcIP)
	if srcEntry != nil {
		// Increment the packet count for the source IP
		srcEntry.count++
		currentTime := time.Now()

		// Reset the packet count every 5 seconds
		if currentTime.Sub(srcEntry.lastTime).Seconds() >= 5 {
			srcEntry.count = 1
			srcEntry.lastTime = currentTime
		}
	}

	// Check for suspicious activity based on packet frequency
	fmt.Printf("Packet received from %s to %s\n", srcIP, dstIP)
	detectDdosOrDos(srcIP)
}

// Function to start packet sniffing and monitoring traffic
func startMonitoring(ipAddress string) {
	handle, err := pcap.OpenLive("eth0", 1600, true, pcap.BlockForever)
	if err != nil {
		fmt.Printf("Error opening device: %s\n", err)
		return
	}
	defer handle.Close()

	fmt.Printf("Starting packet capture for IP: %s\n", ipAddress)

	// Start capturing packets and process them using the callback function
	err = handle.SetBPFFilter("ip host " + ipAddress)
	if err != nil {
		fmt.Printf("Error setting BPF filter: %s\n", err)
		return
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		packetCallback(packet, ipAddress)
	}

	// After capturing, analyze the traffic for potential attacks
	fmt.Printf("Monitoring complete. No major attacks detected within the last %d seconds.\n", TIMEOUT)
}

func main() {
	var ipAddress string
	fmt.Print("Enter the IP address to monitor for potential attacks:")
	fmt.Scanln(&ipAddress)

	// Start monitoring the network traffic
	startMonitoring(ipAddress)
}
