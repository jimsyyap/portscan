package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fatih/color"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"golang.org/x/sync/semaphore"
)

// Configuration Flags
var (
	targets       = flag.String("t", "", "Targets (e.g. 192.168.1.1,10.0.0.0/24)")
	ports         = flag.String("p", "1-1024", "Ports (e.g. 80,443 ciblage,1-1000)")
	outputJSON    = flag.Bool("json", false, "Output JSON format")
	timeout       = flag.Duration("timeout", 2*time.Second, "Scan timeout")
	concurrency   = flag.Int("c", 500, "Concurrency limit")
	interfaceName = flag.String("i", "", "Network interface to use (default: auto-detect)")
	serviceLookup = flag.Bool("service", true, "Enable service name lookup")
	bannerGrab    = flag.Bool("banner", false, "Enable banner grabbing for open ports")
	scanType      = flag.String("scan-type", "syn", "Scan type: syn, connect")
	delay         = flag.Duration("delay", 0, "Delay between scans for stealth (e.g., 10ms)")
	logFile       = flag.String("log", "", "Log results to a file")
	verbose       = flag.Bool("v", false, "Enable verbose logging")
)

// ServiceInfo maps common ports to their service names
var ServiceInfo = map[int]string{
	21:   "FTP",
	22:   "SSH",
	23:   "Telnet",
	25:   "SMTP",
	53:   "DNS",
	80:   "HTTP",
	110:  "POP3",
	111:  "RPC",
	135:  "RPC",
	139:  "NetBIOS",
	143:  "IMAP",
	443:  "HTTPS",
	445:  "SMB",
	993:  "IMAPS",
	995:  "POP3S",
	1723: "PPTP",
	3306: "MySQL",
	3389: "RDP",
	5900: "VNC",
	8080: "HTTP-Proxy",
}

// ScanResult represents the outcome of scanning a single port
type ScanResult struct {
	Target    string    `json:"target"`
	Port      int       `json:"port"`
	Status    string    `json:"status"`
	Service   string    `json:"service,omitempty"`
	Banner    string    `json:"banner,omitempty"`
	Timestamp time.Time `json:"timestamp"`
}

// Scanner handles the port scanning process
type Scanner struct {
	Timeout        time.Duration
	Delay          time.Duration
	Results        chan ScanResult
	done           chan struct{}
	semaphore      *semaphore.Weighted
	handle         *pcap.Handle
	localIP        string
	interfaceName  string
	serviceLookup  bool
	bannerGrab     bool
	scanType       string
	totalScans     int64
	completedScans int64
	logger         *log.Logger
	logWriter      io.Writer
}

// NewScanner creates and initializes a new scanner
func NewScanner(timeout, delay time.Duration, concurrency int, interfaceName string, serviceLookup, bannerGrab bool, scanType string, logFile string, verbose bool) (*Scanner, error) {
	var logWriter io.Writer
	logger := log.New(os.Stderr, "scanner: ", log.LstdFlags)

	if logFile != "" {
		f, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			return nil, fmt.Errorf("failed to open log file: %v", err)
		}
		logWriter = f
		if verbose {
			logger.SetOutput(io.MultiWriter(f, os.Stderr))
		} else {
			logger.SetOutput(f)
		}
	} else if verbose {
		logger.SetOutput(os.Stderr)
	} else {
		logger.SetOutput(io.Discard)
	}

	s := &Scanner{
		Timeout:       timeout,
		Delay:         delay,
		Results:       make(chan ScanResult),
		done:          make(chan struct{}),
		semaphore:     semaphore.NewWeighted(int64(concurrency)),
		interfaceName: interfaceName,
		serviceLookup: serviceLookup,
		bannerGrab:    bannerGrab,
		scanType:      scanType,
		logger:        logger,
		logWriter:     logWriter,
	}

	if scanType == "syn" {
		// Determine interface to use
		ifaceName := interfaceName
		if ifaceName == "" {
			iface, err := getDefaultInterface()
			if err != nil {
				return nil, fmt.Errorf("failed to find default interface: %v", err)
			}
			ifaceName = iface
		}

		// Open pcap handle
		handle, err := pcap.OpenLive(ifaceName, 65535, false, pcap.BlockForever)
		if err != nil {
			return nil, fmt.Errorf("failed to open pcap: %v", err)
		}
		s.handle = handle

		// Get local IP for the selected interface
		localIP, err := getInterfaceIP(ifaceName)
		if err != nil {
			s.handle.Close()
			return nil, fmt.Errorf("failed to determine local IP: %v", err)
		}
		s.localIP = localIP

		s.logger.Printf("Using interface %s with IP %s", ifaceName, localIP)
	} else if scanType != "connect" {
		return nil, fmt.Errorf("unsupported scan type: %s", scanType)
	}

	return s, nil
}

// Close releases resources used by the scanner
func (s *Scanner) Close() {
	if s.handle != nil {
		s.handle.Close()
	}
	if f, ok := s.logWriter.(*os.File); ok {
		f.Close()
	}
}

// Start begins scanning all target IPs and ports
func (s *Scanner) Start(targets []string, ports []int) {
	var wg sync.WaitGroup
	s.totalScans = int64(len(targets) * len(ports))

	for _, target := range targets {
		for _, port := range ports {
			wg.Add(1)
			s.semaphore.Acquire(context.Background(), 1)

			go func(t string, p int) {
				defer wg.Done()
				defer s.semaphore.Release(1)

				if s.Delay > 0 {
					time.Sleep(s.Delay)
				}

				ctx, cancel := context.WithTimeout(context.Background(), s.Timeout)
				defer cancel()

				var isOpen bool
				if s.scanType == "syn" {
					isOpen = s.synScan(ctx, t, p)
				} else {
					isOpen = s.connectScan(ctx, t, p)
				}

				if isOpen {
					var service, banner string
					if s.serviceLookup {
						if svc, ok := ServiceInfo[p]; ok {
							service = svc
						}
					}
					if s.bannerGrab {
						banner = grabBanner(ctx, t, p)
					}

					result := ScanResult{
						Target:    t,
						Port:      p,
						Status:    "open",
						Service:   service,
						Banner:    banner,
						Timestamp: time.Now(),
					}
					s.Results <- result
					if s.logWriter != nil && !*outputJSON {
						printTextResultToWriter(result, s.logWriter)
					}
				}

				// Update progress
				completed := atomic.AddInt64(&s.completedScans, 1)
				if completed%100 == 0 || completed == s.totalScans {
					progress := float64(completed) / float64(s.totalScans) * 100
					s.logger.Printf("Progress: %.1f%% (%d/%d scans)", progress, completed, s.totalScans)
				}
			}(target, port)
		}
	}

	wg.Wait()
	close(s.Results)
}

// synScan performs a SYN scan on a single target IP and port
func (s *Scanner) synScan(ctx context.Context, target string, port int) bool {
	s.logger.Printf("SYN scanning %s:%d", target, port)

	// Set up BPF filter to only capture relevant packets
	filter := fmt.Sprintf("tcp and src host %s and tcp[tcpflags] & (tcp-syn|tcp-ack) == (tcp-syn|tcp-ack)", target)
	if err := s.handle.SetBPFFilter(filter); err != nil {
		s.logger.Printf("Failed to set BPF filter: %v", err)
		return false
	}

	// Generate random source port to avoid conflicts
	srcPort := layers.TCPPort(10000 + port%55535)
	dstPort := layers.TCPPort(port)

	// Craft SYN packet
	ipLayer := &layers.IPv4{
		SrcIP:    net.ParseIP(s.localIP),
		DstIP:    net.ParseIP(target),
		Protocol: layers.IPProtocolTCP,
		TTL:      64,
	}

	tcpLayer := &layers.TCP{
		SrcPort: srcPort,
		DstPort: dstPort,
		SYN:     true,
		Window:  65535,
		Seq:     1234,
	}
	tcpLayer.SetNetworkLayerForChecksum(ipLayer)

	// Serialize packet
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}

	if err := gopacket.SerializeLayers(buf, opts, ipLayer, tcpLayer); err != nil {
		s.logger.Printf("Failed to serialize packet: %v", err)
		return false
	}

	// Create packet source for reading responses
	packetSource := gopacket.NewPacketSource(s.handle, s.handle.LinkType())
	packetSource.DecodeOptions.Lazy = true
	packetSource.DecodeOptions.NoCopy = true
	packets := packetSource.Packets()

	// Send the SYN packet
	if err := s.handle.WritePacketData(buf.Bytes()); err != nil {
		s.logger.Printf("Failed to send packet: %v", err)
		return false
	}

	// Check for SYN-ACK response with timeout
	for {
		select {
		case <-ctx.Done():
			s.logger.Printf("Timeout on %s:%d", target, port)
			return false
		case packet, ok := <-packets:
			if !ok {
				s.logger.Printf("Packet source closed for %s:%d", target, port)
				return false
			}

			tcpLayer := packet.Layer(layers.LayerTypeTCP)
			if tcpLayer == nil {
				continue
			}

			tcp, _ := tcpLayer.(*layers.TCP)
			if tcp.DstPort == srcPort && tcp.SrcPort == dstPort && tcp.SYN && tcp.ACK {
				s.logger.Printf("SYN-ACK received for %s:%d", target, port)
				return true
			}
		}
	}
}

// connectScan performs a TCP Connect scan
func (s *Scanner) connectScan(ctx context.Context, target string, port int) bool {
	s.logger.Printf("Connect scanning %s:%d", target, port)

	addr := fmt.Sprintf("%s:%d", target, port)
	conn, err := net.DialTimeout("tcp", addr, s.Timeout)
	if err != nil {
		s.logger.Printf("Connect failed for %s:%d: %v", target, port, err)
		return false
	}
	conn.Close()
	s.logger.Printf("Connection established for %s:%d", target, port)
	return true
}

// grabBanner attempts to retrieve a service banner
func grabBanner(ctx context.Context, target string, port int) string {
	addr := fmt.Sprintf("%s:%d", target, port)
	conn, err := net.DialTimeout("tcp", addr, 1*time.Second)
	if err != nil {
		return ""
	}
	defer conn.Close()

	conn.SetReadDeadline(time.Now().Add(1 * time.Second))
	banner := make([]byte, 256)
	n, err := conn.Read(banner)
	if err != nil && err != io.EOF {
		return ""
	}
	return strings.TrimSpace(string(banner[:n]))
}

func main() {
	flag.Parse()

	if *targets == "" {
		fmt.Println("Error: Target (-t) is required")
		flag.Usage()
		os.Exit(1)
	}

	// Only validate root for SYN scans
	if *scanType == "syn" && os.Getenv("OS") != "Windows_NT" {
		validateRoot()
	}

	targetIPs, err := parseTargets(*targets)
	if err != nil {
		fmt.Printf("Target error: %v\n", err)
		os.Exit(1)
	}

	portList, err := parsePorts(*ports)
	if err != nil {
		fmt.Printf("Port error: %v\n", err)
		os.Exit(1)
	}

	// Print scan summary
	fmt.Printf("Starting scan of %d targets and %d ports (%s scan)\n", len(targetIPs), len(portList), *scanType)

	// Create and configure scanner
	scanner, err := NewScanner(*timeout, *delay, *concurrency, *interfaceName, *serviceLookup, *bannerGrab, *scanType, *logFile, *verbose)
	if err != nil {
		fmt.Printf("Failed to initialize scanner: %v\n", err)
		os.Exit(1)
	}
	defer scanner.Close()

	// Start scanning in background
	go func() {
		scanner.Start(targetIPs, portList)
		close(scanner.done)
	}()

	// Process results
	var results []ScanResult
	for result := range scanner.Results {
		if *outputJSON {
			results = append(results, result)
		} else {
			printTextResult(result)
		}
	}

	if *outputJSON {
		jsonData, _ := json.MarshalIndent(results, "", "  ")
		fmt.Println(string(jsonData))
		if scanner.logWriter != nil {
			if f, ok := scanner.logWriter.(*os.File); ok {
				f.WriteString(string(jsonData) + "\n")
			}
		}
	}

	fmt.Println("Scan completed")
}

// --- Helper Functions ---

// validateRoot checks if the program is running with root privileges
func validateRoot() {
	if os.Getuid() != 0 {
		fmt.Println("Error: SYN scanning requires root privileges")
		os.Exit(1)
	}
}

// getDefaultInterface finds the best interface for outgoing connections
func getDefaultInterface() (string, error) {
	conn, err := net.Dial("udp", "8.8.8.8:53")
	if err != nil {
		return "", err
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)
	interfaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}

	for _, iface := range interfaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok {
				if ipnet.IP.Equal(localAddr.IP) {
					return iface.Name, nil
				}
			}
		}
	}

	return "eth0", nil
}

// getInterfaceIP returns the IP address of the specified interface
func getInterfaceIP(ifaceName string) (string, error) {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return "", err
	}

	addrs, err := iface.Addrs()
	if err != nil {
		return "", err
	}

	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				return ipnet.IP.String(), nil
			}
		}
	}

	return "", fmt.Errorf("no suitable IP address found for interface %s", ifaceName)
}

// parseTargets converts the target string into a list of IP addresses
func parseTargets(input string) ([]string, error) {
	if input == "" {
		return nil, fmt.Errorf("no targets specified")
	}

	var targets []string
	for _, target := range strings.Split(input, ",") {
		target = strings.TrimSpace(target)

		if strings.Contains(target, "/") {
			ips, err := expandCIDR(target)
			if err != nil {
				return nil, err
			}
			targets = append(targets, ips...)
		} else {
			if net.ParseIP(target) == nil {
				ips, err := net.LookupIP(target)
				if err != nil {
					return nil, fmt.Errorf("invalid IP or hostname: %s", target)
				}
				for _, ip := range ips {
					if ipv4 := ip.To4(); ipv4 != nil {
						targets = append(targets, ipv4.String())
					}
				}
			} else {
				targets = append(targets, target)
			}
		}
	}

	return targets, nil
}

// expandCIDR converts a CIDR notation to a list of IP addresses
func expandCIDR(cidr string) ([]string, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	var ips []string
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); incrementIP(ip) {
		ips = append(ips, ip.String())
	}

	if len(ips) > 2 {
		return ips[1 : len(ips)-1], nil
	}

	return ips, nil
}

// incrementIP increments an IP address by 1
func incrementIP(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] > 0 {
			break
		}
	}
}

// parsePorts converts port specification to a slice of port numbers
func parsePorts(input string) ([]int, error) {
	if input == "" {
		return nil, fmt.Errorf("no ports specified")
	}

	var ports []int
	for _, portItem := range strings.Split(input, ",") {
		portItem = strings.TrimSpace(portItem)

		if strings.Contains(portItem, "-") {
			rangeParts := strings.Split(portItem, "-")
			if len(rangeParts) != 2 {
				return nil, fmt.Errorf("invalid port range: %s", portItem)
			}

			start, err := strconv.Atoi(strings.TrimSpace(rangeParts[0]))
			if err != nil {
				return nil, fmt.Errorf("invalid start port: %s", rangeParts[0])
			}

			end, err := strconv.Atoi(strings.TrimSpace(rangeParts[1]))
			if err != nil {
				return nil, fmt.Errorf("invalid end port: %s", rangeParts[1])
			}

			if start < 1 || end > 65535 || start > end {
				return nil, fmt.Errorf("port range must be between 1-65535 and start must be less than end")
			}

			for p := start; p <= end; p++ {
				ports = append(ports, p)
			}
		} else {
			port, err := strconv.Atoi(portItem)
			if err != nil {
				return nil, fmt.Errorf("invalid port: %s", portItem)
			}

			if port < 1 || port > 65535 {
				return nil, fmt.Errorf("port must be between 1-65535")
			}

			ports = append(ports, port)
		}
	}

	sort.Ints(ports)
	return ports, nil
}

// printTextResult formats and prints a scan result to the console
func printTextResult(res ScanResult) {
	printTextResultToWriter(res, os.Stdout)
}

// printTextResultToWriter formats and prints a scan result to a writer
func printTextResultToWriter(res ScanResult, w io.Writer) {
	status := color.New(color.FgGreen).Sprint("OPEN")
	output := fmt.Sprintf("%-15s %-8d %-8s", res.Target, res.Port, status)
	if res.Service != "" {
		output += fmt.Sprintf(" %s", res.Service)
	}
	if res.Banner != "" {
		output += fmt.Sprintf(" (%s)", res.Banner)
	}
	fmt.Fprintln(w, output)
}
