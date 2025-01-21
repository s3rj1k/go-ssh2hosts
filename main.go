package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"math/rand/v2"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode"

	"golang.org/x/crypto/ssh"
)

// ExpandCIDR converts a CIDR notation string into a slice of individual IP addresses.
func ExpandCIDR(cidr string) ([]netip.Addr, error) {
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR: %w", err)
	}

	var ips []netip.Addr

	// iterate through all possible IPs in the CIDR range
	for addr := prefix.Addr(); prefix.Contains(addr); addr = addr.Next() {
		ips = append(ips, addr)
	}

	return ips, nil
}

// ScanResult represents a successful SSH server discovery.
type ScanResult struct {
	Addr        netip.Addr // IP address of the server
	Port        uint16     // Port number where SSH is running
	Fingerprint string     // SSH host key fingerprint
}

// ScanDestination attempts to establish an SSH connection to a single IP:port combination.
func ScanDestination(ctx context.Context, addr netip.Addr, port uint16) *ScanResult {
	select {
	case <-ctx.Done():
		return nil // early return if context is cancelled
	default:
	}

	var hostKey ssh.PublicKey

	// configure SSH client with dummy credentials - we're only interested in the host key
	config := &ssh.ClientConfig{
		User: "nobody",
		Auth: []ssh.AuthMethod{
			ssh.Password(""),
		},
		// capture the host key instead of verifying it
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			hostKey = key
			return nil
		},
		Timeout: 3 * time.Second,
	}

	// attempt connection - we're only interested in a host key
	sshConn, _ := ssh.Dial("tcp", net.JoinHostPort(addr.String(), fmt.Sprint(port)), config)
	if sshConn != nil {
		sshConn.Close()
	}

	// no host key means no SSH server was found
	if hostKey == nil {
		return nil
	}

	return &ScanResult{
		Addr:        addr,
		Port:        port,
		Fingerprint: ssh.FingerprintSHA256(hostKey),
	}
}

// ScanAddrsMultiPort scans multiple IP addresses across multiple ports for SSH servers.
func ScanAddrsMultiPort(ctx context.Context, addrs []netip.Addr, ports []uint16) (scanned []*ScanResult) {
	workers := runtime.NumCPU()
	seen := sync.Map{} // track IPs we've already found SSH servers on

	// randomize the order of addresses
	rand.Shuffle(len(addrs), func(i, j int) {
		addrs[i], addrs[j] = addrs[j], addrs[i]
	})

	semaphore := make(chan struct{}, workers)  // limit concurrent workers
	results := make(chan *ScanResult, workers) // channel for collecting results

	var wg, scanWg sync.WaitGroup

	// start collector goroutine to gather results
	wg.Add(1)
	go func() {
		defer wg.Done()
		for r := range results {
			scanned = append(scanned, r)
		}
	}()

	// launch workers for each address
	for _, addr := range addrs {
		select {
		case <-ctx.Done():
			break
		case semaphore <- struct{}{}: // acquire worker slot
			scanWg.Add(1)

			go func(addr netip.Addr) {
				defer func() {
					<-semaphore // release worker slot
					scanWg.Done()
				}()

				// skip if we already found this host
				if _, exists := seen.Load(addr.String()); exists {
					return
				}

				// try each port until we find a fingerprint
				for _, port := range ports {
					if result := ScanDestination(ctx, addr, port); result != nil {
						seen.Store(addr.String(), true)
						select {
						case <-ctx.Done():
							return
						case results <- result:
							return // skip remaining ports after finding fingerprint
						}
					}
				}
			}(addr)
		}
	}

	// wait for all scanning goroutines to finish before closing results
	go func() {
		scanWg.Wait()
		close(results)
	}()

	wg.Wait()

	return scanned
}

// ParsePortList converts a string of port numbers into a slice of uint16.
func ParsePortList(portList string) ([]uint16, error) {
	fields := strings.FieldsFunc(portList, func(r rune) bool {
		return unicode.IsSpace(r) || r == ',' || r == ';' || r == '|' || r == '/'
	})

	ports := make([]uint16, 0, len(fields))

	for _, p := range fields {
		port, err := strconv.ParseUint(p, 10, 16)
		if err != nil {
			return nil, fmt.Errorf("invalid port number: %s", p)
		}

		ports = append(ports, uint16(port))
	}

	return ports, nil
}

func main() {
	// CPU profiling with `github.com/pkg/profile`, go tool pprof -http=:8080 cpu.pprof
	// cpuProfile := profile.Start(
	// 	profile.CPUProfile,
	// 	profile.ProfilePath("."),
	// 	profile.NoShutdownHook,
	// )
	// defer cpuProfile.Stop()

	// Memory profiling with `github.com/pkg/profile`, go tool pprof -http=:8080 mem.pprof
	// defer profile.Start(
	// 	profile.MemProfile,
	// 	profile.ProfilePath("."),
	// 	profile.NoShutdownHook,
	// ).Stop()

	var (
		flagCIDR     string
		flagPorts    string
		flagTemplate string
		flagOutput   string
	)

	flag.StringVar(&flagCIDR, "network", "", "Network CIDR to scan (e.g., 192.168.1.0/24)")
	flag.StringVar(&flagPorts, "ports", "22", "Comma-separated list of SSH ports to scan")
	flag.StringVar(&flagTemplate, "template", "", "Path to template file (optional)")
	flag.StringVar(&flagOutput, "output", "", "Output file path (defaults to stdout)")
	flag.Parse()

	ports, err := ParsePortList(flagPorts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing ports: %v\n", err)
		os.Exit(1)
	}

	addrs, err := ExpandCIDR(flagCIDR)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing CIDR: %v\n", err)
		os.Exit(1)
	}

	// set up cancellation context for graceful shutdown
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	// perform the scan
	results := ScanAddrsMultiPort(ctx, addrs, ports)

	// set up output destination (stdout or file)
	var output *os.File = os.Stdout

	if flagOutput != "" {
		var err error

		output, err = os.OpenFile(flagOutput, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to open output file: %v\n", err)
			os.Exit(1)
		}

		defer output.Close()
	}

	if flagTemplate != "" { // template mode: Replace fingerprints in template with IP addresses
		b, err := os.ReadFile(flagTemplate)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to read template: %v\n", err)
			os.Exit(1)
		}

		for _, r := range results {
			b = bytes.ReplaceAll(b, []byte("#"+r.Fingerprint), []byte(r.Addr.String()))
		}

		fmt.Fprintf(output, "%s", b)
	} else { // discovery mode: Output fingerprint and address:port pairs
		for _, r := range results {
			fmt.Fprintf(output, "%s %s\n", r.Fingerprint,
				net.JoinHostPort(r.Addr.String(), strconv.FormatUint(uint64(r.Port), 10)),
			)
		}
	}
}
