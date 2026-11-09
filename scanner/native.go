package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const (
	nativeDefaultWorkers   = 512
	nativeDefaultRate      = 500
	nativeDefaultHostRate  = 100
	nativeDefaultTimeout   = 750 * time.Millisecond
	nativeMaxDiscoveryIPs  = 1 << 16
	nativeProgressInterval = 1024
)

type NativeScanMode string

const (
	NativeSYNScan     NativeScanMode = "s"
	NativeConnectScan NativeScanMode = "c"
)

// NativeEngine is Fortag's database-free IPv4 discovery and TCP scanner. It
// relies only on the Go standard library and Linux's raw socket/ARP interfaces.
type NativeEngine struct {
	Mode           NativeScanMode
	Workers        int
	Rate           int
	PerHostRate    int
	Timeout        time.Duration
	Retries        int
	Ports          []int
	ARPPath        string
	DiscoveryPorts []int
}

func NewNativeEngine() *NativeEngine {
	return &NativeEngine{
		Mode:           NativeSYNScan,
		Workers:        nativeDefaultWorkers,
		Rate:           nativeDefaultRate,
		PerHostRate:    nativeDefaultHostRate,
		Timeout:        nativeDefaultTimeout,
		Retries:        3,
		ARPPath:        "/proc/net/arp",
		DiscoveryPorts: []int{22, 80, 443},
	}
}

func (e *NativeEngine) Name() string { return "fortag" }

func (e *NativeEngine) Capabilities() EngineCapabilities {
	return EngineCapabilities{HostDiscovery: true, MACAddresses: true}
}

func (e *NativeEngine) Discover(ctx context.Context, request DiscoveryRequest) (DiscoveryResult, error) {
	ips, network, err := discoveryIPs(request.Target)
	if err != nil {
		return DiscoveryResult{}, e.engineError(EngineErrorValidation, "discover", request.Target, err)
	}
	workers, _, timeout, retries, err := e.settings()
	if err != nil {
		return DiscoveryResult{}, e.engineError(EngineErrorValidation, "discover", request.Target, err)
	}
	ports := e.DiscoveryPorts
	if len(ports) == 0 {
		ports = []int{22, 80, 443}
	}
	for _, port := range ports {
		if port < 1 || port > 65535 {
			return DiscoveryResult{}, e.engineError(EngineErrorValidation, "discover", request.Target, fmt.Errorf("invalid discovery port %d", port))
		}
	}

	found := make(map[string]DiscoveredHost)
	var foundMu sync.Mutex
	jobs := make(chan string)
	var group sync.WaitGroup
	for range min(workers, len(ips)) {
		group.Add(1)
		go func() {
			defer group.Done()
			for ip := range jobs {
				if ctx.Err() != nil {
					continue
				}
				// A UDP write triggers neighbor resolution on local networks. A TCP
				// success also discovers hosts reached through a router.
				conn, dialErr := net.DialTimeout("udp4", net.JoinHostPort(ip, "9"), timeout)
				if dialErr == nil {
					_, _ = conn.Write([]byte{0})
					_ = conn.Close()
				}
				alive := false
				for attempt := 0; attempt < retries && !alive; attempt++ {
					for _, port := range ports {
						conn, dialErr = (&net.Dialer{Timeout: timeout}).DialContext(ctx, "tcp4", net.JoinHostPort(ip, strconv.Itoa(port)))
						if dialErr == nil {
							_ = conn.Close()
							alive = true
							break
						}
					}
				}
				if alive {
					foundMu.Lock()
					found[ip] = DiscoveredHost{IP: ip}
					foundMu.Unlock()
				}
			}
		}()
	}
	for _, ip := range ips {
		select {
		case jobs <- ip:
		case <-ctx.Done():
			close(jobs)
			group.Wait()
			return DiscoveryResult{}, e.engineError(EngineErrorCancelled, "discover", request.Target, ctx.Err())
		}
	}
	close(jobs)
	group.Wait()
	if err := ctx.Err(); err != nil {
		return DiscoveryResult{}, e.engineError(EngineErrorCancelled, "discover", request.Target, err)
	}

	arpHosts, err := readARP(e.arpPath(), network)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return DiscoveryResult{}, e.engineError(EngineErrorExecution, "discover", request.Target, err)
	}
	for _, host := range arpHosts {
		found[host.IP] = host
	}
	for _, local := range localIPv4Addresses(network) {
		found[local] = DiscoveredHost{IP: local}
	}

	result := DiscoveryResult{Targets: make([]string, 0, len(found)), Hosts: make([]DiscoveredHost, 0, len(found))}
	for ip := range found {
		result.Targets = append(result.Targets, ip)
	}
	sort.Slice(result.Targets, func(i, j int) bool {
		return ipv4Number(net.ParseIP(result.Targets[i])) < ipv4Number(net.ParseIP(result.Targets[j]))
	})
	for _, ip := range result.Targets {
		result.Hosts = append(result.Hosts, found[ip])
	}
	if request.Progress != nil {
		request.Progress(EngineProgress{Phase: "discover", Target: request.Target})
	}
	return result, nil
}

func (e *NativeEngine) Scan(ctx context.Context, request PortScanRequest) (EngineScanResult, error) {
	return e.ScanBatch(ctx, []PortScanRequest{request})
}

func (e *NativeEngine) ScanBatch(ctx context.Context, requests []PortScanRequest) (EngineScanResult, error) {
	if len(requests) == 0 {
		return EngineScanResult{}, e.engineError(EngineErrorValidation, "scan", "", errors.New("port scan requires at least one target"))
	}
	macs := make(map[string]string, len(requests))
	seenTargets := make(map[string]bool, len(requests))
	for _, request := range requests {
		if err := ValidateScanTarget(request.Target); err != nil || strings.Contains(request.Target, "/") {
			if err == nil {
				err = errors.New("port scans require one IPv4 address")
			}
			return EngineScanResult{}, e.engineError(EngineErrorValidation, "scan", request.Target, err)
		}
		if seenTargets[request.Target] {
			return EngineScanResult{}, e.engineError(EngineErrorValidation, "scan", request.Target, errors.New("duplicate port-scan target"))
		}
		seenTargets[request.Target] = true
		mac, err := normalizeNaabuMAC(request.MAC)
		if err != nil {
			return EngineScanResult{}, e.engineError(EngineErrorValidation, "scan", request.Target, err)
		}
		macs[request.Target] = mac
		if _, err := validatedPorts(request.PriorityPorts); err != nil {
			return EngineScanResult{}, e.engineError(EngineErrorValidation, "scan", request.Target, fmt.Errorf("priority ports: %w", err))
		}
	}
	workers, rate, timeout, retries, err := e.settings()
	if err != nil {
		return EngineScanResult{}, e.engineError(EngineErrorValidation, "scan", "batch", err)
	}
	ports, err := e.scanPorts()
	if err != nil {
		return EngineScanResult{}, e.engineError(EngineErrorValidation, "scan", "batch", err)
	}
	effectiveRate := min(rate, e.perHostRate(rate)*len(requests))
	lowPorts := min(len(ports), 1024)
	probeBudget := len(ports)*len(requests) + lowPorts*len(requests)*(retries-1)
	watchdog := time.Duration(probeBudget/effectiveRate+60)*time.Second + 2*timeout
	ctx, cancel := context.WithTimeout(ctx, watchdog)
	defer cancel()

	mode := e.Mode
	if mode == "" {
		mode = NativeSYNScan
	}
	openByTarget := make(map[string][]int, len(requests))
	if mode == NativeSYNScan {
		openByTarget, err = e.scanSYNBatch(ctx, requests, ports, rate, e.perHostRate(rate), timeout, retries)
		if err != nil && rawSocketUnavailable(err) {
			log.Printf("Native SYN scan unavailable (%v); falling back to TCP CONNECT", err)
			openByTarget = make(map[string][]int, len(requests))
			for _, request := range requests {
				openByTarget[request.Target], err = e.scanConnect(ctx, request.Target, ports, workers, min(rate, e.perHostRate(rate)), timeout, retries, request.Progress)
				if err != nil {
					break
				}
			}
		}
	} else if mode == NativeConnectScan {
		for _, request := range requests {
			openByTarget[request.Target], err = e.scanConnect(ctx, request.Target, ports, workers, min(rate, e.perHostRate(rate)), timeout, retries, request.Progress)
			if err != nil {
				break
			}
		}
	} else {
		err = fmt.Errorf("unsupported scan mode %q", mode)
	}
	if err != nil {
		kind := EngineErrorExecution
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			kind = EngineErrorCancelled
		}
		return EngineScanResult{}, e.engineError(kind, "scan", "batch", err)
	}
	result := EngineScanResult{Hosts: make([]ObservedHost, 0, len(requests))}
	for _, request := range requests {
		host := ObservedHost{IP: request.Target, MAC: macs[request.Target], ClearMissingMetadata: true}
		for _, port := range openByTarget[request.Target] {
			host.Ports = append(host.Ports, ObservedPort{Port: port, Protocol: "tcp", State: "open"})
		}
		if request.Progress != nil {
			request.Progress(EngineProgress{Phase: "scan", Target: request.Target})
		}
		result.Hosts = append(result.Hosts, host)
	}
	return result, nil
}

func (e *NativeEngine) scanConnect(ctx context.Context, target string, ports []int, workers, rate int, timeout time.Duration, retries int, progress func(EngineProgress)) ([]int, error) {
	jobs := make(chan int)
	open := make(chan int, workers)
	var group sync.WaitGroup
	for range min(workers, len(ports)) {
		group.Add(1)
		go func() {
			defer group.Done()
			for port := range jobs {
				for attempt := 0; attempt < retries; attempt++ {
					conn, dialErr := (&net.Dialer{Timeout: timeout}).DialContext(ctx, "tcp4", net.JoinHostPort(target, strconv.Itoa(port)))
					if dialErr == nil {
						_ = conn.Close()
						open <- port
						break
					}
					if errors.Is(dialErr, syscall.ECONNREFUSED) {
						break
					}
					if ctx.Err() != nil {
						break
					}
					if attempt+1 < retries {
						select {
						case <-time.After(time.Duration(attempt+1) * 250 * time.Millisecond):
						case <-ctx.Done():
						}
					}
				}
			}
		}()
	}
	done := make(chan struct{})
	go func() { group.Wait(); close(open); close(done) }()

	interval := time.Second / time.Duration(rate)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	var submitted atomic.Int64
	feedErr := make(chan error, 1)
	go func() {
		defer close(jobs)
		for _, port := range ports {
			select {
			case <-ticker.C:
			case <-ctx.Done():
				feedErr <- ctx.Err()
				return
			}
			select {
			case jobs <- port:
				count := submitted.Add(1)
				if progress != nil && count%nativeProgressInterval == 0 {
					progress(EngineProgress{Phase: "scan", Target: target})
				}
			case <-ctx.Done():
				feedErr <- ctx.Err()
				return
			}
		}
		feedErr <- nil
	}()

	var openPorts []int
	for port := range open {
		openPorts = append(openPorts, port)
	}
	<-done
	if err := <-feedErr; err != nil {
		return nil, err
	}
	sort.Ints(openPorts)
	return openPorts, nil
}

func (e *NativeEngine) settings() (int, int, time.Duration, int, error) {
	workers, rate, timeout, retries := e.Workers, e.Rate, e.Timeout, e.Retries
	if workers == 0 {
		workers = nativeDefaultWorkers
	}
	if rate == 0 {
		rate = nativeDefaultRate
	}
	if timeout == 0 {
		timeout = nativeDefaultTimeout
	}
	if retries == 0 {
		retries = 3
	}
	if workers < 1 || workers > 2048 || rate < 1 || rate > 100000 || timeout < 10*time.Millisecond || timeout > 30*time.Second || retries < 1 || retries > 3 {
		return 0, 0, 0, 0, errors.New("workers, rate, timeout, or retries are outside safe bounds")
	}
	if e.PerHostRate < 0 || e.PerHostRate > 10000 {
		return 0, 0, 0, 0, errors.New("per-host rate is outside safe bounds")
	}
	return workers, rate, timeout, retries, nil
}

func (e *NativeEngine) perHostRate(globalRate int) int {
	rate := e.PerHostRate
	if rate == 0 {
		rate = nativeDefaultHostRate
	}
	if rate < 1 {
		return 1
	}
	return min(rate, globalRate)
}

func (e *NativeEngine) scanPorts() ([]int, error) {
	if len(e.Ports) == 0 {
		ports := make([]int, 65535)
		for i := range ports {
			ports[i] = i + 1
		}
		return ports, nil
	}
	return validatedPorts(e.Ports)
}

func validatedPorts(input []int) ([]int, error) {
	ports := append([]int(nil), input...)
	sort.Ints(ports)
	for i, port := range ports {
		if port < 1 || port > 65535 || (i > 0 && port == ports[i-1]) {
			return nil, fmt.Errorf("invalid or duplicate TCP port %d", port)
		}
	}
	return ports, nil
}

func discoveryIPs(target string) ([]string, *net.IPNet, error) {
	if err := ValidateScanTarget(target); err != nil {
		return nil, nil, err
	}
	if !strings.Contains(target, "/") {
		ip := net.ParseIP(target).To4()
		return []string{ip.String()}, &net.IPNet{IP: ip, Mask: net.CIDRMask(32, 32)}, nil
	}
	_, network, _ := net.ParseCIDR(target)
	ones, bits := network.Mask.Size()
	count := 1 << (bits - ones)
	if count > nativeMaxDiscoveryIPs {
		return nil, nil, fmt.Errorf("discovery range contains %d addresses; maximum is %d", count, nativeMaxDiscoveryIPs)
	}
	start := ipv4Number(network.IP)
	ips := make([]string, 0, count)
	for i := 0; i < count; i++ {
		// Exclude network and broadcast except for /31 and /32.
		if count > 2 && (i == 0 || i == count-1) {
			continue
		}
		ips = append(ips, numberIPv4(start+uint32(i)))
	}
	return ips, network, nil
}

func readARP(path string, network *net.IPNet) ([]DiscoveredHost, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	var hosts []DiscoveredHost
	scanner := bufio.NewScanner(file)
	if scanner.Scan() { // header
	}
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 4 || fields[2] != "0x2" {
			continue
		}
		ip := net.ParseIP(fields[0])
		mac, macErr := normalizeNaabuMAC(fields[3])
		if ip == nil || ip.To4() == nil || !network.Contains(ip) || macErr != nil || mac == "" {
			continue
		}
		hosts = append(hosts, DiscoveredHost{IP: ip.To4().String(), MAC: mac})
	}
	return hosts, scanner.Err()
}

func localIPv4Addresses(network *net.IPNet) []string {
	addresses, _ := net.InterfaceAddrs()
	var result []string
	for _, address := range addresses {
		ip, _, err := net.ParseCIDR(address.String())
		if err == nil && ip.To4() != nil && network.Contains(ip) {
			result = append(result, ip.To4().String())
		}
	}
	return result
}

func ipv4Number(ip net.IP) uint32 {
	ip = ip.To4()
	return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
}

func numberIPv4(value uint32) string {
	return net.IPv4(byte(value>>24), byte(value>>16), byte(value>>8), byte(value)).String()
}

func (e *NativeEngine) arpPath() string {
	if e.ARPPath == "" {
		return "/proc/net/arp"
	}
	return e.ARPPath
}

func (e *NativeEngine) engineError(kind EngineErrorKind, op, target string, err error) error {
	return &EngineError{Engine: e.Name(), Kind: kind, Op: op, Target: target, Err: err}
}

var _ ScanEngine = (*NativeEngine)(nil)
var _ BatchScanEngine = (*NativeEngine)(nil)
