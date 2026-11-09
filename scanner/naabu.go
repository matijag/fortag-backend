package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	naabuFullTCPRange      = "1-65535"
	naabuDefaultRate       = 500
	naabuDefaultWorkers    = 25
	naabuDefaultTimeoutMS  = 1000
	naabuDefaultRetries    = 2
	naabuMaxOutputBytes    = 16 << 20
	naabuMaxOutputLineSize = 64 << 10
)

type NaabuScanMode string

const (
	NaabuConnectScan NaabuScanMode = "c"
	NaabuSYNScan     NaabuScanMode = "s"
)

// NaabuEngine exposes only Fortag's reviewed subset of Naabu. There is no
// arbitrary-argument field: callers therefore cannot enable config discovery,
// DNS, passive/cloud integrations, Nmap, service probes, UDP, top ports, or
// predictive scanning.
type NaabuEngine struct {
	Executable   string
	Mode         NaabuScanMode
	Rate         int
	Workers      int
	TimeoutMS    int
	Retries      int
	StallTimeout time.Duration
}

func NewNaabuEngine() *NaabuEngine {
	return &NaabuEngine{
		Executable:   "/usr/local/bin/naabu",
		Mode:         NaabuConnectScan,
		Rate:         naabuDefaultRate,
		Workers:      naabuDefaultWorkers,
		TimeoutMS:    naabuDefaultTimeoutMS,
		Retries:      naabuDefaultRetries,
		StallTimeout: defaultEngineStallTimeout,
	}
}

func (e *NaabuEngine) Name() string { return "naabu" }

func (e *NaabuEngine) Capabilities() EngineCapabilities {
	return EngineCapabilities{HostDiscovery: true, MACAddresses: true}
}

type naabuJSONResult struct {
	IP         string `json:"ip"`
	Port       int    `json:"port"`
	Protocol   string `json:"protocol"`
	MACAddress string `json:"mac_address"`
}

func (e *NaabuEngine) Discover(ctx context.Context, request DiscoveryRequest) (DiscoveryResult, error) {
	if err := ValidateScanTarget(request.Target); err != nil {
		return DiscoveryResult{}, e.engineError(EngineErrorValidation, "discover", request.Target, err)
	}
	args, err := e.discoveryArgs(request.Target)
	if err != nil {
		return DiscoveryResult{}, e.engineError(EngineErrorValidation, "discover", request.Target, err)
	}
	lines, err := e.run(ctx, "discover", request.Target, args, request.Progress)
	if err != nil {
		return DiscoveryResult{}, err
	}

	hosts := make(map[string]DiscoveredHost)
	for _, line := range lines {
		var item naabuJSONResult
		if err := json.Unmarshal(line, &item); err != nil {
			return DiscoveryResult{}, e.engineError(EngineErrorOutput, "discover", request.Target, fmt.Errorf("invalid JSON output: %w", err))
		}
		ip, err := validateNaabuResultIP(item.IP, request.Target)
		if err != nil {
			return DiscoveryResult{}, e.engineError(EngineErrorOutput, "discover", request.Target, err)
		}
		mac, err := normalizeNaabuMAC(item.MACAddress)
		if err != nil {
			return DiscoveryResult{}, e.engineError(EngineErrorOutput, "discover", request.Target, err)
		}
		hosts[ip] = DiscoveredHost{IP: ip, MAC: mac}
	}

	result := DiscoveryResult{Targets: make([]string, 0, len(hosts)), Hosts: make([]DiscoveredHost, 0, len(hosts))}
	for ip := range hosts {
		result.Targets = append(result.Targets, ip)
	}
	sort.Strings(result.Targets)
	for _, ip := range result.Targets {
		result.Hosts = append(result.Hosts, hosts[ip])
	}
	return result, nil
}

func (e *NaabuEngine) Scan(ctx context.Context, request PortScanRequest) (EngineScanResult, error) {
	if err := ValidateScanTarget(request.Target); err != nil {
		return EngineScanResult{}, e.engineError(EngineErrorValidation, "scan", request.Target, err)
	}
	if strings.Contains(request.Target, "/") {
		return EngineScanResult{}, e.engineError(EngineErrorValidation, "scan", request.Target, errors.New("port scans require one IPv4 address"))
	}
	mac, err := normalizeNaabuMAC(request.MAC)
	if err != nil {
		return EngineScanResult{}, e.engineError(EngineErrorValidation, "scan", request.Target, err)
	}
	args, err := e.scanArgs(request.Target)
	if err != nil {
		return EngineScanResult{}, e.engineError(EngineErrorValidation, "scan", request.Target, err)
	}
	lines, err := e.run(ctx, "scan", request.Target, args, request.Progress)
	if err != nil {
		return EngineScanResult{}, err
	}

	host := ObservedHost{IP: request.Target, MAC: mac, ClearMissingMetadata: true}
	seen := make(map[int]bool)
	for _, line := range lines {
		var item naabuJSONResult
		if err := json.Unmarshal(line, &item); err != nil {
			return EngineScanResult{}, e.engineError(EngineErrorOutput, "scan", request.Target, fmt.Errorf("invalid JSON output: %w", err))
		}
		ip, err := validateNaabuResultIP(item.IP, request.Target)
		if err != nil || ip != request.Target {
			if err == nil {
				err = fmt.Errorf("unexpected result IP %q", ip)
			}
			return EngineScanResult{}, e.engineError(EngineErrorOutput, "scan", request.Target, err)
		}
		if item.Port < 1 || item.Port > 65535 || (item.Protocol != "tcp" && item.Protocol != "") {
			return EngineScanResult{}, e.engineError(EngineErrorOutput, "scan", request.Target, fmt.Errorf("invalid TCP port result: %d/%q", item.Port, item.Protocol))
		}
		resultMAC, err := normalizeNaabuMAC(item.MACAddress)
		if err != nil {
			return EngineScanResult{}, e.engineError(EngineErrorOutput, "scan", request.Target, err)
		}
		if resultMAC != "" {
			if host.MAC != "" && host.MAC != resultMAC {
				return EngineScanResult{}, e.engineError(EngineErrorOutput, "scan", request.Target, errors.New("port result MAC differs from discovery"))
			}
			host.MAC = resultMAC
		}
		if !seen[item.Port] {
			host.Ports = append(host.Ports, ObservedPort{Port: item.Port, Protocol: "tcp", State: "open"})
			seen[item.Port] = true
		}
	}
	sort.Slice(host.Ports, func(i, j int) bool { return host.Ports[i].Port < host.Ports[j].Port })
	return EngineScanResult{Hosts: []ObservedHost{host}}, nil
}

func (e *NaabuEngine) commonArgs(target string) ([]string, error) {
	mode := e.Mode
	if mode == "" {
		mode = NaabuConnectScan
	}
	if mode != NaabuConnectScan && mode != NaabuSYNScan {
		return nil, fmt.Errorf("unsupported scan mode %q", mode)
	}
	rate, workers, timeoutMS, retries := e.Rate, e.Workers, e.TimeoutMS, e.Retries
	if rate == 0 {
		rate = naabuDefaultRate
	}
	if workers == 0 {
		workers = naabuDefaultWorkers
	}
	if timeoutMS == 0 {
		timeoutMS = naabuDefaultTimeoutMS
	}
	if retries == 0 {
		retries = naabuDefaultRetries
	}
	if rate < 1 || rate > 10000 || workers < 1 || workers > 256 || timeoutMS < 100 || timeoutMS > 30000 || retries < 1 || retries > 10 {
		return nil, errors.New("Naabu rate, workers, timeout, or retries are outside safe bounds")
	}
	return []string{
		"-host", target, "-json", "-silent", "-no-color", "-no-stdin",
		"-disable-update-check",
		"-ip-version", "4", "-rate", strconv.Itoa(rate), "-c", strconv.Itoa(workers),
		"-timeout", strconv.Itoa(timeoutMS), "-retries", strconv.Itoa(retries),
		"-warm-up-time", "0", "-scan-type", string(mode),
	}, nil
}

func (e *NaabuEngine) discoveryArgs(target string) ([]string, error) {
	args, err := e.commonArgs(target)
	if err != nil {
		return nil, err
	}
	for i := range args {
		if i > 0 && args[i-1] == "-scan-type" {
			args[i] = string(NaabuSYNScan)
		}
	}
	// v2.6.1 requires -with-host-discovery when explicit probes accompany
	// -host-discovery, even though its help describes -host-discovery as enough.
	return append(args, "-host-discovery", "-with-host-discovery", "-arp-ping", "-probe-icmp-echo", "-probe-tcp-syn", "80,443", "-probe-tcp-ack", "443", "-auth=false"), nil
}

func (e *NaabuEngine) scanArgs(target string) ([]string, error) {
	args, err := e.commonArgs(target)
	if err != nil {
		return nil, err
	}
	return append(args, "-port", naabuFullTCPRange, "-skip-host-discovery", "-auth=false"), nil
}

type naabuProcessEvent struct {
	line []byte
	err  error
}

func (e *NaabuEngine) run(ctx context.Context, op, target string, args []string, progress func(EngineProgress)) ([][]byte, error) {
	cmd := exec.CommandContext(ctx, e.executable(), args...)
	configureProcessGroup(cmd)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, e.engineError(EngineErrorStart, op, target, err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, e.engineError(EngineErrorStart, op, target, err)
	}
	if err := cmd.Start(); err != nil {
		return nil, e.engineError(EngineErrorStart, op, target, err)
	}

	events := make(chan naabuProcessEvent, 32)
	var readers sync.WaitGroup
	readers.Add(2)
	read := func(reader io.Reader, output bool) {
		defer readers.Done()
		scanner := bufio.NewScanner(reader)
		scanner.Buffer(make([]byte, 4096), naabuMaxOutputLineSize)
		for scanner.Scan() {
			line := append([]byte(nil), scanner.Bytes()...)
			if output {
				events <- naabuProcessEvent{line: line}
			} else {
				events <- naabuProcessEvent{}
			}
		}
		if err := scanner.Err(); err != nil {
			events <- naabuProcessEvent{err: err}
		}
	}
	go read(stdout, true)
	go read(stderr, false)
	readersDone := make(chan struct{})
	go func() { readers.Wait(); close(readersDone) }()
	commandDone := make(chan error, 1)
	go func() { commandDone <- cmd.Wait() }()

	timer := time.NewTimer(e.stallTimeout())
	defer timer.Stop()
	var lines [][]byte
	total := 0
	var commandErr error
	commandFinished, readersFinished := false, false
	for !commandFinished || !readersFinished {
		select {
		case event := <-events:
			if event.err != nil {
				_ = killProcessGroup(cmd)
				return nil, e.engineError(EngineErrorOutput, op, target, event.err)
			}
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			timer.Reset(e.stallTimeout())
			if len(event.line) > 0 {
				total += len(event.line)
				if total > naabuMaxOutputBytes {
					_ = killProcessGroup(cmd)
					return nil, e.engineError(EngineErrorOutput, op, target, errors.New("Naabu output exceeded limit"))
				}
				lines = append(lines, event.line)
			}
			if progress != nil {
				progress(EngineProgress{Phase: op, Target: target})
			}
		case commandErr = <-commandDone:
			commandFinished = true
			commandDone = nil
		case <-readersDone:
			readersFinished = true
			readersDone = nil
		case <-ctx.Done():
			_ = killProcessGroup(cmd)
			return nil, e.engineError(EngineErrorCancelled, op, target, ctx.Err())
		case <-timer.C:
			_ = killProcessGroup(cmd)
			return nil, e.engineError(EngineErrorTimeout, op, target, fmt.Errorf("no output for %v", e.stallTimeout()))
		}
	}
	if commandErr != nil {
		kind := EngineErrorExecution
		if ctx.Err() != nil {
			kind = EngineErrorCancelled
		}
		return nil, e.engineError(kind, op, target, commandErr)
	}
	return lines, nil
}

func (e *NaabuEngine) executable() string {
	if e.Executable == "" {
		return "/usr/local/bin/naabu"
	}
	return e.Executable
}

func (e *NaabuEngine) stallTimeout() time.Duration {
	if e.StallTimeout <= 0 {
		return defaultEngineStallTimeout
	}
	return e.StallTimeout
}

func (e *NaabuEngine) engineError(kind EngineErrorKind, op, target string, err error) error {
	return &EngineError{Engine: e.Name(), Kind: kind, Op: op, Target: target, Err: err}
}

func normalizeNaabuMAC(value string) (string, error) {
	if value == "" {
		return "", nil
	}
	mac, err := net.ParseMAC(value)
	if err != nil || len(mac) != 6 {
		return "", fmt.Errorf("invalid MAC address %q", value)
	}
	return strings.ToUpper(mac.String()), nil
}

func validateNaabuResultIP(value, requested string) (string, error) {
	ip := net.ParseIP(value)
	if ip == nil || ip.To4() == nil {
		return "", fmt.Errorf("invalid IPv4 result %q", value)
	}
	canonical := ip.To4().String()
	if strings.Contains(requested, "/") {
		_, network, err := net.ParseCIDR(requested)
		if err != nil || !network.Contains(ip) {
			return "", fmt.Errorf("result IP %q is outside requested target", value)
		}
	} else if canonical != requested {
		return "", fmt.Errorf("result IP %q does not match requested target", value)
	}
	return canonical, nil
}

var _ ScanEngine = (*NaabuEngine)(nil)
