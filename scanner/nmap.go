package main

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"log"
	"os/exec"
	"strings"
	"time"
)

const defaultEngineStallTimeout = 15 * time.Minute

type NmapEngine struct {
	Executable   string
	StallTimeout time.Duration
}

func NewNmapEngine() *NmapEngine {
	return &NmapEngine{Executable: "nmap", StallTimeout: defaultEngineStallTimeout}
}

func (e *NmapEngine) Name() string { return "nmap" }

func (e *NmapEngine) Capabilities() EngineCapabilities {
	return EngineCapabilities{
		HostDiscovery: true,
		MACAddresses:  true,
		Hostnames:     true,
		OS:            true,
		Services:      true,
		Scripts:       true,
	}
}

// nmapRun and the related types are private to the adapter. Nothing outside
// this file should depend on the engine's XML schema.
type nmapRun struct {
	Hosts []nmapHost `xml:"host"`
}

type nmapHost struct {
	Addresses []nmapAddress  `xml:"address"`
	Hostnames []nmapHostname `xml:"hostnames>hostname"`
	Ports     []nmapPort     `xml:"ports>port"`
	OS        nmapOS         `xml:"os"`
}

type nmapAddress struct {
	Addr     string `xml:"addr,attr"`
	AddrType string `xml:"addrtype,attr"`
}

type nmapHostname struct {
	Name string `xml:"name,attr"`
	Type string `xml:"type,attr"`
}

type nmapPort struct {
	PortID   int          `xml:"portid,attr"`
	Protocol string       `xml:"protocol,attr"`
	State    nmapState    `xml:"state"`
	Service  nmapService  `xml:"service"`
	Scripts  []nmapScript `xml:"script"`
}

type nmapOS struct {
	Matches []nmapOSMatch `xml:"osmatch"`
}

type nmapOSMatch struct {
	Name     string `xml:"name,attr"`
	Accuracy int    `xml:"accuracy,attr"`
}

type nmapScript struct {
	ID     string `xml:"id,attr"`
	Output string `xml:"output,attr"`
}

type nmapState struct {
	State string `xml:"state,attr"`
}

type nmapService struct {
	Name string `xml:"name,attr"`
	Desc string `xml:"product,attr"`
}

func (e *NmapEngine) Discover(ctx context.Context, request DiscoveryRequest) (DiscoveryResult, error) {
	if err := ValidateScanTarget(request.Target); err != nil {
		return DiscoveryResult{}, e.engineError(EngineErrorValidation, "discover", request.Target, err)
	}

	// -sn: No port scan
	// -n: No DNS
	args := []string{"-oX", "-", "-sn", "-n", "--max-retries", "2", request.Target}
	log.Printf("DEBUG: Executing Host Discovery: nmap %v", args)

	cmd := exec.CommandContext(ctx, e.executable(), args...)
	configureProcessGroup(cmd)
	output, err := cmd.Output()
	if err != nil {
		kind := EngineErrorExecution
		if errors.Is(ctx.Err(), context.Canceled) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
			kind = EngineErrorCancelled
		}
		return DiscoveryResult{}, e.engineError(kind, "discover", request.Target, err)
	}

	var result nmapRun
	if err := xml.Unmarshal(output, &result); err != nil {
		return DiscoveryResult{}, e.engineError(EngineErrorOutput, "discover", request.Target, err)
	}

	var ips []string
	for _, host := range result.Hosts {
		for _, addr := range host.Addresses {
			if addr.AddrType == "ipv4" {
				ips = append(ips, addr.Addr)
			}
		}
	}
	return DiscoveryResult{Targets: ips}, nil
}

func (e *NmapEngine) Scan(ctx context.Context, request PortScanRequest) (EngineScanResult, error) {
	if err := ValidateScanTarget(request.Target); err != nil {
		return EngineScanResult{}, e.engineError(EngineErrorValidation, "scan", request.Target, err)
	}

	// Request stats every 30 seconds to ensure progressive output
	// -n: disable DNS
	// --max-retries 2: avoid getting stuck on bad hosts
	args := []string{"-oX", "-", "-n", "--max-retries", "2", "--stats-every", "30s", "-A", "-T4", request.Target}

	log.Printf("DEBUG: Executing: nmap %v", args)
	cmd := exec.CommandContext(ctx, e.executable(), args...)
	configureProcessGroup(cmd)

	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		return EngineScanResult{}, e.engineError(EngineErrorStart, "scan", request.Target, err)
	}
	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		return EngineScanResult{}, e.engineError(EngineErrorStart, "scan", request.Target, err)
	}

	if err := cmd.Start(); err != nil {
		return EngineScanResult{}, e.engineError(EngineErrorStart, "scan", request.Target, err)
	}
	log.Printf("DEBUG: Nmap process started with PID %d", cmd.Process.Pid)

	progressChan := make(chan []byte, 32)
	var outputBuf bytes.Buffer
	reportProgress := func(data []byte) {
		select {
		case progressChan <- append([]byte(nil), data...):
		default:
			// A queued progress signal is sufficient to reset the watchdog. Never
			// block pipe readers, especially while a timed-out process is exiting.
		}
	}

	// Goroutine to read stdout (XML data)
	go func() {
		for {
			buf := make([]byte, 2048)
			n, err := stdoutPipe.Read(buf)
			if n > 0 {
				outputBuf.Write(buf[:n])
				reportProgress(buf[:n])
			}
			if err != nil {
				break
			}
		}
	}()

	// Goroutine to read stderr (Stats and errors)
	go func() {
		for {
			buf := make([]byte, 2048)
			n, err := stderrPipe.Read(buf)
			if n > 0 {
				reportProgress(buf[:n])
			}
			if err != nil {
				break
			}
		}
	}()

	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()

	timeoutDuration := e.stallTimeout()
	timer := time.NewTimer(timeoutDuration)
	defer timer.Stop()

	for {
		select {
		case data := <-progressChan:
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			timer.Reset(timeoutDuration)
			log.Printf("DEBUG: Watchdog reset (received %d bytes)", len(data))

			str := string(data)
			// Capture XML progress tags and standard stats lines
			if strings.Contains(str, "Stats:") ||
				strings.Contains(str, "About") ||
				strings.Contains(str, "<taskprogress") ||
				strings.Contains(str, "<status") {
				log.Print("DEBUG Nmap progress: " + str)
			}
			if request.Progress != nil {
				request.Progress(EngineProgress{Phase: "scanning_ports", Target: request.Target, Message: str})
			}

		case <-ctx.Done():
			if cmd.Process != nil {
				_ = killProcessGroup(cmd)
			}
			<-done
			return EngineScanResult{}, e.engineError(EngineErrorCancelled, "scan", request.Target, ctx.Err())

		case <-timer.C:
			if cmd.Process != nil {
				log.Printf("CRITICAL: Nmap PID %d timed out after %v", cmd.Process.Pid, timeoutDuration)
				if err := killProcessGroup(cmd); err != nil && !errors.Is(err, context.Canceled) {
					log.Printf("ERROR: Failed to kill timed-out nmap PID %d: %v", cmd.Process.Pid, err)
				}
			}
			<-done
			return EngineScanResult{}, e.engineError(EngineErrorTimeout, "scan", request.Target, fmt.Errorf("no output for %v", timeoutDuration))

		case err := <-done:
			if err != nil {
				kind := EngineErrorExecution
				if ctx.Err() != nil {
					kind = EngineErrorCancelled
				}
				return EngineScanResult{}, e.engineError(kind, "scan", request.Target, fmt.Errorf("%w (stderr + partial stdout size: %d)", err, outputBuf.Len()))
			}

			log.Printf("DEBUG: Nmap execution finished successfully. Output size: %d bytes", outputBuf.Len())
			var result nmapRun
			if err := xml.Unmarshal(outputBuf.Bytes(), &result); err != nil {
				return EngineScanResult{}, e.engineError(EngineErrorOutput, "scan", request.Target, err)
			}
			return result.toEngineResult(), nil
		}
	}
}

func (e *NmapEngine) executable() string {
	if e.Executable == "" {
		return "nmap"
	}
	return e.Executable
}

func (e *NmapEngine) stallTimeout() time.Duration {
	if e.StallTimeout <= 0 {
		return defaultEngineStallTimeout
	}
	return e.StallTimeout
}

func (e *NmapEngine) engineError(kind EngineErrorKind, op, target string, err error) error {
	return &EngineError{Engine: e.Name(), Kind: kind, Op: op, Target: target, Err: err}
}

func (run nmapRun) toEngineResult() EngineScanResult {
	result := EngineScanResult{Hosts: make([]ObservedHost, 0, len(run.Hosts))}
	for _, host := range run.Hosts {
		observed := ObservedHost{}
		for _, address := range host.Addresses {
			switch address.AddrType {
			case "mac":
				observed.MAC = address.Addr
			case "ipv4":
				observed.IP = address.Addr
			}
		}
		if len(host.Hostnames) > 0 {
			observed.Hostname = host.Hostnames[0].Name
		}
		if len(host.OS.Matches) > 0 {
			observed.OS = host.OS.Matches[0].Name
		}
		for _, port := range host.Ports {
			converted := ObservedPort{
				Port: port.PortID, Protocol: port.Protocol, State: port.State.State,
				Service: port.Service.Name,
			}
			for _, script := range port.Scripts {
				converted.Scripts = append(converted.Scripts, ObservedScript{ID: script.ID, Output: script.Output})
			}
			observed.Ports = append(observed.Ports, converted)
		}
		result.Hosts = append(result.Hosts, observed)
	}
	return result
}
