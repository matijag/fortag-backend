package main

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"log"
	"os/exec"
	"strings"
	"time"
)

// NmapRun represents the root of the nmap XML output
type NmapRun struct {
	Hosts []Host `xml:"host"`
}

type Host struct {
	Addresses []Address  `xml:"address"`
	Hostnames []Hostname `xml:"hostnames>hostname"`
	Ports     []Port     `xml:"ports>port"`
	OS        OS         `xml:"os"`
}

type Address struct {
	Addr     string `xml:"addr,attr"`
	AddrType string `xml:"addrtype,attr"`
}

type Hostname struct {
	Name string `xml:"name,attr"`
	Type string `xml:"type,attr"`
}

type Port struct {
	PortID   int      `xml:"portid,attr"`
	Protocol string   `xml:"protocol,attr"`
	State    State    `xml:"state"`
	Service  Service  `xml:"service"`
	Scripts  []Script `xml:"script"`
}

type OS struct {
	Matches []OSMatch `xml:"osmatch"`
}

type OSMatch struct {
	Name     string `xml:"name,attr"`
	Accuracy int    `xml:"accuracy,attr"`
}

type Script struct {
	ID     string `xml:"id,attr"`
	Output string `xml:"output,attr"`
}

type State struct {
	State string `xml:"state,attr"`
}

type Service struct {
	Name string `xml:"name,attr"`
	Desc string `xml:"product,attr"`
}

func RunHostDiscovery(target string) ([]string, error) {
	if err := ValidateScanTarget(target); err != nil {
		return nil, fmt.Errorf("host-discovery target rejected: %w", err)
	}

	// -sn: No port scan
	// -n: No DNS
	args := []string{"-oX", "-", "-sn", "-n", "--max-retries", "2", target}
	log.Printf("DEBUG: Executing Host Discovery: nmap %v", args)

	cmd := exec.Command("nmap", args...)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("host discovery failed: %w", err)
	}

	var result NmapRun
	if err := xml.Unmarshal(output, &result); err != nil {
		return nil, fmt.Errorf("failed to parse discovery output: %w", err)
	}

	var ips []string
	for _, host := range result.Hosts {
		for _, addr := range host.Addresses {
			if addr.AddrType == "ipv4" {
				ips = append(ips, addr.Addr)
			}
		}
	}
	return ips, nil
}

func RunScan(target string, flags []string) (*NmapRun, error) {
	if err := ValidateScanTarget(target); err != nil {
		return nil, fmt.Errorf("port-scan target rejected: %w", err)
	}

	// Request stats every 30 seconds to ensure progressive output
	// -n: disable DNS
	// --max-retries 2: avoid getting stuck on bad hosts
	args := append([]string{"-oX", "-", "-n", "--max-retries", "2", "--stats-every", "30s"}, flags...)
	args = append(args, target)

	log.Printf("DEBUG: Executing: nmap %v", args)
	cmd := exec.Command("nmap", args...)

	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		return nil, err
	}

	if err := cmd.Start(); err != nil {
		return nil, err
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

	timeoutDuration := 15 * time.Minute
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

		case <-timer.C:
			if cmd.Process != nil {
				log.Printf("CRITICAL: Nmap PID %d timed out after %v", cmd.Process.Pid, timeoutDuration)
				if err := cmd.Process.Kill(); err != nil {
					log.Printf("ERROR: Failed to kill timed-out nmap PID %d: %v", cmd.Process.Pid, err)
				}
			}
			<-done
			return nil, fmt.Errorf("nmap stalled: no output for %v", timeoutDuration)

		case err := <-done:
			if err != nil {
				return nil, fmt.Errorf("nmap execution failed: %w (stderr + partial stdout size: %d)", err, outputBuf.Len())
			}

			log.Printf("DEBUG: Nmap execution finished successfully. Output size: %d bytes", outputBuf.Len())
			var result NmapRun
			if err := xml.Unmarshal(outputBuf.Bytes(), &result); err != nil {
				return nil, fmt.Errorf("failed to parse nmap output: %w", err)
			}
			return &result, nil
		}
	}
}
