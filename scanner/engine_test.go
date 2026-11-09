package main

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

type fakeScanEngine struct {
	discovery DiscoveryResult
	scan      EngineScanResult
}

func (f fakeScanEngine) Name() string { return "fake" }
func (f fakeScanEngine) Capabilities() EngineCapabilities {
	return EngineCapabilities{HostDiscovery: true, MACAddresses: true}
}
func (f fakeScanEngine) Discover(context.Context, DiscoveryRequest) (DiscoveryResult, error) {
	return f.discovery, nil
}
func (f fakeScanEngine) Scan(context.Context, PortScanRequest) (EngineScanResult, error) {
	return f.scan, nil
}

var _ ScanEngine = fakeScanEngine{}

func TestNeutralEngineResultCanBePersisted(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(schema); err != nil {
		t.Fatal(err)
	}

	engine := fakeScanEngine{
		discovery: DiscoveryResult{Targets: []string{"192.168.1.20"}},
		scan: EngineScanResult{Hosts: []ObservedHost{{
			MAC: "00:11:22:33:44:55", IP: "192.168.1.20",
			Ports: []ObservedPort{{Port: 443, Protocol: "tcp", State: "open"}},
		}}},
	}
	discovery, err := engine.Discover(context.Background(), DiscoveryRequest{Target: "192.168.1.0/24"})
	if err != nil || len(discovery.Targets) != 1 {
		t.Fatalf("discovery = %#v, %v", discovery, err)
	}
	result, err := engine.Scan(context.Background(), PortScanRequest{Target: discovery.Targets[0]})
	if err != nil {
		t.Fatal(err)
	}
	processed, err := ProcessScan(db, result)
	if err != nil {
		t.Fatal(err)
	}
	if len(processed) != 1 || len(processed[0].Ports) != 1 || processed[0].Ports[0].Port != 443 {
		t.Fatalf("processed neutral result = %#v", processed)
	}
}

func TestNmapXMLConvertsAtAdapterBoundary(t *testing.T) {
	run := nmapRun{Hosts: []nmapHost{{
		Addresses: []nmapAddress{{Addr: "192.168.1.20", AddrType: "ipv4"}, {Addr: "00:11:22:33:44:55", AddrType: "mac"}},
		Hostnames: []nmapHostname{{Name: "printer.local"}},
		OS:        nmapOS{Matches: []nmapOSMatch{{Name: "Printer OS", Accuracy: 90}}},
		Ports: []nmapPort{{
			PortID: 631, Protocol: "tcp", State: nmapState{State: "open"}, Service: nmapService{Name: "ipp"},
			Scripts: []nmapScript{{ID: "banner", Output: "printer"}},
		}},
	}}}

	got := run.toEngineResult()
	if len(got.Hosts) != 1 {
		t.Fatalf("converted hosts = %#v", got.Hosts)
	}
	host := got.Hosts[0]
	if host.MAC != "00:11:22:33:44:55" || host.IP != "192.168.1.20" || host.Hostname != "printer.local" || host.OS != "Printer OS" {
		t.Fatalf("converted host = %#v", host)
	}
	if len(host.Ports) != 1 || host.Ports[0].Service != "ipp" || len(host.Ports[0].Scripts) != 1 {
		t.Fatalf("converted ports = %#v", host.Ports)
	}
}

func TestNmapAdapterReturnsCategorizedValidationError(t *testing.T) {
	_, err := NewNmapEngine().Scan(context.Background(), PortScanRequest{Target: "example.com"})
	var engineErr *EngineError
	if !errors.As(err, &engineErr) || engineErr.Kind != EngineErrorValidation {
		t.Fatalf("error = %#v, want validation EngineError", err)
	}
}

func TestNmapAdapterCategorizesMalformedOutput(t *testing.T) {
	executable := writeTestExecutable(t, "#!/bin/sh\nprintf 'not xml'\n")
	engine := &NmapEngine{Executable: executable, StallTimeout: time.Second}
	_, err := engine.Scan(context.Background(), PortScanRequest{Target: "192.168.1.20"})
	var engineErr *EngineError
	if !errors.As(err, &engineErr) || engineErr.Kind != EngineErrorOutput {
		t.Fatalf("error = %#v, want output EngineError", err)
	}
}

func TestNmapAdapterCancellation(t *testing.T) {
	executable := writeTestExecutable(t, "#!/bin/sh\nsleep 30\n")
	engine := &NmapEngine{Executable: executable, StallTimeout: time.Minute}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	started := time.Now()
	_, err := engine.Scan(ctx, PortScanRequest{Target: "192.168.1.20"})
	var engineErr *EngineError
	if !errors.As(err, &engineErr) || engineErr.Kind != EngineErrorCancelled {
		t.Fatalf("error = %#v, want cancelled EngineError", err)
	}
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("cancellation took %v", elapsed)
	}
}

func TestNmapAdapterCategorizesStallTimeout(t *testing.T) {
	executable := writeTestExecutable(t, "#!/bin/sh\nsleep 30\n")
	engine := &NmapEngine{Executable: executable, StallTimeout: 50 * time.Millisecond}
	started := time.Now()
	_, err := engine.Scan(context.Background(), PortScanRequest{Target: "192.168.1.20"})
	var engineErr *EngineError
	if !errors.As(err, &engineErr) || engineErr.Kind != EngineErrorTimeout {
		t.Fatalf("error = %#v, want timeout EngineError", err)
	}
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("stall timeout took %v", elapsed)
	}
}

func writeTestExecutable(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "fake-nmap")
	if err := os.WriteFile(path, []byte(body), 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}
