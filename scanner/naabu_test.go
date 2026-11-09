package main

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestNaabuCommandConstructionIsClosedAndExplicit(t *testing.T) {
	engine := NewNaabuEngine()
	discovery, err := engine.discoveryArgs("192.168.1.0/24")
	if err != nil {
		t.Fatal(err)
	}
	scan, err := engine.scanArgs("192.168.1.10")
	if err != nil {
		t.Fatal(err)
	}

	for name, args := range map[string][]string{"discovery": discovery, "scan": scan} {
		joined := " " + strings.Join(args, " ") + " "
		for _, required := range []string{
			" -host ", " -json ", " -no-stdin ", " -disable-update-check ",
			" -auth=false ", " -ip-version 4 ",
			" -rate 500 ", " -c 25 ", " -timeout 1000 ", " -retries 2 ",
		} {
			if !strings.Contains(joined, required) {
				t.Errorf("%s args lack %q: %v", name, required, args)
			}
		}
		for _, forbidden := range []string{
			" -nmap ", " -nmap-cli ", " -service-discovery ", " -service-version ",
			" -udp-probes ", " -top-ports ", " -smart-scan ", " -passive ",
			" -rev-ptr ", " -dashboard ", " -update ", " -list ", " -ports-file ",
			" -config ",
		} {
			if strings.Contains(joined, forbidden) {
				t.Errorf("%s args contain forbidden flag %q: %v", name, forbidden, args)
			}
		}
		if args[len(args)-1] != "-auth=false" {
			t.Errorf("%s must place Naabu's dynamic auth flag last: %v", name, args)
		}
	}
	if !containsAdjacent(scan, "-scan-type", "c") {
		t.Fatalf("port scan must explicitly select CONNECT mode: %v", scan)
	}
	if !containsAdjacent(scan, "-port", "1-65535") {
		t.Fatalf("scan does not use explicit full range: %v", scan)
	}
	if !containsAdjacent(scan, "-skip-host-discovery", "") {
		t.Fatalf("scan does not skip duplicate discovery: %v", scan)
	}
	for _, flag := range []string{"-host-discovery", "-with-host-discovery", "-arp-ping", "-probe-icmp-echo", "-probe-tcp-syn", "-probe-tcp-ack"} {
		if !containsAdjacent(discovery, flag, "") {
			t.Errorf("discovery lacks %s: %v", flag, discovery)
		}
	}
	if !containsAdjacent(discovery, "-scan-type", "s") {
		t.Fatalf("discovery must explicitly select SYN mode: %v", discovery)
	}
}

func TestNaabuSupportsReviewedSYNModeOnly(t *testing.T) {
	engine := NewNaabuEngine()
	engine.Mode = NaabuSYNScan
	args, err := engine.scanArgs("192.168.1.10")
	if err != nil {
		t.Fatal(err)
	}
	if !containsAdjacent(args, "-scan-type", "s") {
		t.Fatalf("SYN args = %v", args)
	}
	engine.Mode = "udp"
	if _, err := engine.scanArgs("192.168.1.10"); err == nil {
		t.Fatal("unsupported mode accepted")
	}
}

func TestNaabuDiscoveryParsesAndBoundsJSONL(t *testing.T) {
	executable := writeTestExecutable(t, `#!/bin/sh
printf '%s\n' '{"ip":"192.168.1.20","mac_address":"00:11:22:33:44:55"}' '{"ip":"192.168.1.10"}' '{"ip":"192.168.1.20","mac_address":"00:11:22:33:44:55"}'
`)
	engine := NewNaabuEngine()
	engine.Executable = executable
	result, err := engine.Discover(context.Background(), DiscoveryRequest{Target: "192.168.1.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(result.Targets, []string{"192.168.1.10", "192.168.1.20"}) {
		t.Fatalf("targets = %#v", result.Targets)
	}
	if result.Hosts[1].MAC != "00:11:22:33:44:55" {
		t.Fatalf("hosts = %#v", result.Hosts)
	}
}

func TestNaabuScanReturnsOnlyValidatedOpenTCPPorts(t *testing.T) {
	executable := writeTestExecutable(t, `#!/bin/sh
printf '%s\n' '{"ip":"192.168.1.20","port":443,"protocol":"tcp"}' '{"ip":"192.168.1.20","port":22,"protocol":"tcp"}' '{"ip":"192.168.1.20","port":443,"protocol":"tcp"}'
`)
	engine := NewNaabuEngine()
	engine.Executable = executable
	result, err := engine.Scan(context.Background(), PortScanRequest{Target: "192.168.1.20", MAC: "00-11-22-33-44-55"})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Hosts) != 1 || result.Hosts[0].MAC != "00:11:22:33:44:55" {
		t.Fatalf("result = %#v", result)
	}
	ports := result.Hosts[0].Ports
	if len(ports) != 2 || ports[0].Port != 22 || ports[1].Port != 443 || ports[0].State != "open" {
		t.Fatalf("ports = %#v", ports)
	}
	if ports[0].Service != "" || len(ports[0].Scripts) != 0 {
		t.Fatalf("Nmap-derived enrichment was fabricated: %#v", ports[0])
	}
}

func TestNaabuScanUsesValidatedResultMACWhenDiscoveryHadNone(t *testing.T) {
	executable := writeTestExecutable(t, `#!/bin/sh
printf '%s\n' '{"ip":"192.168.1.20","port":443,"protocol":"tcp","mac_address":"00:11:22:33:44:55"}'
`)
	engine := NewNaabuEngine()
	engine.Executable = executable
	result, err := engine.Scan(context.Background(), PortScanRequest{Target: "192.168.1.20"})
	if err != nil {
		t.Fatal(err)
	}
	if result.Hosts[0].MAC != "00:11:22:33:44:55" {
		t.Fatalf("MAC = %q", result.Hosts[0].MAC)
	}
}

func TestNaabuRejectsHostileOutput(t *testing.T) {
	tests := map[string]string{
		"malformed JSON": `not-json`,
		"outside target": `{"ip":"192.168.2.20","mac_address":"00:11:22:33:44:55"}`,
		"invalid MAC":    `{"ip":"192.168.1.20","mac_address":"not-a-mac"}`,
	}
	for name, output := range tests {
		t.Run(name, func(t *testing.T) {
			executable := writeTestExecutable(t, "#!/bin/sh\nprintf '%s\\n' '"+output+"'\n")
			engine := NewNaabuEngine()
			engine.Executable = executable
			_, err := engine.Discover(context.Background(), DiscoveryRequest{Target: "192.168.1.0/24"})
			var engineErr *EngineError
			if !errors.As(err, &engineErr) || engineErr.Kind != EngineErrorOutput {
				t.Fatalf("error = %#v", err)
			}
		})
	}
}

func TestNaabuCancellationAndStallTimeout(t *testing.T) {
	executable := writeTestExecutable(t, "#!/bin/sh\nsleep 30\n")
	for name, setup := range map[string]func(*NaabuEngine) (context.Context, context.CancelFunc, EngineErrorKind){
		"cancelled": func(e *NaabuEngine) (context.Context, context.CancelFunc, EngineErrorKind) {
			ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
			e.StallTimeout = time.Minute
			return ctx, cancel, EngineErrorCancelled
		},
		"stalled": func(e *NaabuEngine) (context.Context, context.CancelFunc, EngineErrorKind) {
			e.StallTimeout = 50 * time.Millisecond
			return context.Background(), func() {}, EngineErrorTimeout
		},
	} {
		t.Run(name, func(t *testing.T) {
			engine := NewNaabuEngine()
			engine.Executable = executable
			ctx, cancel, want := setup(engine)
			defer cancel()
			start := time.Now()
			_, err := engine.Scan(ctx, PortScanRequest{Target: "192.168.1.20"})
			var engineErr *EngineError
			if !errors.As(err, &engineErr) || engineErr.Kind != want {
				t.Fatalf("error = %#v, want %s", err, want)
			}
			if time.Since(start) > 2*time.Second {
				t.Fatalf("termination was too slow: %v", time.Since(start))
			}
		})
	}
}

func containsAdjacent(args []string, key, value string) bool {
	for i, arg := range args {
		if arg == key && (value == "" || i+1 < len(args) && args[i+1] == value) {
			return true
		}
	}
	return false
}
