package main

import (
	"context"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestNativeFieldValidation is opt-in because it sends probes to a real network.
func TestNativeFieldValidation(t *testing.T) {
	target := os.Getenv("FORTAG_FIELD_TARGET")
	if target == "" {
		t.Skip("set FORTAG_FIELD_TARGET to an authorized private IPv4 target")
	}
	fullRange := os.Getenv("FORTAG_FIELD_FULL_RANGE") == "1"
	portList := os.Getenv("FORTAG_FIELD_PORTS")
	if portList == "" && !fullRange {
		t.Skip("set FORTAG_FIELD_PORTS for the release gate or FORTAG_FIELD_FULL_RANGE=1 for endurance validation")
	}
	if portList != "" && fullRange {
		t.Fatal("FORTAG_FIELD_PORTS and FORTAG_FIELD_FULL_RANGE=1 are mutually exclusive")
	}
	engine := NewNativeEngine()
	if value := os.Getenv("FORTAG_FIELD_RATE"); value != "" {
		rate, err := strconv.Atoi(value)
		if err != nil {
			t.Fatalf("invalid FORTAG_FIELD_RATE: %v", err)
		}
		engine.Rate = rate
	}
	if portList != "" {
		for _, item := range strings.Split(portList, ",") {
			port, err := strconv.Atoi(item)
			if err != nil {
				t.Fatalf("invalid FORTAG_FIELD_PORTS: %v", err)
			}
			engine.Ports = append(engine.Ports, port)
		}
	}
	discoveryCtx, cancelDiscovery := context.WithTimeout(context.Background(), time.Minute)
	defer cancelDiscovery()
	started := time.Now()
	discovery, err := engine.Discover(discoveryCtx, DiscoveryRequest{Target: target})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("discovered %d hosts in %v", len(discovery.Hosts), time.Since(started))
	hosts := discovery.Hosts
	requests := make([]PortScanRequest, 0, len(hosts))
	for _, host := range hosts {
		requests = append(requests, PortScanRequest{Target: host.IP, MAC: host.MAC})
	}
	scanCtx := context.Background()
	if !fullRange {
		var cancelScan context.CancelFunc
		scanCtx, cancelScan = context.WithTimeout(scanCtx, 15*time.Minute)
		defer cancelScan()
	} else {
		t.Log("running non-release-blocking full-range endurance validation; set an adequate go test -timeout")
	}
	scanStarted := time.Now()
	result, err := engine.ScanBatch(scanCtx, requests)
	if err != nil {
		t.Fatal(err)
	}
	for _, host := range result.Hosts {
		var ports []int
		for _, port := range host.Ports {
			ports = append(ports, port.Port)
		}
		t.Logf("host=%s ports=%v", host.IP, ports)
	}
	t.Logf("multiplexed %d hosts in %v", len(hosts), time.Since(scanStarted))
}
