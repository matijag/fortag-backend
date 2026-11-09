package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNativeDiscoveryReadsOnlyCompleteARPEntriesInTarget(t *testing.T) {
	arp := filepath.Join(t.TempDir(), "arp")
	contents := "IP address HW type Flags HW address Mask Device\n" +
		"192.168.1.2 0x1 0x2 00:11:22:33:44:55 * eth0\n" +
		"192.168.1.3 0x1 0x0 00:00:00:00:00:00 * eth0\n" +
		"192.168.2.2 0x1 0x2 00:11:22:33:44:66 * eth0\n"
	if err := os.WriteFile(arp, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	engine := NewNativeEngine()
	engine.Mode = NativeConnectScan
	engine.ARPPath = arp
	engine.DiscoveryPorts = []int{1}
	engine.Timeout = 10 * time.Millisecond
	result, err := engine.Discover(context.Background(), DiscoveryRequest{Target: "192.168.1.0/30"})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Hosts) != 1 || result.Hosts[0].IP != "192.168.1.2" || result.Hosts[0].MAC != "00:11:22:33:44:55" {
		t.Fatalf("discovery = %#v", result)
	}
}

func TestNativeScanFindsExactOpenPorts(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	openPort := listener.Addr().(*net.TCPAddr).Port
	closedListener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closedPort := closedListener.Addr().(*net.TCPAddr).Port
	closedListener.Close()

	engine := NewNativeEngine()
	engine.Mode = NativeConnectScan
	engine.Ports = []int{closedPort, openPort}
	engine.Rate = 100000
	result, err := engine.Scan(context.Background(), PortScanRequest{Target: "127.0.0.1", MAC: "00:11:22:33:44:55"})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Hosts) != 1 || len(result.Hosts[0].Ports) != 1 || result.Hosts[0].Ports[0].Port != openPort {
		t.Fatalf("scan = %#v", result)
	}
}

func TestNativeEngineValidationAndCancellation(t *testing.T) {
	engine := NewNativeEngine()
	if _, err := engine.Discover(context.Background(), DiscoveryRequest{Target: "10.0.0.0/8"}); !isEngineError(err, EngineErrorValidation) {
		t.Fatalf("large discovery error = %#v", err)
	}
	engine.Ports = []int{80, 80}
	if _, err := engine.Scan(context.Background(), PortScanRequest{Target: "127.0.0.1"}); !isEngineError(err, EngineErrorValidation) {
		t.Fatalf("duplicate port error = %#v", err)
	}

	engine = NewNativeEngine()
	engine.Mode = NativeConnectScan
	engine.Ports = make([]int, 65535)
	for i := range engine.Ports {
		engine.Ports[i] = i + 1
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	started := time.Now()
	_, err := engine.Scan(ctx, PortScanRequest{Target: "127.0.0.1"})
	if !isEngineError(err, EngineErrorCancelled) || time.Since(started) > time.Second {
		t.Fatalf("cancelled scan error = %#v, duration=%v", err, time.Since(started))
	}
}

func isEngineError(err error, kind EngineErrorKind) bool {
	var engineErr *EngineError
	return errors.As(err, &engineErr) && engineErr.Kind == kind
}

func BenchmarkNativeLocalScan(b *testing.B) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	defer listener.Close()
	port := listener.Addr().(*net.TCPAddr).Port
	engine := NewNativeEngine()
	engine.Mode = NativeConnectScan
	engine.Ports = []int{port}
	engine.Rate = 100000
	for b.Loop() {
		if _, err := engine.Scan(context.Background(), PortScanRequest{Target: "127.0.0.1"}); err != nil {
			b.Fatal(fmt.Errorf("scan: %w", err))
		}
	}
}
