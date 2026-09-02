package main

import (
	"database/sql"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

func TestProcessScan(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	if _, err := db.Exec(schema); err != nil {
		t.Fatal(err)
	}

	// Mock Nmap Output
	mockRun := &NmapRun{
		Hosts: []Host{
			{
				Addresses: []Address{
					{Addr: "00:11:22:33:44:55", AddrType: "mac"},
					{Addr: "192.168.1.50", AddrType: "ipv4"},
				},
				Ports: []Port{
					{PortID: 80, Protocol: "tcp", State: State{State: "open"}, Service: Service{Name: "http"}},
				},
			},
		},
	}

	// First scan - New Host
	results, err := ProcessScan(db, mockRun)
	if err != nil {
		t.Fatalf("ProcessScan failed: %v", err)
	}

	if len(results) != 1 {
		t.Errorf("Expected 1 result, got %d", len(results))
	}
	if !results[0].IsNewHost {
		t.Errorf("Expected IsNewHost to be true")
	}
	if !results[0].Ports[0].IsNew {
		t.Errorf("Expected port 80 to be new")
	}

	// Second scan - Same Host, New Port
	mockRun.Hosts[0].Ports = append(mockRun.Hosts[0].Ports, Port{
		PortID: 443, Protocol: "tcp", State: State{State: "open"}, Service: Service{Name: "https"},
	})

	results, err = ProcessScan(db, mockRun)
	if err != nil {
		t.Fatalf("ProcessScan failed: %v", err)
	}

	if results[0].IsNewHost {
		t.Errorf("Expected IsNewHost to be false on second scan")
	}
	if results[0].Ports[0].IsNew {
		t.Errorf("Expected port 80 to NOT be new")
	}
	if !results[0].Ports[1].IsNew {
		t.Errorf("Expected port 443 to be new")
	}

	// A successful scan with no open ports closes previously open history and
	// does not publish closed or filtered ports as current exposure.
	if _, err := db.Exec("UPDATE ports SET acknowledged = TRUE WHERE mac = ?", "00:11:22:33:44:55"); err != nil {
		t.Fatal(err)
	}
	mockRun.Hosts[0].Ports = []Port{
		{PortID: 443, Protocol: "tcp", State: State{State: "closed"}, Service: Service{Name: "https"}},
		{PortID: 22, Protocol: "tcp", State: State{State: "filtered"}, Service: Service{Name: "ssh"}},
	}
	results, err = ProcessScan(db, mockRun)
	if err != nil {
		t.Fatal(err)
	}
	if len(results[0].Ports) != 0 {
		t.Fatalf("closed/filtered ports were published: %#v", results[0].Ports)
	}
	for _, port := range []int{80, 443} {
		var state string
		if err := db.QueryRow("SELECT state FROM ports WHERE mac = ? AND port = ?", "00:11:22:33:44:55", port).Scan(&state); err != nil {
			t.Fatal(err)
		}
		if state != "closed" {
			t.Errorf("port %d state = %q, want closed", port, state)
		}
	}

	// Reopening a previously closed, acknowledged port is a fresh,
	// unacknowledged security exposure.
	mockRun.Hosts[0].Ports = []Port{
		{PortID: 80, Protocol: "tcp", State: State{State: "open"}, Service: Service{Name: "http"}},
	}
	results, err = ProcessScan(db, mockRun)
	if err != nil {
		t.Fatal(err)
	}
	if len(results[0].Ports) != 1 || !results[0].Ports[0].IsNew || results[0].Ports[0].IsAcknowledged {
		t.Fatalf("reopened port was not a new unacknowledged exposure: %#v", results[0].Ports)
	}
}

func TestGenerateFingerprintUsesOnlyOpenPorts(t *testing.T) {
	openOnly := []Port{{PortID: 80, Protocol: "tcp", State: State{State: "open"}}}
	withClosed := append(append([]Port{}, openOnly...),
		Port{PortID: 22, Protocol: "tcp", State: State{State: "closed"}},
		Port{PortID: 443, Protocol: "tcp", State: State{State: "filtered"}},
	)
	if generateFingerprint("device", openOnly) != generateFingerprint("device", withClosed) {
		t.Fatal("closed or filtered ports changed the device fingerprint")
	}
}

func TestProcessScanPreservesKnownMetadataWhenNewScanIsEmpty(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(schema); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO hosts (mac, ip, hostname, os_info)
		VALUES ('00:11:22:33:44:55', '192.168.1.50', 'known-host', 'Known OS')`); err != nil {
		t.Fatal(err)
	}

	run := &NmapRun{Hosts: []Host{{Addresses: []Address{
		{Addr: "00:11:22:33:44:55", AddrType: "mac"},
		{Addr: "192.168.1.50", AddrType: "ipv4"},
	}}}}
	results, err := ProcessScan(db, run)
	if err != nil {
		t.Fatal(err)
	}
	if results[0].Hostname != "known-host" || results[0].OS != "Known OS" {
		t.Fatalf("published metadata was not preserved: %#v", results[0])
	}
	var hostname, osInfo string
	if err := db.QueryRow("SELECT hostname, os_info FROM hosts WHERE mac = '00:11:22:33:44:55'").Scan(&hostname, &osInfo); err != nil {
		t.Fatal(err)
	}
	if hostname != "known-host" || osInfo != "Known OS" {
		t.Fatalf("stored metadata was overwritten: hostname=%q os=%q", hostname, osInfo)
	}
}

func TestLatestScanMetrics(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(schema); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO scan_history
		(timestamp, duration_seconds, status) VALUES
		('2026-08-22 10:00:00', 12, 'success'),
		('2026-08-22 11:30:45', 34, 'success')`); err != nil {
		t.Fatal(err)
	}
	lastScan, duration, err := LatestScanMetrics(db)
	if err != nil {
		t.Fatal(err)
	}
	if lastScan != "2026-08-22T11:30:45Z" || duration != 34*time.Second {
		t.Fatalf("got lastScan=%q duration=%v", lastScan, duration)
	}
}
