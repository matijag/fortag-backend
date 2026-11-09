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

	mockRun := EngineScanResult{
		Hosts: []ObservedHost{
			{
				MAC: "00:11:22:33:44:55", IP: "192.168.1.50",
				Ports: []ObservedPort{
					{Port: 80, Protocol: "tcp", State: "open", Service: "http"},
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
	mockRun.Hosts[0].Ports = append(mockRun.Hosts[0].Ports, ObservedPort{
		Port: 443, Protocol: "tcp", State: "open", Service: "https",
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
	mockRun.Hosts[0].Ports = []ObservedPort{
		{Port: 443, Protocol: "tcp", State: "closed", Service: "https"},
		{Port: 22, Protocol: "tcp", State: "filtered", Service: "ssh"},
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
	mockRun.Hosts[0].Ports = []ObservedPort{
		{Port: 80, Protocol: "tcp", State: "open", Service: "http"},
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
	openOnly := []ObservedPort{{Port: 80, Protocol: "tcp", State: "open"}}
	withClosed := append(append([]ObservedPort{}, openOnly...),
		ObservedPort{Port: 22, Protocol: "tcp", State: "closed"},
		ObservedPort{Port: 443, Protocol: "tcp", State: "filtered"},
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

	run := EngineScanResult{Hosts: []ObservedHost{{
		MAC: "00:11:22:33:44:55", IP: "192.168.1.50",
	}}}
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

func TestProcessScanClearsMetadataUnavailableFromEngine(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(schema); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO hosts (mac, ip, hostname, os_info)
		VALUES ('00:11:22:33:44:55', '192.168.1.50', 'stale-nmap-host', 'Stale Nmap OS')`); err != nil {
		t.Fatal(err)
	}

	results, err := ProcessScan(db, EngineScanResult{Hosts: []ObservedHost{{
		MAC: "00:11:22:33:44:55", IP: "192.168.1.50", ClearMissingMetadata: true,
	}}})
	if err != nil {
		t.Fatal(err)
	}
	if results[0].Hostname != "" || results[0].OS != "" {
		t.Fatalf("stale metadata was published: %#v", results[0])
	}
	var hostname, osInfo string
	if err := db.QueryRow("SELECT hostname, os_info FROM hosts WHERE mac = '00:11:22:33:44:55'").Scan(&hostname, &osInfo); err != nil {
		t.Fatal(err)
	}
	if hostname != "" || osInfo != "" {
		t.Fatalf("stale metadata was retained: hostname=%q os=%q", hostname, osInfo)
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
		('2026-08-22 11:30:45', 34, 'success'),
		('2026-08-22 12:00:00', 50, 'partial'),
		('2026-08-22 12:30:00', 3, 'failed')`); err != nil {
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
