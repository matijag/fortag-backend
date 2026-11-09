package main

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	_ "modernc.org/sqlite"
)

func TestSafeScanFailureDoesNotExposeRawError(t *testing.T) {
	report := safeScanFailure("discovery", &EngineError{
		Kind: EngineErrorStart,
		Err:  errors.New("secret filesystem path and broker address"),
	})
	if report.code != "discovery_unavailable" || report.message != "Host discovery could not start" {
		t.Fatalf("unexpected report: %#v", report)
	}
	if strings.Contains(report.detail, "secret") {
		t.Fatalf("raw error leaked into report: %#v", report)
	}

	timeout := safeScanFailure("port_scan", context.DeadlineExceeded)
	if timeout.code != "port_scan_timeout" {
		t.Fatalf("timeout report = %#v", timeout)
	}
}

func TestGetCurrentRangeFallsBackWithoutPersistingAndReadsSQLite(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(schema); err != nil {
		t.Fatal(err)
	}

	got, err := getCurrentRange(db, "192.168.1.0/24")
	if err != nil || got != "192.168.1.0/24" {
		t.Fatalf("fallback range = %q, %v", got, err)
	}
	var count int
	if err := db.QueryRow("SELECT count(*) FROM config WHERE key = 'scan_range'").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatal("auto-detected fallback was unexpectedly persisted")
	}
	if _, err := db.Exec("INSERT INTO config (key, value) VALUES ('scan_range', '10.0.0.0/24')"); err != nil {
		t.Fatal(err)
	}
	got, err = getCurrentRange(db, "192.168.1.0/24")
	if err != nil || got != "10.0.0.0/24" {
		t.Fatalf("persisted range = %q, %v", got, err)
	}
	if _, err := db.Exec("UPDATE config SET value = '8.8.8.8' WHERE key = 'scan_range'"); err != nil {
		t.Fatal(err)
	}
	if _, err := getCurrentRange(db, "192.168.1.0/24"); err == nil {
		t.Fatal("expected an invalid persisted range to be rejected")
	}
}

func TestConfigureScanRangeCanPersistAndReturnToAutoDetection(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(schema); err != nil {
		t.Fatal(err)
	}

	got, automatic, err := configureScanRange(db, " 10.20.0.0/16 ", func() (string, error) {
		return "192.168.50.0/24", nil
	})
	if err != nil || automatic || got != "10.20.0.0/16" {
		t.Fatalf("configured range = %q, automatic=%v, err=%v", got, automatic, err)
	}
	got, automatic, err = configureScanRange(db, "", func() (string, error) {
		return "192.168.50.0/24", nil
	})
	if err != nil || !automatic || got != "192.168.50.0/24" {
		t.Fatalf("auto range = %q, automatic=%v, err=%v", got, automatic, err)
	}
	var count int
	if err := db.QueryRow("SELECT count(*) FROM config WHERE key = 'scan_range'").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatal("persisted override was not removed")
	}
}

func TestConfigureScanRangePreservesOverrideWhenDetectionFails(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(schema); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("INSERT INTO config (key, value) VALUES ('scan_range', '10.0.0.0/24')"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := configureScanRange(db, "", func() (string, error) {
		return "", errors.New("no suitable interface")
	}); err == nil || !strings.Contains(err.Error(), "cannot enable automatic") {
		t.Fatalf("unexpected error: %v", err)
	}
	got, err := getCurrentRange(db, "192.168.1.0/24")
	if err != nil || got != "10.0.0.0/24" {
		t.Fatalf("override was changed after detection failure: %q, %v", got, err)
	}
}

func TestSecurityAlerts(t *testing.T) {
	results := []ScanResult{{
		MAC: "00:11:22:33:44:55", IP: "192.168.1.5", CustomName: "Office Printer", IsNewHost: true,
		Ports: []PortResult{{Port: 80, Protocol: "tcp", IsNew: true}, {Port: 22, Protocol: "tcp"}},
	}, {
		MAC: "02:11:22:33:44:66", IP: "192.168.1.6", MatchedFrom: "02:11:22:33:44:55",
		Ports: []PortResult{{Port: 443, Protocol: "tcp"}},
	}}

	alerts := securityAlerts(results)
	if len(alerts) != 2 {
		t.Fatalf("got %d alerts, want 2", len(alerts))
	}
	if alerts[0].alertType != "new_host" || alerts[0].extra["ip"] != "192.168.1.5" {
		t.Errorf("unexpected host alert: %#v", alerts[0])
	}
	if alerts[1].alertType != "new_port" || alerts[1].extra["port"] != 80 {
		t.Errorf("unexpected port alert: %#v", alerts[1])
	}
	for _, alert := range alerts {
		if alert.extra["custom_name"] != "Office Printer" {
			t.Errorf("alert custom name = %v, want Office Printer", alert.extra["custom_name"])
		}
	}
}

func TestGetAllScanResultsPublishesOnlyOpenPorts(t *testing.T) {
	db, err := initDB(filepath.Join(t.TempDir(), "open-ports.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`INSERT INTO hosts (mac, ip) VALUES ('00:11:22:33:44:55', '192.168.1.5');
		INSERT INTO ports (mac, port, protocol, service, state) VALUES
		('00:11:22:33:44:55', 80, 'tcp', 'http', 'open'),
		('00:11:22:33:44:55', 22, 'tcp', 'ssh', 'closed'),
		('00:11:22:33:44:55', 443, 'tcp', 'https', 'filtered')`); err != nil {
		t.Fatal(err)
	}
	results, err := getAllScanResults(db)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 || len(results[0].Ports) != 1 || results[0].Ports[0].Port != 80 {
		t.Fatalf("published ports = %#v, want only 80/tcp open", results)
	}
}

func TestSetCurrentHostsReplacesPreviousSelection(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(schema); err != nil {
		t.Fatal(err)
	}

	if _, err := db.Exec(`INSERT INTO hosts (mac, ip, is_current) VALUES
		('00:11:22:33:44:55', '192.168.1.5', TRUE),
		('00:11:22:33:44:66', '192.168.1.6', FALSE),
		('00:11:22:33:44:77', '192.168.1.7', TRUE)`); err != nil {
		t.Fatal(err)
	}

	if err := setCurrentHosts(db, []string{"00:11:22:33:44:66"}); err != nil {
		t.Fatal(err)
	}

	rows, err := db.Query("SELECT ip, is_current FROM hosts ORDER BY ip")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()

	want := map[string]bool{
		"192.168.1.5": false,
		"192.168.1.6": true,
		"192.168.1.7": false,
	}
	for rows.Next() {
		var ip string
		var current bool
		if err := rows.Scan(&ip, &current); err != nil {
			t.Fatal(err)
		}
		if current != want[ip] {
			t.Errorf("current state for %s = %v, want %v", ip, current, want[ip])
		}
		delete(want, ip)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if len(want) != 0 {
		t.Fatalf("missing host rows: %v", want)
	}
}
