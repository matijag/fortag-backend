package main

import (
	"path/filepath"
	"testing"
	"time"
)

func TestHARegistrySnapshotCorrelatesMACBeforeIPAndConverges(t *testing.T) {
	db, err := initDB(filepath.Join(t.TempDir(), "ha-registry.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`INSERT INTO hosts (mac, ip, is_current) VALUES
		('00:11:22:33:44:55', '192.168.1.20', 1),
		('00:11:22:33:44:66', '192.168.1.30', 1)`); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	snapshot := HARegistrySnapshot{
		SchemaVersion: 1, ScannerUUID: "scanner", Revision: "88bfc372-67ef-4ec5-a257-388d0bb3f1da",
		Devices: []HARegistryDevice{
			{DeviceID: "printer", Name: "Office Printer", Manufacturer: "Example", MACAddresses: []string{"00:11:22:33:44:55"}, IPAddresses: []string{"192.168.1.30"}},
			{DeviceID: "speaker", Name: "Kitchen Speaker", IPAddresses: []string{"192.168.1.30"}},
		},
	}
	if err := validateHARegistrySnapshot(&snapshot, "scanner"); err != nil {
		t.Fatal(err)
	}
	if err := applyHARegistrySnapshot(db, snapshot, now); err != nil {
		t.Fatal(err)
	}
	var value, stability string
	if err := db.QueryRow(`SELECT display_value, stability FROM identity_observations
		WHERE mac = '00:11:22:33:44:55' AND source = 'home_assistant'
		AND kind = 'friendly_name' AND active = 1`).Scan(&value, &stability); err != nil {
		t.Fatal(err)
	}
	if value != "Office Printer" || stability != "stable" {
		t.Fatalf("MAC observation = %q/%q", value, stability)
	}
	selected, err := selectDisplayIdentity(db, "00:11:22:33:44:55", now)
	if err != nil {
		t.Fatal(err)
	}
	if selected.Value != "Office Printer" || selected.Source != "home_assistant" {
		t.Fatalf("selected Home Assistant identity = %#v", selected)
	}
	if err := db.QueryRow(`SELECT display_value, stability FROM identity_observations
		WHERE mac = '00:11:22:33:44:66' AND source = 'home_assistant'
		AND kind = 'friendly_name' AND active = 1`).Scan(&value, &stability); err != nil {
		t.Fatal(err)
	}
	if value != "Kitchen Speaker" || stability != "transient" {
		t.Fatalf("IP observation = %q/%q", value, stability)
	}

	empty := HARegistrySnapshot{SchemaVersion: 1, ScannerUUID: "scanner", Revision: "82556448-a00b-44e9-b9b7-b0f10df67d48"}
	if err := applyHARegistrySnapshot(db, empty, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	var active int
	if err := db.QueryRow("SELECT count(*) FROM identity_observations WHERE source = 'home_assistant' AND active = 1").Scan(&active); err != nil {
		t.Fatal(err)
	}
	if active != 0 {
		t.Fatalf("active Home Assistant observations after empty snapshot = %d", active)
	}
}

func TestHARegistrySnapshotRejectsUnsafeOrOversizedInput(t *testing.T) {
	tests := []HARegistrySnapshot{
		{SchemaVersion: 2, ScannerUUID: "scanner", Revision: "88bfc372-67ef-4ec5-a257-388d0bb3f1da"},
		{SchemaVersion: 1, ScannerUUID: "other", Revision: "88bfc372-67ef-4ec5-a257-388d0bb3f1da"},
		{SchemaVersion: 1, ScannerUUID: "scanner", Revision: "invalid"},
		{SchemaVersion: 1, ScannerUUID: "scanner", Revision: "88bfc372-67ef-4ec5-a257-388d0bb3f1da", Devices: []HARegistryDevice{{DeviceID: "device", Name: "Name", IPAddresses: []string{"8.8.8.8"}}}},
	}
	for index := range tests {
		if err := validateHARegistrySnapshot(&tests[index], "scanner"); err == nil {
			t.Errorf("case %d was accepted", index)
		}
	}
}

func TestHARegistrySnapshotDoesNotGuessSharedCurrentIP(t *testing.T) {
	db, err := initDB(filepath.Join(t.TempDir(), "ha-shared-ip.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`INSERT INTO hosts (mac, ip, is_current) VALUES
		('00:11:22:33:44:55', '192.168.1.20', 1),
		('00:11:22:33:44:66', '192.168.1.20', 1)`); err != nil {
		t.Fatal(err)
	}
	snapshot := HARegistrySnapshot{
		SchemaVersion: 1, ScannerUUID: "scanner", Revision: "88bfc372-67ef-4ec5-a257-388d0bb3f1da",
		Devices: []HARegistryDevice{{DeviceID: "shared", Name: "Ambiguous", IPAddresses: []string{"192.168.1.20"}}},
	}
	if err := applyHARegistrySnapshot(db, snapshot, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := db.QueryRow("SELECT count(*) FROM identity_observations WHERE source = 'home_assistant'").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("stored %d observations for an ambiguous IP", count)
	}
}
