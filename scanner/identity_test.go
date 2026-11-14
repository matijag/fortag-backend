package main

import (
	"database/sql"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func identityTestDB(t *testing.T) (*sql.DB, string) {
	t.Helper()
	db, err := initDB(filepath.Join(t.TempDir(), "identity-observations.db"))
	if err != nil {
		t.Fatal(err)
	}
	mac := "00:11:22:33:44:55"
	if _, err := db.Exec("INSERT INTO hosts (mac, ip) VALUES (?, ?)", mac, "192.168.1.5"); err != nil {
		db.Close()
		t.Fatal(err)
	}
	return db, mac
}

func TestIdentityObservationValidationAndUpsert(t *testing.T) {
	db, mac := identityTestDB(t)
	defer db.Close()
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	observation := IdentityObservation{
		MAC: mac, Source: "mdns", Kind: "friendly_name", Value: "  Office   Printer  ",
		Confidence: 80, Stability: "transient", EvidenceJSON: `{"service":"_ipp._tcp"}`,
	}
	if err := upsertIdentityObservation(db, observation, now); err != nil {
		t.Fatal(err)
	}
	observation.Value = "Office Printer"
	observation.Confidence = 90
	if err := upsertIdentityObservation(db, observation, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	var count, confidence int
	var normalized, display, firstSeen, lastSeen string
	var expiresAt sql.NullString
	if err := db.QueryRow(`SELECT count(*), confidence, normalized_value,
		display_value, first_seen, last_seen, expires_at
		FROM identity_observations WHERE mac = ?`, mac).Scan(
		&count, &confidence, &normalized, &display, &firstSeen, &lastSeen, &expiresAt,
	); err != nil {
		t.Fatal(err)
	}
	if count != 1 || confidence != 90 || normalized != "office printer" || display != "Office Printer" {
		t.Fatalf("unexpected upsert result: count=%d confidence=%d normalized=%q display=%q", count, confidence, normalized, display)
	}
	if firstSeen == lastSeen || !expiresAt.Valid {
		t.Fatalf("timestamps/expiry were not preserved and refreshed: first=%q last=%q expiry=%q", firstSeen, lastSeen, expiresAt.String)
	}

	bad := observation
	bad.Source = "unknown"
	if err := upsertIdentityObservation(db, bad, now); err == nil {
		t.Fatal("unknown source was accepted")
	}
	bad = observation
	bad.EvidenceJSON = "not-json"
	if err := upsertIdentityObservation(db, bad, now); err == nil {
		t.Fatal("invalid evidence JSON was accepted")
	}
}

func TestIdentityExpirySelectionAndCustomNamePriority(t *testing.T) {
	db, mac := identityTestDB(t)
	defer db.Close()
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	expired := now.Add(-time.Minute)
	for _, observation := range []IdentityObservation{
		{MAC: mac, Source: "nmap", Kind: "hostname", Value: "legacy-host", Confidence: 90, Stability: "transient", ExpiresAt: &expired},
		{MAC: mac, Source: "mdns", Kind: "friendly_name", Value: "Kitchen Speaker", Confidence: 70, Stability: "transient"},
		{MAC: mac, Source: "home_assistant", Kind: "friendly_name", Value: "HA Speaker", Confidence: 100, Stability: "stable"},
	} {
		if err := upsertIdentityObservation(db, observation, now); err != nil {
			t.Fatal(err)
		}
	}
	if expiredCount, err := expireIdentityObservations(db, now); err != nil || expiredCount != 1 {
		t.Fatalf("expired=%d err=%v", expiredCount, err)
	}
	selected, err := selectDisplayIdentity(db, mac, now)
	if err != nil {
		t.Fatal(err)
	}
	if selected.Value != "HA Speaker" || selected.Source != "home_assistant" {
		t.Fatalf("selected identity = %#v", selected)
	}
	if _, err := db.Exec("UPDATE hosts SET custom_name = 'My speaker' WHERE mac = ?", mac); err != nil {
		t.Fatal(err)
	}
	selected, err = selectDisplayIdentity(db, mac, now)
	if err != nil || selected.Value != "My speaker" || selected.Source != "user" {
		t.Fatalf("custom identity = %#v, %v", selected, err)
	}
}

func TestIdentityObservationPerHostBound(t *testing.T) {
	db, mac := identityTestDB(t)
	defer db.Close()
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	for i := 0; i < maxIdentityObservations+5; i++ {
		observation := IdentityObservation{
			MAC: mac, Source: "mdns", Kind: "service", Value: strings.Repeat("x", i+1),
			Confidence: i % 100, Stability: "transient",
		}
		if err := upsertIdentityObservation(db, observation, now.Add(time.Duration(i)*time.Second)); err != nil {
			t.Fatal(err)
		}
	}
	var count int
	if err := db.QueryRow("SELECT count(*) FROM identity_observations WHERE mac = ?", mac).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != maxIdentityObservations {
		t.Fatalf("observation count = %d, want %d", count, maxIdentityObservations)
	}
}

func TestVersion3MigrationSeedsLegacyHostnameAndDumpIncludesObservations(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "version-two.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(schema + scannerIdentitySchema); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO scanner_identity (id, scanner_uuid, scanner_name)
		VALUES (1, '00000000-0000-4000-8000-000000000001', 'test')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO hosts (mac, ip, hostname)
		VALUES ('00:11:22:33:44:55', '192.168.1.5', 'Legacy Host')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("PRAGMA user_version = 2"); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	db, err = initDB(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var source, normalized string
	if err := db.QueryRow("SELECT source, normalized_value FROM identity_observations").Scan(&source, &normalized); err != nil {
		t.Fatal(err)
	}
	if source != "nmap" || normalized != "legacy host" {
		t.Fatalf("seeded observation = %q/%q", source, normalized)
	}
	var output strings.Builder
	if err := DumpDatabase(db, &output); err != nil {
		t.Fatal(err)
	}
	var dump []map[string]any
	if err := json.Unmarshal([]byte(output.String()), &dump); err != nil {
		t.Fatal(err)
	}
	if observations, ok := dump[0]["identity_observations"].([]any); !ok || len(observations) != 1 {
		t.Fatalf("dump omitted observations: %s", output.String())
	}
}
