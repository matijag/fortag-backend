package main

import (
	"database/sql"
	"path/filepath"
	"strings"
	"testing"
)

const legacySchema = `
CREATE TABLE hosts (
    mac TEXT PRIMARY KEY,
    ip TEXT NOT NULL,
    hostname TEXT,
    custom_name TEXT,
    last_seen DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE ports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    mac TEXT NOT NULL,
    port INTEGER NOT NULL,
    protocol TEXT NOT NULL,
    service TEXT,
    state TEXT,
    last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(mac, port, protocol)
);
`

func TestInitDBAdoptsUnversionedLegacyDatabase(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "legacy.db")
	legacyDB, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := legacyDB.Exec(legacySchema); err != nil {
		t.Fatal(err)
	}
	if _, err := legacyDB.Exec(
		"INSERT INTO hosts (mac, ip, last_seen) VALUES (?, ?, ?)",
		"00:11:22:33:44:55",
		"192.168.1.5",
		"2026-01-02 03:04:05",
	); err != nil {
		t.Fatal(err)
	}
	if err := legacyDB.Close(); err != nil {
		t.Fatal(err)
	}

	db, err := initDB(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	var version int
	if err := db.QueryRow("PRAGMA user_version").Scan(&version); err != nil {
		t.Fatal(err)
	}
	if version != currentSchemaVersion {
		t.Fatalf("schema version = %d, want %d", version, currentSchemaVersion)
	}

	for _, column := range []string{
		"fingerprint", "os_info", "acknowledged", "created_at", "is_randomized", "is_current",
	} {
		var count int
		if err := db.QueryRow(
			"SELECT count(*) FROM pragma_table_info('hosts') WHERE name = ?",
			column,
		).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 1 {
			t.Errorf("hosts.%s was not migrated", column)
		}
	}

	var lastSeen string
	var createdAt string
	if err := db.QueryRow(
		"SELECT last_seen, created_at FROM hosts WHERE mac = ?",
		"00:11:22:33:44:55",
	).Scan(&lastSeen, &createdAt); err != nil {
		t.Fatal(err)
	}
	if createdAt != lastSeen {
		t.Fatalf("created_at = %q, want preserved last_seen %q", createdAt, lastSeen)
	}
	identity, err := getScannerIdentity(db)
	if err != nil {
		t.Fatal(err)
	}
	if identity.UUID == "" || identity.Name == "" {
		t.Fatalf("identity was not initialized: %#v", identity)
	}
}

func TestInitDBRejectsNewerSchemaVersion(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "future.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("PRAGMA user_version = 3"); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	_, err = initDB(dbPath)
	if err == nil {
		t.Fatal("expected a newer schema version to be rejected")
	}
	if !strings.Contains(err.Error(), "newer than supported") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestInitDBMigratesVersion1ToVersion2(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "version-one.db")
	legacyDB, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := legacyDB.Exec(schema); err != nil {
		t.Fatal(err)
	}
	if _, err := legacyDB.Exec("PRAGMA user_version = 1"); err != nil {
		t.Fatal(err)
	}
	if _, err := legacyDB.Exec(
		"INSERT INTO config (key, value) VALUES ('scan_range', '192.168.10.0/24')",
	); err != nil {
		t.Fatal(err)
	}
	if err := legacyDB.Close(); err != nil {
		t.Fatal(err)
	}

	db, err := initDB(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var version int
	if err := db.QueryRow("PRAGMA user_version").Scan(&version); err != nil {
		t.Fatal(err)
	}
	if version != 2 {
		t.Fatalf("schema version = %d, want 2", version)
	}
	if identity, err := getScannerIdentity(db); err != nil || identity.UUID == "" {
		t.Fatalf("version 2 identity missing: %#v, %v", identity, err)
	}
	var scanRange string
	if err := db.QueryRow("SELECT value FROM config WHERE key = 'scan_range'").Scan(&scanRange); err != nil {
		t.Fatal(err)
	}
	if scanRange != "192.168.10.0/24" {
		t.Fatalf("scan range = %q", scanRange)
	}
}

func TestReplaceScannerUUIDPreservesAuditMetadata(t *testing.T) {
	db, err := initDB(filepath.Join(t.TempDir(), "identity.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	before, err := getScannerIdentity(db)
	if err != nil {
		t.Fatal(err)
	}
	after, err := replaceScannerUUID(db, "uuid_collision")
	if err != nil {
		t.Fatal(err)
	}
	if after.UUID == before.UUID {
		t.Fatal("scanner UUID did not change")
	}
	if after.PreviousUUID.String != before.UUID || after.UUIDChangeReason.String != "uuid_collision" {
		t.Fatalf("unexpected audit metadata: %#v", after)
	}
	if !after.UUIDChangedAt.Valid || after.UUIDChangedAt.String == "" {
		t.Fatal("UUID change timestamp was not recorded")
	}
}

func TestRenameScannerPersistsName(t *testing.T) {
	db, err := initDB(filepath.Join(t.TempDir(), "identity.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	identity, err := renameScanner(db, "  Upstairs scanner  ")
	if err != nil {
		t.Fatal(err)
	}
	if identity.Name != "Upstairs scanner" {
		t.Fatalf("scanner name = %q", identity.Name)
	}
	if _, err := renameScanner(db, "   "); err == nil {
		t.Fatal("empty scanner name was accepted")
	}
}

func TestDatabaseLocks(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "scanner.db")
	sharedOne, err := acquireDatabaseLock(dbPath, true)
	if err != nil {
		t.Fatal(err)
	}
	defer sharedOne.Close()
	sharedTwo, err := acquireDatabaseLock(dbPath, true)
	if err != nil {
		t.Fatalf("second shared lock failed: %v", err)
	}
	defer sharedTwo.Close()
	if exclusive, err := acquireDatabaseLock(dbPath, false); err == nil {
		exclusive.Close()
		t.Fatal("exclusive lock unexpectedly succeeded while shared locks were held")
	}
	if err := sharedOne.Close(); err != nil {
		t.Fatal(err)
	}
	if err := sharedTwo.Close(); err != nil {
		t.Fatal(err)
	}
	exclusive, err := acquireDatabaseLock(dbPath, false)
	if err != nil {
		t.Fatalf("exclusive lock failed after shared locks were released: %v", err)
	}
	defer exclusive.Close()
	if second, err := acquireDatabaseLock(dbPath, false); err == nil {
		second.Close()
		t.Fatal("second exclusive lock unexpectedly succeeded")
	}
}

func TestInitDBIsIdempotentAtCurrentSchemaVersion(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "current.db")
	db, err := initDB(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(
		`INSERT INTO hosts (
			mac, ip, hostname, custom_name, fingerprint, os_info,
			acknowledged, last_seen, created_at, is_randomized, is_current
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"00:11:22:33:44:55",
		"192.168.1.5",
		"host-one",
		"Office host",
		"fingerprint-one",
		"Linux",
		true,
		"2026-01-02 03:04:05",
		"2025-12-01 02:03:04",
		false,
		true,
	); err != nil {
		t.Fatal(err)
	}

	var schemaRevisionBefore int
	if err := db.QueryRow("PRAGMA schema_version").Scan(&schemaRevisionBefore); err != nil {
		t.Fatal(err)
	}
	var customNameBefore string
	var createdAtBefore string
	var isCurrentBefore bool
	if err := db.QueryRow(
		"SELECT custom_name, created_at, is_current FROM hosts WHERE mac = ?",
		"00:11:22:33:44:55",
	).Scan(&customNameBefore, &createdAtBefore, &isCurrentBefore); err != nil {
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

	var schemaRevisionAfter int
	if err := db.QueryRow("PRAGMA schema_version").Scan(&schemaRevisionAfter); err != nil {
		t.Fatal(err)
	}
	if schemaRevisionAfter != schemaRevisionBefore {
		t.Fatalf(
			"SQLite schema revision changed on reopen: %d -> %d",
			schemaRevisionBefore,
			schemaRevisionAfter,
		)
	}

	var userVersion int
	if err := db.QueryRow("PRAGMA user_version").Scan(&userVersion); err != nil {
		t.Fatal(err)
	}
	if userVersion != currentSchemaVersion {
		t.Fatalf("schema version = %d, want %d", userVersion, currentSchemaVersion)
	}

	var customName string
	var createdAt string
	var isCurrent bool
	if err := db.QueryRow(
		"SELECT custom_name, created_at, is_current FROM hosts WHERE mac = ?",
		"00:11:22:33:44:55",
	).Scan(&customName, &createdAt, &isCurrent); err != nil {
		t.Fatal(err)
	}
	if customName != customNameBefore || createdAt != createdAtBefore || isCurrent != isCurrentBefore {
		t.Fatalf(
			"host changed on reopen: before=(%q, %q, %v), after=(%q, %q, %v)",
			customNameBefore,
			createdAtBefore,
			isCurrentBefore,
			customName,
			createdAt,
			isCurrent,
		)
	}
}
