package main

import (
	"database/sql"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/google/uuid"
	_ "modernc.org/sqlite"
)

const schema = `
CREATE TABLE IF NOT EXISTS hosts (
    mac TEXT PRIMARY KEY,
    ip TEXT NOT NULL,
    hostname TEXT,
    custom_name TEXT,
    fingerprint TEXT,
    os_info TEXT,
    acknowledged BOOLEAN DEFAULT FALSE,
    last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    is_randomized BOOLEAN DEFAULT FALSE,
    is_current BOOLEAN DEFAULT FALSE
);

CREATE TABLE IF NOT EXISTS ports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    mac TEXT NOT NULL,
    port INTEGER NOT NULL,
    protocol TEXT NOT NULL,
    service TEXT,
    state TEXT,
    script_data TEXT,
    acknowledged BOOLEAN DEFAULT FALSE,
    last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (mac) REFERENCES hosts(mac),
    UNIQUE(mac, port, protocol)
);

CREATE TABLE IF NOT EXISTS scan_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    duration_seconds INTEGER,
    status TEXT,
    error_message TEXT
);

CREATE TABLE IF NOT EXISTS config (
    key TEXT PRIMARY KEY,
    value TEXT
);
`

const currentSchemaVersion = 2

const scannerIdentitySchema = `
CREATE TABLE scanner_identity (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    scanner_uuid TEXT NOT NULL UNIQUE,
    scanner_name TEXT NOT NULL,
    previous_uuid TEXT,
    uuid_changed_at DATETIME,
    uuid_change_reason TEXT,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);`

type ScannerIdentity struct {
	UUID             string
	Name             string
	PreviousUUID     sql.NullString
	UUIDChangedAt    sql.NullString
	UUIDChangeReason sql.NullString
	CreatedAt        string
	UpdatedAt        string
}

func columnExists(tx *sql.Tx, table string, column string) (bool, error) {
	var exists int
	query := fmt.Sprintf(
		"SELECT count(*) FROM pragma_table_info('%s') WHERE name = ?",
		table,
	)
	if err := tx.QueryRow(query, column).Scan(&exists); err != nil {
		return false, fmt.Errorf("inspect %s.%s: %w", table, column, err)
	}
	return exists > 0, nil
}

func addColumnIfMissing(tx *sql.Tx, table string, column string, definition string) (bool, error) {
	exists, err := columnExists(tx, table, column)
	if err != nil {
		return false, err
	}
	if exists {
		return false, nil
	}
	if _, err := tx.Exec(fmt.Sprintf("ALTER TABLE %s ADD COLUMN %s %s", table, column, definition)); err != nil {
		return false, fmt.Errorf("add %s.%s: %w", table, column, err)
	}
	return true, nil
}

// migrateToVersion1 adopts both new databases and legacy unversioned databases.
// All operations run in the caller's transaction, including the version update.
func migrateToVersion1(tx *sql.Tx) error {
	if _, err := tx.Exec(schema); err != nil {
		return fmt.Errorf("initialize schema: %w", err)
	}

	columns := []struct {
		table      string
		name       string
		definition string
	}{
		{"hosts", "fingerprint", "TEXT"},
		{"hosts", "os_info", "TEXT"},
		{"ports", "script_data", "TEXT"},
		{"hosts", "acknowledged", "BOOLEAN DEFAULT FALSE"},
		{"ports", "acknowledged", "BOOLEAN DEFAULT FALSE"},
		{"hosts", "is_randomized", "BOOLEAN DEFAULT FALSE"},
		{"hosts", "is_current", "BOOLEAN DEFAULT FALSE"},
	}
	for _, column := range columns {
		if _, err := addColumnIfMissing(tx, column.table, column.name, column.definition); err != nil {
			return err
		}
	}

	if _, err := addColumnIfMissing(tx, "hosts", "created_at", "DATETIME"); err != nil {
		return err
	}
	if _, err := tx.Exec("UPDATE hosts SET created_at = last_seen WHERE created_at IS NULL"); err != nil {
		return fmt.Errorf("initialize hosts.created_at: %w", err)
	}

	return nil
}

func initialScannerName(scannerUUID string) string {
	if hostname, err := os.Hostname(); err == nil && strings.TrimSpace(hostname) != "" {
		return strings.TrimSpace(hostname)
	}
	shortUUID := scannerUUID
	if len(shortUUID) > 8 {
		shortUUID = shortUUID[:8]
	}
	return "Fortag " + shortUUID
}

func migrateToVersion2(tx *sql.Tx) error {
	if _, err := tx.Exec(scannerIdentitySchema); err != nil {
		return fmt.Errorf("create scanner_identity: %w", err)
	}
	scannerUUID := uuid.NewString()
	if _, err := tx.Exec(
		"INSERT INTO scanner_identity (id, scanner_uuid, scanner_name) VALUES (1, ?, ?)",
		scannerUUID,
		initialScannerName(scannerUUID),
	); err != nil {
		return fmt.Errorf("initialize scanner identity: %w", err)
	}
	return nil
}

func getScannerIdentity(db *sql.DB) (ScannerIdentity, error) {
	var identity ScannerIdentity
	err := db.QueryRow(`SELECT scanner_uuid, scanner_name, previous_uuid,
		uuid_changed_at, uuid_change_reason, created_at, updated_at
		FROM scanner_identity WHERE id = 1`).Scan(
		&identity.UUID,
		&identity.Name,
		&identity.PreviousUUID,
		&identity.UUIDChangedAt,
		&identity.UUIDChangeReason,
		&identity.CreatedAt,
		&identity.UpdatedAt,
	)
	if err != nil {
		return ScannerIdentity{}, fmt.Errorf("read scanner identity: %w", err)
	}
	return identity, nil
}

func replaceScannerUUID(db *sql.DB, reason string) (ScannerIdentity, error) {
	tx, err := db.Begin()
	if err != nil {
		return ScannerIdentity{}, fmt.Errorf("begin scanner UUID replacement: %w", err)
	}
	defer tx.Rollback()

	var oldUUID string
	if err := tx.QueryRow("SELECT scanner_uuid FROM scanner_identity WHERE id = 1").Scan(&oldUUID); err != nil {
		return ScannerIdentity{}, fmt.Errorf("read current scanner UUID: %w", err)
	}
	newUUID := uuid.NewString()
	if _, err := tx.Exec(`UPDATE scanner_identity
		SET scanner_uuid = ?, previous_uuid = ?, uuid_changed_at = CURRENT_TIMESTAMP,
			uuid_change_reason = ?, updated_at = CURRENT_TIMESTAMP
		WHERE id = 1`, newUUID, oldUUID, reason); err != nil {
		return ScannerIdentity{}, fmt.Errorf("replace scanner UUID: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return ScannerIdentity{}, fmt.Errorf("commit scanner UUID replacement: %w", err)
	}
	return getScannerIdentity(db)
}

func renameScanner(db *sql.DB, name string) (ScannerIdentity, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return ScannerIdentity{}, errors.New("scanner name cannot be empty")
	}
	if len(name) > 128 {
		return ScannerIdentity{}, errors.New("scanner name cannot exceed 128 bytes")
	}
	result, err := db.Exec(`UPDATE scanner_identity
		SET scanner_name = ?, updated_at = CURRENT_TIMESTAMP WHERE id = 1`, name)
	if err != nil {
		return ScannerIdentity{}, fmt.Errorf("rename scanner: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return ScannerIdentity{}, fmt.Errorf("inspect scanner rename: %w", err)
	}
	if rows != 1 {
		return ScannerIdentity{}, errors.New("scanner identity row is missing")
	}
	return getScannerIdentity(db)
}

func migrateSchema(db *sql.DB) error {
	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("begin schema migration: %w", err)
	}
	defer tx.Rollback()

	var version int
	if err := tx.QueryRow("PRAGMA user_version").Scan(&version); err != nil {
		return fmt.Errorf("read schema version: %w", err)
	}
	if version > currentSchemaVersion {
		return fmt.Errorf(
			"database schema version %d is newer than supported version %d",
			version,
			currentSchemaVersion,
		)
	}

	if version < 1 {
		log.Printf("Migrating unversioned database schema to version %d", currentSchemaVersion)
		if err := migrateToVersion1(tx); err != nil {
			return fmt.Errorf("migrate schema from version %d to 1: %w", version, err)
		}
		if _, err := tx.Exec("PRAGMA user_version = 1"); err != nil {
			return fmt.Errorf("record schema version 1: %w", err)
		}
		version = 1
	}

	if version < 2 {
		log.Println("Migrating database schema from version 1 to 2")
		if err := migrateToVersion2(tx); err != nil {
			return fmt.Errorf("migrate schema from version 1 to 2: %w", err)
		}
		if _, err := tx.Exec("PRAGMA user_version = 2"); err != nil {
			return fmt.Errorf("record schema version 2: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit schema migration: %w", err)
	}
	log.Printf("Database schema is at version %d", currentSchemaVersion)
	return nil
}

func initDB(dbPath string) (*sql.DB, error) {
	dsn := fmt.Sprintf("file:%s?_pragma=busy_timeout(5000)", dbPath)
	log.Printf("DEBUG: Opening SQLite connection (DSN: %s)", dsn)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}
	log.Println("DEBUG: SQLite connection opened successfully")

	if err := migrateSchema(db); err != nil {
		db.Close()
		return nil, err
	}

	return db, nil
}

func openReadOnlyDB(dbPath string) (*sql.DB, error) {
	dsn := fmt.Sprintf("file:%s?mode=ro&_pragma=busy_timeout(5000)", dbPath)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open database read-only: %w", err)
	}
	var version int
	if err := db.QueryRow("PRAGMA user_version").Scan(&version); err != nil {
		db.Close()
		return nil, fmt.Errorf("read schema version: %w", err)
	}
	if version > currentSchemaVersion {
		db.Close()
		return nil, fmt.Errorf(
			"database schema version %d is newer than supported version %d",
			version,
			currentSchemaVersion,
		)
	}
	return db, nil
}
