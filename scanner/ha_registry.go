package main

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/google/uuid"
)

const (
	maxHARegistryPayloadBytes = 128 * 1024
	maxHARegistryDevices      = 256
	maxHARegistryAddresses    = 8
)

type HARegistryDevice struct {
	DeviceID     string   `json:"device_id"`
	Name         string   `json:"name"`
	Manufacturer string   `json:"manufacturer,omitempty"`
	Model        string   `json:"model,omitempty"`
	MACAddresses []string `json:"mac_addresses,omitempty"`
	IPAddresses  []string `json:"ip_addresses,omitempty"`
}

type HARegistrySnapshot struct {
	SchemaVersion int                `json:"schema_version"`
	ScannerUUID   string             `json:"scanner_uuid"`
	Revision      string             `json:"revision"`
	Devices       []HARegistryDevice `json:"devices"`
}

func validateHARegistrySnapshot(snapshot *HARegistrySnapshot, scannerUUID string) error {
	if snapshot.SchemaVersion != 1 || snapshot.ScannerUUID != scannerUUID {
		return errors.New("Home Assistant registry identity or schema does not match this scanner")
	}
	if _, err := uuid.Parse(snapshot.Revision); err != nil {
		return errors.New("Home Assistant registry revision is invalid")
	}
	if len(snapshot.Devices) > maxHARegistryDevices {
		return fmt.Errorf("Home Assistant registry exceeds %d devices", maxHARegistryDevices)
	}
	for index := range snapshot.Devices {
		device := &snapshot.Devices[index]
		device.DeviceID = strings.TrimSpace(device.DeviceID)
		if device.DeviceID == "" || len(device.DeviceID) > 128 {
			return errors.New("Home Assistant registry device ID is invalid")
		}
		for _, value := range []*string{&device.Name, &device.Manufacturer, &device.Model} {
			_, display, err := normalizeIdentityValue(*value)
			if *value != "" && err != nil {
				return fmt.Errorf("Home Assistant registry device %s contains invalid identity text", device.DeviceID)
			}
			*value = display
		}
		if device.Name == "" || len(device.MACAddresses) > maxHARegistryAddresses || len(device.IPAddresses) > maxHARegistryAddresses {
			return fmt.Errorf("Home Assistant registry device %s is incomplete or exceeds address limits", device.DeviceID)
		}
		for addressIndex, mac := range device.MACAddresses {
			parsed, err := net.ParseMAC(mac)
			if err != nil || len(parsed) != 6 {
				return fmt.Errorf("Home Assistant registry device %s has an invalid MAC", device.DeviceID)
			}
			device.MACAddresses[addressIndex] = strings.ToUpper(parsed.String())
		}
		for _, ip := range device.IPAddresses {
			if net.ParseIP(ip) == nil || strings.Contains(ip, ":") || ValidateScanTarget(ip) != nil {
				return fmt.Errorf("Home Assistant registry device %s has an invalid IPv4 address", device.DeviceID)
			}
		}
		if len(device.MACAddresses) == 0 && len(device.IPAddresses) == 0 {
			return fmt.Errorf("Home Assistant registry device %s has no correlation address", device.DeviceID)
		}
	}
	return nil
}

type haRegistryMatch struct {
	device    HARegistryDevice
	mac       string
	address   string
	matchKind string
}

func matchHARegistryDevice(tx *sql.Tx, device HARegistryDevice) (haRegistryMatch, error) {
	for _, mac := range device.MACAddresses {
		var storedMAC, address string
		err := tx.QueryRow("SELECT mac, ip FROM hosts WHERE mac = ?", mac).Scan(&storedMAC, &address)
		if err == nil {
			return haRegistryMatch{device: device, mac: storedMAC, address: address, matchKind: "mac"}, nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return haRegistryMatch{}, err
		}
	}
	for _, address := range device.IPAddresses {
		rows, err := tx.Query(`SELECT mac FROM hosts WHERE ip = ? AND is_current = 1
			ORDER BY last_seen DESC LIMIT 2`, address)
		if err != nil {
			return haRegistryMatch{}, err
		}
		var matches []string
		for rows.Next() {
			var mac string
			if err := rows.Scan(&mac); err != nil {
				rows.Close()
				return haRegistryMatch{}, err
			}
			matches = append(matches, mac)
		}
		if err := rows.Close(); err != nil {
			return haRegistryMatch{}, err
		}
		if len(matches) == 1 {
			return haRegistryMatch{device: device, mac: matches[0], address: address, matchKind: "ip"}, nil
		}
	}
	return haRegistryMatch{}, nil
}

func applyHARegistrySnapshot(db *sql.DB, snapshot HARegistrySnapshot, now time.Time) error {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if _, err := tx.Exec("UPDATE identity_observations SET active = 0 WHERE source = 'home_assistant'"); err != nil {
		return fmt.Errorf("deactivate old Home Assistant observations: %w", err)
	}
	matchedMACs := make(map[string]bool)
	for _, device := range snapshot.Devices {
		match, err := matchHARegistryDevice(tx, device)
		if err != nil {
			return fmt.Errorf("match Home Assistant device %s: %w", device.DeviceID, err)
		}
		if match.mac == "" {
			continue
		}
		matchedMACs[match.mac] = true
		stability, confidence := "stable", 100
		var expiresAt any
		if match.matchKind == "ip" {
			stability, confidence = "transient", 85
			expiresAt = now.Add(24 * time.Hour)
		}
		evidence, _ := json.Marshal(map[string]string{"device_id": device.DeviceID, "match": match.matchKind})
		values := []struct{ kind, value string }{
			{"friendly_name", device.Name}, {"manufacturer", device.Manufacturer}, {"model", device.Model},
		}
		for _, value := range values {
			if value.value == "" {
				continue
			}
			normalized, display, _ := normalizeIdentityValue(value.value)
			if _, err := tx.Exec(`INSERT INTO identity_observations (
				mac, source, kind, normalized_value, display_value, confidence, stability,
				evidence_json, observed_address, collection_run, first_seen, last_seen,
				expires_at, active
			) VALUES (?, 'home_assistant', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
			ON CONFLICT(mac, source, kind, normalized_value) DO UPDATE SET
				display_value = excluded.display_value, confidence = excluded.confidence,
				stability = excluded.stability, evidence_json = excluded.evidence_json,
				observed_address = excluded.observed_address,
				collection_run = excluded.collection_run, last_seen = excluded.last_seen,
				expires_at = excluded.expires_at, active = 1`, match.mac, value.kind,
				normalized, display, confidence, stability, string(evidence),
				nullableString(match.address), snapshot.Revision, now.UTC(), now.UTC(), expiresAt); err != nil {
				return fmt.Errorf("store Home Assistant observation: %w", err)
			}
		}
	}
	for mac := range matchedMACs {
		if _, err := tx.Exec(`DELETE FROM identity_observations WHERE id IN (
			SELECT id FROM identity_observations WHERE mac = ?
			ORDER BY active DESC, confidence DESC, last_seen DESC, id DESC
			LIMIT -1 OFFSET ?
		)`, mac, maxIdentityObservations); err != nil {
			return fmt.Errorf("bound Home Assistant observations: %w", err)
		}
	}
	return tx.Commit()
}
