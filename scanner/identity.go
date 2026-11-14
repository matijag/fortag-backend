package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	maxIdentityValueBytes    = 256
	maxIdentityEvidenceBytes = 2048
	maxIdentityObservations  = 64
	maxPublishedObservations = 16
	maxPendingObservations   = 256
)

var identitySources = map[string]bool{
	"nmap": true, "mac_vendor": true, "mdns": true, "ssdp": true,
	"home_assistant": true, "tls": true, "http": true, "ipp": true,
	"smb": true, "llmnr": true, "nbns": true, "dhcp": true,
	"ipv6_ndp": true,
}

var identityKinds = map[string]bool{
	"hostname": true, "friendly_name": true, "manufacturer": true,
	"model": true, "device_type": true, "service": true, "address": true,
}

var transientIdentityTTL = map[string]time.Duration{
	"nmap": 30 * 24 * time.Hour, "mdns": 24 * time.Hour,
	"ssdp": 24 * time.Hour, "tls": 7 * 24 * time.Hour,
	"http": 24 * time.Hour, "ipp": 24 * time.Hour,
	"smb": 24 * time.Hour, "llmnr": 24 * time.Hour,
	"nbns": 24 * time.Hour, "dhcp": 7 * 24 * time.Hour,
	"ipv6_ndp": 24 * time.Hour,
}

type IdentityObservation struct {
	MAC             string
	Source          string
	Kind            string
	Value           string
	Confidence      int
	Stability       string
	EvidenceJSON    string
	ObservedAddress string
	CollectionRun   string
	ExpiresAt       *time.Time
	FirstSeen       time.Time
	LastSeen        time.Time
	Active          bool
	NormalizedValue string
	DisplayValue    string
}

type SelectedIdentity struct {
	Value  string
	Source string
}

type IdentitySummary struct {
	Source          string         `json:"source"`
	Kind            string         `json:"kind"`
	Value           string         `json:"value"`
	Confidence      int            `json:"confidence"`
	Stability       string         `json:"stability"`
	Evidence        map[string]any `json:"evidence,omitempty"`
	ObservedAddress string         `json:"observed_address,omitempty"`
	CollectionRun   string         `json:"collection_run,omitempty"`
	FirstSeen       string         `json:"first_seen"`
	LastSeen        string         `json:"last_seen"`
	ExpiresAt       string         `json:"expires_at,omitempty"`
}

// IdentityCollector is the internal boundary used by later passive collectors.
type IdentityCollector interface {
	Name() string
	Collect(context.Context) ([]IdentityObservation, error)
}

func normalizeIdentityValue(value string) (string, string, error) {
	display := strings.Join(strings.FieldsFunc(value, unicode.IsSpace), " ")
	if display == "" {
		return "", "", errors.New("identity value cannot be empty")
	}
	for _, r := range display {
		if unicode.IsControl(r) {
			return "", "", errors.New("identity value contains control characters")
		}
	}
	if len(display) > maxIdentityValueBytes {
		for len(display) > maxIdentityValueBytes {
			_, size := utf8.DecodeLastRuneInString(display)
			display = display[:len(display)-size]
		}
		display = strings.TrimSpace(display)
	}
	return strings.ToLower(display), display, nil
}

func validateIdentityObservation(observation *IdentityObservation) error {
	observation.MAC = strings.ToUpper(strings.TrimSpace(observation.MAC))
	if !identitySources[observation.Source] {
		return fmt.Errorf("unknown identity source %q", observation.Source)
	}
	if !identityKinds[observation.Kind] {
		return fmt.Errorf("unknown identity kind %q", observation.Kind)
	}
	if observation.Confidence < 0 || observation.Confidence > 100 {
		return errors.New("identity confidence must be between 0 and 100")
	}
	if observation.Stability != "stable" && observation.Stability != "transient" {
		return errors.New("identity stability must be stable or transient")
	}
	if len(observation.EvidenceJSON) > maxIdentityEvidenceBytes {
		return errors.New("identity evidence exceeds 2048 bytes")
	}
	if observation.EvidenceJSON != "" && !json.Valid([]byte(observation.EvidenceJSON)) {
		return errors.New("identity evidence is not valid JSON")
	}
	normalized, display, err := normalizeIdentityValue(observation.Value)
	if err != nil {
		return err
	}
	observation.NormalizedValue = normalized
	observation.DisplayValue = display
	return nil
}

func upsertIdentityObservation(db *sql.DB, observation IdentityObservation, now time.Time) error {
	if err := validateIdentityObservation(&observation); err != nil {
		return err
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if observation.Stability == "transient" && observation.ExpiresAt == nil {
		if ttl := transientIdentityTTL[observation.Source]; ttl > 0 {
			expires := now.Add(ttl)
			observation.ExpiresAt = &expires
		}
	}
	expiresAt := any(nil)
	if observation.ExpiresAt != nil {
		expiresAt = observation.ExpiresAt.UTC()
	}
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.Exec(`INSERT INTO identity_observations (
		mac, source, kind, normalized_value, display_value, confidence, stability,
		evidence_json, observed_address, collection_run, first_seen, last_seen,
		expires_at, active
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
	ON CONFLICT(mac, source, kind, normalized_value) DO UPDATE SET
		display_value = excluded.display_value,
		confidence = excluded.confidence,
		stability = excluded.stability,
		evidence_json = excluded.evidence_json,
		observed_address = excluded.observed_address,
		collection_run = excluded.collection_run,
		last_seen = excluded.last_seen,
		expires_at = excluded.expires_at,
		active = 1`, observation.MAC, observation.Source, observation.Kind,
		observation.NormalizedValue, observation.DisplayValue, observation.Confidence,
		observation.Stability, nullableString(observation.EvidenceJSON),
		nullableString(observation.ObservedAddress), nullableString(observation.CollectionRun),
		now.UTC(), now.UTC(), expiresAt)
	if err != nil {
		return fmt.Errorf("store identity observation: %w", err)
	}
	if rows, _ := result.RowsAffected(); rows != 1 {
		return errors.New("identity observation was not stored")
	}
	if _, err := tx.Exec(`DELETE FROM identity_observations WHERE id IN (
		SELECT id FROM identity_observations WHERE mac = ?
		ORDER BY active DESC, confidence DESC, last_seen DESC, id DESC
		LIMIT -1 OFFSET ?
	)`, observation.MAC, maxIdentityObservations); err != nil {
		return fmt.Errorf("bound identity observations: %w", err)
	}
	return tx.Commit()
}

func upsertPendingIdentityObservation(db *sql.DB, observation IdentityObservation, now time.Time) error {
	if observation.ObservedAddress == "" {
		return errors.New("pending identity observation requires an address")
	}
	observation.MAC = "pending"
	if err := validateIdentityObservation(&observation); err != nil {
		return err
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	ttl := transientIdentityTTL[observation.Source]
	if ttl <= 0 || ttl > 24*time.Hour {
		ttl = 24 * time.Hour
	}
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`INSERT INTO pending_identity_observations (
		observed_address, source, kind, normalized_value, display_value,
		confidence, evidence_json, collection_run, first_seen, last_seen, expires_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	ON CONFLICT(observed_address, source, kind, normalized_value) DO UPDATE SET
		display_value = excluded.display_value, confidence = excluded.confidence,
		evidence_json = excluded.evidence_json, collection_run = excluded.collection_run,
		last_seen = excluded.last_seen, expires_at = excluded.expires_at`,
		observation.ObservedAddress, observation.Source, observation.Kind,
		observation.NormalizedValue, observation.DisplayValue, observation.Confidence,
		nullableString(observation.EvidenceJSON), nullableString(observation.CollectionRun),
		now.UTC(), now.UTC(), now.Add(ttl).UTC()); err != nil {
		return fmt.Errorf("store pending identity observation: %w", err)
	}
	if _, err := tx.Exec(`DELETE FROM pending_identity_observations WHERE expires_at <= ?
		OR id IN (SELECT id FROM pending_identity_observations
		ORDER BY last_seen DESC, id DESC LIMIT -1 OFFSET ?)`, now.UTC(), maxPendingObservations); err != nil {
		return fmt.Errorf("bound pending identity observations: %w", err)
	}
	return tx.Commit()
}

func promotePendingIdentityObservations(tx *sql.Tx, mac, address string, now time.Time) error {
	var pendingTableExists int
	if err := tx.QueryRow(`SELECT count(*) FROM sqlite_master
		WHERE type = 'table' AND name = 'pending_identity_observations'`).Scan(&pendingTableExists); err != nil {
		return fmt.Errorf("inspect pending identity storage: %w", err)
	}
	if pendingTableExists == 0 {
		return nil
	}
	_, err := tx.Exec(`INSERT INTO identity_observations (
		mac, source, kind, normalized_value, display_value, confidence, stability,
		evidence_json, observed_address, collection_run, first_seen, last_seen,
		expires_at, active
	) SELECT ?, source, kind, normalized_value, display_value, confidence,
		'transient', evidence_json, observed_address, collection_run, first_seen,
		last_seen, expires_at, 1 FROM pending_identity_observations
	WHERE observed_address = ? AND expires_at > ?
	ON CONFLICT(mac, source, kind, normalized_value) DO UPDATE SET
		display_value = excluded.display_value, confidence = excluded.confidence,
		evidence_json = excluded.evidence_json, observed_address = excluded.observed_address,
		collection_run = excluded.collection_run, last_seen = excluded.last_seen,
		expires_at = excluded.expires_at, active = 1`, strings.ToUpper(mac), address, now.UTC())
	if err != nil {
		return fmt.Errorf("promote pending identity observations: %w", err)
	}
	if _, err := tx.Exec(`DELETE FROM pending_identity_observations
		WHERE observed_address = ? OR expires_at <= ?`, address, now.UTC()); err != nil {
		return fmt.Errorf("remove promoted identity observations: %w", err)
	}
	return nil
}

func nullableString(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func expireIdentityObservations(db *sql.DB, now time.Time) (int64, error) {
	result, err := db.Exec(`UPDATE identity_observations SET active = 0
		WHERE active = 1 AND expires_at IS NOT NULL AND expires_at <= ?`, now.UTC())
	if err != nil {
		return 0, fmt.Errorf("expire identity observations: %w", err)
	}
	return result.RowsAffected()
}

func selectDisplayIdentity(db *sql.DB, mac string, now time.Time) (SelectedIdentity, error) {
	mac = strings.ToUpper(strings.TrimSpace(mac))
	var customName, ip sql.NullString
	if err := db.QueryRow("SELECT custom_name, ip FROM hosts WHERE mac = ?", mac).Scan(&customName, &ip); err != nil {
		return SelectedIdentity{}, err
	}
	if strings.TrimSpace(customName.String) != "" {
		return SelectedIdentity{Value: customName.String, Source: "user"}, nil
	}
	rows, err := db.Query(`SELECT source, kind, display_value FROM identity_observations
		WHERE mac = ? AND active = 1 AND (expires_at IS NULL OR expires_at > ?)
		ORDER BY CASE
			WHEN source = 'home_assistant' THEN 1
			WHEN kind = 'friendly_name' AND source IN ('mdns', 'ssdp') THEN 2
			WHEN kind = 'hostname' AND source = 'mdns' THEN 3
			WHEN kind = 'hostname' AND source = 'llmnr' THEN 4
			WHEN kind = 'hostname' AND source = 'nbns' THEN 5
			WHEN kind = 'hostname' AND source = 'dhcp' THEN 6
			WHEN kind = 'hostname' AND source = 'nmap' THEN 7
			ELSE 100 END,
		confidence DESC, last_seen DESC`, mac, now.UTC())
	if err != nil {
		return SelectedIdentity{}, err
	}
	defer rows.Close()
	var manufacturer, model, deviceType string
	for rows.Next() {
		var source, kind, value string
		if err := rows.Scan(&source, &kind, &value); err != nil {
			return SelectedIdentity{}, err
		}
		if source == "home_assistant" || kind == "friendly_name" || kind == "hostname" {
			return SelectedIdentity{Value: value, Source: source}, nil
		}
		switch kind {
		case "manufacturer":
			if manufacturer == "" {
				manufacturer = value
			}
		case "model":
			if model == "" {
				model = value
			}
		case "device_type":
			if deviceType == "" {
				deviceType = value
			}
		}
	}
	if err := rows.Err(); err != nil {
		return SelectedIdentity{}, err
	}
	if manufacturer != "" {
		if model != "" {
			return SelectedIdentity{Value: manufacturer + " " + model, Source: "observed"}, nil
		}
		if deviceType != "" {
			return SelectedIdentity{Value: manufacturer + " " + deviceType, Source: "observed"}, nil
		}
	}
	if ip.String != "" {
		return SelectedIdentity{Value: ip.String, Source: "address"}, nil
	}
	return SelectedIdentity{Value: mac, Source: "address"}, nil
}

func activeIdentitySummaries(db *sql.DB, mac string, now time.Time) ([]IdentitySummary, error) {
	rows, err := db.Query(`SELECT source, kind, display_value, confidence,
		stability, evidence_json, observed_address, collection_run, first_seen,
		last_seen, expires_at
		FROM identity_observations
		WHERE mac = ? AND active = 1 AND (expires_at IS NULL OR expires_at > ?)
		ORDER BY confidence DESC, last_seen DESC LIMIT ?`,
		strings.ToUpper(mac), now.UTC(), maxPublishedObservations)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var summaries []IdentitySummary
	for rows.Next() {
		var summary IdentitySummary
		var evidence, address, run, expires sql.NullString
		if err := rows.Scan(&summary.Source, &summary.Kind, &summary.Value,
			&summary.Confidence, &summary.Stability, &evidence, &address, &run,
			&summary.FirstSeen, &summary.LastSeen, &expires); err != nil {
			return nil, err
		}
		if evidence.Valid {
			_ = json.Unmarshal([]byte(evidence.String), &summary.Evidence)
		}
		summary.ObservedAddress = address.String
		summary.CollectionRun = run.String
		summary.ExpiresAt = expires.String
		summaries = append(summaries, summary)
	}
	return summaries, rows.Err()
}
