package main

import (
	"database/sql"
	"encoding/json"
	"io"
	"log"
)

func DumpDatabase(db *sql.DB, w io.Writer) error {
	// Simple JSON dump of hosts and their current ports
	log.Println("DEBUG: DB query starting in DumpDatabase (SELECT hosts)")
	rows, err := db.Query("SELECT mac, ip, hostname, custom_name, is_randomized FROM hosts")
	log.Printf("DEBUG: DB query finished in DumpDatabase (SELECT hosts, err: %v)", err)
	if err != nil {
		return err
	}
	defer rows.Close()

	var dump []map[string]interface{}
	for rows.Next() {
		var mac, ip, hostname, customName sql.NullString
		var isRandomized bool
		if err := rows.Scan(&mac, &ip, &hostname, &customName, &isRandomized); err != nil {
			return err
		}

		hostMap := map[string]interface{}{
			"mac":           mac.String,
			"ip":            ip.String,
			"hostname":      hostname.String,
			"custom_name":   customName.String,
			"is_randomized": isRandomized,
		}

		// Get ports for this host
		log.Printf("DEBUG: DB query starting in DumpDatabase (SELECT ports for MAC: %s)", mac.String)
		portRows, err := db.Query("SELECT port, protocol, service, state FROM ports WHERE mac = ?", mac.String)
		log.Printf("DEBUG: DB query finished in DumpDatabase (SELECT ports for MAC: %s, err: %v)", mac.String, err)
		if err != nil {
			return err
		}
		var ports []map[string]interface{}
		for portRows.Next() {
			var port int
			var protocol, service, state string
			if err := portRows.Scan(&port, &protocol, &service, &state); err != nil {
				portRows.Close()
				return err
			}
			ports = append(ports, map[string]interface{}{
				"port":     port,
				"protocol": protocol,
				"service":  service,
				"state":    state,
			})
		}
		portRows.Close()
		hostMap["ports"] = ports

		observationRows, err := db.Query(`SELECT source, kind, display_value,
			confidence, stability, evidence_json, observed_address, collection_run,
			first_seen, last_seen, expires_at, active
			FROM identity_observations WHERE mac = ? ORDER BY id`, mac.String)
		if err != nil {
			return err
		}
		var observations []map[string]interface{}
		for observationRows.Next() {
			var source, kind, value, stability, firstSeen, lastSeen string
			var evidence, address, run, expires sql.NullString
			var confidence int
			var active bool
			if err := observationRows.Scan(&source, &kind, &value, &confidence,
				&stability, &evidence, &address, &run, &firstSeen, &lastSeen,
				&expires, &active); err != nil {
				observationRows.Close()
				return err
			}
			observations = append(observations, map[string]interface{}{
				"source": source, "kind": kind, "value": value,
				"confidence": confidence, "stability": stability,
				"evidence": evidence.String, "observed_address": address.String,
				"collection_run": run.String, "first_seen": firstSeen,
				"last_seen": lastSeen, "expires_at": expires.String, "active": active,
			})
		}
		if err := observationRows.Close(); err != nil {
			return err
		}
		hostMap["identity_observations"] = observations
		dump = append(dump, hostMap)
	}

	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(dump)
}
