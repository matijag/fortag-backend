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
		dump = append(dump, hostMap)
	}

	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(dump)
}
