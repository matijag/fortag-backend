package main

import (
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"sort"
	"strings"
	"time"
)

type ScanResult struct {
	MAC            string       `json:"mac"`
	IP             string       `json:"ip"`
	Hostname       string       `json:"hostname"`
	CustomName     string       `json:"custom_name"`
	OS             string       `json:"os"`
	Ports          []PortResult `json:"ports"`
	IsNewHost      bool         `json:"is_new_host"`
	IsAcknowledged bool         `json:"is_acknowledged"`
	IsRandomized   bool         `json:"is_randomized"`
	IsCurrent      bool         `json:"is_current"`
	MatchedFrom    string       `json:"matched_from"` // The old MAC this was bridged from
	CreatedAt      string       `json:"created_at"`
	LastSeen       string       `json:"last_seen"`
}

type PortResult struct {
	Port           int    `json:"port"`
	Protocol       string `json:"protocol"`
	Service        string `json:"service"`
	State          string `json:"state"`
	Scripts        string `json:"scripts"`
	IsNew          bool   `json:"is_new"`
	IsAcknowledged bool   `json:"is_acknowledged"`
}

func generateFingerprint(hostname string, ports []ObservedPort) string {
	var portStrings []string
	for _, p := range ports {
		if p.State != "open" {
			continue
		}
		portStrings = append(portStrings, fmt.Sprintf("%d/%s", p.Port, p.Protocol))
	}
	sort.Strings(portStrings)
	data := fmt.Sprintf("%s|%s", hostname, strings.Join(portStrings, ","))
	return fmt.Sprintf("%x", sha256.Sum256([]byte(data)))
}

func ProcessScan(db *sql.DB, run EngineScanResult) ([]ScanResult, error) {
	var results []ScanResult

	log.Println("DEBUG: DB tx starting in ProcessScan")
	tx, err := db.Begin()
	log.Printf("DEBUG: DB tx started in ProcessScan (err: %v)", err)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	for _, host := range run.Hosts {
		nowUTC := time.Now().UTC().Format("2006-01-02 15:04:05")
		mac := strings.ToUpper(host.MAC)
		ip := host.IP
		hostname := host.Hostname

		if mac == "" {
			continue
		}

		// Extract OS Info
		osInfo := host.OS

		fingerprint := generateFingerprint(hostname, host.Ports)
		isRandomized := isLocallyAdministered(mac)

		res := ScanResult{
			MAC:          mac,
			IP:           ip,
			Hostname:     hostname,
			OS:           osInfo,
			IsRandomized: isRandomized,
		}

		// 1. Check if host exists
		var existingMAC string
		var customName, existingHostname, existingOS sql.NullString
		var acknowledged bool
		var createdAt, lastSeen sql.NullString
		log.Printf("DEBUG: DB query starting in ProcessScan (SELECT hosts for MAC: %s)", mac)
		err := tx.QueryRow("SELECT mac, custom_name, hostname, os_info, acknowledged, created_at, last_seen FROM hosts WHERE mac = ?", mac).Scan(&existingMAC, &customName, &existingHostname, &existingOS, &acknowledged, &createdAt, &lastSeen)
		log.Printf("DEBUG: DB query finished in ProcessScan (SELECT hosts for MAC: %s, err: %v)", mac, err)

		if err == sql.ErrNoRows {
			// Host is new to the DB
			if isRandomized {
				// Try Identity Bridging
				var oldMAC string
				var oldName sql.NullString
				var oldAck bool
				var oldCreated sql.NullString
				log.Printf("DEBUG: DB query starting in ProcessScan (SELECT hosts bridge for MAC: %s)", mac)
				err = tx.QueryRow("SELECT mac, custom_name, acknowledged, created_at FROM hosts WHERE fingerprint = ? AND mac != ? AND last_seen < datetime('now', '-5 minutes') LIMIT 1", fingerprint, mac).Scan(&oldMAC, &oldName, &oldAck, &oldCreated)
				log.Printf("DEBUG: DB query finished in ProcessScan (SELECT hosts bridge for MAC: %s, err: %v)", mac, err)
				if err == nil {
					// Found a bridge!
					res.MatchedFrom = oldMAC
					res.IsNewHost = false
					res.CustomName = oldName.String
					res.IsAcknowledged = oldAck
					insertCreated := oldCreated.String
					if insertCreated == "" {
						insertCreated = nowUTC
					}
					res.CreatedAt = insertCreated
					res.LastSeen = nowUTC
					log.Printf("DEBUG: DB exec starting in ProcessScan (INSERT hosts bridge, mac: %s)", mac)
					_, err = tx.Exec(`INSERT INTO hosts (mac, ip, hostname, custom_name, fingerprint, os_info, acknowledged, is_randomized, created_at)
						VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
						mac, ip, hostname, oldName.String, fingerprint, osInfo, oldAck, true, insertCreated)
					log.Printf("DEBUG: DB exec finished in ProcessScan (INSERT hosts bridge, mac: %s, err: %v)", mac, err)

					// Inherit Port History
					log.Printf("DEBUG: DB exec starting in ProcessScan (INSERT ports bridge, mac: %s)", mac)
					_, _ = tx.Exec(`INSERT OR IGNORE INTO ports (mac, port, protocol, service, state, script_data, acknowledged, last_seen)
						SELECT ?, port, protocol, service, state, script_data, acknowledged, last_seen FROM ports WHERE mac = ?`,
						mac, oldMAC)
					log.Printf("DEBUG: DB exec finished in ProcessScan (INSERT ports bridge, mac: %s)", mac)
				}
			}

			if res.MatchedFrom == "" {
				// No bridge, truly new host
				res.IsNewHost = true
				res.IsAcknowledged = false
				res.CreatedAt = nowUTC
				res.LastSeen = nowUTC
				log.Printf("DEBUG: DB exec starting in ProcessScan (INSERT hosts new, mac: %s)", mac)
				_, err = tx.Exec(`INSERT INTO hosts (mac, ip, hostname, fingerprint, os_info, acknowledged, is_randomized, created_at)
					VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)`,
					mac, ip, hostname, fingerprint, osInfo, false, isRandomized)
				log.Printf("DEBUG: DB exec finished in ProcessScan (INSERT hosts new, mac: %s, err: %v)", mac, err)
			}
		} else if err == nil {
			// Host exists, update it
			res.IsNewHost = false
			res.CustomName = customName.String
			res.IsAcknowledged = acknowledged
			if res.Hostname == "" && !host.ClearMissingMetadata {
				res.Hostname = existingHostname.String
			}
			if res.OS == "" && !host.ClearMissingMetadata {
				res.OS = existingOS.String
			}
			res.CreatedAt = createdAt.String
			res.LastSeen = nowUTC
			log.Printf("DEBUG: DB exec starting in ProcessScan (UPDATE hosts existing, mac: %s)", mac)
			if host.ClearMissingMetadata {
				_, err = tx.Exec(`UPDATE hosts SET ip = ?, hostname = ?, fingerprint = ?, os_info = ?, last_seen = CURRENT_TIMESTAMP
					WHERE mac = ?`, ip, hostname, fingerprint, osInfo, mac)
			} else {
				_, err = tx.Exec(`UPDATE hosts SET ip = ?, hostname = COALESCE(NULLIF(?, ''), hostname), fingerprint = ?, os_info = COALESCE(NULLIF(?, ''), os_info), last_seen = CURRENT_TIMESTAMP
					WHERE mac = ?`, ip, hostname, fingerprint, osInfo, mac)
			}
			log.Printf("DEBUG: DB exec finished in ProcessScan (UPDATE hosts existing, mac: %s, err: %v)", mac, err)
		}

		if err != nil {
			return nil, fmt.Errorf("failed to process host %s: %w", mac, err)
		}

		// Snapshot the previous state before closing ports which were not observed
		// as open in this successful host scan. The table remains a history of
		// known ports, while only exact Nmap state "open" is current exposure.
		type knownPort struct {
			state        string
			acknowledged bool
		}
		knownPorts := make(map[string]knownPort)
		portRows, err := tx.Query("SELECT port, protocol, state, acknowledged FROM ports WHERE mac = ?", mac)
		if err != nil {
			return nil, fmt.Errorf("read known ports for host %s: %w", mac, err)
		}
		for portRows.Next() {
			var port int
			var protocol string
			var state sql.NullString
			var acknowledged bool
			if err := portRows.Scan(&port, &protocol, &state, &acknowledged); err != nil {
				portRows.Close()
				return nil, fmt.Errorf("read known port for host %s: %w", mac, err)
			}
			knownPorts[fmt.Sprintf("%d/%s", port, protocol)] = knownPort{
				state: state.String, acknowledged: acknowledged,
			}
		}
		if err := portRows.Close(); err != nil {
			return nil, fmt.Errorf("close known-port rows for host %s: %w", mac, err)
		}
		if _, err := tx.Exec(`UPDATE ports SET state = 'closed', last_seen = CURRENT_TIMESTAMP
			WHERE mac = ? AND state = 'open'`, mac); err != nil {
			return nil, fmt.Errorf("close ports no longer observed for host %s: %w", mac, err)
		}

		// Process every explicit engine port state for history, but publish and
		// alert only exact open ports.
		for _, p := range host.Ports {
			var scriptData []string
			for _, s := range p.Scripts {
				scriptData = append(scriptData, fmt.Sprintf("[%s] %s", s.ID, s.Output))
			}
			scripts := strings.Join(scriptData, "\n")

			portRes := PortResult{
				Port:     p.Port,
				Protocol: p.Protocol,
				Service:  p.Service,
				State:    p.State,
				Scripts:  scripts,
			}

			key := fmt.Sprintf("%d/%s", p.Port, p.Protocol)
			previous, existed := knownPorts[key]
			isOpen := p.State == "open"
			portRes.IsNew = isOpen && (!existed || previous.state != "open")
			portRes.IsAcknowledged = existed && previous.acknowledged
			if portRes.IsNew {
				// Reopening is a new exposure and needs a fresh acknowledgement.
				portRes.IsAcknowledged = false
			}

			if !existed {
				log.Printf("DEBUG: DB exec starting in ProcessScan (INSERT ports new, mac: %s, port: %d)", mac, p.Port)
				_, err = tx.Exec(`INSERT INTO ports (mac, port, protocol, service, state, script_data, acknowledged)
					VALUES (?, ?, ?, ?, ?, ?, ?)`,
					mac, p.Port, p.Protocol, p.Service, p.State, scripts, portRes.IsAcknowledged)
				log.Printf("DEBUG: DB exec finished in ProcessScan (INSERT ports new, mac: %s, port: %d, err: %v)", mac, p.Port, err)
			} else {
				log.Printf("DEBUG: DB exec starting in ProcessScan (UPDATE ports existing, mac: %s, port: %d)", mac, p.Port)
				_, err = tx.Exec(`UPDATE ports SET service = ?, state = ?, script_data = ?,
					acknowledged = ?, last_seen = CURRENT_TIMESTAMP
					WHERE mac = ? AND port = ? AND protocol = ?`,
					p.Service, p.State, scripts, portRes.IsAcknowledged, mac, p.Port, p.Protocol)
				log.Printf("DEBUG: DB exec finished in ProcessScan (UPDATE ports existing, mac: %s, port: %d, err: %v)", mac, p.Port, err)
			}

			if err != nil {
				return nil, fmt.Errorf("failed to update port %d for host %s: %w", p.Port, mac, err)
			}
			if isOpen {
				res.Ports = append(res.Ports, portRes)
			}
		}

		results = append(results, res)
	}

	log.Println("DEBUG: DB tx commit starting in ProcessScan")
	if err := tx.Commit(); err != nil {
		log.Printf("DEBUG: DB tx commit failed in ProcessScan (err: %v)", err)
		return nil, err
	}
	log.Println("DEBUG: DB tx commit finished in ProcessScan")

	return results, nil
}

func RecordScanHistory(db *sql.DB, duration time.Duration, status string, errMsg string) error {
	log.Println("DEBUG: DB exec starting in RecordScanHistory")
	_, err := db.Exec("INSERT INTO scan_history (duration_seconds, status, error_message) VALUES (?, ?, ?)", int(duration.Seconds()), status, errMsg)
	log.Printf("DEBUG: DB exec finished in RecordScanHistory (err: %v)", err)
	return err
}

func LatestScanMetrics(db *sql.DB) (string, time.Duration, error) {
	var timestamp string
	var durationSeconds int64
	err := db.QueryRow(`SELECT timestamp, duration_seconds FROM scan_history
		WHERE status = 'success' ORDER BY id DESC LIMIT 1`).Scan(&timestamp, &durationSeconds)
	if errors.Is(err, sql.ErrNoRows) {
		return "", 0, nil
	}
	if err != nil {
		return "", 0, fmt.Errorf("query latest scan metrics: %w", err)
	}
	parsed, err := time.Parse(time.RFC3339Nano, timestamp)
	if err != nil {
		parsed, err = time.ParseInLocation("2006-01-02 15:04:05", timestamp, time.UTC)
		if err != nil {
			return "", 0, fmt.Errorf("parse latest scan timestamp %q: %w", timestamp, err)
		}
	}
	return parsed.UTC().Format(time.RFC3339), time.Duration(durationSeconds) * time.Second, nil
}

func isLocallyAdministered(mac string) bool {
	if len(mac) < 2 {
		return false
	}
	secondDigit := mac[1]
	return secondDigit == '2' || secondDigit == '6' || secondDigit == 'a' || secondDigit == 'A' || secondDigit == 'e' || secondDigit == 'E'
}
