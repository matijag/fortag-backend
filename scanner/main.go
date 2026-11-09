package main

import (
	"context"
	"database/sql"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/google/uuid"
	_ "modernc.org/sqlite"
)

const mqttAPIVersion = 2

// scannerVersion is set at build time with -ldflags. Local builds report "dev".
var scannerVersion = "dev"

type scanFailure struct {
	code    string
	message string
	detail  string
}

func safeScanFailure(operation string, err error) scanFailure {
	label := "Port scan"
	if operation == "discovery" {
		label = "Host discovery"
	}
	kind := EngineErrorExecution
	var engineErr *EngineError
	if errors.As(err, &engineErr) {
		kind = engineErr.Kind
	}
	if errors.Is(err, context.DeadlineExceeded) {
		kind = EngineErrorTimeout
	}
	switch kind {
	case EngineErrorValidation:
		return scanFailure{operation + "_invalid", label + " configuration was rejected", "The target or scanner settings are invalid."}
	case EngineErrorStart:
		return scanFailure{operation + "_unavailable", label + " could not start", "Required scanner resources or permissions are unavailable."}
	case EngineErrorTimeout:
		return scanFailure{operation + "_timeout", label + " timed out", "The operation exceeded its safety timeout before it completed."}
	case EngineErrorCancelled:
		return scanFailure{operation + "_cancelled", label + " was cancelled", "The scanner stopped the operation before it completed."}
	case EngineErrorOutput:
		return scanFailure{operation + "_invalid_result", label + " returned invalid results", "The scanner rejected malformed or unsafe result data."}
	default:
		return scanFailure{operation + "_failed", label + " failed", "A network or scanner error stopped the operation."}
	}
}

func summarizeScanFailures(failures []scanFailure) scanFailure {
	if len(failures) == 0 {
		return scanFailure{"scan_incomplete", "Scan completed with errors", "One or more results may be incomplete."}
	}
	if len(failures) == 1 {
		return failures[0]
	}
	return scanFailure{
		"scan_incomplete",
		"Scan completed with multiple errors",
		fmt.Sprintf("%d problems occurred. First problem: %s", len(failures), failures[0].detail),
	}
}

func getCurrentRange(db *sql.DB, defaultRange string) (string, error) {
	var val string
	log.Println("DEBUG: DB query starting in getCurrentRange (SELECT scan_range)")
	err := db.QueryRow("SELECT value FROM config WHERE key = 'scan_range'").Scan(&val)
	log.Printf("DEBUG: DB query finished in getCurrentRange (SELECT scan_range, err: %v)", err)
	if errors.Is(err, sql.ErrNoRows) {
		if defaultRange == "" {
			return "", errors.New("scan range is not configured and no local RFC1918 network was detected")
		}
		if validationErr := ValidateScanTarget(defaultRange); validationErr != nil {
			return "", fmt.Errorf("fallback scan range is invalid: %w", validationErr)
		}
		return defaultRange, nil
	}
	if err != nil {
		return "", fmt.Errorf("read scan range: %w", err)
	}
	if val == "" {
		return "", errors.New("configured scan range is empty")
	}
	if validationErr := ValidateScanTarget(val); validationErr != nil {
		return "", fmt.Errorf("persisted scan range is invalid: %w", validationErr)
	}
	return val, nil
}

func configureScanRange(db *sql.DB, requested string, detect func() (string, error)) (string, bool, error) {
	requested = strings.TrimSpace(requested)
	if requested == "" {
		detected, err := detect()
		if err != nil {
			return "", false, fmt.Errorf("cannot enable automatic scan-range detection: %w", err)
		}
		if err := ValidateScanTarget(detected); err != nil {
			return "", false, fmt.Errorf("auto-detection returned an unusable range: %w", err)
		}
		if _, err := db.Exec("DELETE FROM config WHERE key = 'scan_range'"); err != nil {
			return "", false, fmt.Errorf("remove persisted scan-range override: %w", err)
		}
		return detected, true, nil
	}
	if err := ValidateScanTarget(requested); err != nil {
		return "", false, err
	}
	if _, err := db.Exec("INSERT OR REPLACE INTO config (key, value) VALUES ('scan_range', ?)", requested); err != nil {
		return "", false, fmt.Errorf("persist scan range: %w", err)
	}
	return requested, false, nil
}

type securityAlert struct {
	alertType string
	mac       string
	extra     map[string]interface{}
}

func securityAlerts(results []ScanResult) []securityAlert {
	var alerts []securityAlert
	for _, result := range results {
		hostDetails := map[string]interface{}{}
		if result.CustomName != "" {
			hostDetails["custom_name"] = result.CustomName
		}
		if result.IsNewHost {
			extra := map[string]interface{}{"ip": result.IP}
			for key, value := range hostDetails {
				extra[key] = value
			}
			alerts = append(alerts, securityAlert{
				alertType: "new_host",
				mac:       result.MAC,
				extra:     extra,
			})
		}
		for _, port := range result.Ports {
			if port.IsNew {
				extra := map[string]interface{}{
					"port": port.Port, "protocol": port.Protocol,
				}
				for key, value := range hostDetails {
					extra[key] = value
				}
				alerts = append(alerts, securityAlert{
					alertType: "new_port",
					mac:       result.MAC,
					extra:     extra,
				})
			}
		}
	}
	return alerts
}

func getAllScanResults(db *sql.DB) ([]ScanResult, error) {
	log.Println("DEBUG: DB query starting in getAllScanResults (SELECT hosts)")
	rows, err := db.Query("SELECT mac, ip, hostname, custom_name, os_info, acknowledged, is_randomized, is_current, created_at, last_seen FROM hosts")
	log.Printf("DEBUG: DB query finished in getAllScanResults (SELECT hosts, err: %v)", err)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []ScanResult
	for rows.Next() {
		var r ScanResult
		var hn, cn, osi sql.NullString
		var createdAt, lastSeen sql.NullString
		if err := rows.Scan(&r.MAC, &r.IP, &hn, &cn, &osi, &r.IsAcknowledged, &r.IsRandomized, &r.IsCurrent, &createdAt, &lastSeen); err != nil {
			return nil, err
		}
		r.Hostname = hn.String
		r.CustomName = cn.String
		r.OS = osi.String
		r.CreatedAt = createdAt.String
		r.LastSeen = lastSeen.String

		// Get ports
		log.Printf("DEBUG: DB query starting in getAllScanResults (SELECT ports for MAC: %s)", r.MAC)
		pRows, err := db.Query(`SELECT port, protocol, service, state, script_data, acknowledged
			FROM ports WHERE mac = ? AND state = 'open' ORDER BY port, protocol`, r.MAC)
		log.Printf("DEBUG: DB query finished in getAllScanResults (SELECT ports for MAC: %s, err: %v)", r.MAC, err)
		if err == nil {
			for pRows.Next() {
				var p PortResult
				var sv, st, sd sql.NullString
				if err := pRows.Scan(&p.Port, &p.Protocol, &sv, &st, &sd, &p.IsAcknowledged); err == nil {
					p.Service = sv.String
					p.State = st.String
					p.Scripts = sd.String
					r.Ports = append(r.Ports, p)
				} else {
					log.Printf("ERROR: Failed to scan port row for %s: %v", r.MAC, err)
				}
			}
			pRows.Close()
		} else {
			log.Printf("ERROR: Failed to query ports for %s: %v", r.MAC, err)
		}
		results = append(results, r)
	}
	return results, nil
}

func setCurrentHosts(db *sql.DB, macs []string) error {
	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("begin current-host update: %w", err)
	}
	defer tx.Rollback()

	if _, err := tx.Exec("UPDATE hosts SET is_current = FALSE"); err != nil {
		return fmt.Errorf("clear current hosts: %w", err)
	}

	stmt, err := tx.Prepare("UPDATE hosts SET is_current = TRUE WHERE mac = ?")
	if err != nil {
		return fmt.Errorf("prepare current-host update: %w", err)
	}
	defer stmt.Close()

	for _, mac := range macs {
		if _, err := stmt.Exec(mac); err != nil {
			return fmt.Errorf("mark current host %s: %w", mac, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit current-host update: %w", err)
	}
	return nil
}

func main() {
	dbPath := flag.String("db", "scanner.db", "Path to SQLite database")
	mqttBroker := flag.String("mqtt", "tcp://localhost:1883", "MQTT broker URL")
	mqttUser := flag.String("user", os.Getenv("MQTT_USER"), "MQTT username")
	mqttPass := flag.String("password", os.Getenv("MQTT_PASSWORD"), "MQTT password")
	targetRangeFlag := flag.String("range", "", "RFC1918 range to scan")
	frequency := flag.Duration("freq", 8*time.Hour, "Scan frequency")
	dumpMode := flag.Bool("dump", false, "Dump database to stdout and exit")
	flag.Parse()
	log.Printf("Starting Fortag scanner %s (MQTT API v%d)", scannerVersion, mqttAPIVersion)

	dbLock, err := acquireDatabaseLock(*dbPath, *dumpMode)
	if err != nil {
		log.Fatalf("Database lock error: %v", err)
	}
	defer dbLock.Close()

	if *dumpMode {
		db, err := openReadOnlyDB(*dbPath)
		if err != nil {
			log.Fatalf("Database error: %v", err)
		}
		defer db.Close()
		if err := DumpDatabase(db, os.Stdout); err != nil {
			log.Fatalf("Dump error: %v", err)
		}
		return
	}

	// initDB opens the database and completes all schema migrations before any
	// state is exposed to MQTT or a scan is started.
	db, err := initDB(*dbPath)
	if err != nil {
		log.Fatalf("Database error: %v", err)
	}
	defer db.Close()

	// Resolve target range
	targetRange := *targetRangeFlag
	if targetRange == "" {
		targetRange, err = DetectLocalRFC1918()
		if err != nil {
			log.Printf("Local scan range auto-detection failed: %v", err)
		} else {
			log.Printf("Auto-detected local scan range %s", targetRange)
		}
	}
	// Sync with DB config
	targetRange, err = getCurrentRange(db, targetRange)
	if err != nil {
		log.Fatalf("Scan range error: %v", err)
	}
	var fallbackRange atomic.Value
	fallbackRange.Store(targetRange)

	identity, err := getScannerIdentity(db)
	if err != nil {
		log.Fatalf("Scanner identity error: %v", err)
	}
	instanceID := uuid.NewString()
	var mqttClient *MQTTClient
	for {
		mqttClient = NewMQTTClient(*mqttBroker, *mqttUser, *mqttPass, identity, instanceID, targetRange)
		log.Printf("Waiting for Home Assistant approval of scanner %s instance %s", identity.UUID, instanceID)
		if approvalErr := mqttClient.WaitForApproval(); approvalErr == nil {
			break
		} else if !errors.Is(approvalErr, ErrScannerUUIDCollision) {
			log.Fatalf("Scanner approval error: %v", approvalErr)
		}
		mqttClient.Close()
		identity, err = replaceScannerUUID(db, "uuid_collision")
		if err != nil {
			log.Fatalf("Scanner UUID collision resolution failed: %v", err)
		}
		log.Printf("Scanner UUID collision resolved; registering replacement UUID %s", identity.UUID)
	}
	defer mqttClient.Close()
	log.Printf("Home Assistant approved scanner %s instance %s", identity.UUID, instanceID)

	var scanInProgress atomic.Bool
	var scanEngine ScanEngine = NewNativeEngine()

	publishCurrentState := func() error {
		res, err := getAllScanResults(db)
		if err != nil {
			return fmt.Errorf("fetch scan results for state publication: %w", err)
		}
		scanRange, err := getCurrentRange(db, fallbackRange.Load().(string))
		if err != nil {
			return fmt.Errorf("fetch scan range for state publication: %w", err)
		}
		lastScan, duration, err := LatestScanMetrics(db)
		if err != nil {
			return fmt.Errorf("fetch latest scan metrics for state publication: %w", err)
		}
		return mqttClient.PublishState(res, lastScan, duration, scanRange)
	}
	// Discard the initial approval transition, then republish the database after
	// any later MQTT/HA approval recovery. This covers scans that completed
	// locally while publication was unavailable.
	select {
	case <-mqttClient.ApprovalRestored():
	default:
	}
	go func() {
		for range mqttClient.ApprovalRestored() {
			if err := publishCurrentState(); err != nil {
				log.Printf("ERROR: Failed to republish state after approval recovery: %v", err)
			}
		}
	}()

	doScan := func() {
		if !mqttClient.HasApproval() {
			log.Println("Scan not started: MQTT connection or Home Assistant approval is unavailable.")
			return
		}
		if !scanInProgress.CompareAndSwap(false, true) {
			log.Println("Scan already in progress, skipping trigger.")
			return
		}
		defer scanInProgress.Store(false)

		startTime := time.Now()
		rangeToScan, err := getCurrentRange(db, fallbackRange.Load().(string))
		if err != nil {
			log.Printf("Scan aborted: %v", err)
			if historyErr := RecordScanHistory(db, time.Since(startTime), "failed", err.Error()); historyErr != nil {
				log.Printf("ERROR: Failed to record scan range failure: %v", historyErr)
			}
			mqttClient.PublishScanOutcome(
				"failed", "invalid_scan_range", "Scan could not start",
				"The configured scan range is invalid or unavailable.",
			)
			return
		}
		log.Printf("Starting phased scan of %s", rangeToScan)

		mqttClient.PublishProgress("scanning_hosts", rangeToScan)
		discovery, err := scanEngine.Discover(context.Background(), DiscoveryRequest{Target: rangeToScan})
		if err != nil {
			log.Printf("Discovery failed: %v", err)
			duration := time.Since(startTime)
			if historyErr := RecordScanHistory(db, duration, "failed", err.Error()); historyErr != nil {
				log.Printf("ERROR: Failed to record discovery failure: %v", historyErr)
			}
			failure := safeScanFailure("discovery", err)
			mqttClient.PublishScanOutcome("failed", failure.code, failure.message, failure.detail)
			return
		}

		log.Printf("Found %d up hosts. Starting targeted deep scans with %s...", len(discovery.Targets), scanEngine.Name())
		discoveredMACs := make(map[string]string, len(discovery.Hosts))
		for _, host := range discovery.Hosts {
			discoveredMACs[host.IP] = host.MAC
		}
		var scanErrors []string
		var safeFailures []scanFailure
		var currentMACs []string
		processResult := func(label string, engineResult EngineScanResult, scanErr error) {
			if scanErr != nil {
				log.Printf("Scan failed for %s: %v", label, scanErr)
				scanErrors = append(scanErrors, fmt.Sprintf("%s: %s: %v", label, scanEngine.Name(), scanErr))
				safeFailures = append(safeFailures, safeScanFailure("port_scan", scanErr))
				return
			}
			processed, processErr := ProcessScan(db, engineResult)
			if processErr != nil {
				log.Printf("Failed to process scan for %s: %v", label, processErr)
				scanErrors = append(scanErrors, fmt.Sprintf("%s: persistence: %v", label, processErr))
				safeFailures = append(safeFailures, scanFailure{
					code: "database_write_failed", message: "Scan results could not be saved",
					detail: "The scanner database rejected one or more result updates.",
				})
				return
			}
			for _, alert := range securityAlerts(processed) {
				mqttClient.PublishAlert(alert.alertType, alert.mac, alert.extra)
			}
			for _, result := range processed {
				currentMACs = append(currentMACs, result.MAC)
			}
		}
		if batchEngine, ok := scanEngine.(BatchScanEngine); ok {
			requests := make([]PortScanRequest, 0, len(discovery.Targets))
			for _, ip := range discovery.Targets {
				priorityPorts, priorityErr := getKnownOpenPorts(db, discoveredMACs[ip])
				if priorityErr != nil {
					scanErrors = append(scanErrors, fmt.Sprintf("%s: prior ports: %v", ip, priorityErr))
					safeFailures = append(safeFailures, scanFailure{
						code: "database_read_failed", message: "Previous port history could not be read",
						detail: "One or more hosts were skipped because their saved port history was unavailable.",
					})
					continue
				}
				requests = append(requests, PortScanRequest{
					Target:        ip,
					MAC:           discoveredMACs[ip],
					PriorityPorts: priorityPorts,
					Progress: func(progress EngineProgress) {
						mqttClient.PublishProgress("scanning_ports", progress.Target)
					},
				})
			}
			engineResult, scanErr := batchEngine.ScanBatch(context.Background(), requests)
			processResult("discovered hosts", engineResult, scanErr)
		} else {
			for _, ip := range discovery.Targets {
				mqttClient.PublishProgress("scanning_ports", ip)
				engineResult, scanErr := scanEngine.Scan(context.Background(), PortScanRequest{Target: ip, MAC: discoveredMACs[ip]})
				processResult(ip, engineResult, scanErr)
			}
		}

		if err := setCurrentHosts(db, currentMACs); err != nil {
			log.Printf("Failed to update current hosts: %v", err)
			scanErrors = append(scanErrors, fmt.Sprintf("current hosts: %v", err))
			safeFailures = append(safeFailures, scanFailure{
				code: "database_write_failed", message: "Current host state could not be saved",
				detail: "The displayed current-host set may be stale.",
			})
		}

		duration := time.Since(startTime)
		status := "success"
		errMessage := ""
		if len(scanErrors) > 0 {
			status = "partial"
			errMessage = strings.Join(scanErrors, "; ")
		}
		if err := RecordScanHistory(db, duration, status, errMessage); err != nil {
			log.Printf("ERROR: Failed to record scan history: %v", err)
			status = "partial"
			safeFailures = append(safeFailures, scanFailure{
				code: "scan_history_write_failed", message: "Scan completion could not be recorded",
				detail: "Results may be current, but the last successful scan time could not be updated.",
			})
		}

		// Final full state publish uses the persisted scan-history metrics so
		// later rename/acknowledge refreshes cannot corrupt them.
		if err := publishCurrentState(); err != nil {
			log.Printf("ERROR: Failed to publish state after scan: %v", err)
			status = "partial"
			safeFailures = append(safeFailures, scanFailure{
				code: "state_publish_failed", message: "Updated results could not be published",
				detail: "Home Assistant may continue showing results from the previous successful scan.",
			})
		}
		if status == "partial" {
			failure := summarizeScanFailures(safeFailures)
			mqttClient.PublishScanOutcome("partial", failure.code, failure.message, failure.detail)
		} else {
			mqttClient.PublishScanOutcome("success", "", "Scan completed successfully", "")
		}
	}

	onRename := func(mac, name string) error {
		mac = strings.ToUpper(mac)
		log.Printf("Renaming %s to %s", mac, name)
		log.Printf("DEBUG: DB exec starting in onRename (mac: %s, name: %s)", mac, name)
		res, err := db.Exec("UPDATE hosts SET custom_name = ?, acknowledged = TRUE WHERE mac = ?", name, mac)
		log.Printf("DEBUG: DB exec finished in onRename (mac: %s, err: %v)", mac, err)
		if err != nil {
			log.Printf("ERROR: Rename failed for %s: %v", mac, err)
			return err
		}
		rows, _ := res.RowsAffected()
		log.Printf("Rename successful. Rows affected: %d", rows)
		if err := publishCurrentState(); err != nil {
			log.Printf("ERROR: Failed to publish state after rename: %v", err)
			return err
		}
		return nil
	}
	onRenameScanner := func(name string) error {
		updatedIdentity, err := renameScanner(db, name)
		if err != nil {
			return err
		}
		return mqttClient.SetScannerName(updatedIdentity.Name)
	}

	onAck := func(mac string, port int, proto string) error {
		mac = strings.ToUpper(mac)
		var err error
		var res sql.Result
		if port > 0 {
			log.Printf("DEBUG: DB exec starting in onAck (port update, mac: %s, port: %d)", mac, port)
			res, err = db.Exec("UPDATE ports SET acknowledged = TRUE WHERE mac = ? AND port = ? AND protocol = ?", mac, port, proto)
			log.Printf("DEBUG: DB exec finished in onAck (port update, mac: %s, port: %d, err: %v)", mac, port, err)
		} else {
			log.Printf("DEBUG: DB exec starting in onAck (host update, mac: %s)", mac)
			res, err = db.Exec("UPDATE hosts SET acknowledged = TRUE WHERE mac = ?", mac)
			log.Printf("DEBUG: DB exec finished in onAck (host update, mac: %s, err: %v)", mac, err)
		}
		if err != nil {
			log.Printf("ERROR: Acknowledge failed for %s (port: %d): %v", mac, port, err)
			return err
		}
		rows, _ := res.RowsAffected()
		log.Printf("Acknowledge successful. Rows affected: %d", rows)
		if err := publishCurrentState(); err != nil {
			log.Printf("ERROR: Failed to publish state after acknowledgement: %v", err)
			return err
		}
		return nil
	}

	onSetRange := func(newRange string) error {
		activeRange, automatic, err := configureScanRange(db, newRange, DetectLocalRFC1918)
		if err != nil {
			log.Printf("Scan range change rejected: %v", err)
			return err
		}
		if automatic {
			fallbackRange.Store(activeRange)
			log.Printf("Removed scan-range override; auto-detected %s", activeRange)
		} else {
			log.Printf("Updated persisted scan range to %s", activeRange)
		}
		if err := mqttClient.SetScanRange(activeRange); err != nil {
			log.Printf("ERROR: Range was saved but registration publication failed: %v", err)
		}
		if err := publishCurrentState(); err != nil {
			log.Printf("ERROR: Range was saved but state publication failed: %v", err)
		}
		return nil
	}

	triggerScan := make(chan bool, 1)
	onScanNow := func() error {
		if !mqttClient.HasApproval() {
			return errors.New("MQTT connection or Home Assistant approval is unavailable")
		}
		if scanInProgress.Load() {
			return errors.New("scan already in progress")
		}
		select {
		case triggerScan <- true:
			return nil
		default:
			return errors.New("scan trigger is already queued")
		}
	}

	if err := mqttClient.SubscribeCommands(onRename, onRenameScanner, onAck, onSetRange, onScanNow); err != nil {
		log.Fatalf("Subscribe to scanner commands: %v", err)
	}

	// Replace any retained state from an older scanner before the initial scan,
	// which may take a long time to finish on a populated network.
	if err := publishCurrentState(); err != nil {
		log.Fatalf("Failed to publish initial scanner state: %v", err)
	}
	log.Printf("Published initial database state for scanner %s", scannerVersion)

	ticker := time.NewTicker(*frequency)
	defer ticker.Stop()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	go doScan()

	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			go doScan()
		case <-triggerScan:
			go doScan()
		}
	}
}
