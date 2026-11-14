package main

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/rand"
	"sync"
	"sync/atomic"
	"time"

	mqtt "github.com/eclipse/paho.mqtt.golang"
	"github.com/google/uuid"
)

const (
	presenceInterval      = 15 * time.Second
	defaultApprovalLease  = 60 * time.Second
	commandCacheLimit     = 1000
	commandCacheTTL       = 24 * time.Hour
	configSchemaVersion   = 1
	progressSchemaVersion = 1
	maxDesiredConfigBytes = 16 * 1024
)

var ErrScannerUUIDCollision = errors.New("scanner UUID is already active")

type commandCacheEntry struct {
	payloadHash [32]byte
	result      []byte
	receivedAt  time.Time
}

type MQTTClient struct {
	client      mqtt.Client
	broker      string
	user        string
	password    string
	scannerUUID string
	instanceID  string
	scannerName string
	scanRange   string
	startedAt   time.Time

	connected atomic.Bool
	closing   atomic.Bool

	approvalMu       sync.RWMutex
	approvalUntil    time.Time
	approved         atomic.Bool
	collision        chan struct{}
	approvalRestored chan struct{}

	reconnectMu  sync.Mutex
	reconnecting bool
	backoff      time.Duration
	connectedAt  time.Time

	cacheMu           sync.Mutex
	commandCache      map[string]commandCacheEntry
	metadataMu        sync.RWMutex
	progressMu        sync.RWMutex
	progressRevision  atomic.Uint64
	schedulerSnapshot SchedulerSnapshot
	lastOutcome       map[string]any

	stop chan struct{}
	done chan struct{}
}

func NewMQTTClient(broker, user, password string, identity ScannerIdentity, instanceID, scanRange string) *MQTTClient {
	m := &MQTTClient{
		broker:           broker,
		user:             user,
		password:         password,
		scannerUUID:      identity.UUID,
		instanceID:       instanceID,
		scannerName:      identity.Name,
		scanRange:        scanRange,
		startedAt:        time.Now().UTC(),
		collision:        make(chan struct{}, 1),
		approvalRestored: make(chan struct{}, 1),
		backoff:          time.Second,
		commandCache:     make(map[string]commandCacheEntry),
		stop:             make(chan struct{}),
		done:             make(chan struct{}),
	}

	opts := mqtt.NewClientOptions()
	opts.AddBroker(broker)
	opts.SetClientID("fortag-" + identity.UUID + "-" + instanceID)
	opts.SetCleanSession(true)
	opts.SetAutoReconnect(false)
	opts.SetKeepAlive(30 * time.Second)
	opts.SetPingTimeout(10 * time.Second)
	opts.SetConnectTimeout(15 * time.Second)
	opts.SetOrderMatters(false)
	opts.SetWill(m.instanceTopic(), m.presencePayload("offline"), 1, true)
	opts.SetResumeSubs(true)
	if user != "" {
		opts.SetUsername(user)
	}
	if password != "" {
		opts.SetPassword(password)
	}
	opts.SetOnConnectHandler(func(_ mqtt.Client) {
		m.connected.Store(true)
		m.reconnectMu.Lock()
		m.connectedAt = time.Now()
		m.reconnectMu.Unlock()
		if err := m.subscribeApproval(); err != nil {
			log.Printf("ERROR: Subscribe to HA approval: %v", err)
		}
		if err := m.publishRegistration(); err != nil {
			log.Printf("ERROR: Publish scanner registration: %v", err)
		}
	})
	opts.SetConnectionLostHandler(func(_ mqtt.Client, err error) {
		m.connected.Store(false)
		m.clearApproval()
		if !m.closing.Load() {
			log.Printf("MQTT connection lost: %v", err)
			go m.reconnect()
		}
	})
	m.client = mqtt.NewClient(opts)
	m.connectWithBackoff()
	go m.presenceLoop()
	return m
}

func (m *MQTTClient) scannerTopic(suffix string) string {
	return fmt.Sprintf("fortag/scanners/%s/%s", m.scannerUUID, suffix)
}

func (m *MQTTClient) instanceTopic() string {
	return fmt.Sprintf("fortag/discovery/%s/instances/%s", m.scannerUUID, m.instanceID)
}

func (m *MQTTClient) approvalTopic() string {
	return fmt.Sprintf("fortag/scanners/%s/instances/%s/approval", m.scannerUUID, m.instanceID)
}

func (m *MQTTClient) availabilityTopic() string {
	return m.scannerTopic("availability")
}

func (m *MQTTClient) availabilityPayload(status string) string {
	payload, _ := json.Marshal(map[string]any{
		"scanner_uuid": m.scannerUUID,
		"instance_id":  m.instanceID,
		"status":       status,
		"updated_at":   time.Now().UTC().Format(time.RFC3339),
	})
	return string(payload)
}

func (m *MQTTClient) presencePayload(status string) string {
	m.metadataMu.RLock()
	scannerName := m.scannerName
	scanRange := m.scanRange
	m.metadataMu.RUnlock()
	payload, _ := json.Marshal(map[string]any{
		"scanner_uuid":    m.scannerUUID,
		"instance_id":     m.instanceID,
		"scanner_name":    scannerName,
		"scan_range":      scanRange,
		"registered_at":   m.startedAt.Format(time.RFC3339),
		"updated_at":      time.Now().UTC().Format(time.RFC3339),
		"status":          status,
		"api_version":     mqttAPIVersion,
		"config_schema":   configSchemaVersion,
		"progress_schema": progressSchemaVersion,
		"capabilities":    []string{"identity_observations", "mdns", "ssdp", "targeted_scans", "scheduler_progress"},
	})
	return string(payload)
}

func (m *MQTTClient) connectWithBackoff() {
	for !m.closing.Load() {
		token := m.client.Connect()
		token.Wait()
		if token.Error() == nil {
			return
		}
		delay := m.jitteredBackoff()
		log.Printf("MQTT connection failed: %v; retrying in %v", token.Error(), delay)
		select {
		case <-time.After(delay):
		case <-m.stop:
			return
		}
	}
}

func (m *MQTTClient) jitteredBackoff() time.Duration {
	m.reconnectMu.Lock()
	defer m.reconnectMu.Unlock()
	base := m.backoff
	if base < time.Second {
		base = time.Second
	}
	delay := base/2 + time.Duration(rand.Int63n(int64(base/2)+1))
	m.backoff *= 2
	if m.backoff > 60*time.Second {
		m.backoff = 60 * time.Second
	}
	return delay
}

func (m *MQTTClient) reconnect() {
	m.reconnectMu.Lock()
	if m.reconnecting || m.closing.Load() {
		m.reconnectMu.Unlock()
		return
	}
	m.reconnecting = true
	if !m.connectedAt.IsZero() && time.Since(m.connectedAt) >= 2*time.Minute {
		m.backoff = time.Second
	}
	m.reconnectMu.Unlock()

	m.connectWithBackoff()
	m.reconnectMu.Lock()
	m.reconnecting = false
	m.reconnectMu.Unlock()
}

func (m *MQTTClient) publish(topic string, qos byte, retained bool, payload any) error {
	var data []byte
	switch value := payload.(type) {
	case []byte:
		data = value
	case string:
		data = []byte(value)
	default:
		var err error
		data, err = json.Marshal(payload)
		if err != nil {
			return fmt.Errorf("encode MQTT payload for %s: %w", topic, err)
		}
	}
	token := m.client.Publish(topic, qos, retained, data)
	token.Wait()
	if err := token.Error(); err != nil {
		return fmt.Errorf("publish %s: %w", topic, err)
	}
	return nil
}

func (m *MQTTClient) publishRegistration() error {
	m.metadataMu.RLock()
	scannerName := m.scannerName
	scanRange := m.scanRange
	m.metadataMu.RUnlock()
	info := map[string]any{
		"scanner_uuid":    m.scannerUUID,
		"scanner_name":    scannerName,
		"scanner_version": scannerVersion,
		"api_version":     mqttAPIVersion,
		"scan_range":      scanRange,
		"config_schema":   configSchemaVersion,
		"progress_schema": progressSchemaVersion,
		"capabilities":    []string{"identity_observations", "mdns", "ssdp", "targeted_scans", "scheduler_progress"},
	}
	if err := m.publish(fmt.Sprintf("fortag/discovery/%s/info", m.scannerUUID), 1, true, info); err != nil {
		return err
	}
	return m.publish(m.instanceTopic(), 1, true, m.presencePayload("online"))
}

func (m *MQTTClient) SetScanRange(scanRange string) error {
	m.metadataMu.Lock()
	m.scanRange = scanRange
	m.metadataMu.Unlock()
	if m.connected.Load() {
		return m.publishRegistration()
	}
	return nil
}

func (m *MQTTClient) SetScannerName(name string) error {
	m.metadataMu.Lock()
	m.scannerName = name
	m.metadataMu.Unlock()
	if m.connected.Load() {
		return m.publishRegistration()
	}
	return nil
}

func (m *MQTTClient) presenceLoop() {
	defer close(m.done)
	ticker := time.NewTicker(presenceInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			if m.connected.Load() {
				if err := m.publishRegistration(); err != nil {
					log.Printf("ERROR: Publish scanner presence: %v", err)
				}
			}
		case <-m.stop:
			return
		}
	}
}

func (m *MQTTClient) subscribeApproval() error {
	token := m.client.Subscribe(m.approvalTopic(), 1, func(_ mqtt.Client, msg mqtt.Message) {
		var approval struct {
			ScannerUUID  string `json:"scanner_uuid"`
			InstanceID   string `json:"instance_id"`
			Approved     bool   `json:"approved"`
			LeaseSeconds int    `json:"lease_seconds"`
			ErrorCode    string `json:"error_code"`
		}
		if err := json.Unmarshal(msg.Payload(), &approval); err != nil {
			log.Printf("ERROR: Invalid HA approval payload: %v", err)
			return
		}
		if approval.ScannerUUID != m.scannerUUID || approval.InstanceID != m.instanceID {
			return
		}
		if !approval.Approved {
			m.clearApproval()
			if approval.ErrorCode == "uuid_in_use" {
				select {
				case m.collision <- struct{}{}:
				default:
				}
			}
			return
		}
		wasValid := m.HasApproval()
		lease := time.Duration(approval.LeaseSeconds) * time.Second
		if lease <= 0 || lease > 5*time.Minute {
			lease = defaultApprovalLease
		}
		m.approvalMu.Lock()
		m.approvalUntil = time.Now().Add(lease)
		m.approvalMu.Unlock()
		m.approved.Store(true)
		if !wasValid {
			select {
			case m.approvalRestored <- struct{}{}:
			default:
			}
		}
		if err := m.publish(m.availabilityTopic(), 1, true, m.availabilityPayload("online")); err != nil {
			log.Printf("ERROR: Publish approved scanner availability: %v", err)
		}
	})
	token.Wait()
	return token.Error()
}

func (m *MQTTClient) clearApproval() {
	m.approvalMu.Lock()
	m.approvalUntil = time.Time{}
	m.approvalMu.Unlock()
	m.approved.Store(false)
}

func (m *MQTTClient) HasApproval() bool {
	if !m.connected.Load() {
		return false
	}
	m.approvalMu.RLock()
	defer m.approvalMu.RUnlock()
	return time.Now().Before(m.approvalUntil)
}

func (m *MQTTClient) WaitForApproval() error {
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		if m.HasApproval() {
			return nil
		}
		select {
		case <-m.collision:
			return ErrScannerUUIDCollision
		case <-ticker.C:
		case <-m.stop:
			return errors.New("MQTT client closed while waiting for approval")
		}
	}
}

func (m *MQTTClient) IsConnected() bool {
	return m.connected.Load()
}

func (m *MQTTClient) ApprovalRestored() <-chan struct{} {
	return m.approvalRestored
}

func (m *MQTTClient) Close() {
	if !m.closing.CompareAndSwap(false, true) {
		return
	}
	if m.connected.Load() {
		if err := m.publish(m.instanceTopic(), 1, true, []byte{}); err != nil {
			log.Printf("ERROR: Delete retained scanner presence: %v", err)
		}
		if m.approved.Load() {
			if err := m.publish(m.availabilityTopic(), 1, true, m.availabilityPayload("offline")); err != nil {
				log.Printf("ERROR: Publish scanner offline state: %v", err)
			}
		}
	}
	close(m.stop)
	<-m.done
	if m.client.IsConnected() {
		m.client.Disconnect(1000)
	}
}

func (m *MQTTClient) PublishState(results []ScanResult, lastScan string, duration time.Duration, scanRange string) error {
	m.metadataMu.RLock()
	scannerName := m.scannerName
	m.metadataMu.RUnlock()
	for _, result := range results {
		if result.CustomName != "" {
			log.Printf("DEBUG: Publishing host %s with CustomName: %s", result.MAC, result.CustomName)
		}
	}
	payload := map[string]any{
		"api_version":     mqttAPIVersion,
		"scanner_version": scannerVersion,
		"schema_version":  currentSchemaVersion,
		"scanner_uuid":    m.scannerUUID,
		"instance_id":     m.instanceID,
		"scanner_name":    scannerName,
		"last_scan":       lastScan,
		"duration":        fmt.Sprintf("%.2fs", duration.Seconds()),
		"scan_range":      scanRange,
		"hosts":           results,
	}
	return m.publish(m.scannerTopic("state"), 0, true, payload)
}

type desiredScannerConfig struct {
	SchemaVersion          int             `json:"schema_version"`
	ScannerUUID            string          `json:"scanner_uuid"`
	Revision               string          `json:"revision"`
	Collectors             map[string]bool `json:"collectors"`
	AutomaticTargetedScans map[string]bool `json:"automatic_targeted_scans"`
	Unsupported            []string        `json:"-"`
}

func (m *MQTTClient) SubscribeDesiredConfig(apply func(desiredScannerConfig) error) error {
	topic := m.scannerTopic("desired/config")
	token := m.client.Subscribe(topic, 1, func(_ mqtt.Client, msg mqtt.Message) {
		if len(msg.Payload()) > maxDesiredConfigBytes {
			log.Printf("ERROR: Desired config exceeds %d bytes", maxDesiredConfigBytes)
			return
		}
		var raw map[string]json.RawMessage
		if err := json.Unmarshal(msg.Payload(), &raw); err != nil {
			log.Printf("ERROR: Invalid desired config JSON: %v", err)
			return
		}
		var config desiredScannerConfig
		if err := json.Unmarshal(msg.Payload(), &config); err != nil {
			log.Printf("ERROR: Invalid desired config field type: %v", err)
			return
		}
		known := map[string]bool{
			"schema_version": true, "scanner_uuid": true, "revision": true,
			"collectors": true, "automatic_targeted_scans": true, "updated_at": true,
		}
		for name := range raw {
			if !known[name] {
				config.Unsupported = append(config.Unsupported, name)
			}
		}
		if config.SchemaVersion != configSchemaVersion || config.ScannerUUID != m.scannerUUID {
			log.Printf("ERROR: Desired config identity or schema does not match this scanner")
			return
		}
		if _, err := uuid.Parse(config.Revision); err != nil {
			log.Printf("ERROR: Desired config revision is invalid")
			return
		}
		if err := apply(config); err != nil {
			log.Printf("ERROR: Desired config was rejected: %v", err)
		}
	})
	token.Wait()
	return token.Error()
}

func (m *MQTTClient) PublishReportedConfig(revision string, effective map[string]bool, health map[string]collectorHealth, configErrors map[string]string, unsupported []string) error {
	if configErrors == nil {
		configErrors = map[string]string{}
	}
	if unsupported == nil {
		unsupported = []string{}
	}
	payload := map[string]any{
		"schema_version":   configSchemaVersion,
		"scanner_uuid":     m.scannerUUID,
		"instance_id":      m.instanceID,
		"revision":         revision,
		"effective":        map[string]any{"collectors": effective},
		"collector_health": health,
		"errors":           configErrors,
		"unsupported":      unsupported,
		"updated_at":       time.Now().UTC().Format(time.RFC3339),
	}
	return m.publish(m.scannerTopic("reported/config"), 1, true, payload)
}

func (m *MQTTClient) PublishProgress(status, target string) {
	m.publishProgress(progressPayload(m.scannerUUID, m.instanceID, status, target))
}

func (m *MQTTClient) PublishSchedulerSnapshot(snapshot SchedulerSnapshot) {
	m.progressMu.Lock()
	m.schedulerSnapshot = snapshot
	if snapshot.Active != nil {
		m.lastOutcome = nil
	}
	lastOutcome := make(map[string]any, len(m.lastOutcome))
	for key, value := range m.lastOutcome {
		lastOutcome[key] = value
	}
	m.progressMu.Unlock()
	status := "idle"
	target := ""
	if snapshot.Active != nil {
		if snapshot.Active.Kind == ScanJobRoutine {
			status = "scanning_hosts"
		} else {
			status = "scanning_ports"
			target = snapshot.Active.IP
		}
	} else if len(snapshot.Queue) > 0 {
		status = "queued"
	}
	payload := progressPayload(m.scannerUUID, m.instanceID, status, target)
	if snapshot.Active == nil && len(snapshot.Queue) == 0 {
		for key, value := range lastOutcome {
			payload[key] = value
		}
	}
	m.publishProgress(payload)
}

func progressPayload(scannerUUID, instanceID, status, target string) map[string]any {
	return map[string]any{
		"scanner_uuid": scannerUUID,
		"instance_id":  instanceID,
		"status":       status,
		"target":       target,
		"updated_at":   time.Now().UTC().Format(time.RFC3339),
	}
}

func (m *MQTTClient) PublishScanOutcome(outcome, errorCode, message, detail string) {
	payload := scanOutcomePayload(m.scannerUUID, m.instanceID, outcome, errorCode, message, detail)
	m.progressMu.Lock()
	m.lastOutcome = map[string]any{"outcome": outcome, "message": message}
	if errorCode != "" {
		m.lastOutcome["error_code"] = errorCode
	}
	if detail != "" {
		m.lastOutcome["detail"] = detail
	}
	m.progressMu.Unlock()
	m.publishProgress(payload)
}

func scanOutcomePayload(scannerUUID, instanceID, outcome, errorCode, message, detail string) map[string]any {
	payload := map[string]any{
		"scanner_uuid": scannerUUID,
		"instance_id":  instanceID,
		"status":       "idle",
		"target":       "",
		"outcome":      outcome,
		"message":      message,
		"updated_at":   time.Now().UTC().Format(time.RFC3339),
	}
	if errorCode != "" {
		payload["error_code"] = errorCode
	}
	if detail != "" {
		payload["detail"] = detail
	}
	return payload
}

func (m *MQTTClient) publishProgress(payload map[string]any) {
	payload["api_version"] = mqttAPIVersion
	payload["schema_version"] = progressSchemaVersion
	payload["revision"] = m.progressRevision.Add(1)
	m.progressMu.RLock()
	payload["active_job"] = m.schedulerSnapshot.Active
	queue := append([]ScanJob(nil), m.schedulerSnapshot.Queue...)
	m.progressMu.RUnlock()
	payload["queue"] = queue
	if err := m.publish(m.scannerTopic("progress"), 1, true, payload); err != nil {
		log.Printf("ERROR: Publish progress: %v", err)
	}
}

func (m *MQTTClient) PublishAlert(alertType, mac string, extra map[string]any) {
	payload := map[string]any{"type": alertType, "mac": mac, "scanner_uuid": m.scannerUUID}
	for key, value := range extra {
		payload[key] = value
	}
	if err := m.publish(m.scannerTopic("alert"), 0, false, payload); err != nil {
		log.Printf("ERROR: Publish alert: %v", err)
	}
}

func (m *MQTTClient) publishCommandResult(commandID, command, status, errorCode, message string) []byte {
	return m.publishCommandResultWithDetails(commandID, command, status, errorCode, message, nil)
}

func (m *MQTTClient) publishCommandResultWithDetails(commandID, command, status, errorCode, message string, details map[string]any) []byte {
	payload := map[string]any{
		"command_id": commandID,
		"command":    command,
		"status":     status,
		"message":    message,
		"updated_at": time.Now().UTC().Format(time.RFC3339),
	}
	if errorCode != "" {
		payload["error_code"] = errorCode
	}
	if len(details) > 0 {
		payload["details"] = details
	}
	data, _ := json.Marshal(payload)
	if err := m.publish(m.scannerTopic("command/result"), 1, false, data); err != nil {
		log.Printf("ERROR: Publish command result: %v", err)
	}
	return data
}

func (m *MQTTClient) pruneCommandCache(now time.Time) {
	for id, entry := range m.commandCache {
		if now.Sub(entry.receivedAt) >= commandCacheTTL {
			delete(m.commandCache, id)
		}
	}
	for len(m.commandCache) >= commandCacheLimit {
		var oldestID string
		var oldest time.Time
		for id, entry := range m.commandCache {
			if oldestID == "" || entry.receivedAt.Before(oldest) {
				oldestID, oldest = id, entry.receivedAt
			}
		}
		delete(m.commandCache, oldestID)
	}
}

func (m *MQTTClient) handleCommand(command string, msg mqtt.Message, execute func(map[string]any) (map[string]any, error)) {
	var request map[string]any
	if err := json.Unmarshal(msg.Payload(), &request); err != nil {
		m.publishCommandResult("", command, "rejected", "invalid_json", "Command payload is not valid JSON")
		return
	}
	commandID, _ := request["command_id"].(string)
	if _, err := uuid.Parse(commandID); err != nil {
		m.publishCommandResult(commandID, command, "rejected", "invalid_command_id", "command_id must be a UUID")
		return
	}
	hash := sha256.Sum256(msg.Payload())
	now := time.Now()
	m.cacheMu.Lock()
	m.pruneCommandCache(now)
	if cached, ok := m.commandCache[commandID]; ok {
		m.cacheMu.Unlock()
		if cached.payloadHash != hash {
			m.publishCommandResult(commandID, command, "rejected", "command_id_conflict", "command_id was already used with a different payload")
			return
		}
		if len(cached.result) > 0 {
			if err := m.publish(m.scannerTopic("command/result"), 1, false, cached.result); err != nil {
				log.Printf("ERROR: Replay cached command result: %v", err)
			}
		} else {
			m.publishCommandResult(commandID, command, "accepted", "", "Command is still being processed")
		}
		return
	}
	m.commandCache[commandID] = commandCacheEntry{payloadHash: hash, receivedAt: now}
	m.cacheMu.Unlock()

	accepted := m.publishCommandResult(commandID, command, "accepted", "", "Command accepted")
	m.cacheMu.Lock()
	entry := m.commandCache[commandID]
	entry.result = accepted
	m.commandCache[commandID] = entry
	m.cacheMu.Unlock()

	status, errorCode, message := "completed", "", "Command completed"
	details, executeErr := execute(request)
	if executeErr != nil {
		status, errorCode, message = "failed", "command_failed", executeErr.Error()
	}
	terminal := m.publishCommandResultWithDetails(commandID, command, status, errorCode, message, details)
	m.cacheMu.Lock()
	entry = m.commandCache[commandID]
	entry.result = terminal
	m.commandCache[commandID] = entry
	m.cacheMu.Unlock()
}

func (m *MQTTClient) SubscribeCommands(
	onRename func(mac, name string) error,
	onRenameScanner func(name string) error,
	onAck func(mac string, port int, proto string) error,
	onSetRange func(newRange string) error,
	onScanNow func() error,
	onScanTarget func(mac, ip string) (ScanJob, error),
) error {
	subscriptions := map[string]func(map[string]any) (map[string]any, error){
		"rename_scanner": func(request map[string]any) (map[string]any, error) {
			name, _ := request["name"].(string)
			return nil, onRenameScanner(name)
		},
		"rename": func(request map[string]any) (map[string]any, error) {
			mac, _ := request["mac"].(string)
			name, _ := request["name"].(string)
			return nil, onRename(mac, name)
		},
		"acknowledge": func(request map[string]any) (map[string]any, error) {
			mac, _ := request["mac"].(string)
			port, _ := request["port"].(float64)
			proto, _ := request["protocol"].(string)
			return nil, onAck(mac, int(port), proto)
		},
		"set_range": func(request map[string]any) (map[string]any, error) {
			rangeValue, _ := request["range"].(string)
			return nil, onSetRange(rangeValue)
		},
		"scan_now": func(map[string]any) (map[string]any, error) { return nil, onScanNow() },
		"scan_target": func(request map[string]any) (map[string]any, error) {
			mac, _ := request["mac"].(string)
			ip, _ := request["ip"].(string)
			job, err := onScanTarget(mac, ip)
			if err != nil {
				return nil, err
			}
			return map[string]any{"job_id": job.ID, "queue_position": job.QueuePosition}, nil
		},
	}
	for command, execute := range subscriptions {
		command, execute := command, execute
		topic := m.scannerTopic("command/" + command)
		token := m.client.Subscribe(topic, 1, func(_ mqtt.Client, msg mqtt.Message) {
			m.handleCommand(command, msg, execute)
		})
		token.Wait()
		if err := token.Error(); err != nil {
			return fmt.Errorf("subscribe %s: %w", topic, err)
		}
	}
	return nil
}
