package main

import (
	"bufio"
	"context"
	"database/sql"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"golang.org/x/net/dns/dnsmessage"
)

const (
	collectorInterval       = 5 * time.Minute
	collectorNetworkWindow  = 3 * time.Second
	maxCollectorPacketBytes = 16 * 1024
	maxSSDPDescriptionBytes = 64 * 1024
)

type collectedIdentity struct {
	IP         string
	Source     string
	Kind       string
	Value      string
	Confidence int
	Evidence   map[string]any
}

type collectorHealth struct {
	Status    string `json:"status"`
	Message   string `json:"message,omitempty"`
	UpdatedAt string `json:"updated_at"`
}

type identityCollectorManager struct {
	db        *sql.DB
	rangeFn   func() (string, error)
	onUpdate  func()
	mu        sync.RWMutex
	enabled   map[string]bool
	health    map[string]collectorHealth
	cancel    context.CancelFunc
	done      chan struct{}
	refresh   chan struct{}
	collectFn map[string]func(context.Context, string) ([]collectedIdentity, error)
}

func newIdentityCollectorManager(db *sql.DB, rangeFn func() (string, error), onUpdate func()) *identityCollectorManager {
	return &identityCollectorManager{
		db: db, rangeFn: rangeFn, onUpdate: onUpdate,
		enabled: map[string]bool{"mdns": true, "ssdp": true},
		health:  make(map[string]collectorHealth),
		done:    make(chan struct{}),
		refresh: make(chan struct{}, 1),
		collectFn: map[string]func(context.Context, string) ([]collectedIdentity, error){
			"mdns": collectMDNS, "ssdp": collectSSDP,
		},
	}
}

func (m *identityCollectorManager) Start(parent context.Context) {
	ctx, cancel := context.WithCancel(parent)
	m.cancel = cancel
	go m.run(ctx)
}

func (m *identityCollectorManager) Stop() {
	if m.cancel == nil {
		return
	}
	m.cancel()
	<-m.done
}

func (m *identityCollectorManager) SetEnabled(name string, enabled bool) error {
	if _, ok := m.collectFn[name]; !ok {
		return fmt.Errorf("unknown collector %q", name)
	}
	m.mu.Lock()
	m.enabled[name] = enabled
	if !enabled {
		m.health[name] = collectorHealth{Status: "disabled", UpdatedAt: time.Now().UTC().Format(time.RFC3339)}
	}
	m.mu.Unlock()
	select {
	case m.refresh <- struct{}{}:
	default:
	}
	return nil
}

func (m *identityCollectorManager) Effective() map[string]bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return map[string]bool{"mdns": m.enabled["mdns"], "ssdp": m.enabled["ssdp"]}
}

func (m *identityCollectorManager) Health() map[string]collectorHealth {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := make(map[string]collectorHealth, len(m.health))
	for name, health := range m.health {
		result[name] = health
	}
	return result
}

func (m *identityCollectorManager) run(ctx context.Context) {
	defer close(m.done)
	ticker := time.NewTicker(collectorInterval)
	defer ticker.Stop()
	for {
		m.collect(ctx)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		case <-m.refresh:
		}
	}
}

func (m *identityCollectorManager) collect(ctx context.Context) {
	scanRange, err := m.rangeFn()
	if err != nil {
		m.setAllHealth("unavailable", "scan range is unavailable")
		return
	}
	for _, name := range []string{"mdns", "ssdp"} {
		m.mu.RLock()
		enabled := m.enabled[name]
		collect := m.collectFn[name]
		m.mu.RUnlock()
		if !enabled {
			m.setHealth(name, "disabled", "")
			continue
		}
		observations, collectErr := collect(ctx, scanRange)
		if collectErr != nil {
			if errors.Is(collectErr, context.Canceled) {
				return
			}
			m.setHealth(name, "degraded", safeCollectorError(collectErr))
			continue
		}
		if err := m.persist(observations); err != nil {
			m.setHealth(name, "degraded", "observations could not be saved")
			continue
		}
		m.setHealth(name, "running", "")
	}
	if m.onUpdate != nil {
		m.onUpdate()
	}
}

func (m *identityCollectorManager) persist(observations []collectedIdentity) error {
	runID := uuid.NewString()
	now := time.Now().UTC()
	for _, collected := range observations {
		var mac string
		if err := m.db.QueryRow(`SELECT mac FROM hosts WHERE ip = ?
			ORDER BY is_current DESC, last_seen DESC LIMIT 1`, collected.IP).Scan(&mac); err != nil {
			if !errors.Is(err, sql.ErrNoRows) {
				return err
			}
		}
		evidence, err := json.Marshal(collected.Evidence)
		if err != nil {
			return err
		}
		observation := IdentityObservation{
			MAC: mac, Source: collected.Source, Kind: collected.Kind,
			Value: collected.Value, Confidence: collected.Confidence,
			Stability: "transient", EvidenceJSON: string(evidence),
			ObservedAddress: collected.IP, CollectionRun: runID,
		}
		var persistErr error
		if mac == "" {
			persistErr = upsertPendingIdentityObservation(m.db, observation, now)
		} else {
			persistErr = upsertIdentityObservation(m.db, observation, now)
		}
		if persistErr != nil {
			return persistErr
		}
	}
	return nil
}

func (m *identityCollectorManager) setHealth(name, status, message string) {
	m.mu.Lock()
	m.health[name] = collectorHealth{Status: status, Message: message, UpdatedAt: time.Now().UTC().Format(time.RFC3339)}
	m.mu.Unlock()
}

func (m *identityCollectorManager) setAllHealth(status, message string) {
	for _, name := range []string{"mdns", "ssdp"} {
		m.setHealth(name, status, message)
	}
}

func safeCollectorError(err error) string {
	if errors.Is(err, context.DeadlineExceeded) {
		return "collector timed out"
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		return "local network access failed"
	}
	return "collector failed"
}

func collectMDNS(ctx context.Context, scanRange string) ([]collectedIdentity, error) {
	queryName, _ := dnsmessage.NewName("_services._dns-sd._udp.local.")
	message := dnsmessage.Message{
		// The collector uses an ephemeral socket, so request a unicast response
		// instead of asking responders to send only to multicast port 5353.
		Questions: []dnsmessage.Question{{
			Name: queryName, Type: dnsmessage.TypePTR,
			Class: dnsmessage.Class(uint16(dnsmessage.ClassINET) | 0x8000),
		}},
	}
	packet, err := message.Pack()
	if err != nil {
		return nil, err
	}
	connection, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return nil, err
	}
	defer connection.Close()
	deadline := time.Now().Add(collectorNetworkWindow)
	_ = connection.SetDeadline(deadline)
	if _, err := connection.WriteToUDP(packet, &net.UDPAddr{IP: net.ParseIP("224.0.0.251"), Port: 5353}); err != nil {
		return nil, err
	}
	var result []collectedIdentity
	buffer := make([]byte, maxCollectorPacketBytes)
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		n, _, err := connection.ReadFromUDP(buffer)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				return result, nil
			}
			return result, err
		}
		observations, err := parseMDNSPacket(buffer[:n], scanRange)
		if err == nil {
			result = append(result, observations...)
		}
	}
}

func parseMDNSPacket(packet []byte, scanRange string) ([]collectedIdentity, error) {
	var message dnsmessage.Message
	if err := message.Unpack(packet); err != nil {
		return nil, err
	}
	resources := append(message.Answers, message.Additionals...)
	addresses := make(map[string][]string)
	services := make(map[string]string)
	instances := make(map[string]string)
	txt := make(map[string][]string)
	for _, resource := range resources {
		name := strings.TrimSuffix(resource.Header.Name.String(), ".")
		switch body := resource.Body.(type) {
		case *dnsmessage.AResource:
			ip := net.IP(body.A[:]).String()
			if ipWithinRange(ip, scanRange) {
				addresses[name] = append(addresses[name], ip)
			}
		case *dnsmessage.PTRResource:
			instances[strings.TrimSuffix(body.PTR.String(), ".")] = name
		case *dnsmessage.SRVResource:
			services[name] = strings.TrimSuffix(body.Target.String(), ".")
		case *dnsmessage.TXTResource:
			txt[name] = body.TXT
		}
	}
	var result []collectedIdentity
	for host, ips := range addresses {
		for _, ip := range ips {
			result = append(result, collectedIdentity{IP: ip, Source: "mdns", Kind: "hostname", Value: host, Confidence: 70})
		}
	}
	for instance, host := range services {
		serviceType := instances[instance]
		for _, ip := range addresses[host] {
			friendly := strings.TrimSuffix(instance, "."+serviceType)
			if friendly != "" {
				result = append(result, collectedIdentity{IP: ip, Source: "mdns", Kind: "friendly_name", Value: friendly, Confidence: 80, Evidence: map[string]any{"service": serviceType}})
			}
			if serviceType != "" {
				result = append(result, collectedIdentity{IP: ip, Source: "mdns", Kind: "service", Value: serviceType, Confidence: 70})
			}
			result = append(result, mdnsTXTObservations(ip, txt[instance], serviceType)...)
		}
	}
	return result, nil
}

func mdnsTXTObservations(ip string, records []string, service string) []collectedIdentity {
	allowed := map[string]string{"fn": "friendly_name", "name": "friendly_name", "md": "model", "model": "model", "manufacturer": "manufacturer", "ty": "device_type"}
	var result []collectedIdentity
	for _, record := range records {
		key, value, found := strings.Cut(record, "=")
		kind := allowed[strings.ToLower(key)]
		if !found || kind == "" || strings.TrimSpace(value) == "" {
			continue
		}
		result = append(result, collectedIdentity{IP: ip, Source: "mdns", Kind: kind, Value: value, Confidence: 75, Evidence: map[string]any{"service": service, "txt_key": key}})
	}
	return result
}

func collectSSDP(ctx context.Context, scanRange string) ([]collectedIdentity, error) {
	connection, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return nil, err
	}
	defer connection.Close()
	request := "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n"
	_ = connection.SetDeadline(time.Now().Add(collectorNetworkWindow))
	if _, err := connection.WriteToUDP([]byte(request), &net.UDPAddr{IP: net.ParseIP("239.255.255.250"), Port: 1900}); err != nil {
		return nil, err
	}
	client := restrictedHTTPClient(scanRange)
	seen := make(map[string]bool)
	var result []collectedIdentity
	buffer := make([]byte, maxCollectorPacketBytes)
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		n, remote, err := connection.ReadFromUDP(buffer)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				return result, nil
			}
			return result, err
		}
		headers := parseSSDPHeaders(buffer[:n])
		location := headers["location"]
		if location == "" || seen[location] || !ipWithinRange(remote.IP.String(), scanRange) {
			continue
		}
		seen[location] = true
		description, err := fetchSSDPDescription(ctx, client, location, scanRange)
		if err != nil {
			continue
		}
		result = append(result, ssdpDescriptionObservations(remote.IP.String(), description, headers["st"])...)
	}
}

func parseSSDPHeaders(packet []byte) map[string]string {
	headers := make(map[string]string)
	scanner := bufio.NewScanner(strings.NewReader(string(packet)))
	if !scanner.Scan() {
		return headers
	}
	for scanner.Scan() {
		line := scanner.Text()
		key, value, found := strings.Cut(line, ":")
		if found {
			headers[strings.ToLower(strings.TrimSpace(key))] = strings.TrimSpace(value)
		}
	}
	return headers
}

type ssdpDescription struct {
	FriendlyName string `xml:"device>friendlyName"`
	Manufacturer string `xml:"device>manufacturer"`
	ModelName    string `xml:"device>modelName"`
	DeviceType   string `xml:"device>deviceType"`
}

func restrictedHTTPClient(scanRange string) *http.Client {
	transport := &http.Transport{Proxy: nil, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		host, _, err := net.SplitHostPort(address)
		if err != nil || net.ParseIP(host) == nil || !ipWithinRange(host, scanRange) {
			return nil, errors.New("SSDP description target is outside the scan range")
		}
		return (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, network, address)
	}}
	return &http.Client{
		Transport: transport, Timeout: 3 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

func fetchSSDPDescription(ctx context.Context, client *http.Client, location, scanRange string) (ssdpDescription, error) {
	parsed, err := url.Parse(location)
	if err != nil || parsed.Scheme != "http" || net.ParseIP(parsed.Hostname()) == nil || !ipWithinRange(parsed.Hostname(), scanRange) {
		return ssdpDescription{}, errors.New("invalid SSDP description location")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, parsed.String(), nil)
	if err != nil {
		return ssdpDescription{}, err
	}
	response, err := client.Do(request)
	if err != nil {
		return ssdpDescription{}, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return ssdpDescription{}, fmt.Errorf("SSDP description returned status %d", response.StatusCode)
	}
	var description ssdpDescription
	decoder := xml.NewDecoder(io.LimitReader(response.Body, maxSSDPDescriptionBytes))
	if err := decoder.Decode(&description); err != nil {
		return ssdpDescription{}, err
	}
	return description, nil
}

func ssdpDescriptionObservations(ip string, description ssdpDescription, searchTarget string) []collectedIdentity {
	fields := []struct{ kind, value string }{
		{"friendly_name", description.FriendlyName}, {"manufacturer", description.Manufacturer},
		{"model", description.ModelName}, {"device_type", description.DeviceType},
	}
	var result []collectedIdentity
	for _, field := range fields {
		if strings.TrimSpace(field.value) != "" {
			result = append(result, collectedIdentity{IP: ip, Source: "ssdp", Kind: field.kind, Value: field.value, Confidence: 75, Evidence: map[string]any{"search_target": searchTarget}})
		}
	}
	return result
}

func ipWithinRange(ipString, scanRange string) bool {
	ip := net.ParseIP(ipString)
	if ip == nil || ip.To4() == nil {
		return false
	}
	if !strings.Contains(scanRange, "/") {
		return ip.Equal(net.ParseIP(scanRange))
	}
	_, network, err := net.ParseCIDR(scanRange)
	return err == nil && network.Contains(ip)
}
