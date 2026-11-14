package main

import (
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func dnsName(t *testing.T, value string) dnsmessage.Name {
	t.Helper()
	name, err := dnsmessage.NewName(value)
	if err != nil {
		t.Fatal(err)
	}
	return name
}

func TestParseMDNSPacketProducesProvenancedObservations(t *testing.T) {
	host := dnsName(t, "printer.local.")
	instance := dnsName(t, "Office Printer._ipp._tcp.local.")
	service := dnsName(t, "_ipp._tcp.local.")
	message := dnsmessage.Message{Answers: []dnsmessage.Resource{
		{Header: dnsmessage.ResourceHeader{Name: service, Type: dnsmessage.TypePTR, Class: dnsmessage.ClassINET}, Body: &dnsmessage.PTRResource{PTR: instance}},
		{Header: dnsmessage.ResourceHeader{Name: instance, Type: dnsmessage.TypeSRV, Class: dnsmessage.ClassINET}, Body: &dnsmessage.SRVResource{Target: host, Port: 631}},
		{Header: dnsmessage.ResourceHeader{Name: instance, Type: dnsmessage.TypeTXT, Class: dnsmessage.ClassINET}, Body: &dnsmessage.TXTResource{TXT: []string{"md=Laser 2000", "adminurl=http://ignored"}}},
		{Header: dnsmessage.ResourceHeader{Name: host, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}, Body: &dnsmessage.AResource{A: [4]byte{192, 168, 1, 20}}},
	}}
	packet, err := message.Pack()
	if err != nil {
		t.Fatal(err)
	}
	observations, err := parseMDNSPacket(packet, "192.168.1.0/24")
	if err != nil {
		t.Fatal(err)
	}
	wanted := map[string]bool{"hostname:printer.local": false, "friendly_name:Office Printer": false, "service:_ipp._tcp.local": false, "model:Laser 2000": false}
	for _, observation := range observations {
		key := observation.Kind + ":" + observation.Value
		if _, ok := wanted[key]; ok {
			wanted[key] = true
		}
		if observation.Source != "mdns" || observation.IP != "192.168.1.20" {
			t.Fatalf("unexpected observation: %#v", observation)
		}
	}
	for key, found := range wanted {
		if !found {
			t.Errorf("missing %s in %#v", key, observations)
		}
	}
}

func TestSSDPDescriptionIsBoundedToLiteralInRangeAddress(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`<root><device><friendlyName>Living Room TV</friendlyName><manufacturer>Example</manufacturer><modelName>Model 1</modelName><deviceType>urn:schemas-upnp-org:device:MediaRenderer:1</deviceType></device></root>`))
	}))
	defer server.Close()
	description, err := fetchSSDPDescription(context.Background(), restrictedHTTPClient("127.0.0.1/32"), server.URL, "127.0.0.1/32")
	if err != nil {
		t.Fatal(err)
	}
	observations := ssdpDescriptionObservations("127.0.0.1", description, "upnp:rootdevice")
	if len(observations) != 4 || observations[0].Value != "Living Room TV" {
		t.Fatalf("observations = %#v", observations)
	}
	if _, err := fetchSSDPDescription(context.Background(), restrictedHTTPClient("192.168.1.0/24"), server.URL, "192.168.1.0/24"); err == nil {
		t.Fatal("out-of-range SSDP description was fetched")
	}
	if _, err := fetchSSDPDescription(context.Background(), restrictedHTTPClient("127.0.0.1/32"), "http://example.invalid/device.xml", "127.0.0.1/32"); err == nil {
		t.Fatal("hostname SSDP location was accepted")
	}
}

func TestCollectorManagerPersistsEachMatchedObservation(t *testing.T) {
	db, err := initDB(filepath.Join(t.TempDir(), "collectors.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mac := "00:11:22:33:44:55"
	if _, err := db.Exec("INSERT INTO hosts (mac, ip) VALUES (?, ?)", mac, "192.168.1.20"); err != nil {
		t.Fatal(err)
	}
	manager := newIdentityCollectorManager(db, func() (string, error) { return "192.168.1.0/24", nil }, nil)
	if err := manager.persist([]collectedIdentity{
		{IP: "192.168.1.20", Source: "mdns", Kind: "hostname", Value: "printer.local", Confidence: 70},
		{IP: "192.168.1.20", Source: "ssdp", Kind: "model", Value: "Laser 2000", Confidence: 75},
		{IP: "192.168.1.99", Source: "mdns", Kind: "hostname", Value: "unknown.local", Confidence: 70},
	}); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := db.QueryRow("SELECT count(*) FROM identity_observations WHERE mac = ?", mac).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Fatalf("stored %d observations, want 2", count)
	}
	if err := db.QueryRow("SELECT count(*) FROM pending_identity_observations WHERE observed_address = '192.168.1.99'").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("stored %d pending observations, want 1", count)
	}
	if _, err := ProcessScan(db, EngineScanResult{Hosts: []ObservedHost{{
		MAC: "00:11:22:33:44:99", IP: "192.168.1.99",
	}}}); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT count(*) FROM identity_observations
		WHERE mac = '00:11:22:33:44:99' AND source = 'mdns'`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("promoted %d observations, want 1", count)
	}
	selected, err := selectDisplayIdentity(db, mac, time.Now().UTC())
	if err != nil || selected.Value != "printer.local" || selected.Source != "mdns" {
		t.Fatalf("selected identity = %#v, %v", selected, err)
	}
}

func TestCollectorHealthDoesNotExposeRawNetworkErrors(t *testing.T) {
	manager := &identityCollectorManager{
		db:        nil,
		rangeFn:   func() (string, error) { return "", sql.ErrConnDone },
		enabled:   map[string]bool{"mdns": true, "ssdp": true},
		health:    make(map[string]collectorHealth),
		collectFn: map[string]func(context.Context, string) ([]collectedIdentity, error){},
	}
	manager.collect(context.Background())
	for _, health := range manager.Health() {
		if health.Status != "unavailable" || health.Message != "scan range is unavailable" {
			t.Fatalf("health = %#v", health)
		}
	}
}
