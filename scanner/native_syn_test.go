package main

import (
	"encoding/binary"
	"net"
	"testing"
)

func TestTCPSYNPacketChecksumAndResponseParsing(t *testing.T) {
	source := net.ParseIP("192.168.1.10")
	target := net.ParseIP("192.168.1.20")
	const sourcePort = 45678
	const targetPort = 443
	const sequence = 123456
	packet := tcpSYNPacket(source, target, sourcePort, targetPort, sequence+targetPort)
	if len(packet) != 20 || packet[13] != tcpFlagSYN || tcpChecksum(source, target, packet) != 0 {
		t.Fatalf("invalid SYN packet: %x", packet)
	}

	response := make([]byte, 20)
	binary.BigEndian.PutUint16(response[0:2], targetPort)
	binary.BigEndian.PutUint16(response[2:4], sourcePort)
	binary.BigEndian.PutUint32(response[8:12], sequence+targetPort+1)
	response[12] = 5 << 4
	response[13] = tcpFlagSYN | tcpFlagACK
	port, state, ok := parseSYNResponse(response, target, target, sourcePort, sequence)
	if !ok || port != targetPort || state != 1 {
		t.Fatalf("response = port %d state %d ok %v", port, state, ok)
	}
	response[13] = tcpFlagRST | tcpFlagACK
	_, state, ok = parseSYNResponse(response, target, target, sourcePort, sequence)
	if !ok || state != 2 {
		t.Fatalf("RST response = state %d ok %v", state, ok)
	}
	response[8]++
	if _, _, ok := parseSYNResponse(response, target, target, sourcePort, sequence); ok {
		t.Fatal("accepted response with wrong acknowledgement")
	}
}

func TestSYNOpenStateCannotBeDowngraded(t *testing.T) {
	states := make(map[synProbe]byte)
	probe := synProbe{target: "192.168.1.20", port: 443}
	recordSYNState(states, probe, 1)
	recordSYNState(states, probe, 2)
	if states[probe] != 1 {
		t.Fatalf("state = %d, want open", states[probe])
	}
}

func TestSYNProbesAreMultiplexedByPortAcrossHosts(t *testing.T) {
	requests := []PortScanRequest{{Target: "192.168.1.10"}, {Target: "192.168.1.20"}}
	got := pendingSYNProbes(requests, []int{1, 2}, 0, 1, map[synProbe]byte{})
	want := []synProbe{{"192.168.1.10", 1}, {"192.168.1.20", 1}, {"192.168.1.10", 2}, {"192.168.1.20", 2}}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("probe %d = %#v, want %#v", i, got[i], want[i])
		}
	}
}

func TestSYNPreviouslyObservedPortsAreProbedFirst(t *testing.T) {
	requests := []PortScanRequest{{Target: "192.168.1.10", PriorityPorts: []int{49153}}, {Target: "192.168.1.20", PriorityPorts: []int{22000}}}
	got := pendingSYNProbes(requests, []int{1, 22000, 49153}, 0, 1, map[synProbe]byte{})
	want := []synProbe{{"192.168.1.10", 49153}, {"192.168.1.20", 22000}}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("priority probe %d = %#v, want %#v", i, got[i], want[i])
		}
	}
}
