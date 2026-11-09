package main

import (
	"context"
	cryptorand "crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	mathrand "math/rand"
	"net"
	"os"
	"sync"
	"syscall"
	"time"
)

const (
	tcpFlagRST = 0x04
	tcpFlagSYN = 0x02
	tcpFlagACK = 0x10
)

type synProbe struct {
	target string
	port   int
}

func (e *NativeEngine) scanSYNBatch(ctx context.Context, requests []PortScanRequest, ports []int, rate, perHostRate int, timeout time.Duration, retries int) (map[string][]int, error) {
	targetIPs := make(map[string]net.IP, len(requests))
	var sourceIP net.IP
	for _, request := range requests {
		targetIP := net.ParseIP(request.Target).To4()
		routeIP, err := routeSourceIPv4(targetIP)
		if err != nil {
			return nil, err
		}
		if sourceIP == nil {
			sourceIP = routeIP
		} else if !sourceIP.Equal(routeIP) {
			return nil, errors.New("batch targets use different source interfaces")
		}
		targetIPs[request.Target] = targetIP
	}
	conn, err := net.ListenIP("ip4:tcp", &net.IPAddr{IP: sourceIP})
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	sourcePort, sequence, err := synIdentity()
	if err != nil {
		return nil, err
	}
	states := make(map[synProbe]byte, len(ports)*len(requests))
	var statesMu sync.Mutex
	readDone := make(chan error, 1)
	go func() {
		buffer := make([]byte, 64)
		for {
			if err := conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond)); err != nil {
				readDone <- err
				return
			}
			n, address, readErr := conn.ReadFromIP(buffer)
			if readErr != nil {
				if errors.Is(readErr, os.ErrDeadlineExceeded) {
					if ctx.Err() != nil {
						readDone <- ctx.Err()
						return
					}
					continue
				}
				readDone <- readErr
				return
			}
			target := address.IP.To4().String()
			targetIP, expected := targetIPs[target]
			if !expected {
				continue
			}
			port, state, ok := parseSYNResponse(buffer[:n], address.IP, targetIP, sourcePort, synSequence(sequence, targetIP, 0))
			if ok {
				statesMu.Lock()
				recordSYNState(states, synProbe{target: target, port: port}, state)
				statesMu.Unlock()
			}
		}
	}()

	interval := time.Second / time.Duration(rate)
	hostInterval := time.Second / time.Duration(perHostRate)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	lastSend := make(map[string]time.Time, len(requests))
	for attempt := 0; attempt < retries; attempt++ {
		statesMu.Lock()
		pending := pendingSYNProbes(requests, ports, attempt, sequence, states)
		statesMu.Unlock()
		if len(pending) == 0 {
			break
		}
		for i, probe := range pending {
			select {
			case <-ticker.C:
			case <-ctx.Done():
				return nil, ctx.Err()
			case readErr := <-readDone:
				return nil, readErr
			}
			if wait := time.Until(lastSend[probe.target].Add(hostInterval)); !lastSend[probe.target].IsZero() && wait > 0 {
				timer := time.NewTimer(wait)
				select {
				case <-timer.C:
				case <-ctx.Done():
					timer.Stop()
					return nil, ctx.Err()
				}
			}
			targetIP := targetIPs[probe.target]
			packet := tcpSYNPacket(sourceIP, targetIP, sourcePort, probe.port, synSequence(sequence, targetIP, probe.port))
			if _, err := conn.WriteToIP(packet, &net.IPAddr{IP: targetIP}); err != nil {
				return nil, err
			}
			lastSend[probe.target] = time.Now()
			if requests[0].Progress != nil && (i+1)%nativeProgressInterval == 0 {
				requests[0].Progress(EngineProgress{Phase: "scan", Target: probe.target})
			}
		}
		select {
		case <-time.After(timeout):
		case <-ctx.Done():
			return nil, ctx.Err()
		case readErr := <-readDone:
			return nil, readErr
		}
	}

	statesMu.Lock()
	open := make(map[string][]int, len(requests))
	for _, request := range requests {
		for _, port := range ports {
			if states[synProbe{target: request.Target, port: port}] == 1 {
				open[request.Target] = append(open[request.Target], port)
			}
		}
	}
	statesMu.Unlock()
	return open, nil
}

func pendingSYNProbes(requests []PortScanRequest, ports []int, attempt int, seed uint32, states map[synProbe]byte) []synProbe {
	pending := make([]synProbe, 0, len(ports)*len(requests))
	priority := make(map[synProbe]bool)
	for _, request := range requests {
		for _, port := range request.PriorityPorts {
			probe := synProbe{target: request.Target, port: port}
			priority[probe] = true
			if states[probe] == 0 {
				pending = append(pending, probe)
			}
		}
	}
	pendingPorts := append([]int(nil), ports...)
	if attempt > 0 {
		end := 0
		for end < len(pendingPorts) && pendingPorts[end] <= 1024 {
			end++
		}
		pendingPorts = pendingPorts[:end]
	}
	lowEnd := 0
	for lowEnd < len(pendingPorts) && pendingPorts[lowEnd] <= 1024 {
		lowEnd++
	}
	random := mathrand.New(mathrand.NewSource(int64(seed) + int64(attempt)))
	random.Shuffle(len(pendingPorts)-lowEnd, func(i, j int) {
		pendingPorts[lowEnd+i], pendingPorts[lowEnd+j] = pendingPorts[lowEnd+j], pendingPorts[lowEnd+i]
	})
	for _, port := range pendingPorts {
		for _, request := range requests {
			probe := synProbe{target: request.Target, port: port}
			if states[probe] == 0 && !priority[probe] {
				pending = append(pending, probe)
			}
		}
	}
	return pending
}

func recordSYNState(states map[synProbe]byte, probe synProbe, state byte) {
	if state == 1 || states[probe] == 0 {
		states[probe] = state
	}
}

func synSequence(base uint32, target net.IP, port int) uint32 {
	return (base ^ ipv4Number(target)) + uint32(port)
}

func routeSourceIPv4(target net.IP) (net.IP, error) {
	conn, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: target, Port: 9})
	if err != nil {
		return nil, fmt.Errorf("determine source address: %w", err)
	}
	defer conn.Close()
	ip := conn.LocalAddr().(*net.UDPAddr).IP.To4()
	if ip == nil {
		return nil, errors.New("route has no IPv4 source address")
	}
	return ip, nil
}

func synIdentity() (uint16, uint32, error) {
	var value [6]byte
	if _, err := cryptorand.Read(value[:]); err != nil {
		return 0, 0, err
	}
	port := uint16(32768 + binary.BigEndian.Uint16(value[:2])%28232)
	return port, binary.BigEndian.Uint32(value[2:]), nil
}

func tcpSYNPacket(sourceIP, targetIP net.IP, sourcePort uint16, targetPort int, sequence uint32) []byte {
	packet := make([]byte, 20)
	binary.BigEndian.PutUint16(packet[0:2], sourcePort)
	binary.BigEndian.PutUint16(packet[2:4], uint16(targetPort))
	binary.BigEndian.PutUint32(packet[4:8], sequence)
	packet[12] = 5 << 4
	packet[13] = tcpFlagSYN
	binary.BigEndian.PutUint16(packet[14:16], 64240)
	binary.BigEndian.PutUint16(packet[16:18], tcpChecksum(sourceIP, targetIP, packet))
	return packet
}

func parseSYNResponse(packet []byte, sourceIP, targetIP net.IP, destinationPort uint16, sequence uint32) (int, byte, bool) {
	if len(packet) < 20 || !sourceIP.Equal(targetIP) || binary.BigEndian.Uint16(packet[2:4]) != destinationPort {
		return 0, 0, false
	}
	port := int(binary.BigEndian.Uint16(packet[0:2]))
	if port < 1 || binary.BigEndian.Uint32(packet[8:12]) != sequence+uint32(port)+1 {
		return 0, 0, false
	}
	flags := packet[13]
	if flags&(tcpFlagSYN|tcpFlagACK) == tcpFlagSYN|tcpFlagACK {
		return port, 1, true
	}
	if flags&tcpFlagRST != 0 {
		return port, 2, true
	}
	return 0, 0, false
}

func tcpChecksum(sourceIP, targetIP net.IP, packet []byte) uint16 {
	sum := uint32(6 + len(packet))
	for _, ip := range []net.IP{sourceIP.To4(), targetIP.To4()} {
		for i := 0; i < len(ip); i += 2 {
			sum += uint32(binary.BigEndian.Uint16(ip[i : i+2]))
		}
	}
	for i := 0; i < len(packet); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(packet[i : i+2]))
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}

func rawSocketUnavailable(err error) bool {
	return errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) ||
		errors.Is(err, syscall.EAFNOSUPPORT) || errors.Is(err, syscall.EPROTONOSUPPORT)
}
