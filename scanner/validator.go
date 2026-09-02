package main

import (
	"errors"
	"fmt"
	"net"
	"strings"
)

var rfc1918Networks = []*net.IPNet{
	mustParseCIDR("10.0.0.0/8"),
	mustParseCIDR("172.16.0.0/12"),
	mustParseCIDR("192.168.0.0/16"),
	mustParseCIDR("127.0.0.1/32"), // Allow loopback for testing
}

func mustParseCIDR(s string) *net.IPNet {
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		panic(err)
	}
	return n
}

// ValidateScanTarget checks that target is an IPv4 address or CIDR contained
// entirely within one of the ranges Fortag is allowed to scan.
func ValidateScanTarget(target string) error {
	target = strings.TrimSpace(target)
	if target == "" {
		return errors.New("scan range is empty")
	}

	// Try parsing as a single IP first
	ip := net.ParseIP(target)
	if ip != nil {
		if ip.To4() == nil {
			return fmt.Errorf("scan range %q is IPv6; only IPv4 targets are supported", target)
		}
		if !isIPInRFC1918(ip) {
			return fmt.Errorf("IP address %q is outside the supported private IPv4 ranges (10/8, 172.16/12, and 192.168/16)", target)
		}
		return nil
	}

	// Try parsing as CIDR
	_, ipNet, err := net.ParseCIDR(target)
	if err != nil {
		return fmt.Errorf("scan range %q is not a valid IPv4 address or CIDR: %w", target, err)
	}
	if ipNet.IP.To4() == nil {
		return fmt.Errorf("scan range %q is IPv6; only IPv4 targets are supported", target)
	}

	// Check if the entire network is within RFC1918
	for _, rfcNet := range rfc1918Networks {
		start := ipNet.IP.To4()
		if start == nil {
			continue
		}
		end := make(net.IP, net.IPv4len)
		for i := range start {
			end[i] = start[i] | ^ipNet.Mask[i]
		}
		ones, bits := ipNet.Mask.Size()
		rfcOnes, rfcBits := rfcNet.Mask.Size()
		if bits == rfcBits && ones >= rfcOnes && rfcNet.Contains(start) && rfcNet.Contains(end) {
			return nil
		}
	}

	return fmt.Errorf("CIDR %q extends outside the supported private IPv4 ranges (10/8, 172.16/12, and 192.168/16)", target)
}

// IsRFC1918 is retained for callers that need the former boolean interface.
func IsRFC1918(target string) (bool, error) {
	err := ValidateScanTarget(target)
	return err == nil, err
}

func isIPInRFC1918(ip net.IP) bool {
	for _, n := range rfc1918Networks {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// DetectLocalRFC1918 finds the first IPv4 RFC1918 network assigned to a local interface.
func DetectLocalRFC1918() (string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}

	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}

			ip := ipNet.IP.To4()
			if ip == nil {
				continue
			}

			if isIPInRFC1918(ip) {
				// Return the network in CIDR notation
				mask, _ := ipNet.Mask.Size()
				networkIP := ipNet.IP.Mask(ipNet.Mask)
				return fmt.Sprintf("%s/%d", networkIP.String(), mask), nil
			}
		}
	}

	return "", errors.New("auto-detection found no active non-loopback interface with an IPv4 address in 10/8, 172.16/12, or 192.168/16; use host networking or configure the range explicitly")
}
