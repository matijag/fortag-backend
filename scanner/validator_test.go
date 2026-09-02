package main

import (
	"strings"
	"testing"
)

func TestIsRFC1918(t *testing.T) {
	tests := []struct {
		target string
		want   bool
	}{
		{"192.168.1.1", true},
		{"10.0.0.50", true},
		{"172.16.0.100", true},
		{"172.31.255.255", true},
		{"192.168.0.0/24", true},
		{"10.0.0.0/8", true},
		{"172.16.0.0/12", true},
		{"192.168.0.0/16", true},
		{"10.0.0.0/1", false},
		{"10.0.0.0/7", false},
		{"172.16.0.0/10", false},
		{"192.168.0.0/8", false},
		{"192.168.0.0/15", false},
		{"8.8.8.8", false},
		{"1.1.1.1", false},
		{"172.32.0.1", false},
		{"192.169.1.1", false},
		{"google.com", false},
	}

	for _, tt := range tests {
		got, _ := IsRFC1918(tt.target)
		if got != tt.want {
			t.Errorf("IsRFC1918(%q) = %v; want %v", tt.target, got, tt.want)
		}
	}
}

func TestValidateScanTargetDescribesFailure(t *testing.T) {
	tests := []struct {
		target string
		want   string
	}{
		{"", "empty"},
		{"not-a-range", "not a valid IPv4 address or CIDR"},
		{"2001:db8::1", "IPv6"},
		{"8.8.8.8", "outside the supported private IPv4 ranges"},
		{"192.168.0.0/15", "extends outside the supported private IPv4 ranges"},
	}
	for _, tt := range tests {
		err := ValidateScanTarget(tt.target)
		if err == nil || !strings.Contains(err.Error(), tt.want) {
			t.Errorf("ValidateScanTarget(%q) error = %v, want text %q", tt.target, err, tt.want)
		}
	}
}
