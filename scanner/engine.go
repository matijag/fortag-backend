package main

import (
	"context"
	"fmt"
)

// ScanEngine is the internal boundary between scan orchestration and a concrete
// network scanner. Implementations must return Fortag-owned observations rather
// than exposing their native output format to persistence or MQTT code.
type ScanEngine interface {
	Name() string
	Capabilities() EngineCapabilities
	Discover(context.Context, DiscoveryRequest) (DiscoveryResult, error)
	Scan(context.Context, PortScanRequest) (EngineScanResult, error)
}

// BatchScanEngine lets an engine interleave probes across discovered hosts
// while preserving ScanEngine for adapters that only support one target.
type BatchScanEngine interface {
	ScanBatch(context.Context, []PortScanRequest) (EngineScanResult, error)
}

type EngineCapabilities struct {
	HostDiscovery bool
	MACAddresses  bool
	Hostnames     bool
	OS            bool
	Services      bool
	Scripts       bool
}

type DiscoveryRequest struct {
	Target   string
	Progress func(EngineProgress)
}

type DiscoveryResult struct {
	Targets []string
	Hosts   []DiscoveredHost
}

type DiscoveredHost struct {
	IP  string
	MAC string
}

type PortScanRequest struct {
	Target        string
	MAC           string
	PriorityPorts []int
	Progress      func(EngineProgress)
}

type EngineProgress struct {
	Phase   string
	Target  string
	Message string
}

type EngineScanResult struct {
	Hosts []ObservedHost
}

type ObservedHost struct {
	MAC                  string
	IP                   string
	Hostname             string
	OS                   string
	Ports                []ObservedPort
	ClearMissingMetadata bool
}

type ObservedPort struct {
	Port     int
	Protocol string
	State    string
	Service  string
	Scripts  []ObservedScript
}

type ObservedScript struct {
	ID     string
	Output string
}

type EngineErrorKind string

const (
	EngineErrorValidation EngineErrorKind = "validation"
	EngineErrorStart      EngineErrorKind = "start"
	EngineErrorExecution  EngineErrorKind = "execution"
	EngineErrorTimeout    EngineErrorKind = "timeout"
	EngineErrorCancelled  EngineErrorKind = "cancelled"
	EngineErrorOutput     EngineErrorKind = "output"
)

// EngineError gives the scheduler stable error categories without coupling it
// to executable-specific strings.
type EngineError struct {
	Engine string
	Kind   EngineErrorKind
	Op     string
	Target string
	Err    error
}

func (e *EngineError) Error() string {
	return fmt.Sprintf("%s %s %s: %v", e.Engine, e.Op, e.Target, e.Err)
}

func (e *EngineError) Unwrap() error { return e.Err }
