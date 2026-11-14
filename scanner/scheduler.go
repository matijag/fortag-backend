package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

const (
	maxTargetedScanQueue = 64
	targetedJobLifetime  = 10 * time.Minute
	targetedJobCooldown  = 5 * time.Minute
)

var (
	ErrSchedulerStopped = errors.New("scan scheduler is stopped")
	ErrRoutineQueued    = errors.New("routine scan is already active or queued")
	ErrTargetQueued     = errors.New("targeted scan is already active or queued")
	ErrTargetCooldown   = errors.New("targeted scan completed too recently")
	ErrTargetQueueFull  = errors.New("targeted scan queue is full")
	ErrApprovalRequired = errors.New("MQTT connection or Home Assistant approval is unavailable")
)

var targetedJobSources = map[string]bool{"user": true, "dhcp": true, "ipv6_ndp": true}

type ScanJobKind string

const (
	ScanJobRoutine  ScanJobKind = "routine"
	ScanJobTargeted ScanJobKind = "targeted"
)

type ScanJob struct {
	ID            string      `json:"job_id"`
	Kind          ScanJobKind `json:"kind"`
	MAC           string      `json:"mac,omitempty"`
	IP            string      `json:"ip,omitempty"`
	Source        string      `json:"source"`
	CreatedAt     time.Time   `json:"created_at"`
	ExpiresAt     time.Time   `json:"expires_at,omitempty"`
	QueuePosition int         `json:"queue_position,omitempty"`
}

type SchedulerSnapshot struct {
	Active *ScanJob  `json:"active_job"`
	Queue  []ScanJob `json:"queue"`
}

type ScanScheduler struct {
	mu             sync.Mutex
	queue          []ScanJob
	active         *ScanJob
	recentTargets  map[string]time.Time
	wake           chan struct{}
	done           chan struct{}
	ctx            context.Context
	cancel         context.CancelFunc
	now            func() time.Time
	hasApproval    func() bool
	validateTarget func(string) error
	execute        func(context.Context, ScanJob) error
	observer       func(SchedulerSnapshot)
	started        bool
	stopped        bool
}

func (s *ScanScheduler) SetObserver(observer func(SchedulerSnapshot)) {
	s.mu.Lock()
	s.observer = observer
	snapshot := s.snapshotLocked()
	s.mu.Unlock()
	if observer != nil {
		observer(snapshot)
	}
}

func NewScanScheduler(
	hasApproval func() bool,
	validateTarget func(string) error,
	execute func(context.Context, ScanJob) error,
) *ScanScheduler {
	ctx, cancel := context.WithCancel(context.Background())
	return &ScanScheduler{
		recentTargets:  make(map[string]time.Time),
		wake:           make(chan struct{}, 1),
		done:           make(chan struct{}),
		ctx:            ctx,
		cancel:         cancel,
		now:            time.Now,
		hasApproval:    hasApproval,
		validateTarget: validateTarget,
		execute:        execute,
	}
}

func (s *ScanScheduler) Start() {
	s.mu.Lock()
	if s.started || s.stopped {
		s.mu.Unlock()
		return
	}
	s.started = true
	s.mu.Unlock()
	go s.run()
}

func (s *ScanScheduler) Stop() {
	s.mu.Lock()
	if s.stopped {
		s.mu.Unlock()
		return
	}
	s.stopped = true
	s.queue = nil
	started := s.started
	s.cancel()
	s.mu.Unlock()
	if started {
		<-s.done
	}
}

func (s *ScanScheduler) EnqueueRoutine() (ScanJob, error) {
	if !s.hasApproval() {
		return ScanJob{}, ErrApprovalRequired
	}
	s.mu.Lock()
	if s.stopped {
		s.mu.Unlock()
		return ScanJob{}, ErrSchedulerStopped
	}
	if (s.active != nil && s.active.Kind == ScanJobRoutine) || hasRoutineJob(s.queue) {
		s.mu.Unlock()
		return ScanJob{}, ErrRoutineQueued
	}
	job := ScanJob{ID: uuid.NewString(), Kind: ScanJobRoutine, Source: "routine", CreatedAt: s.now().UTC()}
	s.queue = append(s.queue, job)
	snapshot, observer := s.snapshotLocked(), s.observer
	s.mu.Unlock()
	s.signal()
	if observer != nil {
		observer(snapshot)
	}
	return job, nil
}

func (s *ScanScheduler) EnqueueTarget(mac, ip, source string) (ScanJob, error) {
	if !s.hasApproval() {
		return ScanJob{}, ErrApprovalRequired
	}
	if err := s.validateTarget(ip); err != nil {
		return ScanJob{}, err
	}
	if !targetedJobSources[source] {
		return ScanJob{}, fmt.Errorf("unknown targeted scan source %q", source)
	}
	mac = strings.TrimSpace(mac)
	if mac != "" {
		parsedMAC, err := net.ParseMAC(mac)
		if err != nil || len(parsedMAC) != 6 {
			return ScanJob{}, errors.New("targeted scan MAC is invalid")
		}
		mac = strings.ToUpper(parsedMAC.String())
	}
	ip = strings.TrimSpace(ip)
	key := targetJobKey(mac, ip)
	now := s.now().UTC()
	s.mu.Lock()
	if s.stopped {
		s.mu.Unlock()
		return ScanJob{}, ErrSchedulerStopped
	}
	s.purgeLocked(now)
	if s.active != nil && targetJobKey(s.active.MAC, s.active.IP) == key {
		s.mu.Unlock()
		return ScanJob{}, ErrTargetQueued
	}
	for _, queued := range s.queue {
		if queued.Kind == ScanJobTargeted && targetJobKey(queued.MAC, queued.IP) == key {
			s.mu.Unlock()
			return ScanJob{}, ErrTargetQueued
		}
	}
	if completedAt, ok := s.recentTargets[key]; ok && now.Sub(completedAt) < targetedJobCooldown {
		s.mu.Unlock()
		return ScanJob{}, ErrTargetCooldown
	}
	if targetedQueueLength(s.queue) >= maxTargetedScanQueue {
		s.mu.Unlock()
		return ScanJob{}, ErrTargetQueueFull
	}
	job := ScanJob{
		ID: uuid.NewString(), Kind: ScanJobTargeted, MAC: mac, IP: ip,
		Source: source, CreatedAt: now, ExpiresAt: now.Add(targetedJobLifetime),
		QueuePosition: len(s.queue) + 1,
	}
	s.queue = append(s.queue, job)
	snapshot, observer := s.snapshotLocked(), s.observer
	s.mu.Unlock()
	s.signal()
	if observer != nil {
		observer(snapshot)
	}
	return job, nil
}

func (s *ScanScheduler) run() {
	defer close(s.done)
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-s.wake:
		}
		for {
			job, ok := s.next()
			if !ok {
				break
			}
			if s.ctx.Err() != nil {
				return
			}
			_ = s.execute(s.ctx, job)
			s.finish(job)
		}
	}
}

func (s *ScanScheduler) next() (ScanJob, bool) {
	s.mu.Lock()
	now := s.now().UTC()
	s.purgeLocked(now)
	if !s.hasApproval() {
		s.queue = nil
		snapshot, observer := s.snapshotLocked(), s.observer
		s.mu.Unlock()
		if observer != nil {
			observer(snapshot)
		}
		return ScanJob{}, false
	}
	if len(s.queue) == 0 {
		s.mu.Unlock()
		return ScanJob{}, false
	}
	job := s.queue[0]
	s.queue = s.queue[1:]
	s.active = &job
	snapshot, observer := s.snapshotLocked(), s.observer
	s.mu.Unlock()
	if observer != nil {
		observer(snapshot)
	}
	return job, true
}

func (s *ScanScheduler) finish(job ScanJob) {
	s.mu.Lock()
	if job.Kind == ScanJobTargeted {
		s.recentTargets[targetJobKey(job.MAC, job.IP)] = s.now().UTC()
	}
	s.active = nil
	snapshot, observer := s.snapshotLocked(), s.observer
	s.mu.Unlock()
	if observer != nil {
		observer(snapshot)
	}
}

func (s *ScanScheduler) snapshotLocked() SchedulerSnapshot {
	snapshot := SchedulerSnapshot{Queue: append([]ScanJob(nil), s.queue...)}
	for index := range snapshot.Queue {
		snapshot.Queue[index].QueuePosition = index + 1
	}
	if s.active != nil {
		active := *s.active
		snapshot.Active = &active
	}
	return snapshot
}

func (s *ScanScheduler) purgeLocked(now time.Time) {
	kept := s.queue[:0]
	for _, job := range s.queue {
		if job.Kind != ScanJobTargeted || now.Before(job.ExpiresAt) {
			kept = append(kept, job)
		}
	}
	s.queue = kept
	for key, completedAt := range s.recentTargets {
		if now.Sub(completedAt) >= targetedJobCooldown {
			delete(s.recentTargets, key)
		}
	}
}

func (s *ScanScheduler) signal() {
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

func hasRoutineJob(queue []ScanJob) bool {
	for _, job := range queue {
		if job.Kind == ScanJobRoutine {
			return true
		}
	}
	return false
}

func targetedQueueLength(queue []ScanJob) int {
	count := 0
	for _, job := range queue {
		if job.Kind == ScanJobTargeted {
			count++
		}
	}
	return count
}

func targetJobKey(mac, ip string) string {
	if strings.TrimSpace(mac) != "" {
		return "mac:" + strings.ToUpper(strings.TrimSpace(mac))
	}
	return "ip:" + strings.TrimSpace(ip)
}

func targetWithinRange(target, scanRange string) error {
	if err := ValidateScanTarget(target); err != nil {
		return err
	}
	if strings.Contains(target, "/") {
		return errors.New("targeted scan requires one IPv4 address")
	}
	var network *net.IPNet
	if strings.Contains(scanRange, "/") {
		_, parsed, err := net.ParseCIDR(scanRange)
		if err != nil {
			return fmt.Errorf("configured scan range is invalid: %w", err)
		}
		network = parsed
	} else {
		configuredIP := net.ParseIP(scanRange)
		if configuredIP == nil || configuredIP.To4() == nil {
			return errors.New("configured scan range is not IPv4")
		}
		network = &net.IPNet{IP: configuredIP.To4(), Mask: net.CIDRMask(32, 32)}
	}
	ip := net.ParseIP(target)
	if ip == nil || !network.Contains(ip) {
		return fmt.Errorf("target %s is outside configured scan range %s", target, scanRange)
	}
	return nil
}
