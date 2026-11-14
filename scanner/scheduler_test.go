package main

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestSchedulerSerializesRoutineAndTargetedJobs(t *testing.T) {
	firstStarted := make(chan struct{})
	releaseFirst := make(chan struct{})
	var mu sync.Mutex
	var executed []ScanJob
	scheduler := NewScanScheduler(
		func() bool { return true },
		func(string) error { return nil },
		func(ctx context.Context, job ScanJob) error {
			mu.Lock()
			executed = append(executed, job)
			position := len(executed)
			mu.Unlock()
			if position == 1 {
				close(firstStarted)
				select {
				case <-releaseFirst:
				case <-ctx.Done():
				}
			}
			return nil
		},
	)
	scheduler.Start()
	defer scheduler.Stop()
	if _, err := scheduler.EnqueueRoutine(); err != nil {
		t.Fatal(err)
	}
	<-firstStarted
	if _, err := scheduler.EnqueueTarget("00:11:22:33:44:55", "192.168.1.5", "user"); err != nil {
		t.Fatal(err)
	}
	if _, err := scheduler.EnqueueTarget("00:11:22:33:44:66", "192.168.1.6", "dhcp"); err != nil {
		t.Fatal(err)
	}
	close(releaseFirst)
	waitForScheduler(t, scheduler)
	mu.Lock()
	defer mu.Unlock()
	if len(executed) != 3 || executed[0].Kind != ScanJobRoutine || executed[1].IP != "192.168.1.5" || executed[2].IP != "192.168.1.6" {
		t.Fatalf("execution order = %#v", executed)
	}
}

func TestSchedulerCoalescesAndCoolsDownTargets(t *testing.T) {
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	started := make(chan struct{})
	release := make(chan struct{})
	scheduler := NewScanScheduler(
		func() bool { return true }, func(string) error { return nil },
		func(ctx context.Context, _ ScanJob) error {
			close(started)
			select {
			case <-release:
			case <-ctx.Done():
			}
			return nil
		},
	)
	scheduler.now = func() time.Time { return now }
	scheduler.Start()
	defer scheduler.Stop()
	if _, err := scheduler.EnqueueTarget("00:11:22:33:44:55", "192.168.1.5", "user"); err != nil {
		t.Fatal(err)
	}
	<-started
	if _, err := scheduler.EnqueueTarget("00:11:22:33:44:55", "192.168.1.99", "dhcp"); !errors.Is(err, ErrTargetQueued) {
		t.Fatalf("duplicate active target error = %v", err)
	}
	close(release)
	waitForScheduler(t, scheduler)
	if _, err := scheduler.EnqueueTarget("00:11:22:33:44:55", "192.168.1.5", "user"); !errors.Is(err, ErrTargetCooldown) {
		t.Fatalf("cooldown error = %v", err)
	}
	now = now.Add(targetedJobCooldown)
	if _, err := scheduler.EnqueueTarget("00:11:22:33:44:55", "192.168.1.5", "user"); err != nil {
		t.Fatalf("target was not accepted after cooldown: %v", err)
	}
}

func TestSchedulerDropsExpiredOrUnapprovedQueuedJobs(t *testing.T) {
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	approved := true
	var executed int
	scheduler := NewScanScheduler(
		func() bool { return approved }, func(string) error { return nil },
		func(context.Context, ScanJob) error { executed++; return nil },
	)
	scheduler.now = func() time.Time { return now }
	if _, err := scheduler.EnqueueTarget("", "192.168.1.5", "dhcp"); err != nil {
		t.Fatal(err)
	}
	now = now.Add(targetedJobLifetime)
	scheduler.Start()
	waitForScheduler(t, scheduler)
	if executed != 0 {
		t.Fatal("expired target was executed")
	}
	scheduler.Stop()

	scheduler = NewScanScheduler(
		func() bool { return approved }, func(string) error { return nil },
		func(context.Context, ScanJob) error { executed++; return nil },
	)
	approved = true
	if _, err := scheduler.EnqueueRoutine(); err != nil {
		t.Fatal(err)
	}
	approved = false
	scheduler.Start()
	waitForScheduler(t, scheduler)
	scheduler.Stop()
	if executed != 0 {
		t.Fatal("unapproved routine was executed")
	}
}

func TestSchedulerStopCancelsActiveJob(t *testing.T) {
	started := make(chan struct{})
	cancelled := make(chan struct{})
	scheduler := NewScanScheduler(
		func() bool { return true }, func(string) error { return nil },
		func(ctx context.Context, _ ScanJob) error {
			close(started)
			<-ctx.Done()
			close(cancelled)
			return ctx.Err()
		},
	)
	scheduler.Start()
	if _, err := scheduler.EnqueueRoutine(); err != nil {
		t.Fatal(err)
	}
	<-started
	scheduler.Stop()
	select {
	case <-cancelled:
	default:
		t.Fatal("active job was not cancelled")
	}
}

func TestTargetWithinRange(t *testing.T) {
	if err := targetWithinRange("192.168.1.20", "192.168.1.0/24"); err != nil {
		t.Fatal(err)
	}
	if err := targetWithinRange("192.168.2.20", "192.168.1.0/24"); err == nil {
		t.Fatal("outside target was accepted")
	}
	if err := targetWithinRange("192.168.1.0/24", "192.168.1.0/24"); err == nil {
		t.Fatal("CIDR target was accepted for a targeted scan")
	}
}

func TestSchedulerRejectsInvalidTargetMetadata(t *testing.T) {
	scheduler := NewScanScheduler(
		func() bool { return true }, func(string) error { return nil },
		func(context.Context, ScanJob) error { return nil },
	)
	defer scheduler.Stop()
	if _, err := scheduler.EnqueueTarget("not-a-mac", "192.168.1.5", "user"); err == nil {
		t.Fatal("invalid MAC was accepted")
	}
	if _, err := scheduler.EnqueueTarget("", "192.168.1.5", "unknown"); err == nil {
		t.Fatal("invalid source was accepted")
	}
}

func TestSchedulerBoundsTargetQueueAndRoutineRequests(t *testing.T) {
	scheduler := NewScanScheduler(
		func() bool { return true }, func(string) error { return nil },
		func(context.Context, ScanJob) error { return nil },
	)
	defer scheduler.Stop()
	if _, err := scheduler.EnqueueRoutine(); err != nil {
		t.Fatal(err)
	}
	if _, err := scheduler.EnqueueRoutine(); !errors.Is(err, ErrRoutineQueued) {
		t.Fatalf("duplicate routine error = %v", err)
	}
	for i := 0; i < maxTargetedScanQueue; i++ {
		mac := fmt.Sprintf("02:00:00:00:%02X:%02X", i/256, i%256)
		if _, err := scheduler.EnqueueTarget(mac, fmt.Sprintf("192.168.1.%d", i+1), "dhcp"); err != nil {
			t.Fatalf("target %d was rejected: %v", i, err)
		}
	}
	if _, err := scheduler.EnqueueTarget("02:00:00:01:00:00", "192.168.2.1", "dhcp"); !errors.Is(err, ErrTargetQueueFull) {
		t.Fatalf("full queue error = %v", err)
	}
}

func TestSchedulerContinuesAfterExecutorFailure(t *testing.T) {
	var executed int
	scheduler := NewScanScheduler(
		func() bool { return true }, func(string) error { return nil },
		func(context.Context, ScanJob) error {
			executed++
			if executed == 1 {
				return errors.New("database unavailable")
			}
			return nil
		},
	)
	scheduler.Start()
	defer scheduler.Stop()
	if _, err := scheduler.EnqueueTarget("02:00:00:00:00:01", "192.168.1.5", "dhcp"); err != nil {
		t.Fatal(err)
	}
	if _, err := scheduler.EnqueueTarget("02:00:00:00:00:02", "192.168.1.6", "dhcp"); err != nil {
		t.Fatal(err)
	}
	waitForScheduler(t, scheduler)
	if executed != 2 {
		t.Fatalf("executed %d jobs, want 2", executed)
	}
}

func waitForScheduler(t *testing.T, scheduler *ScanScheduler) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		scheduler.mu.Lock()
		idle := scheduler.active == nil && len(scheduler.queue) == 0
		scheduler.mu.Unlock()
		if idle {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("scheduler did not become idle")
}
