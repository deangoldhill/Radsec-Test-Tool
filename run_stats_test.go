package main

import (
	"context"
	"errors"
	"radsec-windows-tester/protocol"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestRunStatsOutcomesAndPercentiles(t *testing.T) {
	s := newRunStats(6, time.Now().Add(-time.Second))
	for i, n := range []string{"Access-Accept", "Access-Reject", "Access-Challenge", "Accounting-Response"} {
		s.record(protocol.Result{Name: n, TLSVersion: 0x0304, Duration: time.Duration(i+1) * time.Millisecond}, nil)
	}
	s.record(protocol.Result{}, errors.New("response authenticator mismatch"))
	s.record(protocol.Result{}, context.Canceled)
	v := s.snapshot(time.Now())
	if v.Completed != 6 || v.Accept != 1 || v.Reject != 1 || v.Challenge != 1 || v.Accounting != 1 || v.Errors != 1 || v.Cancelled != 1 || v.P50 != 2*time.Millisecond || v.P95 != 4*time.Millisecond || v.TLS13 != 4 {
		t.Fatalf("unexpected stats: %+v", v)
	}
	if strings.Contains(v.String(), "response authenticator mismatch") {
		t.Fatal("raw error leaked")
	}
}
func TestRunCancellationStopsSchedulingAndAllowsNextRun(t *testing.T) {
	var started atomic.Int32
	entered := make(chan struct{})
	exchange := func(ctx context.Context) (protocol.Result, error) {
		started.Add(1)
		select {
		case entered <- struct{}{}:
		case <-ctx.Done():
		}
		<-ctx.Done()
		return protocol.Result{}, ctx.Err()
	}
	run := startRun(context.Background(), 100, 2, exchange, nil)
	<-entered
	run.Stop()
	v := run.Wait()
	if v.Completed != int(started.Load()) || v.InFlight != 0 || v.Cancelled == 0 || v.Planned != 100 || v.Completed >= 100 {
		t.Fatalf("cancellation: %+v started=%d", v, started.Load())
	}
	next := startRun(context.Background(), 1, 1, func(context.Context) (protocol.Result, error) {
		return protocol.Result{Name: "Access-Accept", Duration: time.Millisecond}, nil
	}, nil)
	if v := next.Wait(); v.Accept != 1 || v.Completed != 1 {
		t.Fatalf("next run: %+v", v)
	}
}
func TestRunLiveSnapshotAndCategories(t *testing.T) {
	ready := make(chan struct{})
	release := make(chan struct{})
	run := startRun(context.Background(), 2, 1, func(context.Context) (protocol.Result, error) {
		close(ready)
		<-release
		return protocol.Result{}, errors.New("dial tcp: secret path")
	}, nil)
	<-ready
	v := run.Snapshot()
	if v.Planned != 2 || v.InFlight != 1 || v.Completed != 0 {
		t.Fatalf("live: %+v", v)
	}
	run.Stop()
	close(release)
	v = run.Wait()
	if v.Errors != 1 || v.ErrorCategories["transport"] != 1 || strings.Contains(v.String(), "secret path") {
		t.Fatalf("safe categories: %+v", v)
	}
}
