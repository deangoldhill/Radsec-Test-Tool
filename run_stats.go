package main

import (
	"context"
	"errors"
	"fmt"
	"radsec-windows-tester/protocol"
	"sort"
	"strings"
	"sync"
	"time"
)

// Snapshot fields are protected by Run.mu. Latencies sample verified RADIUS responses only.
type RunSnapshot struct {
	Planned, Completed, InFlight, Accept, Reject, Challenge, Accounting, Full, Other, Errors, Cancelled, Malformed int
	TLS12, TLS13, TLSUnknown                                                                                       int
	ErrorCategories                                                                                                map[string]int
	Min, Avg, P50, P90, P95, P99, Max                                                                              time.Duration
	Elapsed                                                                                                        time.Duration
	Throughput, TransportSuccessRate, AuthAcceptRate                                                               float64
	Stopped, Finished                                                                                              bool
	Detail                                                                                                         detailData
}

func (s RunSnapshot) String() string {
	categories := make([]string, 0, len(s.ErrorCategories))
	for k := range s.ErrorCategories {
		categories = append(categories, k)
	}
	sort.Strings(categories)
	var counts []string
	for _, k := range categories {
		counts = append(counts, fmt.Sprintf("%s=%d", k, s.ErrorCategories[k]))
	}
	return fmt.Sprintf("Planned %d | Completed %d | In-flight %d | Not started %d\r\nAccept %d | Reject %d | Challenge %d | Accounting %d | Full %d | Other %d | Errors %d | Cancelled in-flight %d\r\nTransport success %.1f%% (verified/completed) | Auth accept %.1f%% (accept/completed auth)\r\nLatency (verified responses only, n=%d): min %s | avg %s | p50 %s | p90 %s | p95 %s | p99 %s | max %s\r\nElapsed %s | Throughput %.1f completed/s\r\nTLS on verified responses: 1.2=%d | 1.3=%d | unknown=%d\r\nError categories: %s", s.Planned, s.Completed, s.InFlight, s.Planned-s.Completed-s.InFlight, s.Accept, s.Reject, s.Challenge, s.Accounting, s.Full, s.Other, s.Errors, s.Cancelled, s.TransportSuccessRate, s.AuthAcceptRate, s.Accept+s.Reject+s.Challenge+s.Accounting+s.Full+s.Other, s.Min, s.Avg, s.P50, s.P90, s.P95, s.P99, s.Max, s.Elapsed.Round(time.Millisecond), s.Throughput, s.TLS12, s.TLS13, s.TLSUnknown, strings.Join(counts, ", "))
}

type Run struct {
	mu           sync.Mutex
	snapshotData RunSnapshot
	samples      []time.Duration
	detail       detailData
	started      time.Time
	ended        time.Time
	cancel       context.CancelFunc
	done         chan struct{}
	onUpdate     func()
}

func newRunStats(count int, started time.Time) *Run {
	return &Run{snapshotData: RunSnapshot{Planned: count, ErrorCategories: map[string]int{}}, started: started, done: make(chan struct{})}
}
func (r *Run) notify() {
	if r.onUpdate != nil {
		r.onUpdate()
	}
}
func (r *Run) record(result protocol.Result, err error) {
	r.mu.Lock()
	s := &r.snapshotData
	s.Completed++
	r.detail.record(result.Observations, err == nil)
	if s.InFlight > 0 {
		s.InFlight--
	}
	if err != nil {
		if errors.Is(err, context.Canceled) {
			s.Cancelled++
		} else {
			s.Errors++
			s.ErrorCategories[errorCategory(err)]++
			if strings.Contains(err.Error(), "invalid RADIUS length") || strings.Contains(err.Error(), "malformed RADIUS attributes") {
				s.Malformed++
			}
		}
	} else {
		switch result.Name {
		case "Access-Accept":
			s.Accept++
		case "Access-Reject":
			s.Reject++
		case "Access-Challenge":
			s.Challenge++
		case "Accounting-Response":
			s.Accounting++
		case "Full transaction":
			s.Full++
		default:
			s.Other++
		}
		r.samples = append(r.samples, result.Duration)
		switch result.TLSVersion {
		case 0x0303:
			s.TLS12++
		case 0x0304:
			s.TLS13++
		default:
			s.TLSUnknown++
		}
	}
	r.mu.Unlock()
	r.notify()
}
func errorCategory(err error) string {
	if responseValidationError(err) {
		return "response validation"
	}
	msg := safeExchangeError(err)
	switch {
	case strings.HasPrefix(msg, "TLS trust"), strings.HasPrefix(msg, "TLS hostname"), strings.HasPrefix(msg, "TLS certificate"), strings.HasPrefix(msg, "TLS server"):
		return "TLS certificate"
	case strings.HasPrefix(msg, "DNS"):
		return "DNS"
	case strings.Contains(msg, "timed out"):
		return "timeout"
	case strings.HasPrefix(msg, "TCP connection refused"):
		return "connection refused"
	default:
		return "transport"
	}
}
func quantile(sorted []time.Duration, p int) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	index := (len(sorted)*p+99)/100 - 1
	if index < 0 {
		index = 0
	}
	return sorted[index]
}
func (r *Run) snapshot(now time.Time) RunSnapshot {
	r.mu.Lock()
	defer r.mu.Unlock()
	s := r.snapshotData
	s.ErrorCategories = make(map[string]int, len(r.snapshotData.ErrorCategories))
	for k, v := range r.snapshotData.ErrorCategories {
		s.ErrorCategories[k] = v
	}
	if !r.ended.IsZero() {
		now = r.ended
	}
	s.Elapsed = now.Sub(r.started)
	if s.Elapsed < 0 {
		s.Elapsed = 0
	}
	if s.Elapsed > 0 {
		s.Throughput = float64(s.Completed) / s.Elapsed.Seconds()
	}
	n := s.Accept + s.Reject + s.Challenge + s.Accounting + s.Full + s.Other
	if s.Completed > 0 {
		s.TransportSuccessRate = float64(n) * 100 / float64(s.Completed)
	}
	auth := s.Accept + s.Reject + s.Challenge
	if auth > 0 {
		s.AuthAcceptRate = float64(s.Accept) * 100 / float64(auth)
	}
	if len(r.samples) > 0 {
		v := append([]time.Duration(nil), r.samples...)
		sort.Slice(v, func(i, j int) bool { return v[i] < v[j] })
		s.Min = v[0]
		s.Max = v[len(v)-1]
		var total time.Duration
		for _, x := range v {
			total += x
		}
		s.Avg = total / time.Duration(len(v))
		s.P50 = quantile(v, 50)
		s.P90 = quantile(v, 90)
		s.P95 = quantile(v, 95)
		s.P99 = quantile(v, 99)
	}
	s.Detail = r.detail.copy()
	s.Detail.latencies = append([]time.Duration(nil), r.samples...)
	return s
}
func (r *Run) Snapshot() RunSnapshot { return r.snapshot(time.Now()) }
func (r *Run) Stop() {
	r.mu.Lock()
	r.snapshotData.Stopped = true
	cancel := r.cancel
	r.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	r.notify()
}
func (r *Run) Wait() RunSnapshot { <-r.done; return r.Snapshot() }
func startRun(parent context.Context, count, workers int, exchange func(context.Context) (protocol.Result, error), onUpdate func()) *Run {
	ctx, cancel := context.WithCancel(parent)
	r := newRunStats(count, time.Now())
	r.cancel = cancel
	r.onUpdate = onUpdate
	if workers < 1 {
		workers = 1
	}
	if workers > count {
		workers = count
	}
	go func() {
		defer close(r.done)
		defer cancel()
		jobs := make(chan struct{})
		var wg sync.WaitGroup
		for i := 0; i < workers; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for range jobs {
					r.mu.Lock()
					r.snapshotData.InFlight++
					r.mu.Unlock()
					r.notify()
					res, err := exchange(ctx)
					r.record(res, err)
				}
			}()
		}
	dispatch:
		for i := 0; i < count; i++ {
			select {
			case <-ctx.Done():
				break dispatch
			default:
			}
			select {
			case <-ctx.Done():
				break dispatch
			case jobs <- struct{}{}:
			}
		}
		close(jobs)
		wg.Wait()
		r.mu.Lock()
		r.snapshotData.Finished = true
		r.ended = time.Now()
		r.mu.Unlock()
		r.notify()
	}()
	return r
}
