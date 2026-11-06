package main

import (
	"errors"
	"radsec-windows-tester/protocol"
	"strings"
	"testing"
	"time"
)

func TestDetailedStatsAreObservedOnly(t *testing.T) {
	r := newRunStats(3, time.Now().Add(-time.Second))
	r.record(protocol.Result{Name: "Access-Accept", Duration: 30 * time.Millisecond, Observations: protocol.Observations{Phases: map[string]time.Duration{"prepare": 2 * time.Millisecond, "tcp dial": 3 * time.Millisecond, "tls handshake": 5 * time.Millisecond, "request write": 7 * time.Millisecond, "response read": 11 * time.Millisecond, "response verify": 13 * time.Millisecond}, RequestBytes: 78, ResponseBytes: 30, ResponseAttributes: 2, TLSResumed: false, TLSObserved: true, PeerCerts: 2, ConnectionChecks: 1}}, nil)
	r.record(protocol.Result{Name: "Access-Reject", Duration: 50 * time.Millisecond, Observations: protocol.Observations{Phases: map[string]time.Duration{"prepare": 4 * time.Millisecond, "tcp dial": 6 * time.Millisecond, "tls handshake": 8 * time.Millisecond, "request write": 10 * time.Millisecond, "response read": 12 * time.Millisecond, "response verify": 14 * time.Millisecond}, RequestBytes: 80, ResponseBytes: 40, ResponseAttributes: 3, TLSResumed: true, TLSObserved: true, PeerCerts: 1}}, nil)
	s := r.Snapshot()
	detail := s.Detailed()
	for _, part := range []string{"prepare samples: 2", "prepare min: 2ms", "prepare mean: 3ms", "tcp dial max: 6ms", "response verify p50: 13ms", "request bytes total: 158", "response bytes total: 70", "response attributes total: 5", "TLS resumed: 1", "connection checks discarded: 1", "response read samples: 2"} {
		if !strings.Contains(detail, part) {
			t.Errorf("missing %q in %s", part, detail)
		}
	}
	if strings.Contains(detail, "response read p99: 0s") {
		t.Fatal("fabricated zero")
	}
	if got := strings.Count(detail, "\r\n"); got < 50 {
		t.Fatalf("expected >=50 measured/derived entries, got %d", got)
	}
}

func TestInvalidAuthenticatorDoesNotCountResponseAttributes(t *testing.T) {
	r := newRunStats(1, time.Now())
	r.record(protocol.Result{Observations: protocol.Observations{Phases: map[string]time.Duration{"response verify": time.Millisecond}, ResponseBytes: 42}}, errors.New("invalid response authenticator"))
	if got := r.Snapshot().Detailed(); !strings.Contains(got, "response attributes samples: 0") {
		t.Fatalf("invalid response counted as verified: %s", got)
	}
}

func TestDetailedStatsNoSamplesShowUnavailable(t *testing.T) {
	r := newRunStats(1, time.Now())
	s := r.Snapshot()
	detail := s.Detailed()
	for _, part := range []string{"prepare samples: 0", "prepare min: unavailable", "verified latency p95: unavailable", "transport success rate: unavailable", "response bytes mean: unavailable"} {
		if !strings.Contains(detail, part) {
			t.Errorf("missing %q", part)
		}
	}
}
