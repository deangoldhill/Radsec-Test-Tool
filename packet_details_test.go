package main

import (
	"errors"
	"radsec-windows-tester/protocol"
	"strings"
	"testing"
	"time"
)

func TestDetailsCountsPacketsAndMalformedRepliesWithoutInventingSuccess(t *testing.T) {
	r := newRunStats(2, time.Now())
	r.record(protocol.Result{Observations: protocol.Observations{RequestPackets: 1, ResponsePackets: 1, RequestBytes: 40, ResponseBytes: 20}}, nil)
	r.record(protocol.Result{Observations: protocol.Observations{RequestPackets: 1, RequestBytes: 40}}, errors.New("invalid RADIUS length (4 bytes)"))
	details := r.Snapshot().Detailed()
	if rows := strings.Count(details, "\r\n"); rows < 50 {
		t.Fatalf("detailed stats have only %d rows; want at least 50", rows)
	}
	for _, want := range []string{"requests sent: 2", "responses received: 1", "malformed responses: 1", "resource exhaustion: unavailable"} {
		if !strings.Contains(details, want) {
			t.Errorf("missing %q from details", want)
		}
	}
}
