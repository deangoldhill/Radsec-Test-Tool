package protocol

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestTransactionSequenceAndDelay(t *testing.T) {
	var calls []Request
	var sleeps []time.Duration
	q := Request{Username: "alice", Password: "pass", Extra: "NAS-Identifier = test"}
	stages, err := transaction(Config{Secret: "secret"}, q, 25*time.Millisecond, func(_ Config, r Request) (Result, error) {
		calls = append(calls, r)
		if r.Kind == "auth" {
			return Result{Name: "Access-Accept"}, nil
		}
		return Result{Name: "Accounting-Response"}, nil
	}, func(d time.Duration) { sleeps = append(sleeps, d) })
	if err != nil || len(stages) != 4 || len(calls) != 4 || len(sleeps) != 2 {
		t.Fatalf("stages=%v calls=%v sleeps=%v err=%v", stages, calls, sleeps, err)
	}
	for i, status := range []string{"Start", "Interim-Update", "Stop"} {
		if calls[i+1].Kind != "acct" || calls[i+1].Status != status || calls[i+1].SessionID != calls[1].SessionID || calls[i+1].Password != "" {
			t.Fatalf("stage %d: %+v", i, calls[i+1])
		}
	}
	if len(calls[1].SessionID) < 20 || calls[0].SessionID != "" || q.SessionID != "" {
		t.Fatal("session ID isolation failed")
	}
	for _, d := range sleeps {
		if d != 25*time.Millisecond {
			t.Fatal(d)
		}
	}
}
func TestTransactionStopsAtEveryFailure(t *testing.T) {
	for fail := 0; fail < 4; fail++ {
		t.Run([]string{"auth", "start", "interim", "stop"}[fail], func(t *testing.T) {
			calls := 0
			sleeps := 0
			stages, err := transaction(Config{Secret: "s"}, Request{Username: "u", Password: "p"}, 0, func(_ Config, r Request) (Result, error) {
				calls++
				if calls == fail+1 {
					return Result{}, errors.New("failed")
				}
				if r.Kind == "auth" {
					return Result{Name: "Access-Accept"}, nil
				}
				return Result{Name: "Accounting-Response"}, nil
			}, func(time.Duration) { sleeps++ })
			if err == nil || len(stages) != fail+1 || calls != fail+1 || sleeps != 0 {
				t.Fatalf("stages=%d calls=%d sleeps=%d err=%v", len(stages), calls, sleeps, err)
			}
		})
	}
	for _, name := range []string{"Access-Reject", "Access-Challenge"} {
		calls := 0
		_, err := transaction(Config{Secret: "s"}, Request{Username: "u", Password: "p"}, 0, func(Config, Request) (Result, error) { calls++; return Result{Name: name}, nil }, func(time.Duration) {})
		if err == nil || calls != 1 {
			t.Fatalf("%s: calls=%d err=%v", name, calls, err)
		}
	}
}
func TestTransactionRejectsInvalidBeforeSending(t *testing.T) {
	calls := 0
	for _, q := range []Request{{Username: "u"}, {Username: "u", Password: "p", Extra: "unknown=x"}} {
		_, err := transaction(Config{Secret: "s"}, q, 0, func(Config, Request) (Result, error) { calls++; return Result{}, nil }, func(time.Duration) {})
		if err == nil {
			t.Fatal("expected validation error")
		}
	}
	_, err := transaction(Config{Secret: "s"}, Request{Username: "u", Password: "p"}, -time.Second, func(Config, Request) (Result, error) { calls++; return Result{}, nil }, func(time.Duration) {})
	if err == nil || !strings.Contains(err.Error(), "delay") || calls != 0 {
		t.Fatalf("err=%v calls=%d", err, calls)
	}
}
func TestTransactionDistinctSessions(t *testing.T) {
	ids := make([]string, 0, 2)
	for i := 0; i < 2; i++ {
		_, err := transaction(Config{Secret: "s"}, Request{Username: "u", Password: "p"}, 0, func(_ Config, r Request) (Result, error) {
			if r.Status == "Start" {
				ids = append(ids, r.SessionID)
			}
			if r.Kind == "auth" {
				return Result{Name: "Access-Accept"}, nil
			}
			return Result{Name: "Accounting-Response"}, nil
		}, func(time.Duration) {})
		if err != nil {
			t.Fatal(err)
		}
	}
	if ids[0] == ids[1] {
		t.Fatal("duplicate session IDs")
	}
}
