package protocol

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestExchangeContextHonorsAlreadyCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := ExchangeContext(ctx, Config{Host: "127.0.0.1", Port: "9", Secret: "secret", Timeout: time.Second}, Request{Kind: "auth", Username: "user", Password: "pw"})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected cancellation, got %v", err)
	}
}
