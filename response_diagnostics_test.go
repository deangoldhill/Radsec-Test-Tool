package main

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestResponseValidationCountersAreNotTransportErrors(t *testing.T) {
	for _, raw := range []string{"RADIUS identifier mismatch (expected 131, received 0)", "invalid RADIUS length (4 bytes)", "unexpected RADIUS response code 12", "malformed RADIUS attributes", "invalid response authenticator", "invalid response Message-Authenticator"} {
		if !responseValidationError(errors.New(raw)) {
			t.Errorf("not classified as response error: %s", raw)
		}
	}
	if responseValidationError(nil) || responseValidationError(context.DeadlineExceeded) {
		t.Fatal("transport errors misclassified")
	}
}

func TestSafeResponseDiagnosticsDistinguishParserFailures(t *testing.T) {
	cases := []struct{ raw, expected string }{
		{"RADIUS identifier mismatch (expected 131, received 0)", "RADIUS response ID mismatch: expected 131, received 0"},
		{"invalid RADIUS length (4 bytes)", "RADIUS response length invalid: 4 bytes"},
		{"unexpected RADIUS response code 12", "Unexpected RADIUS response code 12"},
		{"malformed RADIUS attributes", "Malformed RADIUS response attributes"},
	}
	for _, tc := range cases {
		t.Run(tc.raw, func(t *testing.T) {
			got := safeExchangeError(errors.New(tc.raw))
			if !strings.Contains(got, tc.expected) {
				t.Fatalf("got %q, want safe detail %q", got, tc.expected)
			}
		})
	}
}
