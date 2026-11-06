package main

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"
)

type severity int

const (
	eventInfo severity = iota
	eventSuccess
	eventWarn
	eventError
)

type logEntry struct {
	level   severity
	message string
}
type eventLog struct {
	entries       []logEntry
	limit         int
	paused        bool
	frozenEntries []logEntry
	minLevel      severity
	search        string
}

func newEventLog(limit int) *eventLog {
	if limit < 1 {
		limit = 1
	}
	return &eventLog{limit: limit}
}
func (l *eventLog) add(level severity, message string) {
	// Only callers holding trusted, fixed-format diagnostics may use this method.
	message = strings.NewReplacer("\r", " ", "\n", " ", "\x00", " ").Replace(message)
	if len(message) > 600 {
		message = message[:600] + "…"
	}
	if len(l.entries) == l.limit {
		copy(l.entries, l.entries[1:])
		l.entries = l.entries[:l.limit-1]
	}
	l.entries = append(l.entries, logEntry{level, message})
}
func (l *eventLog) rendered(entries []logEntry) string {
	var b strings.Builder
	for _, e := range entries {
		if e.level < l.minLevel || !strings.Contains(strings.ToLower(e.message), strings.ToLower(l.search)) {
			continue
		}
		prefix := []string{"INFO", "OK", "REJECT", "ERROR"}[e.level]
		b.WriteString("[" + prefix + "] " + e.message + "\r\n")
	}
	return b.String()
}
func (l *eventLog) view() string {
	if l.paused {
		return l.rendered(l.frozenEntries)
	}
	return l.rendered(l.entries)
}
func (l *eventLog) setPaused(p bool) {
	if p && !l.paused {
		l.frozenEntries = append([]logEntry(nil), l.entries...)
	}
	l.paused = p
	if !p {
		l.frozenEntries = nil
	}
}
func (l *eventLog) setFilter(level severity, search string) { l.minLevel, l.search = level, search }
func (l *eventLog) clear()                                  { l.entries = nil; l.frozenEntries = nil }
func classifyResponse(name string, err error) severity {
	if err != nil {
		return eventError
	}
	if name == "Access-Reject" {
		return eventWarn
	}
	return eventSuccess
}

type uiPosition struct{ X, Y int }

func credentialLayout(mode string) map[string]uiPosition {
	out := map[string]uiPosition{"credentials": {38, 319}, "ca": {0, 319}, "cert": {38, 375}, "key": {0, 375}, "keypass": {38, 431}, "p12": {38, 375}, "p12pass": {0, 375}, "sectionBottom": {0, 484}, "requestTop": {0, 496}}
	if mode == "P12/PFX" {
		out["sectionBottom"] = uiPosition{0, 428}
		out["requestTop"] = uiPosition{0, 440}
	}
	return out
}
func visibleAccountingFields(kind string) map[string]bool {
	return map[string]bool{"status": kind == "acct", "session": kind == "acct", "sessiontime": kind == "acct", "password": kind == "auth" || kind == "full", "delay": kind == "full"}
}
func visibleCredentialFields(mode string) map[string]bool {
	out := map[string]bool{"ca": true}
	switch mode {
	case "Separate PEM":
		out["cert"], out["key"], out["keypass"] = true, true, true
	case "P12/PFX":
		out["p12"], out["p12pass"] = true, true
	}
	return out
}

// Diagnostic messages are fixed and actionable. Never return err.Error(): it may
// contain user-entered paths, a peer-controlled subject, or password material.
func safeExchangeError(err error) string {
	if err == nil {
		return ""
	}
	var unknownCA x509.UnknownAuthorityError
	var hostname x509.HostnameError
	var certInvalid x509.CertificateInvalidError
	var dns *net.DNSError
	if errors.As(err, &unknownCA) {
		return "TLS trust failed: server certificate is not signed by a trusted CA. Select the issuing CA PEM or fix the server chain."
	}
	if errors.As(err, &hostname) {
		return "TLS hostname mismatch: verification name must match the server certificate SAN. Check host, SNI and verification name."
	}
	if errors.As(err, &certInvalid) {
		if certInvalid.Reason == x509.Expired {
			return "TLS certificate expired or not yet valid. Check certificate dates and system clock."
		}
		return "TLS server certificate invalid. Check chain, usage and validity."
	}
	if errors.As(err, &dns) {
		return "DNS lookup failed. Check RadSec host spelling and resolver connectivity."
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded) || os.IsTimeout(err) {
		return "Connection or packet timed out. Check firewall, port, server response and per-request timeout."
	}
	if errors.Is(err, syscall.ECONNREFUSED) || strings.Contains(err.Error(), "connection refused") {
		return "TCP connection refused. Check RadSec host, port and listener."
	}
	// Recognize only fixed internal protocol messages; never interpolate raw error text.
	message := err.Error()
	switch {
	case strings.Contains(message, "unable to decode P12 client certificate"), strings.Contains(message, "pkcs12: incorrect password"):
		return "P12/PFX decode failed. Check bundle and password."
	case strings.Contains(message, "private key passphrase"):
		return "PEM private key failed to decrypt. Check key passphrase and key format."
	case strings.Contains(message, "invalid response authenticator"), strings.Contains(message, "invalid response Message-Authenticator"):
		return "RADIUS response authenticator invalid. Check shared secret and server configuration."
	case strings.HasPrefix(message, "RADIUS identifier mismatch (expected "):
		var expected, received int
		if n, scanErr := fmt.Sscanf(message, "RADIUS identifier mismatch (expected %d, received %d)", &expected, &received); scanErr == nil && n == 2 && expected >= 0 && expected <= 255 && received >= 0 && received <= 255 {
			return fmt.Sprintf("RADIUS response ID mismatch: expected %d, received %d. Check for an unrelated response on this TLS connection.", expected, received)
		}
		return "RADIUS response ID mismatch. Check for an unrelated response on this TLS connection."
	case strings.HasPrefix(message, "invalid RADIUS length ("):
		var length int
		if n, scanErr := fmt.Sscanf(message, "invalid RADIUS length (%d bytes)", &length); scanErr == nil && n == 1 && length >= 0 && length <= 65535 {
			return fmt.Sprintf("RADIUS response length invalid: %d bytes. Check the RadSec listener or proxy.", length)
		}
		return "RADIUS response length invalid. Check the RadSec listener or proxy."
	case strings.HasPrefix(message, "unexpected RADIUS response code "):
		if code, parseErr := strconv.Atoi(strings.TrimPrefix(message, "unexpected RADIUS response code ")); parseErr == nil && code >= 0 && code <= 255 {
			return fmt.Sprintf("Unexpected RADIUS response code %d. Check listener or proxy response type.", code)
		}
		return "Unexpected RADIUS response code. Check listener or proxy response type."
	case strings.Contains(message, "malformed RADIUS attributes"):
		return "Malformed RADIUS response attributes. Check the RadSec listener or proxy."
	case strings.Contains(message, "RADIUS identifier mismatch"), strings.Contains(message, "invalid RADIUS length"):
		return "Invalid RADIUS response. Check listener or proxy."
	case strings.Contains(message, "invalid CA PEM"):
		return "Trusted CA PEM could not be parsed. Select a PEM certificate file."
	case strings.Contains(message, "SNI and verification name must match"):
		return "SNI must match the TLS verification name. Use the same DNS name in both fields."
	case strings.Contains(message, "read P12 file"):
		return "Cannot read P12/PFX bundle. Check path and file permissions."
	case strings.Contains(message, "tls: bad certificate"), strings.Contains(message, "tls: certificate required"):
		return "TLS peer rejected the client certificate. Check certificate, private key and trusted issuing CA."
	default:
		return "Connection, TLS, or RADIUS exchange failed. Check endpoint, trust, certificate and shared secret."
	}
}

// Response validation failures are not transport failures. Keep counters
// separate without exposing a peer-controlled packet or credential in logs.
func responseValidationError(err error) bool {
	if err == nil {
		return false
	}
	message := err.Error()
	for _, marker := range []string{"RADIUS identifier mismatch", "invalid RADIUS length", "unexpected RADIUS response code", "malformed RADIUS attributes", "invalid response authenticator", "invalid response Message-Authenticator"} {
		if strings.Contains(message, marker) {
			return true
		}
	}
	return false
}
