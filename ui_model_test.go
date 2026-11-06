package main

import (
	"context"
	"crypto/x509"
	"errors"
	"net"
	"strings"
	"syscall"
	"testing"
)

func TestVisibleCredentialFields(t *testing.T) {
	pem := visibleCredentialFields("Separate PEM")
	p12 := visibleCredentialFields("P12/PFX")
	for _, key := range []string{"ca", "cert", "key", "keypass"} {
		if !pem[key] {
			t.Errorf("PEM missing %s", key)
		}
	}
	for _, key := range []string{"p12", "p12pass"} {
		if pem[key] {
			t.Errorf("PEM shows %s", key)
		}
	}
	for _, key := range []string{"ca", "p12", "p12pass"} {
		if !p12[key] {
			t.Errorf("P12 missing %s", key)
		}
	}
	for _, key := range []string{"cert", "key", "keypass"} {
		if p12[key] {
			t.Errorf("P12 shows %s", key)
		}
	}
}

func TestAccountingFieldsOnlyForAccounting(t *testing.T) {
	for _, key := range []string{"status", "session", "sessiontime"} {
		if visibleAccountingFields("auth")[key] {
			t.Errorf("auth shows %s", key)
		}
		if !visibleAccountingFields("acct")[key] {
			t.Errorf("acct hides %s", key)
		}
	}
	if visibleAccountingFields("acct")["password"] || !visibleAccountingFields("auth")["password"] {
		t.Fatal("password must only appear for authentication")
	}
}

func TestCredentialReflowHasNoUnusedRow(t *testing.T) {
	pem := credentialLayout("Separate PEM")
	p12 := credentialLayout("P12/PFX")
	if pem["keypass"].Y <= pem["key"].Y {
		t.Fatal("PEM passphrase should follow key")
	}
	if p12["p12pass"].Y != p12["p12"].Y {
		t.Fatal("P12 password should share bundle row")
	}
	if p12["sectionBottom"].Y >= pem["sectionBottom"].Y {
		t.Fatal("P12 section must collapse unused row")
	}
	if p12["requestTop"].Y >= pem["requestTop"].Y {
		t.Fatal("request must reflow up")
	}
}

func TestLogBoundFilterAndPausedView(t *testing.T) {
	l := newEventLog(3)
	l.add(eventInfo, "one")
	l.setPaused(true)
	l.add(eventError, "two")
	if strings.Contains(l.view(), "two") {
		t.Fatal("paused view changed")
	}
	l.setPaused(false)
	l.add(eventWarn, "three")
	l.add(eventInfo, "four")
	if strings.Contains(l.view(), "one") {
		t.Fatal("unbounded log")
	}
	l.setFilter(eventError, "TWO")
	if got := l.view(); !strings.Contains(got, "two") || strings.Contains(got, "three") {
		t.Fatalf("filter: %q", got)
	}
	l.clear()
	if l.view() != "" {
		t.Fatal("clear retained output")
	}
}

func TestPausedFilterDoesNotRevealIncomingEvents(t *testing.T) {
	l := newEventLog(4)
	l.add(eventInfo, "before")
	l.setPaused(true)
	l.add(eventError, "after")
	l.setFilter(eventInfo, "")
	if strings.Contains(l.view(), "after") {
		t.Fatal("filter exposed events received during pause")
	}
	l.setPaused(false)
	if !strings.Contains(l.view(), "after") {
		t.Fatal("resume should reveal retained events")
	}
}

func TestSafeExchangeErrorCategories(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want string
	}{
		{"dns", &net.DNSError{Err: "no such host", Name: "secret.example"}, "DNS"},
		{"refused", syscall.ECONNREFUSED, "refused"},
		{"timeout", context.DeadlineExceeded, "timed out"},
		{"unknown ca", x509.UnknownAuthorityError{}, "trusted CA"},
		{"hostname", x509.HostnameError{}, "hostname"},
		{"expired", x509.CertificateInvalidError{Reason: x509.Expired}, "expired"},
		{"p12", errors.New("unable to decode P12 client certificate (check file and password)"), "P12"},
		{"authenticator", errors.New("invalid response authenticator"), "shared secret"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := safeExchangeError(tc.err)
			if !strings.Contains(got, tc.want) {
				t.Fatalf("got %q; want %q", got, tc.want)
			}
			if strings.Contains(got, "secret.example") {
				t.Fatal("untrusted DNS name leaked")
			}
		})
	}
}

func TestLogCannotIncludeUntrustedNetworkData(t *testing.T) {
	l := newEventLog(4)
	l.add(eventInfo, "safe\r\nspoof")
	if strings.Contains(l.view(), "\r\nspoof") {
		t.Fatal("line injection")
	}
	if classifyResponse("Access-Reject", nil) != eventWarn {
		t.Fatal("valid reject is not transport failure")
	}
	if classifyResponse("Access-Accept", nil) != eventSuccess {
		t.Fatal("accept")
	}
	if classifyResponse("", errTransport{}) != eventError {
		t.Fatal("transport error")
	}
}

type errTransport struct{}

func (errTransport) Error() string { return "secret" }

func TestFullTransactionControls(t *testing.T) {
	full := visibleAccountingFields("full")
	if !full["password"] || !full["delay"] || full["status"] || full["session"] || full["sessiontime"] {
		t.Fatalf("wrong full transaction controls: %v", full)
	}
	if visibleAccountingFields("auth")["delay"] || visibleAccountingFields("acct")["delay"] {
		t.Fatal("delay must only show for full transaction")
	}
}
